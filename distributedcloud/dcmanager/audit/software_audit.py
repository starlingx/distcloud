#
# Copyright (c) 2024-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_log import log as logging

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack import software_v1
from dccommon.drivers.openstack.software_v1 import SoftwareClient
from dccommon import endpoint_cache
from dccommon import utils as cutils
from dcmanager.common import utils

LOG = logging.getLogger(__name__)


class SoftwareAuditData(object):
    def __init__(self, deployed_release_ids, deployed_metapackages=None):
        self.deployed_release_ids = deployed_release_ids
        # Metapackages deployed on RegionOne for releases in the
        # deployed-partial state. Defaults to an empty list so the object
        # stays compatible with peers that send a payload without it.
        self.deployed_metapackages = deployed_metapackages or []

    def to_dict(self):
        data = {
            "deployed_release_ids": self.deployed_release_ids,
        }
        # Only include the metapackages when there are any, so the payload
        # sent to the subcloud keeps its original shape when there is nothing
        # to report. This avoids breaking N-1 subclouds whose dcagent does not
        # yet understand this field.
        if self.deployed_metapackages:
            data["deployed_metapackages"] = self.deployed_metapackages
        return data

    @classmethod
    def from_dict(cls, values):
        if values is None:
            return None
        # Ignore any unknown keys so a newer peer can add fields to the
        # payload without breaking an older peer that does not understand
        # them yet.
        known_fields = ("deployed_release_ids", "deployed_metapackages")
        filtered = {key: values[key] for key in known_fields if key in values}
        return cls(**filtered)


class SoftwareAudit(object):
    """Manages tasks related to software audits."""

    def __init__(self):
        LOG.debug("SoftwareAudit initialization...")
        self.audit_count = 0

    def get_regionone_audit_data(self):
        """Query RegionOne to determine what releases should be deployed

        to the system as well as the current software version

        :return: A new SoftwareAuditData object
        """
        try:
            admin_session = endpoint_cache.EndpointCache.get_admin_session()
            software_client = SoftwareClient(
                admin_session,
                region=cutils.get_region_one_name(),
            )
        except Exception:
            LOG.exception("Failure initializing OS Client, skip software audit.")
            return None
        # First query RegionOne to determine what releases should be deployed
        # to the system.
        regionone_releases = software_client.list()
        LOG.debug(f"regionone_releases: {regionone_releases}")

        # Build lists of releases that should be deployed or committed in all
        # subclouds, based on their state in RegionOne. A release in the
        # deployed-partial state is also considered deployed: it has a product
        # release applied with only a subset of its metapackages.
        deployed_release_ids = list()
        for release in regionone_releases:
            if release["state"] in (
                software_v1.DEPLOYED,
                software_v1.DEPLOYED_PARTIAL,
            ):
                deployed_release_ids.append(release["release_id"])

        # Metapackages deployed for the deployed-partial releases. Used to
        # compare against the subcloud and decide the sync status.
        deployed_metapackages = utils.get_deployed_metapackages(regionone_releases)
        LOG.debug(f"RegionOne deployed_release_ids: {deployed_release_ids}")
        LOG.debug(f"RegionOne deployed_metapackages: {deployed_metapackages}")
        return SoftwareAuditData(deployed_release_ids, list(deployed_metapackages))

    @classmethod
    def get_subcloud_audit_data(
        cls, software_client: SoftwareClient, subcloud_name: str = None
    ):
        # Retrieve all the releases that are present in this subcloud.
        try:
            subcloud_releases = software_client.list()
        except Exception:
            msg = "Cannot retrieve subcloud releases, skip software audit."
            cutils.log_subcloud_msg(LOG.warn, msg, subcloud_name)
            return dccommon_consts.SKIP_AUDIT
        return subcloud_releases

    @classmethod
    def get_subcloud_sync_status(
        cls,
        software_client: SoftwareClient,
        audit_data: SoftwareAuditData,
        subcloud_name: str = None,
    ):
        # Retrieve all the releases that are present in this subcloud.
        subcloud_releases = cls.get_subcloud_audit_data(software_client)
        if subcloud_releases == dccommon_consts.SKIP_AUDIT:
            return None

        msg = f"Releases: {subcloud_releases}"
        cutils.log_subcloud_msg(LOG.debug, msg, subcloud_name)

        sync_status = dccommon_consts.SYNC_STATUS_IN_SYNC

        # audit_data will be a dict due to passing through RPC so objectify it
        audit_data = SoftwareAuditData.from_dict(audit_data)
        expected_releases = set()
        expected_metapackages = set()
        if audit_data:
            expected_releases = set(audit_data.deployed_release_ids)
            expected_metapackages = set(audit_data.deployed_metapackages)
        # A release in the deployed-partial state is considered deployed, with
        # its metapackages audited separately below.
        deployed_releases = {
            release["release_id"]
            for release in subcloud_releases
            if release["state"] in (software_v1.DEPLOYED, software_v1.DEPLOYED_PARTIAL)
        }
        subcloud_metapackages = utils.get_deployed_metapackages(subcloud_releases)
        # TODO(vgluzrom): change audit logic when software supports auditing
        # optional patches
        subcloud_software_version = utils.get_software_version(deployed_releases)
        latest_central_release = utils.get_latest_minor_release(expected_releases)
        latest_subcloud_release = utils.get_latest_minor_release(deployed_releases)
        if latest_central_release != latest_subcloud_release:
            sync_status = dccommon_consts.SYNC_STATUS_OUT_OF_SYNC
        # For the deployed-partial state, the system controller and the subcloud
        # are only in-sync when they have the same metapackages deployed. If one
        # has a deployed-partial release while the other has it fully deployed,
        # their deployed metapackages differ and the result is out-of-sync.
        elif expected_metapackages != subcloud_metapackages:
            sync_status = dccommon_consts.SYNC_STATUS_OUT_OF_SYNC

        return {
            "sync_status": sync_status,
            "software_version": subcloud_software_version,
        }
