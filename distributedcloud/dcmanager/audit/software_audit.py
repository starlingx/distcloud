#
# Copyright (c) 2024-2025 Wind River Systems, Inc.
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
    def __init__(self, deployed_release_ids):
        self.deployed_release_ids = deployed_release_ids

    def to_dict(self):
        return {
            "deployed_release_ids": self.deployed_release_ids,
        }

    @classmethod
    def from_dict(cls, values):
        if values is None:
            return None
        return cls(**values)


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
        # subclouds, based on their state in RegionOne.
        deployed_release_ids = list()
        for release in regionone_releases:
            if release["state"] == software_v1.DEPLOYED:
                deployed_release_ids.append(release["release_id"])
        LOG.debug(f"RegionOne deployed_release_ids: {deployed_release_ids}")
        return SoftwareAuditData(deployed_release_ids)

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
        if audit_data:
            expected_releases = set(audit_data.deployed_release_ids)
        deployed_releases = {
            release["release_id"]
            for release in subcloud_releases
            if release["state"] == software_v1.DEPLOYED
        }
        # TODO(vgluzrom): change audit logic when software supports auditing
        # optional patches
        subcloud_software_version = utils.get_software_version(deployed_releases)
        latest_central_release = utils.get_latest_minor_release(expected_releases)
        latest_subcloud_release = utils.get_latest_minor_release(deployed_releases)
        if latest_central_release != latest_subcloud_release:
            sync_status = dccommon_consts.SYNC_STATUS_OUT_OF_SYNC

        return {
            "sync_status": sync_status,
            "software_version": subcloud_software_version,
        }
