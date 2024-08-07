#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from keystoneauth1 import exceptions as keystone_exceptions
from oslo_log import log as logging

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.keystone_v3 import KeystoneClient as ks_client
from dccommon.drivers.openstack import sdk_platform
from dccommon.drivers.openstack import software_v1
from dccommon.endpoint_cache import build_subcloud_endpoint
from dccommon.utils import log_subcloud_msg
from dcmanager.common import utils

LOG = logging.getLogger(__name__)


class SoftwareAuditData(object):
    def __init__(self, releases, deployed_release_ids, committed_release_ids):
        self.releases = releases
        self.deployed_release_ids = deployed_release_ids
        self.committed_release_ids = committed_release_ids

    def to_dict(self):
        return {
            "releases": self.releases,
            "deployed_release_ids": self.deployed_release_ids,
            "committed_release_ids": self.committed_release_ids,
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

    @staticmethod
    def _get_upgrades(sysinv_client):
        upgrades = None
        try:
            upgrades = sysinv_client.get_upgrades()
        except Exception:
            LOG.exception(
                "Cannot retrieve upgrade info for "
                f"subcloud: {sysinv_client.region_name}"
            )
        return upgrades

    def get_regionone_audit_data(self):
        """Query RegionOne to determine what releases should be deployed

        to the system as well as the current software version

        :return: A new SoftwareAuditData object
        """
        try:
            m_os_ks_client = sdk_platform.OpenStackDriver(
                region_name=dccommon_consts.DEFAULT_REGION_NAME,
                region_clients=None,
                fetch_subcloud_ips=utils.fetch_subcloud_mgmt_ips,
            ).keystone_client
            software_endpoint = m_os_ks_client.endpoint_cache.get_endpoint(
                dccommon_consts.ENDPOINT_TYPE_SOFTWARE
            )
            software_client = software_v1.SoftwareClient(
                dccommon_consts.DEFAULT_REGION_NAME,
                m_os_ks_client.session,
                endpoint=software_endpoint,
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
        committed_release_ids = list()
        for release in regionone_releases:
            if release["state"] == software_v1.DEPLOYED:
                deployed_release_ids.append(release["release_id"])
            elif release["state"] == software_v1.COMMITTED:
                committed_release_ids.append(release["release_id"])
        LOG.debug(f"RegionOne deployed_release_ids: {deployed_release_ids}")
        LOG.debug(f"RegionOne committed_release_ids: {committed_release_ids}")
        return SoftwareAuditData(
            regionone_releases, deployed_release_ids, committed_release_ids
        )

    @classmethod
    def get_subcloud_audit_data(
        cls, software_client: software_v1.SoftwareClient, subcloud_name: str = None
    ):
        # Retrieve all the releases that are present in this subcloud.
        try:
            subcloud_releases = software_client.list()
        except Exception:
            msg = "Cannot retrieve releases, skip software audit."
            log_subcloud_msg(LOG.warn, msg, subcloud_name)
            return dccommon_consts.SKIP_AUDIT
        return subcloud_releases

    @classmethod
    def get_subcloud_sync_status(
        cls,
        software_client: software_v1.SoftwareClient,
        audit_data: SoftwareAuditData,
        subcloud_name: str = None,
    ):
        # Retrieve all the releases that are present in this subcloud.
        subcloud_releases = cls.get_subcloud_audit_data(software_client)
        if subcloud_releases == dccommon_consts.SKIP_AUDIT:
            return None

        msg = f"Releases: {subcloud_releases}"
        log_subcloud_msg(LOG.debug, msg, subcloud_name)

        sync_status = dccommon_consts.SYNC_STATUS_IN_SYNC

        # audit_data will be a dict due to passing through RPC so objectify it
        audit_data = SoftwareAuditData.from_dict(audit_data)

        # Check that all releases in this subcloud are in the correct
        # state, based on the state of the release in RegionOne. For the
        # subcloud.
        for release in subcloud_releases:
            release_id = release.get("release_id")
            if release["state"] == software_v1.DEPLOYED:
                if release_id not in audit_data.deployed_release_ids:
                    if release_id not in audit_data.committed_release_ids:
                        msg = f"Release {release_id} should not be deployed."
                        log_subcloud_msg(LOG.debug, msg, subcloud_name)
                    else:
                        msg = f"Release {release_id} should be committed."
                        log_subcloud_msg(LOG.debug, msg, subcloud_name)
                    sync_status = dccommon_consts.SYNC_STATUS_OUT_OF_SYNC
            elif release["state"] == software_v1.COMMITTED:
                if (
                    release_id not in audit_data.committed_release_ids
                    and release_id not in audit_data.deployed_release_ids
                ):
                    msg = f"Release {release_id} should not be committed."
                    log_subcloud_msg(LOG.warn, msg, subcloud_name)
                    sync_status = dccommon_consts.SYNC_STATUS_OUT_OF_SYNC
            else:
                # In steady state, all releases should either be deployed
                # or committed in each subcloud. Release in other
                # states mean a sync is required.
                sync_status = dccommon_consts.SYNC_STATUS_OUT_OF_SYNC

        # Check that all deployed or committed releases in RegionOne are
        # present in the subcloud.
        for release_id in audit_data.deployed_release_ids:
            if not any(
                release["release_id"] == release_id for release in subcloud_releases
            ):
                msg = f"Release {release_id} is missing."
                log_subcloud_msg(LOG.debug, msg, subcloud_name)
                sync_status = dccommon_consts.SYNC_STATUS_OUT_OF_SYNC
        for release_id in audit_data.committed_release_ids:
            if not any(
                release["release_id"] == release_id for release in subcloud_releases
            ):
                msg = f"Release {release_id} is missing."
                log_subcloud_msg(LOG.debug, msg, subcloud_name)
                sync_status = dccommon_consts.SYNC_STATUS_OUT_OF_SYNC

        return sync_status

    def subcloud_software_audit(
        self,
        keystone_client: ks_client,
        subcloud_management_ip: str,
        subcloud_name: str,
        subcloud_region: str,
        audit_data: SoftwareAuditData,
    ):
        LOG.info(f"Triggered software audit for: {subcloud_name}.")
        try:
            software_endpoint = build_subcloud_endpoint(
                subcloud_management_ip, dccommon_consts.ENDPOINT_TYPE_SOFTWARE
            )
            software_client = software_v1.SoftwareClient(
                subcloud_region, keystone_client.session, endpoint=software_endpoint
            )
        except (
            keystone_exceptions.EndpointNotFound,
            keystone_exceptions.ConnectFailure,
            keystone_exceptions.ConnectTimeout,
            IndexError,
        ):
            LOG.exception(
                f"Endpoint for online subcloud {subcloud_name} not found, skip "
                "software audit."
            )
            return None

        sync_status = self.get_subcloud_sync_status(
            software_client, audit_data, subcloud_name
        )

        if sync_status:
            LOG.info(
                f"Software audit completed for: {subcloud_name}, requesting "
                f"sync_status update to {sync_status}"
            )
            return sync_status
