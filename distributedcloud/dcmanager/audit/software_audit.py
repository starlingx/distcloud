#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from keystoneauth1.session import Session as keystone_session
from oslo_log import log as logging
from tsconfig.tsconfig import SW_VERSION

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.sdk_platform import OpenStackDriver
from dccommon.drivers.openstack import software_v1
from dccommon.drivers.openstack.software_v1 import SoftwareClient
from dccommon import utils as dccommon_utils
from dcmanager.common import utils
from dcmanager.db.sqlalchemy import models

LOG = logging.getLogger(__name__)


class SoftwareAuditData(object):
    def __init__(self, releases, deployed_release_ids):
        self.releases = releases
        self.deployed_release_ids = deployed_release_ids

    def to_dict(self):
        return {
            "releases": self.releases,
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
            m_os_ks_client = OpenStackDriver(
                region_name=dccommon_consts.DEFAULT_REGION_NAME,
                region_clients=None,
                fetch_subcloud_ips=utils.fetch_subcloud_mgmt_ips,
            ).keystone_client
            software_endpoint = m_os_ks_client.endpoint_cache.get_endpoint(
                dccommon_consts.ENDPOINT_NAME_USM
            )
            software_client = SoftwareClient(
                m_os_ks_client.session,
                dccommon_consts.DEFAULT_REGION_NAME,
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
        for release in regionone_releases:
            if release["state"] == software_v1.DEPLOYED:
                deployed_release_ids.append(release["release_id"])
        LOG.debug(f"RegionOne deployed_release_ids: {deployed_release_ids}")
        return SoftwareAuditData(regionone_releases, deployed_release_ids)

    @classmethod
    def get_subcloud_audit_data(
        cls, software_client: SoftwareClient, subcloud_name: str = None
    ):
        # Retrieve all the releases that are present in this subcloud.
        try:
            subcloud_releases = software_client.list()
        except Exception:
            msg = "Cannot retrieve subcloud releases, skip software audit."
            dccommon_utils.log_subcloud_msg(LOG.warn, msg, subcloud_name)
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
        dccommon_utils.log_subcloud_msg(LOG.debug, msg, subcloud_name)

        sync_status = dccommon_consts.SYNC_STATUS_IN_SYNC

        # audit_data will be a dict due to passing through RPC so objectify it
        audit_data = SoftwareAuditData.from_dict(audit_data)
        expected_releases = set(audit_data.deployed_release_ids)
        deployed_releases = {
            release["release_id"]
            for release in subcloud_releases
            if release["state"] == software_v1.DEPLOYED
        }

        # Releases in state DEPLOYED found in the SystemController and not
        # in the subcloud
        missing_releases = expected_releases - deployed_releases

        # Releases in state DEPLOYED found in the Subcloud and not
        # in the SystemController
        extra_releases = deployed_releases - expected_releases

        if missing_releases or extra_releases:
            sync_status = dccommon_consts.SYNC_STATUS_OUT_OF_SYNC

            if missing_releases:
                msg = (
                    f"Releases: {missing_releases} are missing or not deployed "
                    "on the subcloud."
                )
                dccommon_utils.log_subcloud_msg(LOG.debug, msg, subcloud_name)
            if extra_releases:
                msg = f"Extra deployed releases found in the subcloud: {extra_releases}"
                dccommon_utils.log_subcloud_msg(LOG.debug, msg, subcloud_name)
        return sync_status

    def subcloud_software_audit(
        self,
        keystone_session: keystone_session,
        subcloud: models.Subcloud,
        audit_data: SoftwareAuditData,
    ):
        LOG.info(f"Triggered software audit for: {subcloud.name}.")
        # TODO(nicodemos): Remove this method after all support to patching is removed
        # NOTE(nicodemos): Software audit not support on 22.12 subcloud without USM
        if subcloud.software_version != SW_VERSION and not utils.has_usm_service(
            subcloud.region_name, keystone_session
        ):
            LOG.info(f"Software audit not supported for {subcloud.name} without USM.")
            return dccommon_consts.SYNC_STATUS_NOT_AVAILABLE

        try:
            software_endpoint = dccommon_utils.build_subcloud_endpoint(
                subcloud.management_start_ip, dccommon_consts.ENDPOINT_NAME_USM
            )
            software_client = SoftwareClient(
                keystone_session, endpoint=software_endpoint
            )
        except Exception:
            LOG.exception(
                f"Failed to get Software Client for subcloud: {subcloud.name}"
            )
            return None

        sync_status = self.get_subcloud_sync_status(
            software_client, audit_data, subcloud.name
        )

        if sync_status:
            LOG.info(
                f"Software audit completed for: {subcloud.name}, requesting "
                f"sync_status update to {sync_status}"
            )
            return sync_status
