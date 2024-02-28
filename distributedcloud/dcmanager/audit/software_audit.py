#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from keystoneauth1 import exceptions as keystone_exceptions
from oslo_log import log as logging

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack import sdk_platform
from dccommon.drivers.openstack import software_v1

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

    def __init__(self, context, dcmanager_state_rpc_client):
        LOG.debug("SoftwareAudit initialization...")
        self.context = context
        self.state_rpc_client = dcmanager_state_rpc_client
        self.audit_count = 0

    def _update_subcloud_sync_status(
        self, sc_name, sc_region, sc_endpoint_type, sc_status
    ):
        self.state_rpc_client.update_subcloud_endpoint_status(
            self.context,
            subcloud_name=sc_name,
            subcloud_region=sc_region,
            endpoint_type=sc_endpoint_type,
            sync_status=sc_status,
        )

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
                region_name=dccommon_consts.DEFAULT_REGION_NAME, region_clients=None
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
        regionone_releases = software_client.query()
        LOG.debug(f"regionone_releases: {regionone_releases}")
        # Build lists of releases that should be deployed or committed in all
        # subclouds, based on their state in RegionOne.
        deployed_release_ids = list()
        committed_release_ids = list()
        for release_id in regionone_releases.keys():
            if regionone_releases[release_id]["state"] == software_v1.DEPLOYED:
                deployed_release_ids.append(release_id)
            elif regionone_releases[release_id]["state"] == software_v1.COMMITTED:
                committed_release_ids.append(release_id)
        LOG.debug(f"RegionOne deployed_release_ids: {deployed_release_ids}")
        LOG.debug(f"RegionOne committed_release_ids: {committed_release_ids}")
        return SoftwareAuditData(
            regionone_releases, deployed_release_ids, committed_release_ids
        )

    def subcloud_software_audit(self, subcloud_name, subcloud_region, audit_data):
        LOG.info(f"Triggered software audit for: {subcloud_name}.")
        try:
            sc_os_client = sdk_platform.OpenStackDriver(
                region_name=subcloud_region, region_clients=None
            ).keystone_client
            session = sc_os_client.session
            software_endpoint = sc_os_client.endpoint_cache.get_endpoint(
                dccommon_consts.ENDPOINT_TYPE_SOFTWARE
            )
            software_client = software_v1.SoftwareClient(
                subcloud_region, session, endpoint=software_endpoint
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
            return

        # Retrieve all the releases that are present in this subcloud.
        try:
            subcloud_releases = software_client.query()
            LOG.debug(f"Releases for subcloud {subcloud_name}: {subcloud_releases}")
        except Exception:
            LOG.warn(
                f"Cannot retrieve releases for subcloud: {subcloud_name}, "
                "skip software audit."
            )
            return

        out_of_sync = False

        # audit_data will be a dict due to passing through RPC so objectify it
        audit_data = SoftwareAuditData.from_dict(audit_data)

        # Check that all releases in this subcloud are in the correct
        # state, based on the state of the release in RegionOne. For the
        # subcloud.
        for release_id in subcloud_releases.keys():
            if subcloud_releases[release_id]["state"] == software_v1.DEPLOYED:
                if release_id not in audit_data.deployed_release_ids:
                    if release_id not in audit_data.committed_release_ids:
                        LOG.debug(
                            f"Release {release_id} should not be deployed "
                            f"in {subcloud_name}."
                        )
                    else:
                        LOG.debug(
                            f"Release {release_id} should be committed "
                            f"in {subcloud_name}."
                        )
                    out_of_sync = True
            elif subcloud_releases[release_id]["state"] == software_v1.COMMITTED:
                if (
                    release_id not in audit_data.committed_release_ids
                    and release_id not in audit_data.deployed_release_ids
                ):
                    LOG.warn(
                        f"Release {release_id} should not be committed "
                        f"in {subcloud_name}."
                    )
                    out_of_sync = True
            else:
                # In steady state, all releases should either be deployed
                # or committed in each subcloud. Release in other
                # states mean a sync is required.
                out_of_sync = True

        # Check that all deployed or committed releases in RegionOne are
        # present in the subcloud.
        for release_id in audit_data.deployed_release_ids:
            if release_id not in subcloud_releases:
                LOG.debug(f"Release {release_id} missing from {subcloud_name}.")
                out_of_sync = True
        for release_id in audit_data.committed_release_ids:
            if release_id not in subcloud_releases:
                LOG.debug(f"Release {release_id} missing from {subcloud_name}.")
                out_of_sync = True

        if out_of_sync:
            self._update_subcloud_sync_status(
                subcloud_name,
                subcloud_region,
                dccommon_consts.ENDPOINT_TYPE_SOFTWARE,
                dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
            )
        else:
            self._update_subcloud_sync_status(
                subcloud_name,
                subcloud_region,
                dccommon_consts.ENDPOINT_TYPE_SOFTWARE,
                dccommon_consts.SYNC_STATUS_IN_SYNC,
            )
        LOG.info(f"Software audit completed for: {subcloud_name}.")
