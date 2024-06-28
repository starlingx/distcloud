# Copyright 2017 Ericsson AB.
# Copyright (c) 2017-2024 Wind River Systems, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

from keystoneauth1 import exceptions as keystone_exceptions
from oslo_log import log as logging

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack import patching_v1
from dccommon.drivers.openstack.patching_v1 import PatchingClient
from dccommon.drivers.openstack.sdk_platform import OpenStackDriver
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon.endpoint_cache import build_subcloud_endpoint
from dcmanager.common import utils

LOG = logging.getLogger(__name__)


class PatchAuditData(object):
    def __init__(
        self, patches, applied_patch_ids, committed_patch_ids, software_version
    ):
        self.patches = patches
        self.applied_patch_ids = applied_patch_ids
        self.committed_patch_ids = committed_patch_ids
        self.software_version = software_version

    def to_dict(self):
        return {
            "patches": self.patches,
            "applied_patch_ids": self.applied_patch_ids,
            "committed_patch_ids": self.committed_patch_ids,
            "software_version": self.software_version,
        }

    @classmethod
    def from_dict(cls, values):
        if values is None:
            return None
        return cls(**values)


class PatchAudit(object):
    """Manages tasks related to patch audits."""

    def __init__(self, context):
        LOG.debug("PatchAudit initialization...")
        self.context = context
        self.audit_count = 0

    @staticmethod
    def _get_upgrades(sysinv_client):
        upgrades = None
        try:
            upgrades = sysinv_client.get_upgrades()
        except Exception:
            LOG.exception(
                "Cannot retrieve upgrade info for subcloud: %s"
                % sysinv_client.region_name
            )
        return upgrades

    def get_regionone_audit_data(self):
        """Query RegionOne to determine what patches should be applied

        to the system as well as the current software version

        :return: A new PatchAuditData object

        """
        try:
            m_os_ks_client = OpenStackDriver(
                region_name=dccommon_consts.DEFAULT_REGION_NAME,
                region_clients=None,
                fetch_subcloud_ips=utils.fetch_subcloud_mgmt_ips,
            ).keystone_client
            patching_endpoint = m_os_ks_client.endpoint_cache.get_endpoint("patching")
            sysinv_endpoint = m_os_ks_client.endpoint_cache.get_endpoint("sysinv")
            patching_client = PatchingClient(
                dccommon_consts.DEFAULT_REGION_NAME,
                m_os_ks_client.session,
                endpoint=patching_endpoint,
            )
            sysinv_client = SysinvClient(
                dccommon_consts.DEFAULT_REGION_NAME,
                m_os_ks_client.session,
                endpoint=sysinv_endpoint,
            )
        except Exception:
            LOG.exception("Failure initializing OS Client, skip patch audit.")
            return None

        # First query RegionOne to determine what patches should be applied
        # to the system.
        regionone_patches = patching_client.query()
        LOG.debug("regionone_patches: %s" % regionone_patches)

        # Get the active software version in RegionOne as it may be needed
        # later for subcloud load audit.
        regionone_software_version = sysinv_client.get_system().software_version

        # Build lists of patches that should be applied or committed in all
        # subclouds, based on their state in RegionOne. Check repostate
        # (not patchstate) as we only care if the patch has been applied to
        # the repo (not whether it is installed on the hosts).
        applied_patch_ids = list()
        committed_patch_ids = list()
        for patch_id in regionone_patches.keys():
            if (
                regionone_patches[patch_id]["repostate"]
                == patching_v1.PATCH_STATE_APPLIED
            ):
                applied_patch_ids.append(patch_id)
            elif (
                regionone_patches[patch_id]["repostate"]
                == patching_v1.PATCH_STATE_COMMITTED
            ):
                committed_patch_ids.append(patch_id)
        LOG.debug("RegionOne applied_patch_ids: %s" % applied_patch_ids)
        LOG.debug("RegionOne committed_patch_ids: %s" % committed_patch_ids)
        return PatchAuditData(
            regionone_patches,
            applied_patch_ids,
            committed_patch_ids,
            regionone_software_version,
        )

    def subcloud_patch_audit(
        self,
        keystone_session,
        sysinv_client,
        subcloud_management_ip,
        subcloud_name,
        subcloud_region,
        audit_data,
    ):
        LOG.info("Triggered patch audit for: %s." % subcloud_name)

        try:
            patching_endpoint = build_subcloud_endpoint(
                subcloud_management_ip, "patching"
            )
            patching_client = PatchingClient(
                subcloud_region, keystone_session, endpoint=patching_endpoint
            )
        except (
            keystone_exceptions.EndpointNotFound,
            keystone_exceptions.ConnectFailure,
            keystone_exceptions.ConnectTimeout,
            IndexError,
        ):
            LOG.exception(
                "Endpoint for online subcloud %s not found, skip "
                "patch audit." % subcloud_name
            )
            return None

        # Retrieve all the patches that are present in this subcloud.
        try:
            subcloud_patches = patching_client.query()
            LOG.debug("Patches for subcloud %s: %s" % (subcloud_name, subcloud_patches))
        except Exception:
            LOG.warn(
                "Cannot retrieve patches for subcloud: %s, skip patch "
                "audit" % subcloud_name
            )
            return None

        # Determine which loads are present in this subcloud. During an
        # upgrade, there will be more than one load installed.
        try:
            loads = sysinv_client.get_loads()
        except Exception:
            LOG.exception(
                "Cannot retrieve installed loads for subcloud: %s, "
                "skip patch audit" % subcloud_name
            )
            return None

        installed_loads = utils.get_loads_for_patching(loads)

        sync_status = dccommon_consts.SYNC_STATUS_IN_SYNC

        # audit_data will be a dict due to passing through RPC so objectify it
        audit_data = PatchAuditData.from_dict(audit_data)

        # Check that all patches in this subcloud are in the correct
        # state, based on the state of the patch in RegionOne. For the
        # subcloud, we use the patchstate because we care whether the
        # patch is installed on the hosts.
        for patch_id in subcloud_patches.keys():
            if (
                subcloud_patches[patch_id]["patchstate"]
                == patching_v1.PATCH_STATE_APPLIED
            ):
                if patch_id not in audit_data.applied_patch_ids:
                    if patch_id not in audit_data.committed_patch_ids:
                        LOG.debug(
                            "Patch %s should not be applied in %s"
                            % (patch_id, subcloud_name)
                        )
                    else:
                        LOG.debug(
                            "Patch %s should be committed in %s"
                            % (patch_id, subcloud_name)
                        )
                    sync_status = dccommon_consts.SYNC_STATUS_OUT_OF_SYNC
            elif (
                subcloud_patches[patch_id]["patchstate"]
                == patching_v1.PATCH_STATE_COMMITTED
            ):
                if (
                    patch_id not in audit_data.committed_patch_ids
                    and patch_id not in audit_data.applied_patch_ids
                ):
                    LOG.warn(
                        "Patch %s should not be committed in %s"
                        % (patch_id, subcloud_name)
                    )
                    sync_status = dccommon_consts.SYNC_STATUS_OUT_OF_SYNC
            else:
                # In steady state, all patches should either be applied
                # or committed in each subcloud. Patches in other
                # states mean a sync is required.
                sync_status = dccommon_consts.SYNC_STATUS_OUT_OF_SYNC

        # Check that all applied or committed patches in RegionOne are
        # present in the subcloud.
        for patch_id in audit_data.applied_patch_ids:
            if (
                audit_data.patches[patch_id]["sw_version"] in installed_loads
                and patch_id not in subcloud_patches
            ):
                LOG.debug("Patch %s missing from %s" % (patch_id, subcloud_name))
                sync_status = dccommon_consts.SYNC_STATUS_OUT_OF_SYNC
        for patch_id in audit_data.committed_patch_ids:
            if (
                audit_data.patches[patch_id]["sw_version"] in installed_loads
                and patch_id not in subcloud_patches
            ):
                LOG.debug("Patch %s missing from %s" % (patch_id, subcloud_name))
                sync_status = dccommon_consts.SYNC_STATUS_OUT_OF_SYNC

        LOG.info(
            f"Patch audit completed for: {subcloud_name}, requesting "
            f"sync_status update to {sync_status}"
        )
        return sync_status

    def subcloud_load_audit(self, sysinv_client, subcloud_name, audit_data):
        # Check subcloud software version every other audit cycle
        LOG.info("Triggered load audit for: %s." % subcloud_name)
        try:
            upgrades = sysinv_client.get_upgrades()
        except Exception:
            LOG.warn(
                "Cannot retrieve upgrade info for: %s, skip "
                "software version audit" % subcloud_name
            )
            return None

        # audit_data will be a dict due to passing through RPC so objectify it
        audit_data = PatchAuditData.from_dict(audit_data)
        sync_status = dccommon_consts.SYNC_STATUS_IN_SYNC

        if not upgrades:
            # No upgrade in progress
            subcloud_software_version = sysinv_client.get_system().software_version

            if subcloud_software_version != audit_data.software_version:
                sync_status = dccommon_consts.SYNC_STATUS_OUT_OF_SYNC
        else:
            # As upgrade is still in progress, set the subcloud load
            # status as out-of-sync.
            sync_status = dccommon_consts.SYNC_STATUS_OUT_OF_SYNC

        LOG.info(
            f"Load audit completed for: {subcloud_name}, requesting "
            f"sync_status update to {sync_status}"
        )
        return sync_status
