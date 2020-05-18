# Copyright 2017 Ericsson AB.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Copyright (c) 2017-2020 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

from keystoneauth1 import exceptions as keystone_exceptions
from oslo_config import cfg
from oslo_log import log as logging

from dccommon.drivers.openstack import patching_v1
from dccommon.drivers.openstack.patching_v1 import PatchingClient
from dccommon.drivers.openstack.sdk_platform import OpenStackDriver
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient

from dcorch.common import consts as dcorch_consts

from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common.i18n import _
from dcmanager.common import manager
from dcmanager.db import api as db_api


LOG = logging.getLogger(__name__)

# By default the patch audit will only occur every five minutes.
DEFAULT_PATCH_AUDIT_DELAY_SECONDS = 300


class PatchAuditManager(manager.Manager):
    """Manages tasks related to patch audits."""

    def __init__(self, *args, **kwargs):
        LOG.info(_('PatchAuditManager initialization...'))

        super(PatchAuditManager, self).__init__(
            service_name="patch_audit_manager")
        self.context = context.get_admin_context()
        self.subcloud_manager = kwargs['subcloud_manager']
        # Wait 20 seconds before doing the first audit
        self.wait_time_passed = DEFAULT_PATCH_AUDIT_DELAY_SECONDS - 25
        self.audit_count = 0

    # Used to force an audit on the next interval
    _force_audit = False

    @classmethod
    def trigger_audit(cls):
        """Trigger audit at next interval.

        This can be called from outside the audit greenthread.
        """
        cls._force_audit = True

    def periodic_patch_audit(self):
        """Audit patch status of subclouds.

        Audit normally happens every DEFAULT_PATCH_AUDIT_DELAY_SECONDS, but
        can be forced to happen on the next audit interval by calling
        trigger_audit.
        """

        do_audit = False

        if PatchAuditManager._force_audit:
            # Audit has been triggered.
            do_audit = True
        else:
            # This won't be super accurate as we aren't woken up after exactly
            # the interval seconds, but it is good enough for an audit.
            self.wait_time_passed += cfg.CONF.scheduler.patch_audit_interval
            if self.wait_time_passed >= DEFAULT_PATCH_AUDIT_DELAY_SECONDS:
                do_audit = True

        if do_audit:
            self.wait_time_passed = 0
            PatchAuditManager._force_audit = False
            # Blanket catch all exceptions in the audit so that the audit
            # does not die.
            try:
                self._periodic_patch_audit_loop()
            except Exception as e:
                LOG.exception(e)

    def _update_subcloud_sync_status(self, sc_name, sc_endpoint_type, sc_status):
        self.subcloud_manager.update_subcloud_endpoint_status(
            self.context,
            subcloud_name=sc_name,
            endpoint_type=sc_endpoint_type,
            sync_status=sc_status)

    def _periodic_patch_audit_loop(self):
        """Audit patch status of subclouds loop."""

        # We are running in our own green thread here.
        LOG.info('Triggered patch audit.')
        self.audit_count += 1

        try:
            m_os_ks_client = OpenStackDriver(
                region_name=consts.DEFAULT_REGION_NAME,
                region_clients=None).keystone_client
        except Exception:
            LOG.warn('Failure initializing KeystoneClient, exiting audit.')
            return

        # First query RegionOne to determine what patches should be applied
        # to the system.
        patching_client = PatchingClient(
            consts.DEFAULT_REGION_NAME, m_os_ks_client.session)
        regionone_patches = patching_client.query()
        LOG.debug("regionone_patches: %s" % regionone_patches)

        # Get the active software version in RegionOne as it may be needed
        # later for subcloud load audit.
        sysinv_client = SysinvClient(
            consts.DEFAULT_REGION_NAME, m_os_ks_client.session)
        regionone_software_version = sysinv_client.get_system().software_version

        # Build lists of patches that should be applied or committed in all
        # subclouds, based on their state in RegionOne. Check repostate
        # (not patchstate) as we only care if the patch has been applied to
        # the repo (not whether it is installed on the hosts).
        applied_patch_ids = list()
        committed_patch_ids = list()
        for patch_id in regionone_patches.keys():
            if regionone_patches[patch_id]['repostate'] == \
                    patching_v1.PATCH_STATE_APPLIED:
                applied_patch_ids.append(patch_id)
            elif regionone_patches[patch_id]['repostate'] == \
                    patching_v1.PATCH_STATE_COMMITTED:
                committed_patch_ids.append(patch_id)
        LOG.debug("RegionOne applied_patch_ids: %s" % applied_patch_ids)
        LOG.debug("RegionOne committed_patch_ids: %s" % committed_patch_ids)

        # For each subcloud, check whether the patches match the target.
        for subcloud in db_api.subcloud_get_all(self.context):
            # Only audit patching on subclouds that are managed and online
            if (subcloud.management_state != consts.MANAGEMENT_MANAGED or
                    subcloud.availability_status !=
                    consts.AVAILABILITY_ONLINE):
                continue

            try:
                sc_os_client = OpenStackDriver(region_name=subcloud.name,
                                               region_clients=None)
            except (keystone_exceptions.EndpointNotFound,
                    keystone_exceptions.ConnectFailure,
                    keystone_exceptions.ConnectTimeout,
                    IndexError):
                # Since it takes some time to detect that a subcloud has gone
                # offline, these errors are expected from time to time.
                LOG.info("Identity endpoint for online subcloud %s not found."
                         % subcloud.name)
                continue

            try:
                patching_client = PatchingClient(
                    subcloud.name, sc_os_client.keystone_client.session)
            except keystone_exceptions.EndpointNotFound:
                LOG.warn("Patching endpoint for online subcloud %s not found."
                         % subcloud.name)
                continue

            try:
                sysinv_client = SysinvClient(
                    subcloud.name, sc_os_client.keystone_client.session)
            except keystone_exceptions.EndpointNotFound:
                LOG.warn("Sysinv endpoint for online subcloud %s not found."
                         % subcloud.name)
                continue

            # Retrieve all the patches that are present in this subcloud.
            try:
                subcloud_patches = patching_client.query()
                LOG.debug("Patches for subcloud %s: %s" %
                          (subcloud.name, subcloud_patches))
            except Exception:
                LOG.warn('Cannot retrieve patches for subcloud: %s' %
                         subcloud.name)
                continue

            # Determine which loads are present in this subcloud. During an
            # upgrade, there will be more than one load installed.
            installed_loads = list()
            try:
                loads = sysinv_client.get_loads()
            except Exception:
                LOG.warn('Cannot retrieve loads for subcloud: %s' %
                         subcloud.name)
                continue

            for load in loads:
                installed_loads.append(load.software_version)

            out_of_sync = False

            # Check that all patches in this subcloud are in the correct
            # state, based on the state of the patch in RegionOne. For the
            # subcloud, we use the patchstate because we care whether the
            # patch is installed on the hosts.
            for patch_id in subcloud_patches.keys():
                if subcloud_patches[patch_id]['patchstate'] == \
                        patching_v1.PATCH_STATE_APPLIED:
                    if patch_id not in applied_patch_ids:
                        if patch_id not in committed_patch_ids:
                            LOG.debug("Patch %s should not be applied in %s" %
                                      (patch_id, subcloud.name))
                        else:
                            LOG.debug("Patch %s should be committed in %s" %
                                      (patch_id, subcloud.name))
                        out_of_sync = True
                elif subcloud_patches[patch_id]['patchstate'] == \
                        patching_v1.PATCH_STATE_COMMITTED:
                    if patch_id not in committed_patch_ids:
                        LOG.warn("Patch %s should not be committed in %s" %
                                 (patch_id, subcloud.name))
                        out_of_sync = True
                else:
                    # In steady state, all patches should either be applied
                    # or committed in each subcloud. Patches in other
                    # states mean a sync is required.
                    out_of_sync = True

            # Check that all applied or committed patches in RegionOne are
            # present in the subcloud.
            for patch_id in applied_patch_ids:
                if regionone_patches[patch_id]['sw_version'] in \
                        installed_loads and patch_id not in subcloud_patches:
                    LOG.debug("Patch %s missing from %s" %
                              (patch_id, subcloud.name))
                    out_of_sync = True
            for patch_id in committed_patch_ids:
                if regionone_patches[patch_id]['sw_version'] in \
                        installed_loads and patch_id not in subcloud_patches:
                    LOG.debug("Patch %s missing from %s" %
                              (patch_id, subcloud.name))
                    out_of_sync = True

            if out_of_sync:
                LOG.debug("Subcloud %s is out-of-sync for patching" %
                          subcloud.name)
                self._update_subcloud_sync_status(
                    subcloud.name, dcorch_consts.ENDPOINT_TYPE_PATCHING,
                    consts.SYNC_STATUS_OUT_OF_SYNC)
            else:
                LOG.debug("Subcloud %s is in-sync for patching" %
                          subcloud.name)
                self._update_subcloud_sync_status(
                    subcloud.name, dcorch_consts.ENDPOINT_TYPE_PATCHING,
                    consts.SYNC_STATUS_IN_SYNC)

            # Check subcloud software version every other audit cycle
            if self.audit_count % 2 != 0:
                LOG.debug('Auditing load of subcloud %s' % subcloud.name)
                try:
                    upgrades = sysinv_client.get_upgrades()
                except Exception:
                    LOG.warn('Cannot retrieve upgrade info for subcloud: %s' %
                             subcloud.name)
                    continue

                if not upgrades:
                    # No upgrade in progress
                    subcloud_software_version = \
                        sysinv_client.get_system().software_version

                    if subcloud_software_version == regionone_software_version:
                        self._update_subcloud_sync_status(
                            subcloud.name, dcorch_consts.ENDPOINT_TYPE_LOAD,
                            consts.SYNC_STATUS_IN_SYNC)
                    else:
                        self._update_subcloud_sync_status(
                            subcloud.name, dcorch_consts.ENDPOINT_TYPE_LOAD,
                            consts.SYNC_STATUS_OUT_OF_SYNC)
                else:
                    # As upgrade is still in progress, set the subcloud load
                    # status as out-of-sync.
                    self._update_subcloud_sync_status(
                        subcloud.name, dcorch_consts.ENDPOINT_TYPE_LOAD,
                        consts.SYNC_STATUS_OUT_OF_SYNC)

        LOG.info('Patch audit completed.')
