#
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import os
import time

from dccommon.drivers.openstack import patching_v1
from dcmanager.common import consts
from dcmanager.common.exceptions import StrategyStoppedException
from dcmanager.common import utils
from dcmanager.orchestrator.states.base import BaseState

# Max time: 30 minutes = 180 queries x 10 seconds between
DEFAULT_MAX_QUERIES = 180
DEFAULT_SLEEP_DURATION = 10


class UpdatingKubePatchesState(BaseState):
    """Kube upgrade state for updating patches"""

    def __init__(self, region_name):
        super(UpdatingKubePatchesState, self).__init__(
            next_state=consts.STRATEGY_STATE_KUBE_CREATING_VIM_PATCH_STRATEGY,
            region_name=region_name)
        # max time to wait (in seconds) is: sleep_duration * max_queries
        self.sleep_duration = DEFAULT_SLEEP_DURATION
        self.max_queries = DEFAULT_MAX_QUERIES

    def perform_state_action(self, strategy_step):
        """Update patches in this subcloud required for kubernetes upgrade.

        Returns the next state in the state machine on success.
        Any exceptions raised by this method set the strategy to FAILED.
        """

        self.info_log(strategy_step, "Updating kube patches")
        region = self.get_region_name(strategy_step)

        # query RegionOne patches
        regionone_patches = self.get_patching_client(
            consts.DEFAULT_REGION_NAME).query()

        # Query RegionOne loads to filter the patches
        loads = self.get_sysinv_client(consts.DEFAULT_REGION_NAME).get_loads()

        # this filters by active and imported loads
        installed_loads = utils.get_loads_for_patching(loads)

        # Query RegionOne active kube version to examine the patches
        kube_versions = self.get_sysinv_client(
            consts.DEFAULT_REGION_NAME).get_kube_versions()
        active_kube_version = utils.get_active_kube_version(kube_versions)
        if active_kube_version is None:
            message = "Active kube version in RegionOne not found"
            self.warn_log(strategy_step, message)
            raise Exception(message)

        kube_ver = self.get_sysinv_client(
            consts.DEFAULT_REGION_NAME).get_kube_version(active_kube_version)
        kube_details = kube_ver.to_dict()

        # filter the active patches
        filtered_region_one_patches = list()
        applyable_region_one_patches = list()
        for patch_id in regionone_patches.keys():
            # Only the patches for the installed loads will be examined
            if regionone_patches[patch_id]['sw_version'] in installed_loads:
                # Only care about applied/committed patches
                if regionone_patches[patch_id]['repostate'] in [
                        patching_v1.PATCH_STATE_APPLIED,
                        patching_v1.PATCH_STATE_COMMITTED]:
                    filtered_region_one_patches.append(patch_id)
                    # "available_patches" should not be applied
                    if patch_id not in kube_details.get("available_patches"):
                        applyable_region_one_patches.append(patch_id)

        # Retrieve all the patches that are present in this subcloud.
        subcloud_patches = self.get_patching_client(region).query()

        # Not all applied patches can be applied in the subcloud
        # kube patch orchestration requires the vim strategy to apply some
        # No patches are being removed at this time.
        patches_to_upload = list()
        patches_to_apply = list()

        subcloud_patch_ids = list(subcloud_patches.keys())
        for patch_id in subcloud_patch_ids:
            if subcloud_patches[patch_id]['repostate'] == \
                    patching_v1.PATCH_STATE_APPLIED:
                # todo(abailey): determine if we want to support remove
                pass
            elif subcloud_patches[patch_id]['repostate'] == \
                    patching_v1.PATCH_STATE_COMMITTED:
                # todo(abailey): determine if mismatch committed subcloud
                # patches should cause failure
                pass
            elif subcloud_patches[patch_id]['repostate'] == \
                    patching_v1.PATCH_STATE_AVAILABLE:
                # No need to upload. May need to apply
                if patch_id in applyable_region_one_patches:
                    self.info_log(strategy_step,
                                  "Patch %s will be applied" % patch_id)
                    patches_to_apply.append(patch_id)
            else:
                # This patch is in an invalid state
                message = ('Patch %s in subcloud in unexpected state %s' %
                           (patch_id, subcloud_patches[patch_id]['repostate']))
                self.warn_log(strategy_step, message)
                raise Exception(message)

        # Check that all uploaded patches in RegionOne are  in subcloud
        for patch_id in filtered_region_one_patches:
            if patch_id not in subcloud_patch_ids:
                patches_to_upload.append(patch_id)

        # Check that all applyable patches in RegionOne are in subcloud
        for patch_id in applyable_region_one_patches:
            if patch_id not in subcloud_patch_ids:
                patches_to_apply.append(patch_id)

        if patches_to_upload:
            self.info_log(strategy_step,
                          "Uploading patches %s to subcloud"
                          % patches_to_upload)
            for patch in patches_to_upload:
                patch_sw_version = regionone_patches[patch]['sw_version']
                patch_file = "%s/%s/%s.patch" % (consts.PATCH_VAULT_DIR,
                                                 patch_sw_version,
                                                 patch)
                if not os.path.isfile(patch_file):
                    message = ('Patch file %s is missing' % patch_file)
                    self.error_log(strategy_step, message)
                    raise Exception(message)

                self.get_patching_client(region).upload([patch_file])

                if self.stopped():
                    self.info_log(strategy_step,
                                  "Exiting because task is stopped")
                    raise StrategyStoppedException()

        if patches_to_apply:
            self.info_log(strategy_step,
                          "Applying patches %s to subcloud"
                          % patches_to_apply)
            self.get_patching_client(region).apply(patches_to_apply)

        # Now that we have applied/uploaded patches, we need to give
        # the patch controller on this subcloud time to determine whether
        # each host on that subcloud is patch current.
        wait_count = 0
        while True:
            subcloud_hosts = self.get_patching_client(region).query_hosts()

            self.debug_log(strategy_step,
                           "query_hosts for subcloud returned %s"
                           % subcloud_hosts)
            for host in subcloud_hosts:
                if host['interim_state']:
                    # This host is not yet ready.
                    self.debug_log(strategy_step,
                                   "Host %s in subcloud in interim state"
                                   % host["hostname"])
                    break
            else:
                # All hosts in the subcloud are updated
                break
            wait_count += 1
            if wait_count >= 6:
                # We have waited at least 60 seconds. This is too long. We
                # will just log it and move on without failing the step.
                message = ("Too much time expired after applying patches to "
                           "subcloud - continuing.")
                self.warn_log(strategy_step, message)
                break

            if self.stopped():
                self.info_log(strategy_step, "Exiting because task is stopped")
                raise StrategyStoppedException()

            # Wait 10 seconds before doing another query.
            time.sleep(10)

        return self.next_state
