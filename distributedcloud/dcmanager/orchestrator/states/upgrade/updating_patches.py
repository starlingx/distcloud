#
# Copyright (c) 2020-2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import os
import time

from dccommon.drivers.openstack import patching_v1
from dcmanager.common import consts
from dcmanager.common import utils

from dcmanager.common.exceptions import StrategyStoppedException
from dcmanager.orchestrator.states.base import BaseState
from dcmanager.orchestrator.states.upgrade.cache.cache_specifications import \
    REGION_ONE_PATCHING_CACHE_TYPE

# Max time: 30 minutes = 180 queries x 10 seconds between
DEFAULT_MAX_QUERIES = 180
DEFAULT_SLEEP_DURATION = 10


class UpdatingPatchesState(BaseState):
    """Upgrade state for updating patches"""

    def __init__(self, region_name):
        super(UpdatingPatchesState, self).__init__(
            next_state=consts.STRATEGY_STATE_FINISHING_PATCH_STRATEGY,
            region_name=region_name)
        # max time to wait (in seconds) is: sleep_duration * max_queries
        self.sleep_duration = DEFAULT_SLEEP_DURATION
        self.max_queries = DEFAULT_MAX_QUERIES

    # todo(jcasteli): Refactor instead of duplicating code from patch_orch_thread.py
    def perform_state_action(self, strategy_step):
        """Update patches in this subcloud that need to be applied and

        removed to match the applied patches in RegionOne

        Returns the next state in the state machine on success.
        Any exceptions raised by this method set the strategy to FAILED.

        This code is based on patch orchestration.
        """

        self.info_log(strategy_step, "Updating patches")

        if strategy_step.subcloud_id is None:
            # This is the SystemController. It is the master so no update
            # is necessary.
            self.info_log(strategy_step,
                          "Skipping update patches for SystemController")
            return self.next_state

        # First query RegionOne to determine what patches should be applied.
        regionone_patches = self._read_from_cache(REGION_ONE_PATCHING_CACHE_TYPE)
        self.debug_log(strategy_step, "regionone_patches: %s" % regionone_patches)

        # Build lists of patches that should be applied in this subcloud,
        # based on their state in RegionOne. Check repostate (not patchstate)
        # as we only care if the patch has been applied to the repo (not
        # whether it is installed on the hosts). If we were to check the
        # patchstate, we could end up removing patches from this subcloud
        # just because a single host in RegionOne reported that it was not
        # patch current.
        applied_patch_ids = list()
        for patch_id in regionone_patches.keys():
            if regionone_patches[patch_id]['repostate'] in [
                    patching_v1.PATCH_STATE_APPLIED,
                    patching_v1.PATCH_STATE_COMMITTED]:
                applied_patch_ids.append(patch_id)
        self.debug_log(strategy_step, "RegionOne applied_patch_ids: %s" % applied_patch_ids)

        region = self.get_region_name(strategy_step)
        # Retrieve all the patches that are present in this subcloud.
        subcloud_patches = self.get_patching_client(region).query()
        self.debug_log(strategy_step, "Patches for subcloud: %s" %
                       (subcloud_patches))

        # Determine which loads are present in this subcloud. During an
        # upgrade, there will be more than one load installed.
        loads = self.get_sysinv_client(region).get_loads()

        installed_loads = utils.get_loads_for_patching(loads)

        patches_to_upload = list()
        patches_to_apply = list()
        patches_to_remove = list()

        # Figure out which patches in this subcloud need to be applied and
        # removed to match the applied patches in RegionOne. Check the
        # repostate, which indicates whether it is applied or removed in
        # the repo.
        subcloud_patch_ids = list(subcloud_patches.keys())
        for patch_id in subcloud_patch_ids:
            if subcloud_patches[patch_id]['repostate'] == \
                    patching_v1.PATCH_STATE_APPLIED:
                if patch_id not in applied_patch_ids:
                    self.info_log(strategy_step,
                                  "Patch %s will be removed from subcloud" %
                                  (patch_id))
                    patches_to_remove.append(patch_id)
            elif subcloud_patches[patch_id]['repostate'] == \
                    patching_v1.PATCH_STATE_COMMITTED:
                if patch_id not in applied_patch_ids:
                    message = ("Patch %s is committed in subcloud but "
                               "not applied in SystemController" %
                               patch_id)
                    self.warn_log(strategy_step, message)
                    raise Exception(message)
            elif subcloud_patches[patch_id]['repostate'] == \
                    patching_v1.PATCH_STATE_AVAILABLE:
                if patch_id in applied_patch_ids:
                    self.info_log(strategy_step,
                                  "Patch %s will be applied to subcloud" %
                                  (patch_id))
                    patches_to_apply.append(patch_id)
            else:
                # This patch is in an invalid state
                message = ('Patch %s in subcloud in unexpected state %s' %
                           (patch_id,
                            subcloud_patches[patch_id]['repostate']))
                self.warn_log(strategy_step, message)
                raise Exception(message)

        # Check that all applied patches in RegionOne are present in the
        # subcloud.
        for patch_id in applied_patch_ids:
            if regionone_patches[patch_id]['sw_version'] in \
                    installed_loads and patch_id not in subcloud_patch_ids:
                self.info_log(strategy_step,
                              "Patch %s missing from subcloud" %
                              (patch_id))
                patches_to_upload.append(patch_id)
                patches_to_apply.append(patch_id)

        if patches_to_remove:
            self.info_log(strategy_step,
                          "Removing patches %s from subcloud" %
                          (patches_to_remove))
            self.get_patching_client(region).remove(patches_to_remove)

        if patches_to_upload:
            self.info_log(strategy_step,
                          "Uploading patches %s to subcloud" %
                          (patches_to_upload))
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
                          "Applying patches %s to subcloud" %
                          (patches_to_apply))
            self.get_patching_client(region).apply(patches_to_apply)

        # Now that we have applied/removed/uploaded patches, we need to give
        # the patch controller on this subcloud time to determine whether
        # each host on that subcloud is patch current.
        wait_count = 0
        while True:
            subcloud_hosts = self.get_patching_client(
                region).query_hosts()

            self.debug_log(strategy_step,
                           "query_hosts for subcloud: %s" % subcloud_hosts)
            for host in subcloud_hosts:
                if host['interim_state']:
                    # This host is not yet ready.
                    self.debug_log(strategy_step,
                                   "Host %s in subcloud in interim state" %
                                   (host["hostname"]))
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
