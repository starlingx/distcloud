#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import os
import time

from dccommon.drivers.openstack import patching_v1
from dcmanager.common import consts
from dcmanager.common.exceptions import StrategyStoppedException
from dcmanager.orchestrator.states.base import BaseState

# Max time: 1 minute = 6 queries x 10 seconds between
DEFAULT_MAX_QUERIES = 6
DEFAULT_SLEEP_DURATION = 10


class UpdatingPatchesState(BaseState):
    """Patch orchestration state for updating patches"""

    def __init__(self, region_name):
        super(UpdatingPatchesState, self).__init__(
            next_state=consts.STRATEGY_STATE_CREATING_VIM_PATCH_STRATEGY,
            region_name=region_name)
        self.max_queries = DEFAULT_MAX_QUERIES
        self.sleep_duration = DEFAULT_SLEEP_DURATION

        self.region_one_patches = None
        self.region_one_applied_patch_ids = None

    def set_job_data(self, job_data):
        """Store an orch_thread job data object"""
        self.region_one_patches = job_data.region_one_patches
        self.region_one_applied_patch_ids = job_data.region_one_applied_patch_ids
        self.extra_args = job_data.extra_args

    def upload_patch(self, patch_file, strategy_step):
        """Upload a patch file to the subcloud"""

        if not os.path.isfile(patch_file):
            message = f"Patch file {patch_file} is missing"
            self.error_log(strategy_step, message)
            raise Exception(message)

        self.get_patching_client(self.region_name).upload([patch_file])
        if self.stopped():
            self.info_log(strategy_step, "Exiting because task is stopped")
            raise StrategyStoppedException()

    def perform_state_action(self, strategy_step):
        """Update patches in this subcloud"""
        self.info_log(strategy_step, "Updating patches")
        upload_only = self.extra_args.get(consts.EXTRA_ARGS_UPLOAD_ONLY)
        patch_file = self.extra_args.get(consts.EXTRA_ARGS_PATCH)

        # Retrieve all subcloud patches
        try:
            subcloud_patches = self.get_patching_client(self.region_name).query()
        except Exception:
            message = ("Cannot retrieve subcloud patches. Please see logs for "
                       "details.")
            self.exception_log(strategy_step, message)
            raise Exception(message)

        subcloud_patch_ids = subcloud_patches.keys()

        # If a patch file is provided, upload and apply without checking RegionOne
        # patches
        if patch_file:
            self.info_log(
                strategy_step,
                f"Patch {patch_file} will be uploaded and applied to subcloud"
            )
            patch = os.path.basename(patch_file)
            patch_id = os.path.splitext(patch)[0]
            # raise Exception(subcloud_patch_ids)
            if patch_id in subcloud_patch_ids:
                message = f"Patch {patch_id} is already present in subcloud."
                self.info_log(strategy_step, message)
            else:
                self.upload_patch(patch_file, strategy_step)

            if upload_only:
                self.info_log(
                    strategy_step,
                    f"{consts.EXTRA_ARGS_UPLOAD_ONLY} option enabled, skipping "
                    f"execution. Forward to state: {consts.STRATEGY_STATE_COMPLETE}",
                )
                return consts.STRATEGY_STATE_COMPLETE

            self.get_patching_client(self.region_name).apply([patch_id])
        else:
            patches_to_upload = []
            patches_to_apply = []
            patches_to_remove = []

            # RegionOne applied patches not present on the subcloud needs to
            # be uploaded and applied to the subcloud
            for patch_id in self.region_one_applied_patch_ids:
                if patch_id not in subcloud_patch_ids:
                    self.info_log(strategy_step, "Patch %s missing from subloud " %
                                  patch_id)
                    patches_to_upload.append(patch_id)
                    patches_to_apply.append(patch_id)

            # Check that all applied patches in subcloud match RegionOne
            if not upload_only:
                for patch_id in subcloud_patch_ids:
                    repostate = subcloud_patches[patch_id]["repostate"]
                    if repostate == patching_v1.PATCH_STATE_APPLIED:
                        if patch_id not in self.region_one_applied_patch_ids:
                            self.info_log(strategy_step,
                                          "Patch %s will be removed from subcloud " %
                                          patch_id)
                            patches_to_remove.append(patch_id)
                    elif repostate == patching_v1.PATCH_STATE_COMMITTED:
                        if patch_id not in self.region_one_applied_patch_ids:
                            message = ("Patch %s is committed in subcloud but "
                                       "not applied in SystemController" % patch_id)
                            self.warn_log(strategy_step, message)
                            raise Exception(message)
                    elif repostate == patching_v1.PATCH_STATE_AVAILABLE:
                        if patch_id in self.region_one_applied_patch_ids:
                            patches_to_apply.append(patch_id)

                    else:
                        # This patch is in an invalid state
                        message = ("Patch %s in subcloud is in an unexpected state: "
                                   "%s" % (patch_id, repostate))
                        self.warn_log(strategy_step, message)
                        raise Exception(message)

            if patches_to_upload:
                self.info_log(strategy_step, "Uploading patches %s to subcloud" %
                              patches_to_upload)
                for patch in patches_to_upload:
                    patch_sw_version = self.region_one_patches[patch]["sw_version"]
                    patch_file = "%s/%s/%s.patch" % (consts.PATCH_VAULT_DIR,
                                                     patch_sw_version, patch)
                    self.upload_patch(patch_file, strategy_step)

            if upload_only:
                self.info_log(strategy_step, "%s option enabled, skipping forward"
                              " to state:(%s)" % (consts.EXTRA_ARGS_UPLOAD_ONLY,
                                                  consts.STRATEGY_STATE_COMPLETE))
                return consts.STRATEGY_STATE_COMPLETE

            if patches_to_remove:
                self.info_log(strategy_step, "Removing patches %s from subcloud" %
                              patches_to_remove)
                self.get_patching_client(self.region_name).remove(patches_to_remove)

            if patches_to_apply:
                self.info_log(strategy_step, "Applying patches %s to subcloud" %
                              patches_to_apply)
                self.get_patching_client(self.region_name).apply(patches_to_apply)

        # Now that we have applied/removed/uploaded patches, we need to give
        # the patch controller on this subcloud time to determine whether
        # each host on that subcloud is patch current.
        wait_count = 0
        while True:
            subcloud_hosts = self.get_patching_client(self.region_name).\
                query_hosts()
            self.debug_log(strategy_step,
                           "query_hosts for subcloud returned %s" %
                           subcloud_hosts)

            for host in subcloud_hosts:
                if host["interim_state"]:
                    # This host is not yet ready.
                    self.debug_log(strategy_step,
                                   "Host %s in subcloud in interim state" %
                                   host["hostname"])
                    break
            else:
                # All hosts in the subcloud are updated
                break

            wait_count += 1
            if wait_count >= self.max_queries:
                # We have waited too long.
                # We log a warning but do not fail the step
                message = ("Applying patches to subcloud "
                           "taking too long to recover. "
                           "Continuing..")
                self.warn_log(strategy_step, message)
                break
            if self.stopped():
                self.info_log(strategy_step, "Exiting because task is stopped")
                raise StrategyStoppedException()
            # Delay between queries
            time.sleep(self.sleep_duration)

        return self.next_state
