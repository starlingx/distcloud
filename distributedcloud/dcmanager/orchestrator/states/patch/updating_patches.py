#
# Copyright (c) 2023 Wind River Systems, Inc.
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
        self.region_one_applied_patch_ids = job_data.\
            region_one_applied_patch_ids

    def perform_state_action(self, strategy_step):
        """Update patches in this subcloud"""
        self.info_log(strategy_step, "Updating patches")

        # Retrieve all subcloud patches
        try:
            subcloud_patches = self.get_patching_client(self.region_name).\
                query()
        except Exception:
            message = ("Cannot retrieve subcloud patches. Please see logs for"
                       " details.")
            self.exception_log(strategy_step, message)
            raise Exception(message)

        patches_to_upload = []
        patches_to_apply = []
        patches_to_remove = []

        subcloud_patch_ids = subcloud_patches.keys()

        # RegionOne applied patches not present on the subcloud needs to
        # be uploaded and applied to the subcloud
        for patch_id in self.region_one_applied_patch_ids:
            if patch_id not in subcloud_patch_ids:
                self.info_log(strategy_step, "Patch %s missing from subloud" %
                              patch_id)
                patches_to_upload.append(patch_id)
                patches_to_apply.append(patch_id)

        # Check that all applied patches in subcloud match RegionOne
        for patch_id in subcloud_patch_ids:
            repostate = subcloud_patches[patch_id]["repostate"]
            if repostate == patching_v1.PATCH_STATE_APPLIED:
                if patch_id not in self.region_one_applied_patch_ids:
                    self.info_log(strategy_step,
                                  "Patch %s will be removed from subcloud" %
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
                message = ("Patch %s in subcloud is in an unexpected state: %s"
                           % (patch_id, repostate))
                self.warn_log(strategy_step, message)
                raise Exception(message)

        if patches_to_upload:
            self.info_log(strategy_step, "Uploading patches %s to subcloud" %
                          patches_to_upload)
            for patch in patches_to_upload:
                patch_sw_version = self.region_one_patches[patch]["sw_version"]
                patch_file = "%s/%s/%s.patch" % (consts.PATCH_VAULT_DIR,
                                                 patch_sw_version, patch)
                if not os.path.isfile(patch_file):
                    message = "Patch file %s is missing" % patch_file
                    self.error_log(strategy_step, message)
                    raise Exception(message)

                self.get_patching_client(self.region_name).upload([patch_file])
                if self.stopped():
                    self.info_log(strategy_step,
                                  "Exiting because task is stopped")
                    raise StrategyStoppedException()

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
