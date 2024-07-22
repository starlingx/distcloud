#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import os
import time

from dcmanager.common import consts
from dcmanager.common.exceptions import StrategyStoppedException
from dcmanager.common import utils
from dcmanager.orchestrator.states.base import BaseState

# Max time: 1 minute = 6 queries x 10 seconds between
DEFAULT_MAX_QUERIES = 6
DEFAULT_SLEEP_DURATION = 10


class UpdatingPatchesState(BaseState):
    """Patch orchestration state for updating patches"""

    def __init__(self, region_name):
        super(UpdatingPatchesState, self).__init__(
            next_state=consts.STRATEGY_STATE_CREATING_VIM_PATCH_STRATEGY,
            region_name=region_name,
        )
        self.max_queries = DEFAULT_MAX_QUERIES
        self.sleep_duration = DEFAULT_SLEEP_DURATION

        self.region_one_patches = None
        self.region_one_applied_patch_ids = None

    def upload_patch(self, patch_file, strategy_step):
        """Upload a patch file to the subcloud"""

        if not os.path.isfile(patch_file):
            message = f"Patch file {patch_file} is missing"
            self.error_log(strategy_step, message)
            raise Exception(message)

        self.info_log(
            strategy_step,
            f"Patch {patch_file} will be uploaded to subcloud",
        )
        self.get_patching_client(self.region_name).upload([patch_file])
        if self.stopped():
            self.info_log(strategy_step, "Exiting because task is stopped")
            raise StrategyStoppedException()

    def perform_state_action(self, strategy_step):
        """Update patches in this subcloud"""
        self.info_log(strategy_step, "Updating patches")
        extra_args = utils.get_sw_update_strategy_extra_args(self.context)
        upload_only = extra_args.get(consts.EXTRA_ARGS_UPLOAD_ONLY)
        patch_file = extra_args.get(consts.EXTRA_ARGS_PATCH)

        # Retrieve all subcloud patches
        try:
            subcloud_patches = self.get_patching_client(self.region_name).query()
        except Exception:
            message = "Cannot retrieve subcloud patches. Please see logs for details."
            self.exception_log(strategy_step, message)
            raise Exception(message)

        subcloud_patch_ids = subcloud_patches.keys()

        patch = os.path.basename(patch_file)
        patch_id = os.path.splitext(patch)[0]

        if patch_id in subcloud_patch_ids:
            message = f"Patch {patch_id} is already present in the subcloud."
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

        # Apply the patch to the subcloud
        self.info_log(
            strategy_step,
            f"Patch {patch_file} will be applied to subcloud",
        )
        self.get_patching_client(self.region_name).apply([patch_id])

        # Now that we have applied/removed/uploaded patches, we need to give
        # the patch controller on this subcloud time to determine whether
        # each host on that subcloud is patch current.
        wait_count = 0
        while True:
            subcloud_hosts = self.get_patching_client(self.region_name).query_hosts()
            self.debug_log(
                strategy_step, "query_hosts for subcloud returned %s" % subcloud_hosts
            )

            for host in subcloud_hosts:
                if host["interim_state"]:
                    # This host is not yet ready.
                    self.debug_log(
                        strategy_step,
                        "Host %s in subcloud in interim state" % host["hostname"],
                    )
                    break
            else:
                # All hosts in the subcloud are updated
                break

            wait_count += 1
            if wait_count >= self.max_queries:
                # We have waited too long.
                # We log a warning but do not fail the step
                message = (
                    "Applying patches to subcloud taking too long to recover. "
                    "Continuing..."
                )
                self.warn_log(strategy_step, message)
                break
            if self.stopped():
                self.info_log(strategy_step, "Exiting because task is stopped")
                raise StrategyStoppedException()
            # Delay between queries
            time.sleep(self.sleep_duration)

        return self.next_state
