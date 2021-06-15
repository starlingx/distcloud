#
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dccommon.drivers.openstack import patching_v1
from dcmanager.common import consts
from dcmanager.common.exceptions import StrategyStoppedException
from dcmanager.orchestrator.states.base import BaseState

# Max time: 30 minutes = 180 queries x 10 seconds between
DEFAULT_MAX_QUERIES = 180
DEFAULT_SLEEP_DURATION = 10


# todo(jcasteli): Refactor instead of duplicating code from patch_orch_thread.py
class FinishingPatchStrategyState(BaseState):
    """Upgrade state for finishing patch strategy"""

    def __init__(self, region_name):
        super(FinishingPatchStrategyState, self).__init__(
            next_state=consts.STRATEGY_STATE_STARTING_UPGRADE, region_name=region_name)
        # max time to wait (in seconds) is: sleep_duration * max_queries
        self.sleep_duration = DEFAULT_SLEEP_DURATION
        self.max_queries = DEFAULT_MAX_QUERIES

    def perform_state_action(self, strategy_step):
        """Clean up patches in this subcloud (commit, delete).

        Returns the next state in the state machine on success.
        Any exceptions raised by this method set the strategy to FAILED.
        """

        self.info_log(strategy_step, "Finishing patch strategy")

        if strategy_step.subcloud_id is None:
            # This is the SystemController. No cleanup is required.
            self.info_log(strategy_step, "Skipping finish for SystemController")
            return self.next_state

        regionone_committed_patches = self.get_patching_client(
            consts.DEFAULT_REGION_NAME).query(
                state=patching_v1.PATCH_STATE_COMMITTED)
        self.debug_log(strategy_step,
                       "regionone_committed_patches: %s" % regionone_committed_patches)

        committed_patch_ids = list()
        for patch_id in regionone_committed_patches.keys():
            committed_patch_ids.append(patch_id)
        self.debug_log(strategy_step,
                       "RegionOne committed_patch_ids: %s" % committed_patch_ids)

        subcloud_patches = self.get_patching_client(
            strategy_step.subcloud.name).query()
        self.debug_log(strategy_step,
                       "Patches for subcloud: %s" % subcloud_patches)

        patches_to_commit = list()
        patches_to_delete = list()

        # For this subcloud, determine which patches should be committed and
        # which should be deleted. We check the patchstate here because
        # patches cannot be deleted or committed if they are in a partial
        # state (e.g. Partial-Apply or Partial-Remove).
        subcloud_patch_ids = list(subcloud_patches.keys())
        for patch_id in subcloud_patch_ids:
            if subcloud_patches[patch_id]['patchstate'] == \
                    patching_v1.PATCH_STATE_AVAILABLE:
                self.info_log(strategy_step,
                              "Patch %s will be deleted from subcloud" % patch_id)
                patches_to_delete.append(patch_id)
            elif subcloud_patches[patch_id]['patchstate'] == \
                    patching_v1.PATCH_STATE_APPLIED:
                if patch_id in committed_patch_ids:
                    self.info_log(strategy_step,
                                  "Patch %s will be committed in subcloud" % patch_id)
                    patches_to_commit.append(patch_id)

        if patches_to_delete:
            self.info_log(strategy_step, "Deleting patches %s" % patches_to_delete)
            self.get_patching_client(
                strategy_step.subcloud.name).delete(patches_to_delete)

        if self.stopped():
            raise StrategyStoppedException()

        if patches_to_commit:
            self.info_log(strategy_step,
                          "Committing patches %s in subcloud" % patches_to_commit)
            self.get_patching_client(
                strategy_step.subcloud.name).commit(patches_to_commit)

        return self.next_state
