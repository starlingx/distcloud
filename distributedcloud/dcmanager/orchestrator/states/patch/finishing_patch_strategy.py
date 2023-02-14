#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dccommon.drivers.openstack import patching_v1
from dcmanager.common import consts
from dcmanager.common.exceptions import StrategyStoppedException
from dcmanager.orchestrator.states.base import BaseState


class FinishingPatchStrategyState(BaseState):
    """Patch orchestration state for cleaning up patches"""

    def __init__(self, region_name):
        super(FinishingPatchStrategyState, self).__init__(
            next_state=consts.STRATEGY_STATE_COMPLETE,
            region_name=region_name)
        self.region_one_commited_patch_ids = None

    def set_job_data(self, job_data):
        """Store an orch_thread job data object"""
        # This will immediately fail if these attributes are a mismatch
        self.region_one_commited_patch_ids = \
            job_data.region_one_commited_patch_ids

    def perform_state_action(self, strategy_step):
        self.info_log(strategy_step, "Finishing subcloud patching")

        subcloud_patches = self.get_patching_client(self.region_name).query()
        self.debug_log(strategy_step, "Patches for subcloud: %s" %
                       subcloud_patches)

        # For this subcloud, determine which patches should be committed and
        # which should be deleted. We check the patchstate here because
        # patches cannot be deleted or committed if they are in a partial
        # state (e.g. Partial-Apply or Partial-Remove).
        patches_to_commit = []
        patches_to_delete = []

        for patch_id in subcloud_patches.keys():
            patch_state = subcloud_patches[patch_id]["patchstate"]

            if patch_state == patching_v1.PATCH_STATE_AVAILABLE:
                self.info_log(strategy_step,
                              "Patch %s will be deleted from subcloud" %
                              patch_id)
                patches_to_delete.append(patch_id)

            elif (patch_state == patching_v1.PATCH_STATE_APPLIED
                  and patch_id in self.region_one_commited_patch_ids):
                self.info_log(strategy_step,
                              "Patch %s will be committed in subcloud" %
                              patch_id)
                patches_to_commit.append(patch_id)

        if patches_to_delete:
            self.info_log(strategy_step, "Deleting patches %s from subcloud" %
                          patches_to_delete)
            self.get_patching_client(self.region_name).delete(patches_to_delete)

        if self.stopped():
            raise StrategyStoppedException()

        if patches_to_commit:
            self.info_log(strategy_step, "Committing patches %s in subcloud" %
                          patches_to_commit)
            self.get_patching_client(self.region_name).commit(patches_to_commit)

        return self.next_state
