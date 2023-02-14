# Copyright 2017 Ericsson AB.
# Copyright (c) 2017-2023 Wind River Systems, Inc.
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

from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.orchestrator.orch_thread import OrchThread
from dcmanager.orchestrator.states.patch.applying_vim_patch_strategy import \
    ApplyingVIMPatchStrategyState
from dcmanager.orchestrator.states.patch.creating_vim_patch_strategy import \
    CreatingVIMPatchStrategyState
from dcmanager.orchestrator.states.patch.finishing_patch_strategy import \
    FinishingPatchStrategyState
from dcmanager.orchestrator.states.patch.job_data import PatchJobData
from dcmanager.orchestrator.states.patch.pre_check import PreCheckState
from dcmanager.orchestrator.states.patch.updating_patches import \
    UpdatingPatchesState
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class PatchOrchThread(OrchThread):
    STATE_OPERATORS = {
        consts.STRATEGY_STATE_PRE_CHECK:
            PreCheckState,
        consts.STRATEGY_STATE_UPDATING_PATCHES:
            UpdatingPatchesState,
        consts.STRATEGY_STATE_CREATING_VIM_PATCH_STRATEGY:
            CreatingVIMPatchStrategyState,
        consts.STRATEGY_STATE_APPLYING_VIM_PATCH_STRATEGY:
            ApplyingVIMPatchStrategyState,
        consts.STRATEGY_STATE_FINISHING_PATCH_STRATEGY:
            FinishingPatchStrategyState,
    }

    def __init__(self, strategy_lock, audit_rpc_client):
        super(PatchOrchThread, self).__init__(
            strategy_lock,
            audit_rpc_client,
            consts.SW_UPDATE_TYPE_PATCH,
            vim.STRATEGY_NAME_SW_PATCH,
            starting_state=consts.STRATEGY_STATE_PRE_CHECK)

        self.job_data = None

    def pre_apply_setup(self):
        super(PatchOrchThread, self).pre_apply_setup()
        self.job_data = PatchJobData()

    def post_delete_teardown(self):
        super(PatchOrchThread, self).post_delete_teardown()
        self.job_data = None

    def determine_state_operator(self, strategy_step):
        state = super(PatchOrchThread, self).determine_state_operator(
            strategy_step)
        # Share job data with the next state operator
        state.set_job_data(self.job_data)
        return state

    def trigger_audit(self):
        self.audit_rpc_client.trigger_patch_audit(self.context)
