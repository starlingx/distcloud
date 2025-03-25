# Copyright 2017 Ericsson AB.
# Copyright (c) 2017-2025 Wind River Systems, Inc.
# All Rights Reserved.
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

# TODO(nicodemos): Remove this file and all patch states after all support
# to patching is removed

from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.orchestrator.states.patch.applying_vim_patch_strategy import (
    ApplyingVIMPatchStrategyState,
)
from dcmanager.orchestrator.states.patch.creating_vim_patch_strategy import (
    CreatingVIMPatchStrategyState,
)
from dcmanager.orchestrator.states.patch.pre_check import PreCheckState
from dcmanager.orchestrator.states.patch.updating_patches import UpdatingPatchesState
from dcmanager.orchestrator.strategies.base import BaseStrategy


class PatchStrategy(BaseStrategy):
    """Patch orchestration strategy"""

    # Reassign constants to avoid line length issues
    PRE_CHECK = consts.STRATEGY_STATE_PRE_CHECK
    UPDATING_PATCHES = consts.STRATEGY_STATE_UPDATING_PATCHES
    CREATE_VIM_STRATEGY = consts.STRATEGY_STATE_CREATING_VIM_PATCH_STRATEGY
    APPLY_VIM_STRATEGY = consts.STRATEGY_STATE_APPLYING_VIM_PATCH_STRATEGY

    STATE_OPERATORS = {
        PRE_CHECK: PreCheckState,
        UPDATING_PATCHES: UpdatingPatchesState,
        CREATE_VIM_STRATEGY: CreatingVIMPatchStrategyState,
        APPLY_VIM_STRATEGY: ApplyingVIMPatchStrategyState,
    }

    def __init__(self, audit_rpc_client):
        super().__init__(
            audit_rpc_client,
            consts.SW_UPDATE_TYPE_PATCH,
            vim.STRATEGY_NAME_SW_PATCH,
            starting_state=consts.STRATEGY_STATE_PRE_CHECK,
        )

    def trigger_audit(self):
        self.audit_rpc_client.trigger_patch_audit(self.context)
