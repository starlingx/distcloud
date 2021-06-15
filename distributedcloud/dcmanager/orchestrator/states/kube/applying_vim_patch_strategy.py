#
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.orchestrator.states.applying_vim_strategy \
    import ApplyingVIMStrategyState


class ApplyingVIMPatchStrategyState(ApplyingVIMStrategyState):
    """State for applying the VIM patch strategy during kube upgrade."""

    def __init__(self, region_name):
        super(ApplyingVIMPatchStrategyState, self).__init__(
            next_state=consts.STRATEGY_STATE_KUBE_DELETING_VIM_PATCH_STRATEGY,
            region_name=region_name,
            strategy_name=vim.STRATEGY_NAME_SW_PATCH)
