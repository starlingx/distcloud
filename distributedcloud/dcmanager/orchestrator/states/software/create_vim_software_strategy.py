#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.orchestrator.states.creating_vim_strategy import \
    CreatingVIMStrategyState


class CreateVIMSoftwareStrategyState(CreatingVIMStrategyState):
    """Create VIM Software Strategy software orchestration state"""

    def __init__(self, region_name):
        super(CreateVIMSoftwareStrategyState, self).__init__(
            next_state=consts.STRATEGY_STATE_SW_APPLY_VIM_STRATEGY,
            region_name=region_name,
            strategy_name=vim.STRATEGY_NAME_SW_USM
        )
