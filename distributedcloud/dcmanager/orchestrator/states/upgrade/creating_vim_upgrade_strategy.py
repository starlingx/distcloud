#
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.orchestrator.states.creating_vim_strategy \
    import CreatingVIMStrategyState


class CreatingVIMUpgradeStrategyState(CreatingVIMStrategyState):
    """State for creating the VIM upgrade strategy."""

    def __init__(self, region_name):
        super(CreatingVIMUpgradeStrategyState, self).__init__(
            next_state=consts.STRATEGY_STATE_APPLYING_VIM_UPGRADE_STRATEGY,
            region_name=region_name,
            strategy_name=vim.STRATEGY_NAME_SW_UPGRADE)
