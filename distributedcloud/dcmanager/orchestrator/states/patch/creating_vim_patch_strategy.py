#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.orchestrator.states.creating_vim_strategy import CreatingVIMStrategyState


# Max time: 2 minutes = 12 queries x 10 seconds between
DEFAULT_MAX_QUERIES = 12
DEFAULT_SLEEP_DURATION = 10


class CreatingVIMPatchStrategyState(CreatingVIMStrategyState):
    """State for creating a VIM patch strategy."""

    def __init__(self, region_name):
        super(CreatingVIMPatchStrategyState, self).__init__(
            next_state=consts.STRATEGY_STATE_APPLYING_VIM_PATCH_STRATEGY,
            region_name=region_name,
            strategy_name=vim.STRATEGY_NAME_SW_PATCH,
        )

        self.SKIP_REASON = "no software patches need to be applied"
        self.SKIP_STATE = consts.STRATEGY_STATE_COMPLETE

        # Change CreatingVIMStrategyState default values
        self.sleep_duration = DEFAULT_SLEEP_DURATION
        self.max_queries = DEFAULT_MAX_QUERIES

    def skip_check(self, strategy_step, subcloud_strategy):
        """Check if the VIM stategy needs to be skipped"""

        if (
            subcloud_strategy
            and (subcloud_strategy.state == vim.STATE_BUILD_FAILED)
            and (subcloud_strategy.build_phase.reason == self.SKIP_REASON)
        ):
            self.info_log(
                strategy_step,
                "Skip forward in state machine due to: ({})".format(self.SKIP_REASON),
            )
            return self.SKIP_STATE

        # If we get here, there is not a reason to skip
        return None
