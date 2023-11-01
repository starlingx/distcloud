#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dcmanager.common import consts
from dcmanager.orchestrator.states.base import BaseState


class ApplyVIMSoftwareStrategyState(BaseState):
    """Apply VIM Software Strategy software orchestration state"""

    def __init__(self, region_name):
        super(ApplyVIMSoftwareStrategyState, self).__init__(
            next_state=consts.STRATEGY_STATE_SW_SWACT_CONTROLLER_1,
            region_name=region_name
        )

    def perform_state_action(self, strategy_step):
        """Apply VIM Software Strategy region status"""
        return self.next_state
