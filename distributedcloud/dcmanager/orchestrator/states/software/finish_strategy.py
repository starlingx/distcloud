#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dcmanager.common import consts
from dcmanager.orchestrator.states.base import BaseState


class FinishStrategyState(BaseState):
    """Finish Strategy software orchestration state"""

    def __init__(self, region_name):
        super(FinishStrategyState, self).__init__(
            next_state=consts.STRATEGY_STATE_COMPLETE,
            region_name=region_name,
        )

    def perform_state_action(self, strategy_step):
        """Finish Strategy region status"""
        return self.next_state
