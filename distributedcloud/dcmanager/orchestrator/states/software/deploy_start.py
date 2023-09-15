#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dcmanager.common import consts
from dcmanager.orchestrator.states.base import BaseState


class DeployStartState(BaseState):
    """Deploy start software orchestration state"""

    def __init__(self, region_name):
        super(DeployStartState, self).__init__(
            next_state=consts.STRATEGY_STATE_SW_LOCK_CONTROLLER,
            region_name=region_name,
        )

    def perform_state_action(self, strategy_step):
        """Deploy Start region status"""
        return self.next_state
