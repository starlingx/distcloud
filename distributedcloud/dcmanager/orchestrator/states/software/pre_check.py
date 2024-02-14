#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dcmanager.common import consts
from dcmanager.orchestrator.states.base import BaseState


class PreCheckState(BaseState):
    """Pre check software orchestration state"""

    def __init__(self, region_name):
        super().__init__(
            next_state=consts.STRATEGY_STATE_SW_INSTALL_LICENSE,
            region_name=region_name,
        )

    def perform_state_action(self, strategy_step):
        """Pre check region status"""
        return self.next_state
