#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dcmanager.common import consts
from dcmanager.orchestrator.states.swact_host import SwactHostState


class SwactController0State(SwactHostState):
    """Software orchestration state to swact away from controller-0"""

    def __init__(self, region_name):
        super(SwactController0State, self).__init__(
            next_state=consts.STRATEGY_STATE_SW_CREATE_VIM_STRATEGY,
            region_name=region_name,
            active="controller-1",
            standby="controller-0",)
