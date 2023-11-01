#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dcmanager.common import consts
from dcmanager.orchestrator.states.swact_host import SwactHostState


class SwactController1State(SwactHostState):
    """Software orchestration state to swact away from controller-1"""

    def __init__(self, region_name):
        super(SwactController1State, self).__init__(
            next_state=consts.STRATEGY_STATE_SW_DEPLOY_ACTIVATE,
            region_name=region_name,
            active="controller-0",
            standby="controller-1")
