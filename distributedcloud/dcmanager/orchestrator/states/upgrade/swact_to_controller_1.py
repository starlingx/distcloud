#
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dcmanager.common import consts
from dcmanager.orchestrator.states.swact_host import SwactHostState


class SwactToController1State(SwactHostState):
    """Orchestration state for swacting to controller-1 host"""

    def __init__(self, region_name):
        super(SwactToController1State, self).__init__(
            next_state=consts.STRATEGY_STATE_CREATING_VIM_UPGRADE_STRATEGY,
            region_name=region_name,
            active="controller-1",
            standby="controller-0")
