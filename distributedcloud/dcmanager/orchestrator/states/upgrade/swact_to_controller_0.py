#
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dcmanager.common import consts
from dcmanager.orchestrator.states.swact_host import SwactHostState


class SwactToController0State(SwactHostState):
    """Orchestration state for swacting to controller-0 host"""

    def __init__(self, region_name):
        super(SwactToController0State, self).__init__(
            next_state=consts.STRATEGY_STATE_ACTIVATING_UPGRADE,
            region_name=region_name,
            active="controller-0",
            standby="controller-1",)
