#
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dcmanager.common import consts
from dcmanager.orchestrator.states.unlock_host import UnlockHostState


class UnlockDuplexState(UnlockHostState):
    """Orchestration state for unlocking controller-1 host"""

    def __init__(self, region_name):
        super(UnlockDuplexState, self).__init__(
            next_state=consts.STRATEGY_STATE_SWACTING_TO_CONTROLLER_1,
            region_name=region_name,
            hostname="controller-1")
