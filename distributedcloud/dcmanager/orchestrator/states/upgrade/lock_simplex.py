#
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dcmanager.common import consts
from dcmanager.orchestrator.states.lock_host import LockHostState


class LockSimplexState(LockHostState):
    """Orchestration state for locking controller-0 host"""

    def __init__(self, region_name):
        super(LockSimplexState, self).__init__(
            next_state=consts.STRATEGY_STATE_UPGRADING_SIMPLEX,
            region_name=region_name,
            hostname="controller-0",)
