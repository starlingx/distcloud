#
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dcmanager.common import consts
from dcmanager.orchestrator.states.lock_host import LockHostState


class LockDuplexState(LockHostState):
    """Orchestration state for locking controller-1 host"""

    def __init__(self, region_name):
        super(LockDuplexState, self).__init__(
            next_state=consts.STRATEGY_STATE_UPGRADING_DUPLEX,
            region_name=region_name,
            hostname="controller-1")
