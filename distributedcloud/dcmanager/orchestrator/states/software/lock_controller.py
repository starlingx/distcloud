#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dcmanager.common import consts
from dcmanager.orchestrator.states.lock_host import LockHostState


class LockControllerState(LockHostState):
    """Lock controller software orchestration state"""

    def __init__(self, region_name):
        super(LockControllerState, self).__init__(
            next_state=consts.STRATEGY_STATE_SW_DEPLOY_HOST,
            region_name=region_name,
            hostname=self.get_hostname(region_name)
        )

    def get_hostname(self, region_name):
        subcloud_type = self.get_sysinv_client(
            region_name).get_system().system_mode
        if subcloud_type == consts.SYSTEM_MODE_SIMPLEX:
            return "controller-0"
        else:
            return "controller-1"
