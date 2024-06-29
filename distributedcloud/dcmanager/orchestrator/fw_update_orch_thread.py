# Copyright 2017 Ericsson AB.
# Copyright (c) 2017-2021, 2024 Wind River Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.orchestrator.orch_thread import OrchThread
from dcmanager.orchestrator.states.firmware.applying_vim_strategy import (
    ApplyingVIMStrategyState,
)
from dcmanager.orchestrator.states.firmware.creating_vim_strategy import (
    CreatingVIMStrategyState,
)
from dcmanager.orchestrator.states.firmware.finishing_fw_update import (
    FinishingFwUpdateState,
)
from dcmanager.orchestrator.states.firmware.importing_firmware import (
    ImportingFirmwareState,
)


class FwUpdateOrchThread(OrchThread):
    """FwUpdate Orchestration Thread

    This thread is responsible for the firmware orchestration strategy.
    Here is how it works:
    - The user creates an update strategy from CLI (or REST API) of 'firmware'
    - This is being handled by the SwUpdateManager class, which
      runs under the main dcmanager thread. The strategy is created and stored
      in the database.
    - The user then applies the strategy from the CLI (or REST API). The
      SwUpdateManager code updates the state of the strategy in the database.
    - The FwUpdateOrchThread wakes up periodically and checks the database for
      a strategy that is in an active state (applying, aborting, etc...). If
      so, it executes the strategy, updating the strategy and steps in the
      database as it goes, with state and progress information.
    """

    # every state in fw orchestration must have an operator
    STATE_OPERATORS = {
        consts.STRATEGY_STATE_IMPORTING_FIRMWARE: ImportingFirmwareState,
        consts.STRATEGY_STATE_CREATING_FW_UPDATE_STRATEGY: CreatingVIMStrategyState,
        consts.STRATEGY_STATE_APPLYING_FW_UPDATE_STRATEGY: ApplyingVIMStrategyState,
        consts.STRATEGY_STATE_FINISHING_FW_UPDATE: FinishingFwUpdateState,
    }

    def __init__(self, strategy_lock, audit_rpc_client):
        super(FwUpdateOrchThread, self).__init__(
            strategy_lock,
            audit_rpc_client,
            consts.SW_UPDATE_TYPE_FIRMWARE,
            vim.STRATEGY_NAME_FW_UPDATE,
            consts.STRATEGY_STATE_IMPORTING_FIRMWARE,
        )

    def trigger_audit(self):
        """Trigger an audit for firmware"""
        self.audit_rpc_client.trigger_firmware_audit(self.context)
