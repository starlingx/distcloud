# Copyright 2017 Ericsson AB.
# Copyright (c) 2017-2021, 2024-2025 Wind River Systems, Inc.
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
from dcmanager.orchestrator.strategies.base import BaseStrategy


class FirmwareStrategy(BaseStrategy):
    """Firmware orchestration strategy"""

    # Every state in fw orchestration must have an operator
    STATE_OPERATORS = {
        consts.STRATEGY_STATE_IMPORTING_FIRMWARE: ImportingFirmwareState,
        consts.STRATEGY_STATE_CREATING_FW_UPDATE_STRATEGY: CreatingVIMStrategyState,
        consts.STRATEGY_STATE_APPLYING_FW_UPDATE_STRATEGY: ApplyingVIMStrategyState,
        consts.STRATEGY_STATE_FINISHING_FW_UPDATE: FinishingFwUpdateState,
    }

    def __init__(self):
        super().__init__(
            consts.SW_UPDATE_TYPE_FIRMWARE,
            vim.STRATEGY_NAME_FW_UPDATE,
            consts.STRATEGY_STATE_IMPORTING_FIRMWARE,
        )
