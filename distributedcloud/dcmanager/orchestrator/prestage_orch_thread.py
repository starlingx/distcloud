# Copyright (c) 2022 Wind River Systems, Inc.
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
from oslo_log import log as logging

from dcmanager.common import consts
from dcmanager.orchestrator.orch_thread import OrchThread
from dcmanager.orchestrator.states.prestage import states

LOG = logging.getLogger(__name__)


class PrestageOrchThread(OrchThread):
    """Prestage Orchestration Thread"""

    # Every state in prestage orchestration must have an operator
    # The states are listed here in their typical execution order
    STATE_OPERATORS = {
        consts.STRATEGY_STATE_PRESTAGE_PRE_CHECK:
            states.PrestagePreCheckState,
        consts.STRATEGY_STATE_PRESTAGE_PREPARE:
            states.PrestagePrepareState,
        consts.STRATEGY_STATE_PRESTAGE_PACKAGES:
            states.PrestagePackagesState,
        consts.STRATEGY_STATE_PRESTAGE_IMAGES:
            states.PrestageImagesState,
    }

    def __init__(self, strategy_lock, audit_rpc_client):
        super(PrestageOrchThread, self).__init__(
            strategy_lock,
            audit_rpc_client,
            consts.SW_UPDATE_TYPE_PRESTAGE,
            None,
            consts.STRATEGY_STATE_PRESTAGE_PRE_CHECK)

    def trigger_audit(self):
        """Trigger an audit"""
        pass
