# Copyright 2017 Ericsson AB.
# Copyright (c) 2017-2021 Wind River Systems, Inc.
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
from dcmanager.orchestrator.states.kube.applying_vim_kube_upgrade_strategy \
    import ApplyingVIMKubeUpgradeStrategyState
from dcmanager.orchestrator.states.kube.creating_vim_kube_upgrade_strategy \
    import CreatingVIMKubeUpgradeStrategyState
from dcmanager.orchestrator.states.kube.pre_check \
    import KubeUpgradePreCheckState


class KubeUpgradeOrchThread(OrchThread):
    """Kube Upgrade Orchestration Thread"""
    # every state in kube orchestration must have an operator
    # The states are listed here in their typical execution order
    STATE_OPERATORS = {
        consts.STRATEGY_STATE_KUBE_UPGRADE_PRE_CHECK:
            KubeUpgradePreCheckState,
        consts.STRATEGY_STATE_KUBE_CREATING_VIM_KUBE_UPGRADE_STRATEGY:
            CreatingVIMKubeUpgradeStrategyState,
        consts.STRATEGY_STATE_KUBE_APPLYING_VIM_KUBE_UPGRADE_STRATEGY:
            ApplyingVIMKubeUpgradeStrategyState,
    }

    def __init__(self, strategy_lock, audit_rpc_client):
        super(KubeUpgradeOrchThread, self).__init__(
            strategy_lock,
            audit_rpc_client,
            consts.SW_UPDATE_TYPE_KUBERNETES,
            vim.STRATEGY_NAME_KUBE_UPGRADE,
            consts.STRATEGY_STATE_KUBE_UPGRADE_PRE_CHECK)

    def trigger_audit(self):
        """Trigger an audit for kubernetes"""
        self.audit_rpc_client.trigger_kubernetes_audit(self.context)
