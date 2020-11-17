# Copyright 2017 Ericsson AB.
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
# Copyright (c) 2017-2021 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#
from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.orchestrator.orch_thread import OrchThread
from dcmanager.orchestrator.states.kube.applying_vim_kube_upgrade_strategy \
    import ApplyingVIMKubeUpgradeStrategyState
from dcmanager.orchestrator.states.kube.applying_vim_patch_strategy \
    import ApplyingVIMPatchStrategyState
from dcmanager.orchestrator.states.kube.creating_vim_kube_upgrade_strategy \
    import CreatingVIMKubeUpgradeStrategyState
from dcmanager.orchestrator.states.kube.creating_vim_patch_strategy \
    import CreatingVIMPatchStrategyState
from dcmanager.orchestrator.states.kube.deleting_vim_patch_strategy \
    import DeletingVIMPatchStrategyState
from dcmanager.orchestrator.states.kube.updating_kube_patches \
    import UpdatingKubePatchesState


class KubeUpgradeOrchThread(OrchThread):
    """Kube Upgrade Orchestration Thread"""
    # every state in kube orchestration must have an operator
    STATE_OPERATORS = {
        consts.STRATEGY_STATE_KUBE_UPDATING_PATCHES:
            UpdatingKubePatchesState,
        consts.STRATEGY_STATE_KUBE_CREATING_VIM_PATCH_STRATEGY:
            CreatingVIMPatchStrategyState,
        consts.STRATEGY_STATE_KUBE_APPLYING_VIM_PATCH_STRATEGY:
            ApplyingVIMPatchStrategyState,
        consts.STRATEGY_STATE_KUBE_DELETING_VIM_PATCH_STRATEGY:
            DeletingVIMPatchStrategyState,
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
            consts.STRATEGY_STATE_KUBE_UPDATING_PATCHES)

    def trigger_audit(self):
        """Trigger an audit for kubernetes"""
        self.audit_rpc_client.trigger_kubernetes_audit(self.context)
