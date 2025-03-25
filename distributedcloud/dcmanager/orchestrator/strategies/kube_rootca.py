#
# Copyright (c) 2020-2021, 2024-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dccommon.drivers.openstack import vim
from dcmanager.common import consts

from dcmanager.orchestrator.states.kube_rootca.applying_vim_strategy import (
    ApplyingVIMKubeRootcaUpdateStrategyState,
)
from dcmanager.orchestrator.states.kube_rootca.creating_vim_strategy import (
    CreatingVIMKubeRootcaUpdateStrategyState,
)
from dcmanager.orchestrator.states.kube_rootca.pre_check import (
    KubeRootcaUpdatePreCheckState,
)
from dcmanager.orchestrator.states.kube_rootca.start_update import (
    KubeRootcaUpdateStartState,
)
from dcmanager.orchestrator.states.kube_rootca.upload_cert import (
    KubeRootcaUpdateUploadCertState,
)
from dcmanager.orchestrator.strategies.base import BaseStrategy


class KubeRootcaStrategy(BaseStrategy):
    """Kube RootCA orchestration strategy"""

    # Reassign constants to avoid line length issues
    PRE_CHECK = consts.STRATEGY_STATE_KUBE_ROOTCA_UPDATE_PRE_CHECK
    START = consts.STRATEGY_STATE_KUBE_ROOTCA_UPDATE_START
    UPLOAD_CERT = consts.STRATEGY_STATE_KUBE_ROOTCA_UPDATE_UPLOAD_CERT
    CREATE_VIM_STRATEGY = consts.STRATEGY_STATE_CREATING_VIM_KUBE_ROOTCA_UPDATE_STRATEGY
    APPLY_VIM_STRATEGY = consts.STRATEGY_STATE_APPLYING_VIM_KUBE_ROOTCA_UPDATE_STRATEGY

    STATE_OPERATORS = {
        PRE_CHECK: KubeRootcaUpdatePreCheckState,
        START: KubeRootcaUpdateStartState,
        UPLOAD_CERT: KubeRootcaUpdateUploadCertState,
        CREATE_VIM_STRATEGY: CreatingVIMKubeRootcaUpdateStrategyState,
        APPLY_VIM_STRATEGY: ApplyingVIMKubeRootcaUpdateStrategyState,
    }

    def __init__(self, audit_rpc_client):
        super().__init__(
            audit_rpc_client,
            consts.SW_UPDATE_TYPE_KUBE_ROOTCA_UPDATE,
            vim.STRATEGY_NAME_KUBE_ROOTCA_UPDATE,
            consts.STRATEGY_STATE_KUBE_ROOTCA_UPDATE_PRE_CHECK,
        )

    def trigger_audit(self):
        """Trigger an audit for kube rootca update"""
        self.audit_rpc_client.trigger_kube_rootca_update_audit(self.context)
