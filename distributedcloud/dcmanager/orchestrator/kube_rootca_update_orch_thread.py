#
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.orchestrator.orch_thread import OrchThread

from dcmanager.orchestrator.states.kube_rootca.applying_vim_strategy \
    import ApplyingVIMKubeRootcaUpdateStrategyState
from dcmanager.orchestrator.states.kube_rootca.creating_vim_strategy \
    import CreatingVIMKubeRootcaUpdateStrategyState
from dcmanager.orchestrator.states.kube_rootca.pre_check \
    import KubeRootcaUpdatePreCheckState
from dcmanager.orchestrator.states.kube_rootca.start_update \
    import KubeRootcaUpdateStartState
from dcmanager.orchestrator.states.kube_rootca.upload_cert \
    import KubeRootcaUpdateUploadCertState


class KubeRootcaUpdateOrchThread(OrchThread):
    """Kube RootCA Update Orchestration Thread"""
    STATE_OPERATORS = {
        consts.STRATEGY_STATE_KUBE_ROOTCA_UPDATE_PRE_CHECK:
            KubeRootcaUpdatePreCheckState,
        consts.STRATEGY_STATE_KUBE_ROOTCA_UPDATE_START:
            KubeRootcaUpdateStartState,
        consts.STRATEGY_STATE_KUBE_ROOTCA_UPDATE_UPLOAD_CERT:
            KubeRootcaUpdateUploadCertState,
        consts.STRATEGY_STATE_CREATING_VIM_KUBE_ROOTCA_UPDATE_STRATEGY:
            CreatingVIMKubeRootcaUpdateStrategyState,
        consts.STRATEGY_STATE_APPLYING_VIM_KUBE_ROOTCA_UPDATE_STRATEGY:
            ApplyingVIMKubeRootcaUpdateStrategyState,
    }

    def __init__(self, strategy_lock, audit_rpc_client):
        super(KubeRootcaUpdateOrchThread, self).__init__(
            strategy_lock,
            audit_rpc_client,
            consts.SW_UPDATE_TYPE_KUBE_ROOTCA_UPDATE,
            vim.STRATEGY_NAME_KUBE_ROOTCA_UPDATE,
            consts.STRATEGY_STATE_KUBE_ROOTCA_UPDATE_PRE_CHECK)

    def trigger_audit(self):
        """Trigger an audit for kube rootca update"""
        self.audit_rpc_client.trigger_kube_rootca_update_audit(self.context)
