#
# Copyright (c) 2020-2021, 2024-2026 Wind River Systems, Inc.
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
from dcmanager.orchestrator.strategies.base import BaseStrategy


class KubeRootcaStrategy(BaseStrategy):
    """Kube RootCA orchestration strategy"""

    # Reassign constants to avoid line length issues
    CREATE_VIM_STRATEGY = consts.STRATEGY_STATE_CREATING_VIM_KUBE_ROOTCA_UPDATE_STRATEGY
    APPLY_VIM_STRATEGY = consts.STRATEGY_STATE_APPLYING_VIM_KUBE_ROOTCA_UPDATE_STRATEGY

    STATE_OPERATORS = {
        CREATE_VIM_STRATEGY: CreatingVIMKubeRootcaUpdateStrategyState,
        APPLY_VIM_STRATEGY: ApplyingVIMKubeRootcaUpdateStrategyState,
    }

    def __init__(self):
        super().__init__(
            consts.SW_UPDATE_TYPE_KUBE_ROOTCA_UPDATE,
            vim.STRATEGY_NAME_KUBE_ROOTCA_UPDATE,
            consts.STRATEGY_STATE_CREATING_VIM_KUBE_ROOTCA_UPDATE_STRATEGY,
        )
