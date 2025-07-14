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
from dcmanager.orchestrator.cache.shared_cache_repository import SharedCacheRepository
from dcmanager.orchestrator.states.kube.applying_vim_kube_upgrade_strategy import (
    ApplyingVIMKubeUpgradeStrategyState,
)
from dcmanager.orchestrator.states.kube.creating_vim_kube_upgrade_strategy import (
    CreatingVIMKubeUpgradeStrategyState,
)
from dcmanager.orchestrator.states.kube.pre_check import KubeUpgradePreCheckState
from dcmanager.orchestrator.strategies.base import BaseStrategy


class KubernetesStrategy(BaseStrategy):
    """Kubernetes orchestration strategy"""

    # Reassign constants to avoid line length issues
    PRE_CHECK = consts.STRATEGY_STATE_KUBE_UPGRADE_PRE_CHECK
    CREATE_VIM_STRATEGY = consts.STRATEGY_STATE_KUBE_CREATING_VIM_KUBE_UPGRADE_STRATEGY
    APPLY_VIM_STRATEGY = consts.STRATEGY_STATE_KUBE_APPLYING_VIM_KUBE_UPGRADE_STRATEGY

    # every state in kube orchestration must have an operator
    # The states are listed here in their typical execution order
    STATE_OPERATORS = {
        PRE_CHECK: KubeUpgradePreCheckState,
        CREATE_VIM_STRATEGY: CreatingVIMKubeUpgradeStrategyState,
        APPLY_VIM_STRATEGY: ApplyingVIMKubeUpgradeStrategyState,
    }

    def __init__(self):
        super().__init__(
            consts.SW_UPDATE_TYPE_KUBERNETES,
            vim.STRATEGY_NAME_KUBE_UPGRADE,
            consts.STRATEGY_STATE_KUBE_UPGRADE_PRE_CHECK,
        )

        # Initialize shared cache instances for the states that require them
        self._shared_caches = SharedCacheRepository(self.update_type)
        self._shared_caches.initialize_caches()

    def pre_apply_setup(self, strategy):
        # Restart caches for next strategy so that we always have the
        # latest RegionOne data at the moment the strategy is applied
        self._shared_caches.initialize_caches()
        super().pre_apply_setup(strategy)

    def determine_state_operator(self, region_name, strategy_step):
        state = super().determine_state_operator(region_name, strategy_step)
        # Share the cache with the state object
        state.add_shared_caches(self._shared_caches)
        return state
