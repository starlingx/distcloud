# Copyright (c) 2022-2025 Wind River Systems, Inc.
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

from dcmanager.common import consts
from dcmanager.orchestrator.cache.shared_cache_repository import SharedCacheRepository
from dcmanager.orchestrator.states.prestage import states
from dcmanager.orchestrator.strategies.base import BaseStrategy


class PrestageStrategy(BaseStrategy):
    """Prestage orchestration strategy"""

    # Every state in prestage orchestration must have an operator
    # The states are listed here in their typical execution order
    STATE_OPERATORS = {
        consts.STRATEGY_STATE_PRESTAGE_PRE_CHECK: states.PrestagePreCheckState,
        consts.STRATEGY_STATE_PRESTAGE_PACKAGES: states.PrestagePackagesState,
        consts.STRATEGY_STATE_PRESTAGE_IMAGES: states.PrestageImagesState,
    }

    def __init__(self):
        super().__init__(
            consts.SW_UPDATE_TYPE_PRESTAGE,
            None,
            consts.STRATEGY_STATE_PRESTAGE_PRE_CHECK,
        )
        # Initialize shared cache instances for the states that require them
        self._shared_caches = SharedCacheRepository(consts.SW_UPDATE_TYPE_SOFTWARE)
        self._shared_caches.initialize_caches()
        self.extra_args = None
        self.oam_floating_ip_dict = None

    def pre_apply_setup(self, strategy):
        # Restart caches for next strategy
        self._shared_caches.initialize_caches()
        self.extra_args = strategy.extra_args
        self.oam_floating_ip_dict = dict()
        super().pre_apply_setup(strategy)

    def determine_state_operator(self, region_name, strategy_step):
        state = super().determine_state_operator(region_name, strategy_step)
        state.add_shared_caches(self._shared_caches)
        state.add_extra_args(self.extra_args)
        state.add_oam_floating_ip_dict(self.oam_floating_ip_dict)
        return state
