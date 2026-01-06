#
# Copyright (c) 2023-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.orchestrator.cache.shared_cache_repository import SharedCacheRepository
from dcmanager.orchestrator.states.prestage.states import PrestageImagesState
from dcmanager.orchestrator.states.prestage.states import PrestagePackagesState
from dcmanager.orchestrator.states.prestage.states import PrestagePreCheckState
from dcmanager.orchestrator.states.software.apply_vim_software_strategy import (
    ApplyVIMSoftwareStrategyState,
)
from dcmanager.orchestrator.states.software.create_vim_software_strategy import (
    CreateVIMSoftwareStrategyState,
)
from dcmanager.orchestrator.states.software.finish_strategy import FinishStrategyState
from dcmanager.orchestrator.states.software.install_license import InstallLicenseState
from dcmanager.orchestrator.states.software.pre_check import PreCheckState
from dcmanager.orchestrator.strategies.base import BaseStrategy


class SoftwareStrategy(BaseStrategy):
    """Software orchestration strategy"""

    # every state in sw deploy orchestration should have an operator
    STATE_OPERATORS = {
        consts.STRATEGY_STATE_SW_PRE_CHECK: PreCheckState,
        consts.STRATEGY_STATE_SW_INSTALL_LICENSE: InstallLicenseState,
        consts.STRATEGY_STATE_SW_CREATE_VIM_STRATEGY: CreateVIMSoftwareStrategyState,
        consts.STRATEGY_STATE_SW_APPLY_VIM_STRATEGY: ApplyVIMSoftwareStrategyState,
        consts.STRATEGY_STATE_SW_FINISH_STRATEGY: FinishStrategyState,
    }

    def __init__(self):
        super().__init__(
            consts.SW_UPDATE_TYPE_SOFTWARE,  # software update strategy type
            vim.STRATEGY_NAME_SW_USM,  # strategy type used by vim
            consts.STRATEGY_STATE_SW_PRE_CHECK,  # starting state
        )

        # Initialize shared cache instances for the states that require them
        self._shared_caches = SharedCacheRepository(consts.SW_UPDATE_TYPE_SOFTWARE)
        # For prestage operations
        self.oam_floating_ip_dict = dict()

    def pre_apply_setup(self, strategy):
        # Start caches for the strategy
        self.debug_log("Starting caches")
        self._shared_caches.initialize_caches()
        # If sw-deploy needs to be done with prestage, add prestage state operators
        if strategy.extra_args.get(consts.EXTRA_ARGS_WITH_PRESTAGE):
            self.STATE_OPERATORS.update(
                {
                    consts.STRATEGY_STATE_PRESTAGE_PRE_CHECK: PrestagePreCheckState,
                    consts.STRATEGY_STATE_PRESTAGE_PACKAGES: PrestagePackagesState,
                    consts.STRATEGY_STATE_PRESTAGE_IMAGES: PrestageImagesState,
                }
            )
        super().pre_apply_setup(strategy)

    def teardown(self):
        self.oam_floating_ip_dict.clear()
        return super().teardown()

    def determine_state_operator(self, region_name, strategy_step):
        state = super().determine_state_operator(region_name, strategy_step)
        return state
