#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.orchestrator.orch_thread import OrchThread
from dcmanager.orchestrator.states.software.apply_vim_software_strategy import \
    ApplyVIMSoftwareStrategyState
from dcmanager.orchestrator.states.software.cache.shared_cache_repository import \
    SharedCacheRepository
from dcmanager.orchestrator.states.software.create_vim_software_strategy import \
    CreateVIMSoftwareStrategyState
from dcmanager.orchestrator.states.software.finish_strategy import \
    FinishStrategyState
from dcmanager.orchestrator.states.software.install_license import \
    InstallLicenseState
from dcmanager.orchestrator.states.software.pre_check import PreCheckState


class SoftwareOrchThread(OrchThread):
    """Software Orchestration Thread

    This thread is responsible for executing the software orchestration strategy.
    Here is how it works:
    - The user creates an update strategy from CLI (or REST API) of 'usm'
    - This ends up being handled by the SwUpdateManager class, which
      runs under the main dcmanager thread. The strategy is created and stored
      in the database.
    - The user then applies the strategy from the CLI (or REST API). The
      SwUpdateManager code updates the state of the strategy in the database.
    - The SoftwareOrchThread wakes up periodically and checks the database for
      a strategy that is in an active state (applying, aborting, etc...). If
      so, it executes the strategy, updating the strategy and steps in the
      database as it goes, with state and progress information.
    """

    # every state in sw deploy orchestration should have an operator
    STATE_OPERATORS = {
        consts.STRATEGY_STATE_SW_PRE_CHECK: PreCheckState,
        consts.STRATEGY_STATE_SW_INSTALL_LICENSE: InstallLicenseState,
        consts.STRATEGY_STATE_SW_CREATE_VIM_STRATEGY: CreateVIMSoftwareStrategyState,
        consts.STRATEGY_STATE_SW_APPLY_VIM_STRATEGY: ApplyVIMSoftwareStrategyState,
        consts.STRATEGY_STATE_SW_FINISH_STRATEGY: FinishStrategyState,
    }

    def __init__(self, strategy_lock, audit_rpc_client):
        super().__init__(
            strategy_lock,
            audit_rpc_client,
            consts.SW_UPDATE_TYPE_SOFTWARE,      # software update strategy type
            vim.STRATEGY_NAME_SW_USM,            # strategy type used by vim
            consts.STRATEGY_STATE_SW_PRE_CHECK)  # starting state

        # Initialize shared cache instances for the states that require them
        self._shared_caches = SharedCacheRepository(consts.SW_UPDATE_TYPE_SOFTWARE)
        self._shared_caches.initialize_caches()

    def trigger_audit(self):
        """Trigger an audit for software"""
        self.audit_rpc_client.trigger_software_audit(self.context)

    def pre_apply_setup(self):
        # Restart caches for next strategy
        self._shared_caches.initialize_caches()
        super().pre_apply_setup()

    def determine_state_operator(self, strategy_step):
        state = super().determine_state_operator(strategy_step)
        state.add_shared_caches(self._shared_caches)
        return state
