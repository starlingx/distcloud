#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_log import log as logging

from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.orchestrator.orch_thread import OrchThread
from dcmanager.orchestrator.states.software.apply_vim_software_strategy \
    import ApplyVIMSoftwareStrategyState
from dcmanager.orchestrator.states.software.cache.shared_cache_repository import \
    SharedCacheRepository
from dcmanager.orchestrator.states.software.create_vim_software_strategy \
    import CreateVIMSoftwareStrategyState
from dcmanager.orchestrator.states.software.deploy_activate \
    import DeployActivateState
from dcmanager.orchestrator.states.software.deploy_complete \
    import DeployCompleteState
from dcmanager.orchestrator.states.software.deploy_host \
    import DeployHostState
from dcmanager.orchestrator.states.software.deploy_pre_check \
    import DeployPreCheckState
from dcmanager.orchestrator.states.software.deploy_start \
    import DeployStartState
from dcmanager.orchestrator.states.software.finish_strategy \
    import FinishStrategyState
from dcmanager.orchestrator.states.software.install_license \
    import InstallLicenseState
from dcmanager.orchestrator.states.software.lock_controller \
    import LockControllerState
from dcmanager.orchestrator.states.software.pre_check \
    import PreCheckState
from dcmanager.orchestrator.states.software.swact_controller0 \
    import SwactController0State
from dcmanager.orchestrator.states.software.swact_controller1 \
    import SwactController1State
from dcmanager.orchestrator.states.software.unlock_controller \
    import UnlockControllerState
from dcmanager.orchestrator.states.software.upload \
    import UploadState

LOG = logging.getLogger(__name__)


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

    # every state in sw upgrade orchestration should have an operator
    STATE_OPERATORS = {
        consts.STRATEGY_STATE_SW_PRE_CHECK: PreCheckState,
        consts.STRATEGY_STATE_SW_INSTALL_LICENSE: InstallLicenseState,
        consts.STRATEGY_STATE_SW_UPLOAD: UploadState,
        consts.STRATEGY_STATE_SW_DEPLOY_PRE_CHECK: DeployPreCheckState,
        consts.STRATEGY_STATE_SW_DEPLOY_START: DeployStartState,
        consts.STRATEGY_STATE_SW_LOCK_CONTROLLER: LockControllerState,
        consts.STRATEGY_STATE_SW_DEPLOY_HOST: DeployHostState,
        consts.STRATEGY_STATE_SW_UNLOCK_CONTROLLER: UnlockControllerState,
        consts.STRATEGY_STATE_SW_SWACT_CONTROLLER_0: SwactController0State,
        consts.STRATEGY_STATE_SW_CREATE_VIM_STRATEGY: CreateVIMSoftwareStrategyState,
        consts.STRATEGY_STATE_SW_APPLY_VIM_STRATEGY: ApplyVIMSoftwareStrategyState,
        consts.STRATEGY_STATE_SW_SWACT_CONTROLLER_1: SwactController1State,
        consts.STRATEGY_STATE_SW_DEPLOY_ACTIVATE: DeployActivateState,
        consts.STRATEGY_STATE_SW_DEPLOY_COMPLETE: DeployCompleteState,
        consts.STRATEGY_STATE_SW_FINISH_STRATEGY: FinishStrategyState,
    }

    def __init__(self, strategy_lock, audit_rpc_client):
        super(SoftwareOrchThread, self).__init__(
            strategy_lock,
            audit_rpc_client,
            consts.SW_UPDATE_TYPE_UPGRADE,       # software update strategy type
            vim.STRATEGY_NAME_SW_UPGRADE,        # strategy type used by vim
            consts.STRATEGY_STATE_SW_PRE_CHECK)  # starting state

        # Initialize shared cache instances for the states that require them
        self._shared_caches = SharedCacheRepository(consts.SW_UPDATE_TYPE_SOFTWARE)
        self._shared_caches.initialize_caches()

    def trigger_audit(self):
        """Trigger an audit for upgrade (which is combined with patch audit)"""
        self.audit_rpc_client.trigger_patch_audit(self.context)

    def pre_apply_setup(self):
        # Restart caches for next strategy
        self._shared_caches.initialize_caches()
        super(SoftwareOrchThread, self).pre_apply_setup()

    def determine_state_operator(self, strategy_step):
        state = super(SoftwareOrchThread, self).determine_state_operator(
            strategy_step)
        state.add_shared_caches(self._shared_caches)
        return state
