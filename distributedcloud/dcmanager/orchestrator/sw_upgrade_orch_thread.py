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

from dcmanager.orchestrator.states.upgrade.activating \
    import ActivatingUpgradeState
from dcmanager.orchestrator.states.upgrade.applying_vim_upgrade_strategy \
    import ApplyingVIMUpgradeStrategyState
from dcmanager.orchestrator.states.upgrade.completing \
    import CompletingUpgradeState
from dcmanager.orchestrator.states.upgrade.creating_vim_upgrade_strategy \
    import CreatingVIMUpgradeStrategyState
from dcmanager.orchestrator.states.upgrade.deleting_load \
    import DeletingLoadState
from dcmanager.orchestrator.states.upgrade.finishing_patch_strategy \
    import FinishingPatchStrategyState
from dcmanager.orchestrator.states.upgrade.importing_load \
    import ImportingLoadState
from dcmanager.orchestrator.states.upgrade.installing_license \
    import InstallingLicenseState
from dcmanager.orchestrator.states.upgrade.lock_duplex \
    import LockDuplexState
from dcmanager.orchestrator.states.upgrade.lock_simplex \
    import LockSimplexState
from dcmanager.orchestrator.states.upgrade.migrating_data \
    import MigratingDataState
from dcmanager.orchestrator.states.upgrade.pre_check \
    import PreCheckState
from dcmanager.orchestrator.states.upgrade.starting_upgrade \
    import StartingUpgradeState
from dcmanager.orchestrator.states.upgrade.swact_to_controller_0 \
    import SwactToController0State
from dcmanager.orchestrator.states.upgrade.swact_to_controller_1 \
    import SwactToController1State
from dcmanager.orchestrator.states.upgrade.unlock_duplex \
    import UnlockDuplexState
from dcmanager.orchestrator.states.upgrade.unlock_simplex \
    import UnlockSimplexState
from dcmanager.orchestrator.states.upgrade.updating_patches \
    import UpdatingPatchesState
from dcmanager.orchestrator.states.upgrade.upgrading_duplex \
    import UpgradingDuplexState
from dcmanager.orchestrator.states.upgrade.upgrading_simplex \
    import UpgradingSimplexState


class SwUpgradeOrchThread(OrchThread):
    """SwUpgrade Orchestration Thread

    This thread is responsible for executing the upgrade orchestration strategy.
    Here is how it works:
    - The user creates an update strategy from CLI (or REST API) of 'upgrade'
    - This ends up being handled by the SwUpdateManager class, which
      runs under the main dcmanager thread. The strategy is created and stored
      in the database.
    - The user then applies the strategy from the CLI (or REST API). The
      SwUpdateManager code updates the state of the strategy in the database.
    - The SwUpgradeOrchThread wakes up periodically and checks the database for
      a strategy that is in an active state (applying, aborting, etc...). If
      so, it executes the strategy, updating the strategy and steps in the
      database as it goes, with state and progress information.
    """
    # every state in sw upgrade orchestration should have an operator
    STATE_OPERATORS = {
        consts.STRATEGY_STATE_PRE_CHECK: PreCheckState,
        consts.STRATEGY_STATE_INSTALLING_LICENSE: InstallingLicenseState,
        consts.STRATEGY_STATE_IMPORTING_LOAD: ImportingLoadState,
        consts.STRATEGY_STATE_UPDATING_PATCHES: UpdatingPatchesState,
        consts.STRATEGY_STATE_FINISHING_PATCH_STRATEGY:
            FinishingPatchStrategyState,
        consts.STRATEGY_STATE_STARTING_UPGRADE: StartingUpgradeState,
        consts.STRATEGY_STATE_LOCKING_CONTROLLER_0: LockSimplexState,
        consts.STRATEGY_STATE_LOCKING_CONTROLLER_1: LockDuplexState,
        consts.STRATEGY_STATE_UPGRADING_SIMPLEX: UpgradingSimplexState,
        consts.STRATEGY_STATE_UPGRADING_DUPLEX: UpgradingDuplexState,
        consts.STRATEGY_STATE_MIGRATING_DATA: MigratingDataState,
        consts.STRATEGY_STATE_SWACTING_TO_CONTROLLER_0:
            SwactToController0State,
        consts.STRATEGY_STATE_SWACTING_TO_CONTROLLER_1:
            SwactToController1State,
        consts.STRATEGY_STATE_UNLOCKING_CONTROLLER_0: UnlockSimplexState,
        consts.STRATEGY_STATE_UNLOCKING_CONTROLLER_1: UnlockDuplexState,
        consts.STRATEGY_STATE_ACTIVATING_UPGRADE: ActivatingUpgradeState,
        consts.STRATEGY_STATE_COMPLETING_UPGRADE: CompletingUpgradeState,
        consts.STRATEGY_STATE_CREATING_VIM_UPGRADE_STRATEGY:
            CreatingVIMUpgradeStrategyState,
        consts.STRATEGY_STATE_APPLYING_VIM_UPGRADE_STRATEGY:
            ApplyingVIMUpgradeStrategyState,
        consts.STRATEGY_STATE_DELETING_LOAD: DeletingLoadState,
    }

    def __init__(self, strategy_lock, audit_rpc_client):
        super(SwUpgradeOrchThread, self).__init__(
            strategy_lock,
            audit_rpc_client,
            consts.SW_UPDATE_TYPE_UPGRADE,    # software update strategy type
            vim.STRATEGY_NAME_SW_UPGRADE,     # strategy type used by vim
            consts.STRATEGY_STATE_PRE_CHECK)  # starting state

    def trigger_audit(self):
        """Trigger an audit for upgrade (which is combined with patch audit)"""
        self.audit_rpc_client.trigger_patch_audit(self.context)
