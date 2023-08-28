#
# Copyright (c) 2020, 2022, 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock
from tsconfig.tsconfig import SW_VERSION

from dcmanager.common import consts
from dcmanager.db.sqlalchemy import api as db_api
from dcmanager.tests.unit.orchestrator.states.fakes import FakeLoad
from dcmanager.tests.unit.orchestrator.states.fakes import PREVIOUS_VERSION
from dcmanager.tests.unit.orchestrator.states.upgrade.test_base \
    import TestSwUpgradeState

# UpgradingSimplexState uses SW_VERSION as the upgraded version check
UPGRADED_VERSION = SW_VERSION

PREVIOUS_LOAD = FakeLoad(1, software_version=PREVIOUS_VERSION,
                         state='imported')
UPGRADED_LOAD = FakeLoad(2, software_version=UPGRADED_VERSION,
                         state='active')
FAKE_ISO = '/opt/dc-vault/loads/' + UPGRADED_VERSION + '/bootimage.iso'
FAKE_SIG = '/opt/dc-vault/loads/' + UPGRADED_VERSION + '/bootimage.sig'


class TestSwUpgradeUpgradingSimplexStage(TestSwUpgradeState):

    def setUp(self):
        super(TestSwUpgradeUpgradingSimplexStage, self).setUp()

        # next state after 'upgrading simplex is 'migrating data'
        self.on_success_state = consts.STRATEGY_STATE_MIGRATING_DATA

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            self.subcloud.id, consts.STRATEGY_STATE_UPGRADING_SIMPLEX)

        # simulate get_vault_load_files finding the iso and sig in the vault
        p = mock.patch('dcmanager.common.utils.get_vault_load_files')
        self.mock_vault_files = p.start()
        self.mock_vault_files.return_value = (FAKE_ISO, FAKE_SIG)
        self.addCleanup(p.stop)

        # Add mock API endpoints for sysinv client calls invoked by this state
        self.sysinv_client.get_loads = mock.MagicMock()

    def test_success_already_upgraded(self):
        """Test upgrading_simplex where the load already upgraded / active."""

        # The state machine skips if the load is already upgraded and active
        self.sysinv_client.get_loads.return_value = [
            UPGRADED_LOAD,
        ]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # On success, the state should transition to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_subcloud_simplex_upgrade_fails_no_install_data(self):
        """Test the upgrading_simplex fails due to missing install data"""
        self.sysinv_client.get_loads.return_value = [
            PREVIOUS_LOAD,
        ]

        # Update the subcloud to have missing data_install
        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               data_install="")

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Verify it failed due to the get_upgrades failing
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)
