#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock

from dcmanager.common import consts
from dcmanager.manager.states.upgrade import migrating_data
from dcmanager.tests.unit.manager.states.upgrade.test_base import FakeSystem
from dcmanager.tests.unit.manager.states.upgrade.test_base  \
    import TestSwUpgradeState


class TestSwUpgradeMigratingDataStage(TestSwUpgradeState):

    def setUp(self):
        super(TestSwUpgradeMigratingDataStage, self).setUp()

        # next state after 'migrating data' is 'unlocking controller'
        self.on_success_state = consts.STRATEGY_STATE_UNLOCKING_CONTROLLER

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = \
            self.setup_strategy_step(consts.STRATEGY_STATE_MIGRATING_DATA)

        # Add mock API endpoints for sysinv client calls invoked by this state
        self.sysinv_client.get_system = mock.MagicMock()
        self.sysinv_client.get_system.return_value = FakeSystem()

    @mock.patch.object(migrating_data, 'db_api')
    def test_upgrade_subcloud_migrating_data_failure(self, mock_db_api):
        """Test migrating data step where the subprocess call fails."""

        # Simulate data migration has not started yet
        self.sysinv_client.get_system.side_effect = \
            [FakeSystem(), Exception("Fresh install!")]

        # Simulate a failed subprocess call to the platform upgrade playbook
        # on the subcloud.
        p = mock.patch(
            'dcmanager.manager.states.upgrade.migrating_data.migrate_subcloud_data')
        self.mock_platform_upgrade_call = p.start()
        self.mock_platform_upgrade_call.side_effect = Exception("Bad day!")
        self.addCleanup(p.stop)

        # Invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Verify a failure leads to a state failure
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    @mock.patch.object(migrating_data, 'db_api')
    def test_upgrade_subcloud_migrating_data_success(self, mock_db_api):
        """Test migrating data step where the subprocess call passes."""

        # Simulate data migration has not started yet
        self.sysinv_client.get_system.side_effect = \
            [FakeSystem(), Exception("Fresh install!")]

        # Simulate a successful subprocess call to the platform upgrade playbook
        # on the subcloud.
        p = mock.patch(
            'dcmanager.manager.states.upgrade.migrating_data.migrate_subcloud_data')
        self.mock_platform_upgrade_call = p.start()
        self.mock_platform_upgrade_call.return_value = 0
        self.addCleanup(p.stop)

        # Invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # On success, should have moved to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_upgrade_subcloud_migrating_data_skip(self):
        """Test the migrating data step skipped"""

        # get_system is mocked to return the same fake system for both
        # system controller and subclould.

        # Invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # On success, should have moved to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)
