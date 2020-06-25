#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock

from dcmanager.common import consts
from dcmanager.manager.states.upgrade import migrating_data
from dcmanager.tests.unit.manager.states.upgrade.test_base \
    import FakeController
from dcmanager.tests.unit.manager.states.upgrade.test_base import FakeSystem
from dcmanager.tests.unit.manager.states.upgrade.test_base  \
    import TestSwUpgradeState

CONTROLLER_0_LOCKED = FakeController(administrative=consts.ADMIN_LOCKED)
CONTROLLER_0_UNLOCKING = \
    FakeController(administrative=consts.ADMIN_UNLOCKED,
                   operational=consts.OPERATIONAL_DISABLED)
CONTROLLER_0_UNLOCKED = \
    FakeController(administrative=consts.ADMIN_UNLOCKED,
                   operational=consts.OPERATIONAL_ENABLED)


@mock.patch("dcmanager.manager.states.upgrade.migrating_data."
            "DEFAULT_MAX_API_QUERIES", 3)
@mock.patch("dcmanager.manager.states.upgrade.migrating_data."
            "DEFAULT_MAX_FAILED_QUERIES", 3)
@mock.patch("dcmanager.manager.states.upgrade.migrating_data."
            "DEFAULT_API_SLEEP", 1)
@mock.patch("dcmanager.manager.states.upgrade.migrating_data."
            "DEFAULT_FAILED_SLEEP", 1)
@mock.patch("dcmanager.manager.states.upgrade.migrating_data."
            "DEFAULT_ANSIBLE_SLEEP", 3)
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
        self.sysinv_client.get_host = mock.MagicMock()

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

        # mock the get_host queries
        # first query is an exception, to emulate the host being inaccessible
        # query 2 : during the unlock phase
        # query 3 : the host is now unlocked
        self.sysinv_client.get_host.side_effect = [Exception("Bad Connection"),
                                                   CONTROLLER_0_LOCKED,
                                                   CONTROLLER_0_UNLOCKING,
                                                   CONTROLLER_0_UNLOCKED, ]
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

    @mock.patch.object(migrating_data, 'db_api')
    def test_upgrade_subcloud_migrating_data_reboot_timeout(self, mock_db_api):
        """Test migrating data step times out during reboot

        The subprocess call passes however the reboot times out.
        """

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

        # mock the get_host queries as never coming back from reboot
        self.sysinv_client.get_host.side_effect = Exception("Bad Connection")

        # Invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # reboot failed, so the 'failed' query count should have been hit
        self.assertEqual(migrating_data.DEFAULT_MAX_FAILED_QUERIES,
                         self.sysinv_client.get_host.call_count)

        # Due to the timeout, the state goes to failed
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    @mock.patch.object(migrating_data, 'db_api')
    def test_upgrade_subcloud_migrating_data_recover_timeout(self, mock_db_api):
        """Test migrating data step times out enabling after reboot

        The subprocess call passes however the unlock enable times out.
        """

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

        # mock the get_host queries as never coming back from reboot
        self.sysinv_client.get_host.side_effect = CONTROLLER_0_UNLOCKING

        # Invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # reboot passed, so the 'api' query count should have been hit
        self.assertEqual(migrating_data.DEFAULT_MAX_API_QUERIES,
                         self.sysinv_client.get_host.call_count)

        # Due to the timeout, the state goes to failed
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)
