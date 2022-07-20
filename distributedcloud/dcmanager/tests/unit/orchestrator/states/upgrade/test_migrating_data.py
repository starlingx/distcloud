#
# Copyright (c) 2020, 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock

from dcmanager.common import consts
from dcmanager.db.sqlalchemy import api as db_api
from dcmanager.orchestrator.states.upgrade import migrating_data

from dcmanager.tests.unit.orchestrator.states.fakes import FakeController
from dcmanager.tests.unit.orchestrator.states.upgrade.test_base  \
    import TestSwUpgradeState

CONTROLLER_0_LOCKED = FakeController(administrative=consts.ADMIN_LOCKED)
CONTROLLER_0_UNLOCKING = \
    FakeController(administrative=consts.ADMIN_UNLOCKED,
                   operational=consts.OPERATIONAL_DISABLED)
CONTROLLER_0_UNLOCKED = \
    FakeController(administrative=consts.ADMIN_UNLOCKED,
                   operational=consts.OPERATIONAL_ENABLED)


@mock.patch("dcmanager.orchestrator.states.upgrade.migrating_data."
            "DEFAULT_MAX_API_QUERIES", 3)
@mock.patch("dcmanager.orchestrator.states.upgrade.migrating_data."
            "DEFAULT_MAX_FAILED_QUERIES", 3)
@mock.patch("dcmanager.orchestrator.states.upgrade.migrating_data."
            "DEFAULT_API_SLEEP", 1)
@mock.patch("dcmanager.orchestrator.states.upgrade.migrating_data."
            "DEFAULT_FAILED_SLEEP", 1)
@mock.patch("dcmanager.orchestrator.states.upgrade.migrating_data."
            "DEFAULT_ANSIBLE_SLEEP", 3)
class TestSwUpgradeMigratingDataStage(TestSwUpgradeState):

    def setUp(self):
        super(TestSwUpgradeMigratingDataStage, self).setUp()

        # next state after 'migrating data' is 'unlocking controller'
        self.on_success_state = consts.STRATEGY_STATE_UNLOCKING_CONTROLLER_0

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = \
            self.setup_strategy_step(self.subcloud.id, consts.STRATEGY_STATE_MIGRATING_DATA)

        # Add mock API endpoints for sysinv client calls invoked by this state
        self.sysinv_client.get_host = mock.MagicMock()

    def test_upgrade_subcloud_migrating_data_failure(self):
        """Test migrating data step where the subprocess call fails."""

        # Simulate a failed subprocess call to the platform upgrade playbook
        # on the subcloud.
        p = mock.patch(
            'dcmanager.orchestrator.states.upgrade.migrating_data.migrate_subcloud_data')
        self.mock_platform_upgrade_call = p.start()
        self.mock_platform_upgrade_call.side_effect = Exception("Bad day!")
        self.addCleanup(p.stop)

        # Invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Verify a failure leads to a state failure
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_upgrade_subcloud_migrating_data_success(self):
        """Test migrating data step where the subprocess call passes."""

        # Simulate a successful subprocess call to the platform upgrade playbook
        # on the subcloud.
        p = mock.patch(
            'dcmanager.orchestrator.states.upgrade.migrating_data.migrate_subcloud_data')
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

    def test_upgrade_subcloud_migrating_data_skip_migration_done(self):
        """Test the migrating data step skipped (migration completed)"""

        # online subcloud running N load
        # Update the subcloud to have deploy state as "migrated"
        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=consts.DEPLOY_STATE_MIGRATED)

        # Invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # On success, should have moved to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_upgrade_subcloud_migrating_data_skip_deployment_done(self):
        """Test the migrating data step skipped (deployment completed)"""

        # online subcloud running N load
        # Update the subcloud to have deploy state as "done"
        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=consts.DEPLOY_STATE_DONE)

        # Invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # On success, should have moved to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_upgrade_subcloud_migrating_data_interrupted_migration(self):
        """Test the migrating data step skipped"""

        # online subcloud running N load
        # Update the subcloud to have deploy state as "migrating data"
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            deploy_status=consts.DEPLOY_STATE_MIGRATING_DATA)

        # Invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Cannot resume the migration, the state goes to failed
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_upgrade_subcloud_migrating_data_reboot_timeout(self):
        """Test migrating data step times out during reboot

        The subprocess call passes however the reboot times out.
        """

        # Simulate a successful subprocess call to the platform upgrade playbook
        # on the subcloud.
        p = mock.patch(
            'dcmanager.orchestrator.states.upgrade.migrating_data.migrate_subcloud_data')
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

    def test_upgrade_subcloud_migrating_data_recover_timeout(self):
        """Test migrating data step times out enabling after reboot

        The subprocess call passes however the unlock enable times out.
        """

        # Simulate a successful subprocess call to the platform upgrade playbook
        # on the subcloud.
        p = mock.patch(
            'dcmanager.orchestrator.states.upgrade.migrating_data.migrate_subcloud_data')
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
