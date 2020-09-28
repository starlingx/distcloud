#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock

from dcmanager.common import consts

from dcmanager.tests.unit.orchestrator.states.fakes import FakeController
from dcmanager.tests.unit.orchestrator.states.fakes import FakeHostFilesystem
from dcmanager.tests.unit.orchestrator.states.fakes import FakeSubcloud
from dcmanager.tests.unit.orchestrator.states.fakes import FakeSystem
from dcmanager.tests.unit.orchestrator.states.upgrade.test_base \
    import TestSwUpgradeState

CONTROLLER_0_LOCKED = FakeController(administrative=consts.ADMIN_LOCKED)
CONTROLLER_0_HOST_FS_SCRATCH_MIN_SIZED = FakeHostFilesystem(size=16)
CONTROLLER_0_HOST_FS_SCRATCH_UNDER_SIZED = FakeHostFilesystem(size=15)
SYSTEM_HEALTH_RESPONSE_SUCCESS = \
    "System Health:\n" \
    "All hosts are provisioned: [OK]\n" \
    "All hosts are unlocked/enabled: [OK]\n" \
    "All hosts have current configurations: [OK]\n" \
    "All hosts are patch current: [OK]\n" \
    "Ceph Storage Healthy: [OK]\n" \
    "No alarms: [OK]\n" \
    "All kubernetes nodes are ready: [OK]\n" \
    "All kubernetes control plane pods are ready: [OK]"

SYSTEM_HEALTH_RESPONSE_NON_MGMT_AFFECTING_ALARMS =  \
    "System Health:\n" \
    "All hosts are provisioned: [OK]\n" \
    "All hosts are unlocked/enabled: [OK]\n" \
    "All hosts have current configurations: [OK]\n" \
    "All hosts are patch current: [OK]\n" \
    "Ceph Storage Healthy: [OK]\n" \
    "No alarms: [Fail]\n" \
    "[4] alarms found, [0] of which are management affecting\n" \
    "All kubernetes nodes are ready: [OK]\n" \
    "All kubernetes control plane pods are ready: [OK]"

SYSTEM_HEALTH_RESPONSE_MGMT_AFFECTING_ALARM =  \
    "System Health:\n" \
    "All hosts are provisioned: [OK]\n" \
    "All hosts are unlocked/enabled: [OK]\n" \
    "All hosts have current configurations: [OK]\n" \
    "All hosts are patch current: [OK]\n" \
    "Ceph Storage Healthy: [OK]\n" \
    "No alarms: [Fail]\n" \
    "[1] alarms found, [1] of which are management affecting\n" \
    "All kubernetes nodes are ready: [OK]\n" \
    "All kubernetes control plane pods are ready: [OK]"

SYSTEM_HEALTH_RESPONSE_MULTIPLE_FAILED_HEALTH_CHECKS =  \
    "System Health:\n" \
    "All hosts are provisioned: [OK]\n" \
    "All hosts are unlocked/enabled: [OK]\n" \
    "All hosts have current configurations: [OK]\n" \
    "All hosts are patch current: [OK]\n" \
    "Ceph Storage Healthy: [OK]\n" \
    "No alarms: [Fail]\n" \
    "[1] alarms found, [0] of which are management affecting\n" \
    "All kubernetes nodes are ready: [Fail]\n" \
    "Kubernetes nodes not ready: controller-0\n" \
    "All kubernetes control plane pods are ready: [Fail]\n" \
    "Kubernetes control plane pods not ready: kube-apiserver-controller-0"


class TestSwUpgradePreCheckStage(TestSwUpgradeState):

    def setUp(self):
        super(TestSwUpgradePreCheckStage, self).setUp()

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = \
            self.setup_strategy_step(consts.STRATEGY_STATE_PRE_CHECK)

        # Mock the db API call. Each test will override the return value
        p = mock.patch('dcmanager.db.api.subcloud_get')
        self.mock_db_query = p.start()
        self.addCleanup(p.stop)

        self.sysinv_client.get_host = mock.MagicMock()
        self.sysinv_client.get_host_filesystem = mock.MagicMock()
        self.sysinv_client.get_system_health = mock.MagicMock()
        self.sysinv_client.get_system = mock.MagicMock()
        system_values = FakeSystem()
        system_values.system_mode = consts.SYSTEM_MODE_SIMPLEX
        self.sysinv_client.get_system.return_value = system_values
        self.sysinv_client.get_upgrades = mock.MagicMock()

    def test_upgrade_pre_check_subcloud_online_fresh(self):
        """Test pre check step where the subcloud is online and running N load

        The pre-check should transition in this scenario to the first state
        of a normal upgrade orchestration which is 'installing license'.
        """

        # online subcloud running N load
        self.mock_db_query.return_value = FakeSubcloud(
            availability_status=consts.AVAILABILITY_ONLINE,
            deploy_status=consts.DEPLOY_STATE_DONE)

        self.sysinv_client.get_host_filesystem.side_effect = \
            [CONTROLLER_0_HOST_FS_SCRATCH_MIN_SIZED]

        self.sysinv_client.get_system_health.return_value = \
            SYSTEM_HEALTH_RESPONSE_SUCCESS

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the DB query was invoked
        self.mock_db_query.assert_called()

        # verify the get system health API call was invoked
        self.sysinv_client.get_system_health.assert_called()

        # verify the get host filesystem API call was invoked
        self.sysinv_client.get_host_filesystem.assert_called()

        # Verify the expected next state happened (installing license)
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_INSTALLING_LICENSE)

    def test_upgrade_pre_check_subcloud_online_fresh_with_non_management_alarms(self):
        """Test pre check step where the subcloud is online with non mgmt alarms

        The pre-check should transition in this scenario to the first state
        of a normal upgrade orchestration which is 'installing license'.
        """

        # online subcloud running N load
        self.mock_db_query.return_value = FakeSubcloud(
            availability_status=consts.AVAILABILITY_ONLINE,
            deploy_status=consts.DEPLOY_STATE_DONE)

        self.sysinv_client.get_host_filesystem.side_effect = \
            [CONTROLLER_0_HOST_FS_SCRATCH_MIN_SIZED]

        self.sysinv_client.get_system_health.return_value = \
            SYSTEM_HEALTH_RESPONSE_NON_MGMT_AFFECTING_ALARMS

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the DB query was invoked
        self.mock_db_query.assert_called()

        # verify the get system health API call was invoked
        self.sysinv_client.get_system_health.assert_called()

        # verify the get host filesystem API call was invoked
        self.sysinv_client.get_host_filesystem.assert_called()

        # Verify the expected next state happened (installing license)
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_INSTALLING_LICENSE)

    def test_upgrade_pre_check_subcloud_online_migrated(self):
        """Test pre check step where the subcloud is online and running N+1 load

        The pre-check in this scenario should advance directly to 'activating upgrade'.
        """

        # online subcloud running N+1 load
        self.mock_db_query.return_value = FakeSubcloud(
            availability_status=consts.AVAILABILITY_ONLINE,
            deploy_status=consts.DEPLOY_STATE_MIGRATED)

        self.sysinv_client.get_host_filesystem.side_effect = \
            [CONTROLLER_0_HOST_FS_SCRATCH_MIN_SIZED]

        self.sysinv_client.get_system_health.return_value = \
            SYSTEM_HEALTH_RESPONSE_SUCCESS

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the DB query was invoked
        self.mock_db_query.assert_called()

        # verify the get system health API call was invoked
        self.sysinv_client.get_system_health.assert_called()

        # verify the get host filesystem API call was invoked
        self.sysinv_client.get_host_filesystem.assert_called()

        # Verify the expected next state happened (activating upgrade)
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_ACTIVATING_UPGRADE)

    def test_upgrade_pre_check_subcloud_online_management_alarm(self):
        """Test pre check step where the subcloud is online with a mgmt alarm

        The pre-check should raise an exception and transition to the failed
        state when the subcloud is not ready for upgrade due to the management
        affecting alarm.
        """

        # online subcloud running N+1 load
        self.mock_db_query.return_value = FakeSubcloud(
            availability_status=consts.AVAILABILITY_ONLINE,
            deploy_status=consts.DEPLOY_STATE_DONE)

        self.sysinv_client.get_system_health.return_value = \
            SYSTEM_HEALTH_RESPONSE_MGMT_AFFECTING_ALARM

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the DB query was invoked
        self.mock_db_query.assert_called()

        # verify the get system health API call was invoked
        self.sysinv_client.get_system_health.assert_called()

        # Verify the exception caused the state to go to failed
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_upgrade_pre_check_subcloud_online_multiple_failed_health_checks(self):
        """Test pre check step where the subcloud is online but is unhealthy

        The pre-check should raise an exception and transition to the failed
        state when the subcloud is not ready for upgrade due to multiple failed
        health checks.
        """

        # online subcloud running N+1 load
        self.mock_db_query.return_value = FakeSubcloud(
            availability_status=consts.AVAILABILITY_ONLINE,
            deploy_status=consts.DEPLOY_STATE_DONE)

        self.sysinv_client.get_system_health.return_value = \
            SYSTEM_HEALTH_RESPONSE_MULTIPLE_FAILED_HEALTH_CHECKS

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the DB query was invoked
        self.mock_db_query.assert_called()

        # verify the get system health API call was invoked
        self.sysinv_client.get_system_health.assert_called()

        # Verify the exception caused the state to go to failed
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_upgrade_pre_check_subcloud_online_scratch_undersized(self):
        """Test pre check step where the subcloud is online undersized scratch

        The pre-check should raise an exception and transition to the failed
        state when the subcloud scratch filesystem does not meet
        minimum upgrade requirements.
        """

        # subcloud is online
        self.mock_db_query.return_value = \
            FakeSubcloud(availability_status=consts.AVAILABILITY_ONLINE)

        self.sysinv_client.get_host_filesystem.side_effect = \
            [CONTROLLER_0_HOST_FS_SCRATCH_UNDER_SIZED]

        self.sysinv_client.get_system_health.return_value = \
            SYSTEM_HEALTH_RESPONSE_SUCCESS

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the DB query was invoked
        self.mock_db_query.assert_called()

        # verify the get system health API call was invoked
        self.sysinv_client.get_system_health.assert_called()

        # verify the get host filesystem API call was invoked
        self.sysinv_client.get_host_filesystem.assert_called()

        # Verify the exception caused the state to go to failed
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_upgrade_pre_check_subcloud_online_no_data_install(self):
        """Test pre check step where the subcloud is online without data install

        The pre-check should raise an exception and transition to the failed
        state when the data install values for the online
        subcloud does not exist.
        """

        # subcloud is online
        self.mock_db_query.return_value = \
            FakeSubcloud(availability_status=consts.AVAILABILITY_ONLINE,
                         data_install={})

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the DB query was invoked
        self.mock_db_query.assert_called()

        # Verify the exception caused the state to go to failed
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_upgrade_pre_check_subcloud_online_host_locked_install_failed(self):
        """Test pre check step where the subcloud is locked and install-failed

        If the subcloud host is locked, the subcloud's deploy state is
        install-failed it is still online; this means the remote install step
        had previously failed early. Upon retry, the pre-check should transition
        directly to upgrading simplex state.
        """

        # subcloud is online and deploy status is install-failed
        self.mock_db_query.return_value = FakeSubcloud(
            availability_status=consts.AVAILABILITY_ONLINE,
            deploy_status=consts.DEPLOY_STATE_INSTALL_FAILED)

        # subcloud is locked
        self.sysinv_client.get_host.side_effect = [CONTROLLER_0_LOCKED]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the DB query was invoked
        self.mock_db_query.assert_called()

        # Verify the expected next state happened (upgrading)
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_UPGRADING_SIMPLEX)

    def test_upgrade_pre_check_subcloud_offline_no_data_install(self):
        """Test pre check step where the subcloud is offline without data install.

        The pre-check should raise an exception and transition to the failed
        state when the data install values for the offline subcloud
        does not exist.
        """

        # subcloud is online
        self.mock_db_query.return_value = \
            FakeSubcloud(availability_status=consts.AVAILABILITY_OFFLINE,
                         deploy_status=consts.DEPLOY_STATE_INSTALL_FAILED,
                         data_install={})

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the DB query was invoked
        self.mock_db_query.assert_called()

        # Verify the exception caused the state to go to failed
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_upgrade_pre_check_subcloud_jumps_to_migrating(self):
        """Test pre check step which jumps to the migrating data state

        The pre-check should transition in this scenario to the migrating data
        state if the subcloud is now offline, and the deploy status can be
        handled by that state.
        """

        # subcloud is offline but deploy_state of 'installed' should allow
        # the upgrade to resume at the 'migrating data' state
        self.mock_db_query.return_value = FakeSubcloud(
            availability_status=consts.AVAILABILITY_OFFLINE,
            deploy_status=consts.DEPLOY_STATE_INSTALLED)

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the DB query was invoked
        self.mock_db_query.assert_called()

        # Verify the expected next state happened (migrating data)
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_MIGRATING_DATA)

    def test_upgrade_pre_check_subcloud_jumps_to_upgrading(self):
        """Test pre check step which jumps to the upgrading state

        The pre-check should transition in this scenario to the upgrading
        state if the subcloud is now offline, and the deploy status can be
        handled by that state.
        """

        # subcloud is offline but deploy_status of 'migration failed'
        # should be recoverable by an upgrade
        self.mock_db_query.return_value = FakeSubcloud(
            availability_status=consts.AVAILABILITY_OFFLINE,
            deploy_status=consts.DEPLOY_STATE_DATA_MIGRATION_FAILED)

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the DB query was invoked
        self.mock_db_query.assert_called()

        # Verify the expected next state happened (upgrading)
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_UPGRADING_SIMPLEX)

    def test_upgrade_pre_check_subcloud_cannot_proceed(self):
        """Test pre check step which requires manual intervention to proceed

        The pre-check should raise an exception and transition to the failed
        state when an offline subcloud is not in a deploy_status that has a
        known recovery route.
        """

        # subcloud is offline and there does not appear to be a way to revover
        self.mock_db_query.return_value = FakeSubcloud(
            availability_status=consts.AVAILABILITY_OFFLINE,
            deploy_status=consts.DEPLOY_STATE_BOOTSTRAP_FAILED)

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the DB query was invoked
        self.mock_db_query.assert_called()

        # Verify the exception caused the state to go to failed
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)
