#
# Copyright (c) 2020-2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock

from dccommon import consts as dccommon_consts
from dcmanager.common import consts
from dcmanager.db.sqlalchemy import api as db_api
from dcmanager.tests.unit.common import fake_strategy
from dcmanager.tests.unit.common import fake_subcloud
from dcmanager.tests.unit.orchestrator.states.fakes import FakeAlarm
from dcmanager.tests.unit.orchestrator.states.fakes import FakeController
from dcmanager.tests.unit.orchestrator.states.fakes import FakeHostFilesystem
from dcmanager.tests.unit.orchestrator.states.fakes import FakeSystem
from dcmanager.tests.unit.orchestrator.states.fakes import FakeUpgrade
from dcmanager.tests.unit.orchestrator.states.upgrade.test_base \
    import TestSwUpgradeState

CONTROLLER_0_LOCKED = FakeController(administrative=consts.ADMIN_LOCKED)
CONTROLLER_0_HOST_FS_SCRATCH_MIN_SIZED = FakeHostFilesystem(size=16)
CONTROLLER_0_HOST_FS_SCRATCH_UNDER_SIZED = FakeHostFilesystem(size=15)
CONTROLLER_0_LOCKED_AND_STANDBY = FakeController(administrative=consts.ADMIN_LOCKED,
                                                 capabilities={"Personality": "Controller-Standby"})
CONTROLLER_0_UNLOCKED_AND_STANDBY = FakeController(administrative=consts.ADMIN_UNLOCKED,
                                                   capabilities={"Personality": "Controller-Standby"})
CONTROLLER_0_UNLOCKED_AND_ACTIVE = FakeController(administrative=consts.ADMIN_UNLOCKED)
CONTROLLER_0_NOT_UPGRADED = FakeController(administrative=consts.ADMIN_UNLOCKED,
                                           capabilities={"Personality": "Controller-Standby"})
CONTROLLER_0_UPGRADED_STANDBY = FakeController(administrative=consts.ADMIN_UNLOCKED,
                                               capabilities={"Personality": "Controller-Standby"},
                                               software_load='56.78')
CONTROLLER_0_UPGRADED_ACTIVE = FakeController(administrative=consts.ADMIN_UNLOCKED,
                                              software_load='56.78')
CONTROLLER_1_LOCKED_AND_STANDBY = FakeController(host_id=2,
                                                 hostname='controller-1',
                                                 administrative=consts.ADMIN_LOCKED,
                                                 capabilities={"Personality": "Controller-Standby"})
CONTROLLER_1_UNLOCKED_AND_STANDBY = FakeController(host_id=2,
                                                   hostname='controller-1',
                                                   administrative=consts.ADMIN_UNLOCKED,
                                                   capabilities={"Personality": "Controller-Standby"})
CONTROLLER_1_UNLOCKED_AND_ACTIVE = FakeController(host_id=2,
                                                  hostname='controller-1',
                                                  administrative=consts.ADMIN_UNLOCKED)
CONTROLLER_1_NOT_UPGRADED = FakeController(host_id=2,
                                           hostname='controller-1',
                                           administrative=consts.ADMIN_UNLOCKED)
CONTROLLER_1_UPGRADED_ACTIVE = FakeController(host_id=2,
                                              hostname='controller-1',
                                              administrative=consts.ADMIN_UNLOCKED,
                                              software_load='56.78')
CONTROLLER_1_UPGRADED_STANDBY = FakeController(host_id=2,
                                               hostname='controller-1',
                                               administrative=consts.ADMIN_UNLOCKED,
                                               software_load='56.78',
                                               capabilities={"Personality": "Controller-Standby"})
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

SYSTEM_HEALTH_RESPONSE_K8S_FAILED_HEALTH_CHECKS =  \
    "System Health:\n" \
    "All hosts are provisioned: [OK]\n" \
    "All hosts are unlocked/enabled: [OK]\n" \
    "All hosts have current configurations: [OK]\n" \
    "All hosts are patch current: [OK]\n" \
    "Ceph Storage Healthy: [OK]\n" \
    "No alarms: [OK]\n" \
    "All kubernetes nodes are ready: [Fail]\n" \
    "All kubernetes control plane pods are ready: [OK]"

UPGRADE_STARTED = FakeUpgrade(state='started')

UPGRADE_ALARM = FakeAlarm('900.005', 'True')
HOST_LOCKED_ALARM = FakeAlarm('200.001', 'True')


class TestSwUpgradePreCheckStage(TestSwUpgradeState):

    def setUp(self):
        super(TestSwUpgradePreCheckStage, self).setUp()

        # Add the subcloud being processed by this unit test
        # The subcloud is online, managed with deploy_state 'installed'
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = \
            self.setup_strategy_step(self.subcloud.id, consts.STRATEGY_STATE_PRE_CHECK)

        self.sysinv_client.get_host = mock.MagicMock()
        self.sysinv_client.get_host_filesystem = mock.MagicMock()
        self.sysinv_client.get_system_health = mock.MagicMock()
        self.sysinv_client.get_system = mock.MagicMock()
        system_values = FakeSystem()
        system_values.system_mode = consts.SYSTEM_MODE_SIMPLEX
        self.sysinv_client.get_system.return_value = system_values
        self.sysinv_client.get_upgrades = mock.MagicMock()
        self.fm_client.get_alarms = mock.MagicMock()

    def test_upgrade_pre_check_subcloud_online_fresh(self):
        """Test pre check step where the subcloud is online and running N load

        The pre-check should transition in this scenario to the first state
        of a normal upgrade orchestration which is 'installing license'.
        """

        # Update the subcloud to have deploy state as "complete"
        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=consts.DEPLOY_STATE_DONE)

        self.sysinv_client.get_host_filesystem.side_effect = \
            [CONTROLLER_0_HOST_FS_SCRATCH_MIN_SIZED]

        self.sysinv_client.get_system_health.return_value = \
            SYSTEM_HEALTH_RESPONSE_SUCCESS

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

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

        # Update the subcloud to have deploy state as "complete"
        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=consts.DEPLOY_STATE_DONE)

        self.sysinv_client.get_host_filesystem.side_effect = \
            [CONTROLLER_0_HOST_FS_SCRATCH_MIN_SIZED]

        self.sysinv_client.get_system_health.return_value = \
            SYSTEM_HEALTH_RESPONSE_NON_MGMT_AFFECTING_ALARMS

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the get system health API call was invoked
        self.sysinv_client.get_system_health.assert_called()

        # verify the get host filesystem API call was invoked
        self.sysinv_client.get_host_filesystem.assert_called()

        # Verify the expected next state happened (installing license)
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_INSTALLING_LICENSE)

    def test_upgrade_pre_check_subcloud_online_host_locked_upgrade_started_mgmt_alarms(self):
        """Test pre check step where the subcloud is online, locked and upgrade has started.

        The pre-check should move to the next step as the upgrade alarm can
        be ignored and the host locked alarm can also be ignored if upgrade has
        started.
        """

        # Update the subcloud to have deploy state as "complete"
        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=consts.DEPLOY_STATE_DONE)

        # subcloud is locked
        self.sysinv_client.get_host.side_effect = [CONTROLLER_0_LOCKED]

        # upgrade has started
        self.sysinv_client.get_upgrades.return_value = [UPGRADE_STARTED, ]

        self.sysinv_client.get_system_health.return_value = \
            SYSTEM_HEALTH_RESPONSE_MGMT_AFFECTING_ALARM

        self.fm_client.get_alarms.return_value = [UPGRADE_ALARM, HOST_LOCKED_ALARM, ]

        self.sysinv_client.get_host_filesystem.side_effect = \
            [CONTROLLER_0_HOST_FS_SCRATCH_MIN_SIZED]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the get system health API call was invoked
        self.sysinv_client.get_system_health.assert_called()

        # verify the get alarms API call was invoked
        self.fm_client.get_alarms.assert_called()

        # verify the get host filesystem API call was invoked
        self.sysinv_client.get_host_filesystem.assert_called()

        # Verify the expected next state happened (installing license)
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_INSTALLING_LICENSE)

    def test_upgrade_pre_check_subcloud_online_host_locked_no_upgrade_mgmt_alarms(self):
        """Test pre check step where subcloud is online, locked and upgrade has not started.

        The pre-check should raise an exception and transition to the failed
        state as host locked alarm cannot be skipped if upgrade has
        not been started.
        """

        # Update the subcloud to have deploy state as "complete"
        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=consts.DEPLOY_STATE_DONE)

        # subcloud is locked
        self.sysinv_client.get_host.side_effect = [CONTROLLER_0_LOCKED]

        self.sysinv_client.get_upgrades.return_value = []

        self.sysinv_client.get_system_health.return_value = \
            SYSTEM_HEALTH_RESPONSE_MGMT_AFFECTING_ALARM

        self.fm_client.get_alarms.return_value = [HOST_LOCKED_ALARM, ]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the get system health API call was invoked
        self.sysinv_client.get_system_health.assert_called()

        # verify the get alarms API call was invoked
        self.fm_client.get_alarms.assert_called()

        # Verify the exception caused the state to go to failed
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_upgrade_pre_check_subcloud_online_multiple_failed_health_checks(self):
        """Test pre check step where the subcloud is online but is unhealthy

        The pre-check should raise an exception and transition to the failed
        state when the subcloud is not ready for upgrade due to multiple failed
        health checks.
        """

        # Update the subcloud to have deploy state as "complete"
        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=consts.DEPLOY_STATE_DONE)

        self.sysinv_client.get_system_health.return_value = \
            SYSTEM_HEALTH_RESPONSE_MULTIPLE_FAILED_HEALTH_CHECKS

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the get system health API call was invoked
        self.sysinv_client.get_system_health.assert_called()

        # Verify the exception caused the state to go to failed
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_upgrade_pre_check_subcloud_online_failed_health_checks_no_alarms(self):
        """Test pre check step where the subcloud is online but is unhealthy

        The pre-check should raise an exception and transition to the failed
        state when the subcloud is not ready for upgrade due to some failure
        other than platform alarms.
        """

        # Update the subcloud to have deploy state as "complete"
        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=consts.DEPLOY_STATE_DONE)

        self.sysinv_client.get_system_health.return_value = \
            SYSTEM_HEALTH_RESPONSE_K8S_FAILED_HEALTH_CHECKS

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

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

        # Update the subcloud to have deploy state as "complete"
        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=consts.DEPLOY_STATE_DONE)

        self.sysinv_client.get_host_filesystem.side_effect = \
            [CONTROLLER_0_HOST_FS_SCRATCH_UNDER_SIZED]

        self.sysinv_client.get_system_health.return_value = \
            SYSTEM_HEALTH_RESPONSE_SUCCESS

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the get system health API call was invoked
        self.sysinv_client.get_system_health.assert_called()

        # verify the get host filesystem API call was invoked
        self.sysinv_client.get_host_filesystem.assert_called()

        # Verify the exception caused the state to go to failed
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)


class TestSwUpgradePreCheckSimplexStage(TestSwUpgradePreCheckStage):

    def test_upgrade_pre_check_subcloud_online_migrated(self):
        """Test pre check step where the subcloud is online and running N+1 load

        The pre-check in this scenario should advance directly to 'activating upgrade'.
        """

        # Update the subcloud to have deploy state as "migrated"
        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=consts.DEPLOY_STATE_MIGRATED)

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the get system health API call was not invoked
        self.sysinv_client.get_system_health.assert_not_called()

        # verify the get host filesystem API call was not invoked
        self.sysinv_client.get_host_filesystem.assert_not_called()

        # Verify the expected next state happened (activating upgrade)
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_ACTIVATING_UPGRADE)

    def test_upgrade_pre_check_subcloud_online_migrate_failed(self):
        """Test pre check step where the subcloud is online following an unlock timeout

        The pre-check in this scenario should advance directly to 'activating upgrade'.
        """

        # Update the subcloud to have deploy state as "data-migration-failed"
        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=consts.DEPLOY_STATE_DATA_MIGRATION_FAILED)

        self.sysinv_client.get_system_health.return_value = \
            SYSTEM_HEALTH_RESPONSE_MGMT_AFFECTING_ALARM

        self.fm_client.get_alarms.return_value = [UPGRADE_ALARM, ]

        self.sysinv_client.get_host_filesystem.side_effect = \
            [CONTROLLER_0_HOST_FS_SCRATCH_MIN_SIZED]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the get system health API call was invoked
        self.sysinv_client.get_system_health.assert_called()

        # verify the get host filesystem API call was invoked
        self.sysinv_client.get_host_filesystem.assert_called()

        # verify the DB update was invoked
        updated_subcloud = db_api.subcloud_get(self.ctx,
                                               self.subcloud.id)
        self.assertEqual(updated_subcloud.deploy_status, consts.DEPLOY_STATE_MIGRATED)

        # Verify the expected next state happened (activating upgrade)
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_ACTIVATING_UPGRADE)

    def test_upgrade_pre_check_subcloud_online_no_data_install(self):
        """Test pre check step where the subcloud is online without data install

        The pre-check should raise an exception and transition to the failed
        state when the data install values for the online
        subcloud does not exist.
        """

        # Create a subcloud with deploy state as "complete"
        # and no data install values
        self.subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx,
            name="subcloud2",
            data_install=None
        )

        # Update the subcloud to be online
        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE)

        # Create a fake strategy
        fake_strategy.create_fake_strategy_step(
            self.ctx,
            subcloud_id=self.subcloud.id,
            state=consts.STRATEGY_STATE_PRE_CHECK)

        self.strategy_step = db_api.strategy_step_get(self.ctx, self.subcloud.id)

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Verify the exception caused the state to go to failed
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_upgrade_pre_check_subcloud_online_host_locked_pre_install_failed(self):
        """Test pre check step where the subcloud is locked and install-failed

        If the subcloud host is locked and the subcloud's deploy status is
        pre-install-failed, this means the upgrading simplex step had previously
        failed to retrieve the subcloud install data. Upon retry, the pre-check
        should transition directly to upgrading simplex state.
        """

        # Update the subcloud to have deploy state as "pre-install-failed"
        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=consts.DEPLOY_STATE_INSTALL_FAILED)

        # subcloud is locked
        self.sysinv_client.get_host.side_effect = [CONTROLLER_0_LOCKED]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Verify the expected next state happened (upgrading)
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_UPGRADING_SIMPLEX)

    def test_upgrade_pre_check_subcloud_online_host_locked_install_failed(self):
        """Test pre check step where the subcloud is locked and install-failed

        If the subcloud host is locked and the subcloud's deploy status is
        install-failed and it is still online, this means the upgrading simplex step
        had previously failed early. Upon retry, the pre-check should transition
        directly to upgrading simplex state.
        """

        # Update the subcloud to have deploy state as "install-failed"
        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=consts.DEPLOY_STATE_INSTALL_FAILED)

        # subcloud is locked
        self.sysinv_client.get_host.side_effect = [CONTROLLER_0_LOCKED]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Verify the expected next state happened (upgrading)
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_UPGRADING_SIMPLEX)

    def test_upgrade_pre_check_subcloud_offline_no_data_install(self):
        """Test pre check step where the subcloud is offline without data install.

        The pre-check should raise an exception and transition to the failed
        state when the data install values for the offline subcloud
        does not exist.
        """

        # Create a subcloud with deploy state as "install-failed",
        # availability status as "offline" and no data install values
        self.subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx,
            name="subcloud2",
            data_install=None,
            deploy_status=consts.DEPLOY_STATE_INSTALL_FAILED
        )

        fake_strategy.create_fake_strategy_step(
            self.ctx,
            subcloud_id=self.subcloud.id,
            state=consts.STRATEGY_STATE_PRE_CHECK)

        self.strategy_step = db_api.strategy_step_get(self.ctx, self.subcloud.id)

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Verify the exception caused the state to go to failed
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_upgrade_pre_check_subcloud_jumps_to_migrating(self):
        """Test pre check step which jumps to the migrating data state

        The pre-check should transition in this scenario to the migrating data
        state if the subcloud is now offline, and the deploy status can be
        handled by that state.
        """

        # Update the subcloud to have deploy state as "installed",
        # and availability status as "offline"
        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=consts.DEPLOY_STATE_INSTALLED,
                               availability_status=dccommon_consts.AVAILABILITY_OFFLINE)

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Verify the expected next state happened (migrating data)
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_MIGRATING_DATA)

    def test_upgrade_pre_check_subcloud_jumps_to_upgrading(self):
        """Test pre check step which jumps to the upgrading state

        The pre-check should transition in this scenario to the upgrading
        state if the subcloud is now offline, and the deploy status can be
        handled by that state.
        """

        # Update the subcloud to have deploy state as "data-migration-failed",
        # and availability status as "offline"
        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=consts.DEPLOY_STATE_DATA_MIGRATION_FAILED,
                               availability_status=dccommon_consts.AVAILABILITY_OFFLINE)

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Verify the expected next state happened (upgrading)
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_UPGRADING_SIMPLEX)

    def test_upgrade_pre_check_subcloud_cannot_proceed(self):
        """Test pre check step which requires manual intervention to proceed

        The pre-check should raise an exception and transition to the failed
        state when an offline subcloud is not in a deploy_status that has a
        known recovery route.
        """

        # Update the subcloud to have deploy state as "bootstrap-failed",
        # and availability status as "offline"
        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=consts.DEPLOY_STATE_BOOTSTRAP_FAILED,
                               availability_status=dccommon_consts.AVAILABILITY_OFFLINE)

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Verify the exception caused the state to go to failed
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)


class TestSwUpgradePreCheckDuplexStage(TestSwUpgradePreCheckStage):

    def setUp(self):
        super(TestSwUpgradePreCheckDuplexStage, self).setUp()
        self.sysinv_client.get_hosts = mock.MagicMock()
        system_values = FakeSystem()
        system_values.system_mode = consts.SYSTEM_MODE_DUPLEX
        self.sysinv_client.get_system.return_value = system_values
        self.sysinv_client.get_upgrades.return_value = []
        # Update the subcloud to have deploy state as "complete"
        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=consts.DEPLOY_STATE_DONE)

    def test_upgrade_pre_check_subcloud_online_host_locked_upgrade_started_mgmt_alarms(self):
        """Test pre check step where the subcloud is online, locked and upgrade has started

        The pre-check should move to the next step as the upgrade alarm can
        be ignored and the host locked alarm can also be ignored if upgrade has
        started.
        """

        # subcloud's controller-0 is unlocked and active
        # subcloud's controller-1 is locked and standby
        self.sysinv_client.get_host.side_effect = [CONTROLLER_0_UNLOCKED_AND_ACTIVE,
                                                   CONTROLLER_1_LOCKED_AND_STANDBY]

        # upgrade has started
        upgrade = FakeUpgrade(state='started')
        self.sysinv_client.get_upgrades.return_value = [upgrade, ]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Verify the expected next state happened (installing license)
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_INSTALLING_LICENSE)

    def test_upgrade_pre_check_subcloud_data_migration_failed(self):
        """Test pre check step where the subcloud's controller-1 is locked and

        data-migration-failed.

        If the subcloud host is locked, the subcloud's upgrade status is
        data-migration-failed; this means that one of the data migration scripts
        failed to run. This failure is serious and requires manual recovery. Upon
        retry, the pre-check should raise an exception and transition to the
        failed state.
        """

        # upgrade state is data-migration-failed
        upgrade = FakeUpgrade(state=consts.UPGRADE_STATE_DATA_MIGRATION_FAILED)
        self.sysinv_client.get_upgrades.return_value = [upgrade, ]

        # subcloud's controller-0 is unlocked and active
        # subcloud's controller-1 is locked and standby
        self.sysinv_client.get_host.side_effect = [CONTROLLER_0_UNLOCKED_AND_ACTIVE,
                                                   CONTROLLER_1_LOCKED_AND_STANDBY]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Verify the exception caused the state to go to failed
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_upgrade_pre_check_subcloud_in_data_migration_upgrade_state(self):
        """Test pre check step where the subcloud's controller-1 is locked and

        upgrade state is data-migration.

        If the subcloud host is locked, the subcloud's upgrade status is
        data-migration; this means that installation failed on controller-1.
        This failure is serious and requires manual recovery. Upon retry,
        the pre-check should raise an exception and transition to the failed
        state.
        """

        # upgrade state is data-migration
        upgrade = FakeUpgrade(state=consts.UPGRADE_STATE_DATA_MIGRATION)
        self.sysinv_client.get_upgrades.return_value = [upgrade, ]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Verify the exception caused the state to go to failed
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_upgrade_pre_check_jumps_to_unlock_controller_1(self):
        """Test pre check step which jumps to unlock controller-1 state.

        The upgrade state is upgrading-controllers and subcloud's
        controller-1 is locked. In this case the pre-check should transition
        to the 'unlocking controller-1' state.
        """

        # upgrade state is upgrading-controllers
        upgrade = FakeUpgrade(state=consts.UPGRADE_STATE_UPGRADING_CONTROLLERS)
        self.sysinv_client.get_upgrades.return_value = [upgrade, ]

        # subcloud's controller-0 is unlocked and active
        # subcloud's controller-1 is locked and standby
        self.sysinv_client.get_host.side_effect = [CONTROLLER_0_UNLOCKED_AND_ACTIVE,
                                                   CONTROLLER_1_LOCKED_AND_STANDBY]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Verify the expected next state happened (upgrading)
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_UNLOCKING_CONTROLLER_1)

    def test_upgrade_pre_check_jumps_to_swacting_to_controller_1(self):
        """Test pre check step which jumps to swacting to controller-1 state.

        The upgrade state is upgrading-controllers and subcloud's
        controller-1 is unlocked. In this case the pre-check should transition
        to the 'swacting to controller-1' state.
        """

        # upgrade state is upgrading-controllers
        upgrade = FakeUpgrade(state=consts.UPGRADE_STATE_UPGRADING_CONTROLLERS)
        self.sysinv_client.get_upgrades.return_value = [upgrade, ]

        # subcloud's controller-0 is unlocked and active
        # subcloud's controller-1 is unlocked and standby
        self.sysinv_client.get_host.side_effect = [CONTROLLER_0_UNLOCKED_AND_ACTIVE,
                                                   CONTROLLER_1_UNLOCKED_AND_STANDBY]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Verify the expected next state happened (upgrading)
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_SWACTING_TO_CONTROLLER_1)

    def test_upgrade_pre_check_jumps_to_creating_vim_strategy(self):
        """Test pre check step which jumps to creating vim startegy state.

        The upgrade state is upgrading-controllers and subcloud's
        controller-1 is unlocked and active. In this case the pre-check
        should transition to the 'creating vim strategy' state.
        """

        # upgrade state is upgrading-controllers
        upgrade = FakeUpgrade(state=consts.UPGRADE_STATE_UPGRADING_CONTROLLERS)
        self.sysinv_client.get_upgrades.return_value = [upgrade, ]

        # subcloud's controller-0 is unlocked and active
        # subcloud's controller-1 is unlocked and standby
        self.sysinv_client.get_host.side_effect = [CONTROLLER_0_UNLOCKED_AND_STANDBY,
                                                   CONTROLLER_1_UNLOCKED_AND_ACTIVE]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Verify the expected next state happened (upgrading)
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_CREATING_VIM_UPGRADE_STRATEGY)

    def test_upgrade_pre_check_subcloud_some_hosts_not_upgraded(self):
        """Test pre check step which jumps to creating vim strategy state.

        The upgrade state is upgrading-hosts and subcloud's controller-0
        is not upgraded. In this case the pre-check should transition to
        the 'creating vim strategy' state.
        """

        # upgrade state is upgrading-hosts
        upgrade = FakeUpgrade(state=consts.UPGRADE_STATE_UPGRADING_HOSTS)
        self.sysinv_client.get_upgrades.return_value = [upgrade, ]

        # subcloud's controller-0 is unlocked, standby and not upgraded
        # subcloud's controller-1 is unlocked, active and upgraded
        self.sysinv_client.get_host.side_effect = [CONTROLLER_0_NOT_UPGRADED,
                                                   CONTROLLER_1_UPGRADED_ACTIVE]

        self.sysinv_client.get_hosts.return_value = [CONTROLLER_0_NOT_UPGRADED,
                                                     CONTROLLER_1_UPGRADED_ACTIVE, ]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Verify the expected next state happened (upgrading)
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_CREATING_VIM_UPGRADE_STRATEGY)

    def test_upgrade_pre_check_jumps_to_swacting_to_controller_0(self):
        """Test pre check step which jumps to swacting to controller-0 state.

        The upgrade state is upgrading-hosts, all subcloud hosts are
        upgraded, and subcloud's controller-0 is standby controller.
        In this case the pre-check should transition to the 'swacting
        to controller-0' state.
        """

        # upgrade state is upgrading-hosts
        upgrade = FakeUpgrade(state=consts.UPGRADE_STATE_UPGRADING_HOSTS)
        self.sysinv_client.get_upgrades.return_value = [upgrade, ]

        # subcloud's controller-0 is unlocked, standby and upgraded
        # subcloud's controller-1 is unlocked, active and upgraded
        self.sysinv_client.get_host.side_effect = [CONTROLLER_0_UPGRADED_STANDBY,
                                                   CONTROLLER_1_UPGRADED_ACTIVE]

        self.sysinv_client.get_hosts.return_value = [CONTROLLER_0_UPGRADED_STANDBY,
                                                     CONTROLLER_1_UPGRADED_ACTIVE, ]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Verify the expected next state happened (upgrading)
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_SWACTING_TO_CONTROLLER_0)

    def test_upgrade_pre_check_jumps_to_activating_upgrade(self):
        """Test pre check step which jumps to activating upgrade state.

        The upgrade state is upgrading-hosts, all subcloud hosts are
        upgraded, and subcloud's controller-0 is active controller.
        In this case the pre-check should transition to the 'activating
        upgrade' state.
        """

        # upgrade state is upgrading-hosts
        upgrade = FakeUpgrade(state=consts.UPGRADE_STATE_UPGRADING_HOSTS)
        self.sysinv_client.get_upgrades.return_value = [upgrade, ]

        # subcloud's controller-0 is unlocked, active and upgraded
        # subcloud's controller-1 is unlocked, standby and upgraded
        self.sysinv_client.get_host.side_effect = [CONTROLLER_0_UPGRADED_ACTIVE,
                                                   CONTROLLER_1_UPGRADED_STANDBY]

        self.sysinv_client.get_hosts.return_value = [CONTROLLER_0_UPGRADED_ACTIVE,
                                                     CONTROLLER_1_UPGRADED_STANDBY, ]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Verify the expected next state happened (upgrading)
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_ACTIVATING_UPGRADE)

    def test_upgrade_pre_check_activation_failed_controller_0_active(self):
        """Test pre check step which jumps to activating upgrade state.

        The upgrade state is activation-failed, all subcloud hosts are
        upgraded, and subcloud's controller-0 is active controller.
        In this case the pre-check should transition to the 'activating
        upgrade' state.
        """

        # upgrade state is activation-failed
        upgrade = FakeUpgrade(state=consts.UPGRADE_STATE_ACTIVATION_FAILED)
        self.sysinv_client.get_upgrades.return_value = [upgrade, ]

        # subcloud's controller-0 is unlocked, active and upgraded
        # subcloud's controller-1 is unlocked, standby and upgraded
        self.sysinv_client.get_host.side_effect = [CONTROLLER_0_UPGRADED_ACTIVE,
                                                   CONTROLLER_1_UPGRADED_STANDBY]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Verify the expected next state happened (upgrading)
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_ACTIVATING_UPGRADE)

    def test_upgrade_pre_check_activation_failed_controller_1_active(self):
        """Test pre check step which jumps to activating upgrade state.

        The upgrade state is activation-failed, all subcloud hosts are
        upgraded, and subcloud's controller-0 is standby controller.
        In this case the pre-check should transition to the 'swacting to
        controller-0' upgrade' state.
        """

        # upgrade state is activation-failed
        upgrade = FakeUpgrade(state=consts.UPGRADE_STATE_ACTIVATION_FAILED)
        self.sysinv_client.get_upgrades.return_value = [upgrade, ]

        # subcloud's controller-0 is unlocked, standby and upgraded
        # subcloud's controller-1 is unlocked, active and upgraded
        self.sysinv_client.get_host.side_effect = [CONTROLLER_0_UPGRADED_STANDBY,
                                                   CONTROLLER_1_UPGRADED_ACTIVE]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Verify the expected next state happened (upgrading)
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_SWACTING_TO_CONTROLLER_0)

    def test_upgrade_pre_check_jumps_to_completing_upgrade_state(self):
        """Test pre check step which jumps to completing upgrade state.

        The upgrade state is activation-complete, all subcloud hosts are
        upgraded, and subcloud's controller-0 is active controller.
        In this case the pre-check should transition to the 'swacting to
        controller-0' upgrade' state.
        """

        # upgrade state is activation-complete
        upgrade = FakeUpgrade(state=consts.UPGRADE_STATE_ACTIVATION_COMPLETE)
        self.sysinv_client.get_upgrades.return_value = [upgrade, ]

        # subcloud's controller-0 is unlocked, active and upgraded
        # subcloud's controller-1 is unlocked, standby and upgraded
        self.sysinv_client.get_host.side_effect = [CONTROLLER_0_UPGRADED_ACTIVE,
                                                   CONTROLLER_1_UPGRADED_STANDBY]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Verify the expected next state happened (upgrading)
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_COMPLETING_UPGRADE)
