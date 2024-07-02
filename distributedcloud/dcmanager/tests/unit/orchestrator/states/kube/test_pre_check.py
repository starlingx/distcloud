#
# Copyright (c) 2020, 2022, 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from dcmanager.common.consts import DEPLOY_STATE_DONE
from dcmanager.common.consts import STRATEGY_STATE_COMPLETE
from dcmanager.common.consts import STRATEGY_STATE_FAILED
from dcmanager.common.consts \
    import STRATEGY_STATE_KUBE_CREATING_VIM_KUBE_UPGRADE_STRATEGY
from dcmanager.common.consts import STRATEGY_STATE_KUBE_UPGRADE_PRE_CHECK
from dcmanager.db.sqlalchemy import api as db_api
from dcmanager.orchestrator.states.base import BaseState
from dcmanager.tests.unit.common import fake_strategy
from dcmanager.tests.unit.orchestrator.states.fakes import FakeAlarm
from dcmanager.tests.unit.orchestrator.states.fakes import FakeKubeUpgrade
from dcmanager.tests.unit.orchestrator.states.fakes import FakeKubeVersion
from dcmanager.tests.unit.orchestrator.states.fakes \
    import PREVIOUS_KUBE_VERSION
from dcmanager.tests.unit.orchestrator.states.fakes \
    import UPGRADED_KUBE_VERSION
from dcmanager.tests.unit.orchestrator.states.kube.test_base \
    import TestKubeUpgradeState

KUBERNETES_UPGRADE_HEALTH_RESPONSE_SUCCESS = \
    "System Health:\n" \
    "All hosts are provisioned: [OK]\n" \
    "All hosts are unlocked/enabled: [OK]\n" \
    "All hosts have current configurations: [OK]\n" \
    "All hosts are patch current: [OK]\n" \
    "No alarms: [OK]\n" \
    "All kubernetes nodes are ready: [OK]\n" \
    "All kubernetes control plane pods are ready: [OK]\n" \
    "All kubernetes applications are in a valid state: [OK]"

KUBERNETES_UPGRADE_HEALTH_RESPONSE_MGMT_AFFECTING_ALARM = \
    "System Health:\n" \
    "All hosts are provisioned: [OK]\n" \
    "All hosts are unlocked/enabled: [OK]\n" \
    "All hosts have current configurations: [OK]\n" \
    "All hosts are patch current: [OK]\n" \
    "No alarms: [Fail]\n" \
    "[2] alarms found, [2] of which are management affecting\n" \
    "All kubernetes nodes are ready: [OK]\n" \
    "All kubernetes control plane pods are ready: [OK]\n" \
    "All kubernetes applications are in a valid state: [OK]"

KUBERNETES_UPGRADE_HEALTH_RESPONSE_NON_MGMT_AFFECTING_ALARM = \
    "System Health:\n" \
    "All hosts are provisioned: [OK]\n" \
    "All hosts are unlocked/enabled: [OK]\n" \
    "All hosts have current configurations: [OK]\n" \
    "All hosts are patch current: [OK]\n" \
    "No alarms: [Fail]\n" \
    "[1] alarms found, [0] of which are management affecting\n" \
    "All kubernetes nodes are ready: [OK]\n" \
    "All kubernetes control plane pods are ready: [OK]\n" \
    "All kubernetes applications are in a valid state: [OK]"

KUBERNETES_UPGRADE_HEALTH_RESPONSE_MGMT_AFFECTING_AND_KUBERNETES_ALARM = \
    "System Health:\n" \
    "All hosts are provisioned: [OK]\n" \
    "All hosts are unlocked/enabled: [OK]\n" \
    "All hosts have current configurations: [OK]\n" \
    "All hosts are patch current: [OK]\n" \
    "No alarms: [Fail]\n" \
    "[2] alarms found, [2] of which are management affecting\n" \
    "All kubernetes nodes are ready: [Fail]\n" \
    "All kubernetes control plane pods are ready: [OK]\n" \
    "All kubernetes applications are in a valid state: [OK]"

MEMORY_THRESHOLD_ALARM = FakeAlarm('100.101', 'True')
KUBERNETES_UPGRADE_ALARM = FakeAlarm('900.007', 'True')
CONFIG_OUT_OF_DATE_ALARM = FakeAlarm('250.001', 'False')

KUBE_VERSION_LIST = [
    FakeKubeVersion(obj_id=1, version='v1.2.3', target=True, state='active'),
    FakeKubeVersion(obj_id=2, version='v1.2.5', target=False, state='available'),
]

KUBE_VERSION_LIST_2 = [
    FakeKubeVersion(obj_id=1, version='v1.2.3', target=True, state='active'),
    FakeKubeVersion(obj_id=2, version='v1.2.5', target=False, state='available'),
    FakeKubeVersion(obj_id=3, version='v1.2.6', target=False, state='available'),
]


class TestKubeUpgradePreCheckStage(TestKubeUpgradeState):

    def setUp(self):
        super(TestKubeUpgradePreCheckStage, self).setUp()

        # Add the subcloud being processed by this unit test
        # The subcloud is online, managed with deploy_state 'installed'
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            self.subcloud.id, STRATEGY_STATE_KUBE_UPGRADE_PRE_CHECK)

        # mock there not being a kube upgrade in progress
        self.sysinv_client.get_kube_upgrades = mock.MagicMock()
        self.sysinv_client.get_kube_upgrades.return_value = []

        self.fm_client.get_alarms = mock.MagicMock()
        self.sysinv_client.get_kube_upgrade_health = mock.MagicMock()
        self.sysinv_client.get_kube_upgrade_health.return_value = (
            KUBERNETES_UPGRADE_HEALTH_RESPONSE_SUCCESS)

        # mock the get_kube_versions calls
        self.sysinv_client.get_kube_versions = mock.MagicMock()
        self.sysinv_client.get_kube_versions.return_value = []
        # mock the cached get_kube_versions calls
        self._mock_read_from_cache(BaseState)
        self.mock_read_from_cache.return_value = [
            FakeKubeVersion(obj_id=1,
                            version=PREVIOUS_KUBE_VERSION,
                            target=True,
                            state='active'),
            FakeKubeVersion(obj_id=2,
                            version=UPGRADED_KUBE_VERSION,
                            target=False,
                            state='available'),
        ]

    def test_pre_check_subcloud_existing_upgrade(self):
        """Test pre check step where the subcloud has a kube upgrade

        When a kube upgrade exists in the subcloud, do not skip, go to the
        next step, which is 'create the vim kube upgrade strategy'
        """

        next_state = STRATEGY_STATE_KUBE_CREATING_VIM_KUBE_UPGRADE_STRATEGY
        # Update the subcloud to have deploy state as "complete"
        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=DEPLOY_STATE_DONE)
        self.sysinv_client.get_kube_upgrades.return_value = [FakeKubeUpgrade()]
        # get kube versions invoked only for the system controller
        self.mock_read_from_cache.return_value = [
            FakeKubeVersion(obj_id=1,
                            version=UPGRADED_KUBE_VERSION,
                            target=True,
                            state='active'),
        ]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Verify the single query (for the system controller)
        self.mock_read_from_cache.assert_called_once()

        # Verify the transition to the  expected next state
        self.assert_step_updated(self.strategy_step.subcloud_id, next_state)

    def test_pre_check_succeeds_with_strategy_without_extra_args(self):
        """Test pre-check succeeds with strategy without extra args"""

        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx, self.DEFAULT_STRATEGY_TYPE
        )
        next_state = STRATEGY_STATE_KUBE_CREATING_VIM_KUBE_UPGRADE_STRATEGY

        db_api.subcloud_update(
            self.ctx, self.subcloud.id, deploy_status=DEPLOY_STATE_DONE
        )
        self.sysinv_client.get_kube_upgrades.return_value = [FakeKubeUpgrade()]

        self.mock_read_from_cache.return_value = [
            FakeKubeVersion(
                obj_id=1, version=UPGRADED_KUBE_VERSION, target=True, state='active'
            )
        ]

        self.worker.perform_state_action(self.strategy_step)

        self.mock_read_from_cache.assert_called_once()

        self.assert_step_updated(self.strategy_step.subcloud_id, next_state)

    def test_pre_check_subcloud_failed_health_check_with_management_alarms(self):
        """Test pre check step where subcloud has management affecting alarms"""

        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=DEPLOY_STATE_DONE)

        self.fm_client.get_alarms.return_value = [MEMORY_THRESHOLD_ALARM,
                                                  KUBERNETES_UPGRADE_ALARM]
        self.sysinv_client.get_kube_upgrade_health.return_value = (
            KUBERNETES_UPGRADE_HEALTH_RESPONSE_MGMT_AFFECTING_ALARM)
        self.sysinv_client.get_kube_upgrades.return_value = [FakeKubeUpgrade()]
        self.mock_read_from_cache.return_value = [
            FakeKubeVersion(obj_id=1,
                            version=UPGRADED_KUBE_VERSION,
                            target=True,
                            state='active'),
        ]
        self.worker.perform_state_action(self.strategy_step)
        self.sysinv_client.get_kube_upgrade_health.assert_called_once()
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 STRATEGY_STATE_FAILED)

    def test_pre_check_subcloud_failed_health_check_with_mgmt_and_kubernetes_alarm(
        self
    ):
        """Test pre check step where subcloud has management and kubernetes

        affecting alarms
        """

        db_api.subcloud_update(
            self.ctx, self.subcloud.id, deploy_status=DEPLOY_STATE_DONE
        )

        self.sysinv_client.get_kube_upgrade_health.return_value = \
            KUBERNETES_UPGRADE_HEALTH_RESPONSE_MGMT_AFFECTING_AND_KUBERNETES_ALARM

        self.worker.perform_state_action(self.strategy_step)

        self.sysinv_client.get_kube_upgrade_health.assert_called_once()
        self.assert_step_updated(
            self.strategy_step.subcloud_id, STRATEGY_STATE_FAILED
        )

    def test_pre_check_subcloud_failed_health_check_with_allowed_management_alarms(
        self
    ):
        """Test pre check step where subcloud has management affecting alarms"""

        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=DEPLOY_STATE_DONE)

        self.fm_client.get_alarms.return_value = [CONFIG_OUT_OF_DATE_ALARM,
                                                  KUBERNETES_UPGRADE_ALARM]
        self.sysinv_client.get_kube_upgrade_health.return_value = (
            KUBERNETES_UPGRADE_HEALTH_RESPONSE_MGMT_AFFECTING_ALARM)
        self.sysinv_client.get_kube_upgrades.return_value = [FakeKubeUpgrade()]
        self.mock_read_from_cache.return_value = [
            FakeKubeVersion(obj_id=1,
                            version=UPGRADED_KUBE_VERSION,
                            target=True,
                            state='active'),
        ]
        self.worker.perform_state_action(self.strategy_step)
        self.sysinv_client.get_kube_upgrade_health.assert_called_once()
        self.assert_step_updated(
            self.strategy_step.subcloud_id,
            STRATEGY_STATE_KUBE_CREATING_VIM_KUBE_UPGRADE_STRATEGY)

    def test_pre_check_subcloud_failed_health_check_with_non_management_alarms(self):
        """Test pre check step where subcloud has non-management affecting alarms"""

        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=DEPLOY_STATE_DONE)

        self.sysinv_client.get_kube_upgrade_health.return_value = (
            KUBERNETES_UPGRADE_HEALTH_RESPONSE_NON_MGMT_AFFECTING_ALARM)
        self.sysinv_client.get_kube_upgrades.return_value = [FakeKubeUpgrade()]
        self.mock_read_from_cache.return_value = [
            FakeKubeVersion(obj_id=1,
                            version=UPGRADED_KUBE_VERSION,
                            target=True,
                            state='active'),
        ]
        self.worker.perform_state_action(self.strategy_step)
        self.sysinv_client.get_kube_upgrade_health.assert_called_once()

        self.assert_step_updated(
            self.strategy_step.subcloud_id,
            STRATEGY_STATE_KUBE_CREATING_VIM_KUBE_UPGRADE_STRATEGY)

    def test_pre_check_no_sys_controller_active_version(self):
        """Test pre check step where system controller has no active version

        The subcloud has no existing kube upgrade.
        There is no 'to-version' indicated in extra args.
        The target version is derived from the system controller.  Inability
        to query that version should fail orchestration.
        """

        next_state = STRATEGY_STATE_FAILED
        # Update the subcloud to have deploy state as "complete"
        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=DEPLOY_STATE_DONE)

        # No extra args / to-version in the database
        # Query system controller kube versions
        # override the first get, so that there is no active release
        # 'partial' indicates the system controller is still upgrading
        self.mock_read_from_cache.return_value = [
            FakeKubeVersion(obj_id=1,
                            version=PREVIOUS_KUBE_VERSION,
                            target=True,
                            state='partial'),
            FakeKubeVersion(obj_id=2,
                            version=UPGRADED_KUBE_VERSION,
                            target=False,
                            state='unavailable'),
        ]
        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Verify the expected next state happened
        self.assert_step_updated(self.strategy_step.subcloud_id, next_state)

    def test_pre_check_no_subcloud_available_version(self):
        """Test pre check step where subcloud has no available version

        This test simulates a fully upgraded system controller and subcloud.
        In practice, the audit should not have added this subcloud to orch.

        Setup:
        - The subcloud has no existing kube upgrade.
        - There is no 'to-version' indicated in extra args.
        - System Controller has an 'active' version
        - Subcloud has no 'available' version.
        Expectation:
        - Skip orchestration,  jump to 'complete' for this state.
        """

        # Update the subcloud to have deploy state as "complete"
        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=DEPLOY_STATE_DONE)

        # No extra args / to-version in the database
        # Query system controller kube versions
        self.mock_read_from_cache.side_effect = [
            [   # first list: (system controller) has an active release
                FakeKubeVersion(obj_id=1,
                                version=PREVIOUS_KUBE_VERSION,
                                target=False,
                                state='unavailable'),
                FakeKubeVersion(obj_id=2,
                                version=UPGRADED_KUBE_VERSION,
                                target=True,
                                state='active'),
            ],
            [   # second list: (subcloud) fully upgraded (no available release)
                FakeKubeVersion(obj_id=1,
                                version=PREVIOUS_KUBE_VERSION,
                                target=False,
                                state='unavailable'),
                FakeKubeVersion(obj_id=2,
                                version=UPGRADED_KUBE_VERSION,
                                target=True,
                                state='active'),
            ],
        ]
        # fully upgraded subcloud.  Next state will be complete.
        next_state = STRATEGY_STATE_COMPLETE

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # cached get_kube_versions gets called (more than once)
        self.mock_read_from_cache.assert_called()

        # Verify the expected next state happened
        self.assert_step_updated(self.strategy_step.subcloud_id, next_state)

    def test_pre_check_subcloud_existing_upgrade_resumable(self):
        """Test pre check step where the subcloud has lower kube upgrade

        When a kube upgrade exists in the subcloud, it is skipped if to-version
        if less than its version.  This test should not skip the subcloud.
        """

        next_state = STRATEGY_STATE_KUBE_CREATING_VIM_KUBE_UPGRADE_STRATEGY
        # Update the subcloud to have deploy state as "complete"
        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=DEPLOY_STATE_DONE)

        low_version = "v1.2.3"
        high_partial_version = "v1.3"

        self.sysinv_client.get_kube_upgrades.return_value = [
            FakeKubeUpgrade(to_version=low_version)
        ]

        # The orchestrated version target is higher than the version of the
        # existing upgrade in the subcloud, so the subcloud upgrade should
        # continue
        extra_args = {"to-version": high_partial_version}
        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx,
            self.DEFAULT_STRATEGY_TYPE,
            extra_args=extra_args)

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Do not need to mock query kube versions since extra args will be
        # queried to get the info for the system controller
        # and pre-existing upgrade is used for subcloud
        self.mock_read_from_cache.assert_not_called()

        # Verify the transition to the  expected next state
        self.assert_step_updated(self.strategy_step.subcloud_id, next_state)

    def _test_pre_check_subcloud_existing_upgrade_skip(self,
                                                       target_version,
                                                       subcloud_version):
        """Test pre check step where the subcloud existing upgrade too high.

        When a kube upgrade exists in the subcloud, it is skipped if to-version
        is less than the version of the existing upgrade.
        For this test, the subcloud version is higher than the target, so
        it should not be resumed and the skip should occur.
        """

        next_state = STRATEGY_STATE_COMPLETE
        # Update the subcloud to have deploy state as "complete"
        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=DEPLOY_STATE_DONE)

        self.sysinv_client.get_kube_upgrades.return_value = [
            FakeKubeUpgrade(to_version=subcloud_version)
        ]

        extra_args = {"to-version": target_version}
        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx,
            self.DEFAULT_STRATEGY_TYPE,
            extra_args=extra_args)

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Do not need to mock query kube versions since extra args will be
        # queried to get the info for the system controller
        # and pre-existing upgrade is used for subcloud
        self.mock_read_from_cache.assert_not_called()

        # Verify the transition to the  expected next state
        self.assert_step_updated(self.strategy_step.subcloud_id, next_state)

    def test_pre_check_subcloud_existing_upgrade_too_high(self):
        target_version = "v1.2.1"
        subcloud_version = "v1.3.3"
        self._test_pre_check_subcloud_existing_upgrade_skip(target_version,
                                                            subcloud_version)

    def test_pre_check_subcloud_existing_upgrade_too_high_target_partial(self):
        target_version = "v1.2"
        subcloud_version = "v1.3.3"
        self._test_pre_check_subcloud_existing_upgrade_skip(target_version,
                                                            subcloud_version)

    def test_pre_check_subcloud_existing_upgrade_too_high_subcl_partial(self):
        target_version = "v1.2.1"
        subcloud_version = "v1.3"
        self._test_pre_check_subcloud_existing_upgrade_skip(target_version,
                                                            subcloud_version)

    def _test_pre_check_subcloud_existing_upgrade_resume(self,
                                                         target_version,
                                                         subcloud_version):
        """Test pre check step where target version >= existing upgrade

        When a kube upgrade exists in the subcloud, it is resumed if to-version
        is the same or higher.  The to-version can be a partial version.
        Test supports partial values for target_version and subcloud_version
        """

        next_state = STRATEGY_STATE_KUBE_CREATING_VIM_KUBE_UPGRADE_STRATEGY
        # Update the subcloud to have deploy state as "complete"
        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=DEPLOY_STATE_DONE)

        # Setup a fake kube upgrade in progress
        self.sysinv_client.get_kube_upgrades.return_value = [
            FakeKubeUpgrade(to_version=subcloud_version)
        ]

        # Setup a fake kube upgrade strategy with the to-version specified
        extra_args = {"to-version": target_version}
        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx,
            self.DEFAULT_STRATEGY_TYPE,
            extra_args=extra_args)

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Do not need to mock query kube versions since extra args will be
        # queried to get the info for the system controller
        # and pre-existing upgrade is used for subcloud
        self.mock_read_from_cache.assert_not_called()

        # Verify the transition to the  expected next state
        self.assert_step_updated(self.strategy_step.subcloud_id, next_state)

    def test_pre_check_subcloud_existing_upgrade_match(self):
        target_version = "v1.2.3"
        subcloud_version = "v1.2.3"
        self._test_pre_check_subcloud_existing_upgrade_resume(target_version,
                                                              subcloud_version)

    def test_pre_check_subcloud_existing_upgrade_match_target_partial(self):
        # v1.2 is considered the same as v1.2.3 (micro version gets ignored)
        target_version = "v1.2"
        subcloud_version = "v1.2.3"
        self._test_pre_check_subcloud_existing_upgrade_resume(target_version,
                                                              subcloud_version)

    def test_pre_check_subcloud_existing_upgrade_match_subcloud_partial(self):
        # v1.2 is considered the same as v1.2.3 (micro version gets ignored)
        target_version = "v1.2.3"
        subcloud_version = "v1.2"
        self._test_pre_check_subcloud_existing_upgrade_resume(target_version,
                                                              subcloud_version)

    def test_pre_check_skip_when_target_version_is_greater_than_to_version(self):
        """Test creating pre check when target version is greater than to_version."""

        next_state = STRATEGY_STATE_COMPLETE
        # Update the subcloud to have deploy state as "complete"
        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=DEPLOY_STATE_DONE)

        # Setup a fake kube upgrade in progress
        self.mock_read_from_cache.return_value = KUBE_VERSION_LIST

        # Setup a fake kube upgrade strategy with the to-version specified
        extra_args = {"to-version": "v1.2.4"}
        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx,
            self.DEFAULT_STRATEGY_TYPE,
            extra_args=extra_args)

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Verify the transition to the  expected next state
        self.assert_step_updated(self.strategy_step.subcloud_id, next_state)

    def test_pre_check_skip_when_there_is_no_version_available(self):
        """Test creating pre check when there is no version available."""

        next_state = STRATEGY_STATE_COMPLETE
        # Update the subcloud to have deploy state as "complete"
        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=DEPLOY_STATE_DONE)

        # Setup a fake kube upgrade in progress
        self.mock_read_from_cache.return_value = []

        # Setup a fake kube upgrade strategy with the to-version specified
        extra_args = {"to-version": "v1.2.4"}
        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx,
            self.DEFAULT_STRATEGY_TYPE,
            extra_args=extra_args)

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Verify the transition to the  expected next state
        self.assert_step_updated(self.strategy_step.subcloud_id, next_state)

    def test_pre_check_skip_when_there_are_multiple_available_versions(self):
        """Test creating pre check when there are multiple_available_versions."""

        next_state = STRATEGY_STATE_KUBE_CREATING_VIM_KUBE_UPGRADE_STRATEGY
        # Update the subcloud to have deploy state as "complete"
        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=DEPLOY_STATE_DONE)

        # Setup a fake kube upgrade in progress
        self.sysinv_client.get_kube_versions.return_value = KUBE_VERSION_LIST_2
        self.mock_read_from_cache.return_value = KUBE_VERSION_LIST_2

        # Setup a fake kube upgrade strategy with the to-version specified
        extra_args = {"to-version": "v1.2.6"}
        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx,
            self.DEFAULT_STRATEGY_TYPE,
            extra_args=extra_args)

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Verify the transition to the  expected next state
        self.assert_step_updated(self.strategy_step.subcloud_id, next_state)
