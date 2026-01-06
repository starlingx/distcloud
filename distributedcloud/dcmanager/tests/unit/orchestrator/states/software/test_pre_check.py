#
# Copyright (c) 2023-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dccommon.drivers.openstack.vim import STRATEGY_NAME_SW_USM
from dccommon import exceptions as vim_exc
from dcmanager.common import consts
from dcmanager.orchestrator.states.base import BaseState
from dcmanager.orchestrator.states.software import pre_check
from dcmanager.tests.unit.common import fake_strategy
from dcmanager.tests.unit.orchestrator.states.software.test_base import (
    TestSoftwareOrchestrator,
)

# TODO(nicodemos): Change strategy name after sw-deploy is created
FAKE_VALID_CURRENT_STRATEGY = {"sw-upgrade": "build-failed"}
FAKE_INVALID_CURRENT_STRATEGY = {"sw-upgrade": "building"}
FAKE_EXISTING_CURRENT_STRATEGY = {"sw-patch": "applying"}

FAKE_REGION_ONE_RELEASE_PRESTAGED = [
    {"release_id": "starlingx-25.09.0", "state": "deployed", "sw_version": "25.09.0"},
    {"release_id": "starlingx-25.09.1", "state": "deployed", "sw_version": "25.09.1"},
]

FAKE_SUBCLOUD_RELEASES = [
    {"release_id": "starlingx-25.09.0", "state": "deployed", "sw_version": "25.09.0"},
    {"release_id": "starlingx-25.09.1", "state": "available", "sw_version": "25.09.1"},
]

FAKE_SUBCLOUD_RELEASES_NOT_PRESTAGED = [
    {"release_id": "starlingx-25.09.0", "state": "deployed", "sw_version": "25.09.0"},
]

FAKE_SUBCLOUD_RELEASES_DEPLOYED = [
    {"release_id": "starlingx-25.09.0", "state": "deployed", "sw_version": "25.09.0"},
    {"release_id": "starlingx-25.09.1", "state": "deployed", "sw_version": "25.09.1"},
]

FAKE_SUBCLOUD_RELEASES_DEPLOYING = [
    {"release_id": "starlingx-24.09.0", "state": "deployed", "sw_version": "24.09.0"},
    {"release_id": "starlingx-25.09.0", "state": "deploying", "sw_version": "25.09.0"},
]

FAKE_SUBCLOUD_RELEASES_AVAILABLE = [
    {"release_id": "starlingx-25.09.0", "state": "deployed", "sw_version": "25.09.0"},
    {"release_id": "starlingx-25.09.1", "state": "deployed", "sw_version": "25.09.1"},
    {"release_id": "starlingx-25.09.2", "state": "available", "sw_version": "25.09.2"},
    {"release_id": "starlingx-25.09.3", "state": "available", "sw_version": "25.09.3"},
    {
        "release_id": "starlingx-24.09.0",
        "state": "unavailable",
        "sw_version": "24.09.0",
    },
]

FAKE_SUBCLOUD_RELEASES_DEPLOYED_AVAILABLE = [
    {"release_id": "starlingx-25.09.0", "state": "deployed", "sw_version": "25.09.0"},
    {"release_id": "starlingx-25.09.1", "state": "deployed", "sw_version": "25.09.1"},
    {"release_id": "starlingx-25.09.2", "state": "deployed", "sw_version": "25.09.2"},
    {"release_id": "starlingx-25.09.3", "state": "available", "sw_version": "25.09.3"},
    {"release_id": "starlingx-25.09.4", "state": "available", "sw_version": "25.09.4"},
]


class TestPreCheckStateBase(TestSoftwareOrchestrator):
    """Base class with common setup for all pre-check tests"""

    def setUp(self):
        super().setUp()

        self.on_success_state = consts.STRATEGY_STATE_SW_CREATE_VIM_STRATEGY
        self.on_success_state_license = consts.STRATEGY_STATE_SW_INSTALL_LICENSE
        self.on_success_state_complete = consts.STRATEGY_STATE_COMPLETE
        self.on_success_state_available_or_delete_only = (
            consts.STRATEGY_STATE_SW_FINISH_STRATEGY
        )
        self.current_state = consts.STRATEGY_STATE_SW_PRE_CHECK

        self.strategy = fake_strategy.update_fake_strategy(
            self.ctx,
            self.strategy_type,
            additional_args={consts.EXTRA_ARGS_RELEASE_ID: "starlingx-25.09.1"},
        )

        self.mock_pre_check_time = self._mock_object(pre_check, "time")

        self.mock_is_active_controller = self._mock_object(
            pre_check.utils, "is_active_controller"
        )
        self.mock_is_active_controller.return_value = True

        self.strategy_step = self.setup_strategy_step(
            self.subcloud.id, self.current_state
        )

        self.mock_read_from_cache = self._mock_object(
            pre_check.PreCheckState, "_read_from_cache"
        )
        self.software_client.list.return_value = FAKE_SUBCLOUD_RELEASES
        self.mock_read_from_cache.return_value = FAKE_REGION_ONE_RELEASE_PRESTAGED
        self.vim_client.get_current_strategy.return_value = {}


class TestPreCheckState(TestPreCheckStateBase):
    """Tests for basic pre-check functionality"""

    def test_pre_check_success(self):
        """Test pre-check when the API call succeeds."""

        self._setup_and_assert(self.on_success_state)

        self.vim_client.get_current_strategy.assert_called_once()
        self.vim_client.delete_strategy.assert_not_called()
        self.software_client.list.assert_called()

    def test_pre_check_success_already_deployed(self):
        """Test pre-check when the API call succeeds."""

        self.software_client.list.return_value = FAKE_SUBCLOUD_RELEASES_DEPLOYED

        self._setup_and_assert(self.on_success_state_complete)

        self.vim_client.get_current_strategy.assert_called_once()
        self.vim_client.delete_strategy.assert_not_called()
        self.software_client.list.assert_called()

    def test_pre_check_success_already_deployed_and_available(self):
        """Test pre-check when the API call succeeds."""

        self.software_client.list.return_value = FAKE_SUBCLOUD_RELEASES_AVAILABLE

        self._setup_and_assert(self.on_success_state_available_or_delete_only)

        self.vim_client.get_current_strategy.assert_called_once()
        self.vim_client.delete_strategy.assert_not_called()
        self.software_client.list.assert_called()

    def test_pre_check_success_remove_already_deployed_and_available(self):

        self.software_client.list.return_value = (
            FAKE_SUBCLOUD_RELEASES_DEPLOYED_AVAILABLE
        )

        self._setup_and_assert(self.on_success_state)

        self.vim_client.get_current_strategy.assert_called_once()
        self.vim_client.delete_strategy.assert_not_called()
        self.software_client.list.assert_called()

    def test_pre_check_success_upgrade_release(self):
        """Test pre-check when the API call succeeds."""

        self.strategy_step.subcloud.software_version = "26.09"

        self._setup_and_assert(self.on_success_state_license)

        self.vim_client.get_current_strategy.assert_called_once()
        self.vim_client.delete_strategy.assert_not_called()
        self.software_client.list.assert_called()

    def test_pre_check_success_valid_software_strategy(self):
        """Test pre-check when the API call succeeds with a valid VIM strategy."""

        self.vim_client.get_current_strategy.return_value = FAKE_VALID_CURRENT_STRATEGY

        self._setup_and_assert(self.on_success_state)

        self.vim_client.get_current_strategy.assert_called_once()
        self.vim_client.delete_strategy.assert_called_once_with("sw-upgrade")
        self.software_client.list.assert_called()

    def test_pre_check_fail_without_prestaged_release(self):
        """Test pre-check fails when a release is not prestaged in a subcloud"""

        self.software_client.list.return_value = FAKE_SUBCLOUD_RELEASES_NOT_PRESTAGED

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.current_state}: Failed for subcloud {self.subcloud.name}: Release "
            f"{self.strategy.extra_args['release_id']} is not prestaged."
        )

        self.vim_client.get_current_strategy.assert_called_once()
        self.vim_client.delete_strategy.assert_not_called()
        self.software_client.list.assert_called()

    def test_pre_check_fail_with_invalid_software_strategy(self):
        """Test pre-check when the API call fails with an invalid VIM strategy."""

        self.vim_client.get_current_strategy.return_value = (
            FAKE_INVALID_CURRENT_STRATEGY
        )

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.current_state}: Failed for subcloud {self.subcloud.name}: "
            "sw-upgrade strategy is currently executing and a new strategy cannot "
            "be created. State: building"
        )

        self.vim_client.get_current_strategy.assert_called_once()
        self.vim_client.delete_strategy.assert_not_called()
        self.software_client.list.assert_not_called()

    def test_pre_check_fail_with_existing_strategy(self):
        """Test pre-check when the API call fails with an existing VIM strategy."""

        self.vim_client.get_current_strategy.return_value = (
            FAKE_EXISTING_CURRENT_STRATEGY
        )

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.current_state}: Failed for subcloud {self.subcloud.name}: Subcloud "
            "has an existing sw-patch strategy."
        )

        self.vim_client.get_current_strategy.assert_called_once()
        self.vim_client.delete_strategy.assert_not_called()
        self.software_client.list.assert_not_called()

    def test_pre_check_failed_not_deployed_regionone(self):
        """Test pre-check when the release is not deployed in RegionOne."""

        # No releases in state deployed
        self.mock_read_from_cache.return_value = []

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        extra_args = self.strategy.extra_args
        self._assert_error(
            f"{self.current_state}: Failed for subcloud {self.subcloud.name}: Release "
            f"{extra_args['release_id']} not found or not deployed in RegionOne"
        )

        self.vim_client.get_current_strategy.assert_called_once()
        self.vim_client.delete_strategy.assert_not_called()
        self.assertFalse(self.software_client.list.called)

    def test_pre_check_fail_with_vim_client_exception(self):
        """Test pre-check fail with vim client exception"""

        mock_base_state = self._mock_object(BaseState, "get_vim_client")
        mock_base_state.side_effect = Exception("fake")

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.current_state}: Failed for subcloud {self.subcloud.name}: Get VIM "
            "client failed."
        )

        self.software_client.list.assert_not_called()

    def test_pre_check_fail_with_vim_client_get_current_strategy_exception(self):
        """Test pre-check fail with vim client get_current_strategy exception"""

        self.vim_client.get_current_strategy.side_effect = vim_exc.VIMClientException(
            "fake"
        )
        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.current_state}: Failed for subcloud {self.subcloud.name}: Get "
            "current strategy failed."
        )

        self.vim_client.get_current_strategy.assert_called_once()
        self.vim_client.delete_strategy.assert_not_called()
        self.software_client.list.assert_not_called()

    def test_pre_check_fail_with_software_client_list_exception(self):
        """Test pre-check fail with software client list exception"""

        self.software_client.list.side_effect = Exception("fake")

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.current_state}: Failed for subcloud {self.subcloud.name}: Subcloud "
            "software list failed."
        )

        self.vim_client.get_current_strategy.assert_called_once()
        self.vim_client.delete_strategy.assert_not_called()
        self.software_client.list.assert_called_once()

    def test_pre_check_fail_with_vim_client_delete_strategy_exception(self):
        """Test pre-check fail with vim client delete_strategy exception"""

        self.vim_client.get_current_strategy.return_value = FAKE_VALID_CURRENT_STRATEGY
        self.vim_client.delete_strategy.side_effect = Exception("fake")

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.current_state}: Failed for subcloud {self.subcloud.name}: Delete "
            f"strategy {STRATEGY_NAME_SW_USM} failed."
        )

        self.vim_client.get_current_strategy.assert_called_once()
        self.vim_client.delete_strategy.assert_called_once()
        self.software_client.list.assert_not_called()

    def test_pre_check_success_with_extra_args_rollback(self):
        """Test pre-check success with rollback extra args"""

        self.sysinv_client.get_system.return_value.system_mode = (
            consts.SYSTEM_MODE_SIMPLEX
        )
        self.software_client.list.return_value = FAKE_SUBCLOUD_RELEASES_DEPLOYING

        self.vim_client.get_current_strategy.return_value = FAKE_VALID_CURRENT_STRATEGY

        self.strategy = fake_strategy.update_fake_strategy(
            self.ctx, additional_args={consts.EXTRA_ARGS_ROLLBACK: True}
        )

        self._setup_and_assert(self.on_success_state)

        self.vim_client.get_current_strategy.assert_called_once()
        self.vim_client.delete_strategy.assert_called_once_with("sw-upgrade")
        self.software_client.list.assert_called()

    def test_pre_check_success_with_extra_args_rollback_retry(self):
        """Test pre-check success with rollback extra args"""

        self.sysinv_client.get_system.return_value.system_mode = (
            consts.SYSTEM_MODE_SIMPLEX
        )
        self.software_client.list.return_value = FAKE_SUBCLOUD_RELEASES_DEPLOYED

        self.vim_client.get_current_strategy.return_value = FAKE_VALID_CURRENT_STRATEGY

        self.strategy = fake_strategy.update_fake_strategy(
            self.ctx, additional_args={consts.EXTRA_ARGS_ROLLBACK: True}
        )

        self._setup_and_assert(self.on_success_state_complete)

        self.vim_client.get_current_strategy.assert_called_once()
        self.vim_client.delete_strategy.assert_called_once_with("sw-upgrade")
        self.software_client.list.assert_called()

    def test_pre_check_success_with_extra_args_delete_only(self):
        """Test pre-check success with delete only extra args"""

        self.vim_client.get_current_strategy.return_value = FAKE_VALID_CURRENT_STRATEGY

        self.strategy = fake_strategy.update_fake_strategy(
            self.ctx, additional_args={consts.EXTRA_ARGS_DELETE_ONLY: True}
        )

        self._setup_and_assert(self.on_success_state_available_or_delete_only)

        self.vim_client.get_current_strategy.assert_called_once()
        self.vim_client.delete_strategy.assert_called_once_with("sw-upgrade")
        self.software_client.list.assert_not_called()

    def test_pre_check_fails_with_extra_args_rollback_and_duplex_system(self):
        """Test pre-check fails with rollback extra args"""

        self.sysinv_client.get_system.return_value.system_mode = (
            consts.SYSTEM_MODE_DUPLEX
        )

        self.vim_client.get_current_strategy.return_value = FAKE_VALID_CURRENT_STRATEGY

        self.strategy = fake_strategy.update_fake_strategy(
            self.ctx, additional_args={consts.EXTRA_ARGS_ROLLBACK: True}
        )

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        error_msg = (
            f"{self.current_state}: Failed for subcloud {self.subcloud.name}: "
            "Rollback is only allowed for simplex systems"
        )
        self._assert_error(error_msg)

        self.software_client.list.assert_not_called()


class TestPreCheckStateDuplex(TestPreCheckStateBase):
    """Test class specific for duplex system scenarios"""

    def setUp(self):
        super().setUp()

        # Override for duplex scenarios
        self.strategy_step.subcloud.software_version = "26.03"
        self.sysinv_client.get_system.return_value.system_mode = (
            consts.SYSTEM_MODE_DUPLEX
        )
        self.sysinv_client.get_host.return_value.hostname = "controller-0"
        self.sysinv_client.get_host.return_value.id = "1"
        self.mock_is_active_controller.return_value = False

    def test_check_health_success_completely_healthy(self):
        """Test _check_health when system is completely healthy"""

        self.sysinv_client.get_system_health.return_value = "System Health OK"
        self.sysinv_client.swact_host.return_value.task = "Swacting"
        # Need 3 calls: initial check, polling loop, and final verification
        self.mock_is_active_controller.side_effect = [False, True, True]

        self._setup_and_assert(self.on_success_state_license)

    def test_check_health_success_with_non_mgmt_alarms(self):
        """Test _check_health with non-management affecting alarms only"""

        health_output = (
            "System Health:\n"
            "No alarms: [Fail]\n"
            "[1] of which are management affecting\n"
            "[0] of which are management affecting"
        )
        self.sysinv_client.get_system_health.return_value = health_output
        # Need 3 calls: initial check, polling loop, and final verification
        self.mock_is_active_controller.side_effect = [False, True, True]
        self.sysinv_client.swact_host.return_value.task = "Swacting"

        self._setup_and_assert(self.on_success_state_license)

    def test_check_health_fail_with_non_alarm_issues(self):
        """Test _check_health fail with non-alarm related issues"""

        health_output = "System Health:\n[Fail] Kubernetes issue"
        self.sysinv_client.get_system_health.return_value = health_output

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.current_state}: Failed for subcloud {self.subcloud.name}: "
            "System health check failed. Please run 'system health-query' command "
            f"on the subcloud or {consts.ERROR_DESC_CMD} on central for details"
        )

    def test_check_health_fail_with_mgmt_affecting_alarms(self):
        """Test _check_health fail with management affecting alarms"""

        health_output = (
            "System Health:\n"
            "No alarms: [Fail]\n"
            "[1] of which are management affecting"
        )
        self.sysinv_client.get_system_health.return_value = health_output

        # Mock alarm with mgmt_affecting = True
        class MockAlarm:
            def __init__(self):
                self.alarm_id = "100.001"
                self.mgmt_affecting = "True"

        mock_alarm = MockAlarm()
        self.fm_client.get_alarms.return_value = [mock_alarm]

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.current_state}: Failed for subcloud {self.subcloud.name}: "
            f"System health check failed due to alarm {mock_alarm.alarm_id}. "
            "Please run 'system health-query' command on the subcloud "
            f"or {consts.ERROR_DESC_CMD} on central for details."
        )

    def test_check_health_fail_fm_client_exception(self):
        """Test _check_health fail when FM client creation fails"""

        health_output = (
            "System Health:\n"
            "No alarms: [Fail]\n"
            "[1] of which are management affecting"
        )
        self.sysinv_client.get_system_health.return_value = health_output

        # Mock get_fm_client to raise exception
        mock_get_fm_client = self._mock_object(BaseState, "get_fm_client")
        mock_get_fm_client.side_effect = Exception("fake")

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.current_state}: Failed for subcloud {self.subcloud.name}: "
            f"Subcloud {self.subcloud.name} failed to get FM client"
        )

    def test_check_active_controller_success_already_active(self):
        """Test _check_active_controller when controller-0 is already active"""

        self.mock_is_active_controller.return_value = True

        self._setup_and_assert(self.on_success_state_license)

        self.vim_client.get_current_strategy.assert_called_once()
        self.vim_client.delete_strategy.assert_not_called()
        self.software_client.list.assert_called()

    def test_check_active_controller_success_with_swact(self):
        """Test _check_active_controller when swact is needed and succeeds"""

        # Mock _check_health for this specific test since it needs to pass
        self._mock_object(pre_check.PreCheckState, "_check_health")
        self.sysinv_client.swact_host.return_value.task = "Swacting"
        # Need 3 calls: initial check, polling loop, and final verification
        self.mock_is_active_controller.side_effect = [False, True, True]

        self._setup_and_assert(self.on_success_state_license)

        self.sysinv_client.swact_host.assert_called_once()
        self.vim_client.get_current_strategy.assert_called_once()
        self.vim_client.delete_strategy.assert_not_called()
        self.software_client.list.assert_called()

    def test_check_active_controller_fail_get_sysinv_client_exception(self):
        """Test _check_active_controller fail with sysinv client exception"""

        self.mock_is_active_controller.return_value = True
        self.sysinv_client.get_host.side_effect = Exception("fake")

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.current_state}: Failed for subcloud {self.subcloud.name}: "
            "Get subcloud sysinv client failed"
        )

    def test_check_active_controller_fail_swact_initiation_exception(self):
        """Test _check_active_controller fail with swact initiation exception"""

        self._mock_object(pre_check.PreCheckState, "_check_health")
        self.sysinv_client.swact_host.side_effect = Exception("fake")

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.current_state}: Failed for subcloud {self.subcloud.name}: "
            "Failed to initiate swact"
        )

    def test_check_active_controller_fail_swact_timeout(self):
        """Test _check_active_controller fail with swact timeout"""

        self._mock_object(pre_check.PreCheckState, "_check_health")
        self.sysinv_client.swact_host.return_value.task = "Swacting"

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.current_state}: Failed for subcloud {self.subcloud.name}: "
            "Timeout waiting for swact to complete. Please check sysinv.log on the "
            "subcloud for details."
        )

    def test_check_active_controller_fail_invalid_swact_response(self):
        """Test _check_active_controller fail with invalid swact response"""

        self._mock_object(pre_check.PreCheckState, "_check_health")
        self.sysinv_client.swact_host.return_value.task = "Invalid"

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.current_state}: Failed for subcloud {self.subcloud.name}: "
            "Failed to initiate swact"
        )

    def test_check_active_controller_fail_continuous_get_host_exceptions(self):
        """Test _check_active_controller fail with continuous get_host exceptions"""

        self._mock_object(pre_check.PreCheckState, "_check_health")
        self.sysinv_client.swact_host.return_value.task = "Swacting"

        # Mock handle_exception to verify it’s called with the exception
        # and not by the is_active_controller checks
        mock_handle_exception = self._mock_object(
            pre_check.PreCheckState, "handle_exception"
        )
        mock_handle_exception.side_effect = (
            pre_check.exceptions.SoftwarePreCheckFailedException(
                subcloud="test", details="test"
            )
        )

        # Mock get_host to raise exception only in the while loop
        call_count = 0
        test_exception = Exception("fake")

        # First 2 calls return successful get_host response
        # All subsequent calls raise a test exception (until max_failed_queries)
        def get_host_side_effect(hostname):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return self.sysinv_client.get_host.return_value
            else:
                raise test_exception

        self.sysinv_client.get_host.side_effect = get_host_side_effect

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)

        # Verify handle_exception was called with the correct parameters including exc
        mock_handle_exception.assert_called_with(
            self.strategy_step,
            (
                "Timeout waiting for swact to complete. Please check sysinv.log on "
                "the subcloud for details."
            ),
            pre_check.exceptions.SoftwarePreCheckFailedException,
            exc=test_exception,
        )
