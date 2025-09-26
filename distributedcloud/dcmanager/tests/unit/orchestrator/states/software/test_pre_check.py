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
    {"release_id": "starlingx-9.0.0", "state": "deployed", "sw_version": "9.0.0"},
    {"release_id": "starlingx-9.0.1", "state": "deployed", "sw_version": "9.0.1"},
]

FAKE_SUBCLOUD_RELEASES = [
    {"release_id": "starlingx-9.0.0", "state": "deployed", "sw_version": "9.0.0"},
    {"release_id": "starlingx-9.0.1", "state": "available", "sw_version": "9.0.1"},
]

FAKE_SUBCLOUD_RELEASES_NOT_PRESTAGED = [
    {"release_id": "starlingx-9.0.0", "state": "deployed", "sw_version": "9.0.0"},
]

FAKE_SUBCLOUD_RELEASES_DEPLOYED = [
    {"release_id": "starlingx-9.0.0", "state": "deployed", "sw_version": "9.0.0"},
    {"release_id": "starlingx-9.0.1", "state": "deployed", "sw_version": "9.0.1"},
]

FAKE_SUBCLOUD_RELEASES_DEPLOYING = [
    {"release_id": "starlingx-8.0.0", "state": "deployed", "sw_version": "8.0.0"},
    {"release_id": "starlingx-9.0.0", "state": "deploying", "sw_version": "9.0.0"},
]

FAKE_SUBCLOUD_RELEASES_AVAILABLE = [
    {"release_id": "starlingx-9.0.0", "state": "deployed", "sw_version": "9.0.0"},
    {"release_id": "starlingx-9.0.1", "state": "deployed", "sw_version": "9.0.1"},
    {"release_id": "starlingx-9.0.2", "state": "available", "sw_version": "9.0.2"},
    {"release_id": "starlingx-9.0.3", "state": "available", "sw_version": "9.0.3"},
    {"release_id": "starlingx-8.0", "state": "unavailable", "sw_version": "8.0"},
]

FAKE_SUBCLOUD_RELEASES_DEPLOYED_AVAILABLE = [
    {"release_id": "starlingx-9.0.0", "state": "deployed", "sw_version": "9.0.0"},
    {"release_id": "starlingx-9.0.1", "state": "deployed", "sw_version": "9.0.1"},
    {"release_id": "starlingx-9.0.2", "state": "deployed", "sw_version": "9.0.2"},
    {"release_id": "starlingx-9.0.3", "state": "available", "sw_version": "9.0.3"},
    {"release_id": "starlingx-9.0.4", "state": "available", "sw_version": "9.0.4"},
]


class TestPreCheckState(TestSoftwareOrchestrator):
    def setUp(self):
        super().setUp()

        self.on_success_state = consts.STRATEGY_STATE_SW_INSTALL_LICENSE
        self.on_success_state_patch = consts.STRATEGY_STATE_SW_CREATE_VIM_STRATEGY
        self.on_success_state_complete = consts.STRATEGY_STATE_COMPLETE
        self.on_success_state_available = consts.STRATEGY_STATE_SW_FINISH_STRATEGY
        self.on_success_state_rollback = consts.STRATEGY_STATE_SW_CREATE_VIM_STRATEGY
        self.on_success_state_delete_only = consts.STRATEGY_STATE_SW_FINISH_STRATEGY
        self.current_state = consts.STRATEGY_STATE_SW_PRE_CHECK

        # Create default strategy with release parameter
        self.extra_args = {"release_id": "starlingx-9.0.1"}
        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx, self.strategy_type, extra_args=self.extra_args
        )

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            self.subcloud.id, self.current_state
        )

        self.mock_read_from_cache = self._mock_object(
            pre_check.PreCheckState, "_read_from_cache"
        )
        self.software_client.list.return_value = FAKE_SUBCLOUD_RELEASES
        self.mock_read_from_cache.return_value = FAKE_REGION_ONE_RELEASE_PRESTAGED
        self.vim_client.get_current_strategy.return_value = {}

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

        self._setup_and_assert(self.on_success_state_available)

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

    def test_pre_check_success_patch_release(self):
        """Test pre-check when the API call succeeds."""

        self.strategy_step.subcloud.software_version = "9.0"

        self._setup_and_assert(self.on_success_state_patch)

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
            f"{self.extra_args['release_id']} is not prestaged."
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
        self._assert_error(
            f"{self.current_state}: Failed for subcloud {self.subcloud.name}: Release "
            f"{self.extra_args['release_id']} is not deployed in RegionOne."
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

        mock_sysinv_client = self._mock_object(BaseState, "get_sysinv_client")
        mock_sysinv_client.return_value.get_system.return_value.system_mode = (
            consts.SYSTEM_MODE_SIMPLEX
        )
        self.software_client.list.return_value = FAKE_SUBCLOUD_RELEASES_DEPLOYING

        self.vim_client.get_current_strategy.return_value = FAKE_VALID_CURRENT_STRATEGY

        self.strategy = fake_strategy.update_fake_strategy(
            self.ctx, additional_args={consts.EXTRA_ARGS_ROLLBACK: True}
        )

        self._setup_and_assert(self.on_success_state_rollback)

        self.vim_client.get_current_strategy.assert_called_once()
        self.vim_client.delete_strategy.assert_called_once_with("sw-upgrade")
        self.software_client.list.assert_called()

    def test_pre_check_success_with_extra_args_rollback_retry(self):
        """Test pre-check success with rollback extra args"""

        mock_sysinv_client = self._mock_object(BaseState, "get_sysinv_client")
        mock_sysinv_client.return_value.get_system.return_value.system_mode = (
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

        self._setup_and_assert(self.on_success_state_delete_only)

        self.vim_client.get_current_strategy.assert_called_once()
        self.vim_client.delete_strategy.assert_called_once_with("sw-upgrade")
        self.software_client.list.assert_not_called()

    def test_pre_check_fails_with_extra_args_rollback_and_duplex_system(self):
        """Test pre-check fails with rollback extra args"""

        mock_sysinv_client = self._mock_object(BaseState, "get_sysinv_client")
        mock_sysinv_client.return_value.get_system.return_value.system_mode = (
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
