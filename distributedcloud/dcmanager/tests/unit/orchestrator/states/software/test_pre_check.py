#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from dcmanager.common import consts
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
    {
        "release_id": "starlingx-9.0.1",
        "state": "deployed",
        "sw_version": "9.0.1",
    },
]

FAKE_SUBCLOUD_RELEASES = [
    {
        "release_id": "starlingx-9.0.0",
        "state": "deployed",
        "sw_version": "9.0.0",
    },
    {
        "release_id": "starlingx-9.0.1",
        "state": "available",
        "sw_version": "9.0.1",
    },
]


class TestPreCheckState(TestSoftwareOrchestrator):
    def setUp(self):
        super().setUp()

        self.on_success_state = consts.STRATEGY_STATE_SW_INSTALL_LICENSE

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Create default strategy with release parameter
        extra_args = {"release_id": "starlingx-9.0.1"}
        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx, self.DEFAULT_STRATEGY_TYPE, extra_args=extra_args
        )

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            self.subcloud.id, consts.STRATEGY_STATE_SW_PRE_CHECK
        )

        self._mock_read_from_cache(pre_check.PreCheckState)
        self.software_client.list = mock.MagicMock(return_value=FAKE_SUBCLOUD_RELEASES)
        self.mock_read_from_cache.return_value = FAKE_REGION_ONE_RELEASE_PRESTAGED
        self.vim_client.get_current_strategy = mock.MagicMock(return_value={})
        self.vim_client.delete_strategy = mock.MagicMock()

    def test_pre_check_success(self):
        """Test pre-check when the API call succeeds."""

        self.worker.perform_state_action(self.strategy_step)

        self.vim_client.get_current_strategy.assert_called_once()
        self.vim_client.delete_strategy.assert_not_called()
        self.software_client.list.assert_called()

        # On success, the state should transition to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id, self.on_success_state)

    def test_pre_check_success_valid_software_strategy(self):
        """Test pre-check when the API call succeeds with a valid VIM strategy."""

        self.vim_client.get_current_strategy.return_value = FAKE_VALID_CURRENT_STRATEGY

        self.worker.perform_state_action(self.strategy_step)

        self.vim_client.get_current_strategy.assert_called_once()
        self.vim_client.delete_strategy.assert_called_once_with("sw-upgrade")
        self.software_client.list.assert_called()

        # On success, the state should transition to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id, self.on_success_state)

    def test_pre_check_failed_invalid_software_strategy(self):
        """Test pre-check when the API call fails with an invalid VIM strategy."""

        self.vim_client.get_current_strategy.return_value = (
            FAKE_INVALID_CURRENT_STRATEGY
        )

        self.worker.perform_state_action(self.strategy_step)

        self.vim_client.get_current_strategy.assert_called_once()
        self.vim_client.delete_strategy.assert_not_called()
        self.software_client.list.assert_not_called()

        # On failed, the state should transition to 'failed' state
        self.assert_step_updated(
            self.strategy_step.subcloud_id, consts.STRATEGY_STATE_FAILED
        )

    def test_pre_check_failed_existing_strategy(self):
        """Test pre-check when the API call fails with an existing VIM strategy."""

        self.vim_client.get_current_strategy.return_value = (
            FAKE_EXISTING_CURRENT_STRATEGY
        )

        self.worker.perform_state_action(self.strategy_step)

        self.vim_client.get_current_strategy.assert_called_once()
        self.vim_client.delete_strategy.assert_not_called()
        self.software_client.list.assert_not_called()

        # On failed, the state should transition to 'failed' state
        self.assert_step_updated(
            self.strategy_step.subcloud_id, consts.STRATEGY_STATE_FAILED
        )

    def test_pre_check_failed_not_prestaged(self):
        """Test pre-check when the API call fails release data not prestaged."""

        # No releases in state deployed
        self.mock_read_from_cache.return_value = []

        self.worker.perform_state_action(self.strategy_step)

        self.vim_client.get_current_strategy.assert_called_once()
        self.vim_client.delete_strategy.assert_not_called()
        self.software_client.list.assert_called_once()

        # On failed, the state should transition to 'failed' state
        self.assert_step_updated(
            self.strategy_step.subcloud_id, consts.STRATEGY_STATE_FAILED
        )
