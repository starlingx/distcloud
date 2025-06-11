#
# Copyright (c) 2023-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.tests.unit.common import fake_strategy
from dcmanager.tests.unit import fakes
from dcmanager.tests.unit.orchestrator.states.software.test_base import (
    TestSoftwareOrchestrator,
)

STRATEGY_BUILDING = fakes.FakeVimStrategy(state=vim.STATE_BUILDING)
BUILD_PHASE_ERROR = fakes.FakeVimStrategyPhase(
    response="Installed license is valid: [FAIL]"
)
STRATEGY_BUILDING_FAILED = fakes.FakeVimStrategy(
    state=vim.STATE_BUILD_FAILED, build_phase=BUILD_PHASE_ERROR
)
STRATEGY_DONE_BUILDING = fakes.FakeVimStrategy(state=vim.STATE_READY_TO_APPLY)
RELEASE_ID = "starlingx-9.0.1"


@mock.patch(
    "dcmanager.orchestrator.states.creating_vim_strategy.DEFAULT_MAX_QUERIES", 3
)
@mock.patch(
    "dcmanager.orchestrator.states.creating_vim_strategy.DEFAULT_SLEEP_DURATION", 1
)
class TestCreateVIMSoftwareStrategyState(TestSoftwareOrchestrator):
    def setUp(self):
        super().setUp()

        self.on_success_state = consts.STRATEGY_STATE_SW_APPLY_VIM_STRATEGY

        # Create default strategy with release parameter
        extra_args = {"release_id": RELEASE_ID}
        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx, self.strategy_type, extra_args=extra_args
        )

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            self.subcloud.id, consts.STRATEGY_STATE_SW_CREATE_VIM_STRATEGY
        )

    def test_create_vim_software_strategy_success(self):
        """Test create vim software strategy when the API call succeeds."""

        self.vim_client.get_strategy.side_effect = [
            None,
            STRATEGY_BUILDING,
            STRATEGY_DONE_BUILDING,
        ]

        # API calls acts as expected
        self.vim_client.create_strategy.return_value = STRATEGY_BUILDING

        self.worker._perform_state_action(
            self.strategy_type, self.subcloud.region_name, self.strategy_step
        )

        # Assert release parameter is passed to create_strategy
        self.vim_client.create_strategy.assert_called_with(
            "sw-upgrade",
            "parallel",
            "parallel",
            10,
            "migrate",
            "relaxed",
            release=RELEASE_ID,
            rollback=False,
            delete=True,
        )

        # On success, the state should transition to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id, self.on_success_state)

    @mock.patch.object(exceptions, "CreateVIMStrategyFailedException")
    def test_create_vim_software_strategy_build_failed(self, mock_exception):
        """Test create vim software strategy build failed"""

        self.vim_client.get_strategy.side_effect = [
            None,
            STRATEGY_BUILDING_FAILED,
        ]

        # API calls acts as expected
        self.vim_client.create_strategy.return_value = STRATEGY_BUILDING

        self.worker._perform_state_action(
            self.strategy_type, self.subcloud.region_name, self.strategy_step
        )

        # Assert ApplyVIMStrategyFailedException is called with the correct parameters
        expected_message = f"VIM strategy build failed: {BUILD_PHASE_ERROR.response}"
        mock_exception.assert_called_once_with(
            subcloud=self.subcloud.name,
            details=expected_message,
            strategy_name=vim.STRATEGY_NAME_SW_USM,
            state=vim.STATE_BUILD_FAILED,
        )
