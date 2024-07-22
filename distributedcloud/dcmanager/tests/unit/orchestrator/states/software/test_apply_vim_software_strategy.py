#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
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

STRATEGY_READY_TO_APPLY = fakes.FakeVimStrategy(state=vim.STATE_READY_TO_APPLY)
STRATEGY_APPLYING = fakes.FakeVimStrategy(state=vim.STATE_APPLYING)
STRATEGY_APPLIED = fakes.FakeVimStrategy(state=vim.STATE_APPLIED)
APPLY_PHASE_ERROR = fakes.FakeVimStrategyPhase(response="Deploy Start Failed")
STRATEGY_APPLY_FAILED = fakes.FakeVimStrategy(
    state=vim.STATE_APPLY_FAILED, apply_phase=APPLY_PHASE_ERROR
)
RELEASE_ID = "starlingx-9.0.1"


class TestApplyVIMSoftwareStrategyState(TestSoftwareOrchestrator):
    def setUp(self):
        super().setUp()

        self.on_success_state = consts.STRATEGY_STATE_SW_FINISH_STRATEGY

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Create default strategy with release parameter
        extra_args = {"release_id": RELEASE_ID}
        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx, self.DEFAULT_STRATEGY_TYPE, extra_args=extra_args
        )

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            self.subcloud.id, consts.STRATEGY_STATE_SW_APPLY_VIM_STRATEGY
        )

        # Mock the API calls made by the state
        self.vim_client.get_strategy = mock.MagicMock()
        self.vim_client.apply_strategy = mock.MagicMock()

    @mock.patch(
        "dcmanager.orchestrator.states.applying_vim_strategy."
        "DEFAULT_MAX_FAILED_QUERIES",
        3,
    )
    @mock.patch(
        "dcmanager.orchestrator.states.applying_vim_strategy."
        "DEFAULT_MAX_WAIT_ATTEMPTS",
        3,
    )
    @mock.patch("dcmanager.orchestrator.states.applying_vim_strategy.WAIT_INTERVAL", 1)
    @mock.patch(
        "dcmanager.orchestrator.states.applying_vim_strategy."
        "ApplyingVIMStrategyState.__init__.__defaults__",
        (3, 1),
    )
    def test_apply_vim_software_strategy_success(self):
        """Test apply vim software strategy when the API call succeeds."""

        # first api query is before the apply
        # remaining api query results are after the apply is invoked
        self.vim_client.get_strategy.side_effect = [
            STRATEGY_READY_TO_APPLY,
            STRATEGY_APPLYING,
            STRATEGY_APPLIED,
        ]

        # API calls acts as expected
        self.vim_client.apply_strategy.return_value = STRATEGY_APPLYING

        self.worker.perform_state_action(self.strategy_step)

        # Assert apply_strategy is called with the correct strategy name
        self.vim_client.apply_strategy.assert_called_with(strategy_name="sw-upgrade")

        # On success, the state should transition to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id, self.on_success_state)

    @mock.patch(
        "dcmanager.orchestrator.states.applying_vim_strategy."
        "DEFAULT_MAX_FAILED_QUERIES",
        3,
    )
    @mock.patch(
        "dcmanager.orchestrator.states.applying_vim_strategy."
        "DEFAULT_MAX_WAIT_ATTEMPTS",
        3,
    )
    @mock.patch("dcmanager.orchestrator.states.applying_vim_strategy.WAIT_INTERVAL", 1)
    @mock.patch(
        "dcmanager.orchestrator.states.applying_vim_strategy."
        "ApplyingVIMStrategyState.__init__.__defaults__",
        (3, 1),
    )
    @mock.patch.object(exceptions, "ApplyVIMStrategyFailedException")
    def test_apply_vim_software_strategy_apply_failed(self, mock_exception):
        """Test apply vim software strategy apply failed"""

        self.vim_client.get_strategy.side_effect = [
            STRATEGY_READY_TO_APPLY,
            STRATEGY_APPLYING,
            STRATEGY_APPLY_FAILED,
        ]

        # API calls acts as expected
        self.vim_client.apply_strategy.return_value = STRATEGY_APPLYING

        self.worker.perform_state_action(self.strategy_step)

        # Assert ApplyVIMStrategyFailedException is called with the correct parameters
        expected_message = f"VIM strategy apply failed: {APPLY_PHASE_ERROR.response}"
        mock_exception.assert_called_once_with(
            subcloud=self.subcloud.name,
            name=vim.STRATEGY_NAME_SW_USM,
            state=vim.STATE_APPLY_FAILED,
            details=expected_message,
        )
