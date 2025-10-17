#
# Copyright (c) 2023-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.orchestrator.states import applying_vim_strategy
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


@mock.patch.object(applying_vim_strategy, "DEFAULT_MAX_FAILED_QUERIES", 3)
@mock.patch.object(applying_vim_strategy, "DEFAULT_MAX_WAIT_ATTEMPTS", 3)
@mock.patch.object(applying_vim_strategy, "WAIT_INTERVAL", 1)
@mock.patch(
    "dcmanager.orchestrator.states.applying_vim_strategy."
    "ApplyingVIMStrategyState.__init__.__defaults__",
    (3, 1),
)
class TestApplyVIMSoftwareStrategyState(TestSoftwareOrchestrator):
    def setUp(self):
        super().setUp()

        self.on_success_state = consts.STRATEGY_STATE_SW_FINISH_STRATEGY
        self.current_state = consts.STRATEGY_STATE_SW_APPLY_VIM_STRATEGY

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            self.subcloud.id, self.current_state
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

        self._setup_and_assert(self.on_success_state)

        # Assert apply_strategy is called with the correct strategy name
        self.vim_client.apply_strategy.assert_called_with(strategy_name="sw-upgrade")

    def test_apply_vim_software_strategy_apply_failed(self):
        """Test apply vim software strategy apply failed"""

        self.vim_client.get_strategy.side_effect = [
            STRATEGY_READY_TO_APPLY,
            STRATEGY_APPLYING,
            STRATEGY_APPLY_FAILED,
        ]

        # API calls acts as expected
        self.vim_client.apply_strategy.return_value = STRATEGY_APPLYING

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.current_state}: Failed for subcloud subcloud1: VIM strategy apply "
            "failed: Deploy Start Failed State: apply-failed Strategy: sw-upgrade"
        )
