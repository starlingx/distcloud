#
# Copyright (c) 2020, 2022, 2024-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import itertools
import mock

from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.orchestrator.states.base import BaseState
from dcmanager.orchestrator.states.firmware import applying_vim_strategy
from dcmanager.tests.unit.orchestrator.states.firmware.test_base import (
    TestFwUpdateState,
)


@mock.patch.object(applying_vim_strategy, "DEFAULT_MAX_FAILED_QUERIES", 3)
@mock.patch.object(applying_vim_strategy, "DEFAULT_MAX_WAIT_ATTEMPTS", 5)
@mock.patch.object(applying_vim_strategy, "WAIT_INTERVAL", 1)
class TestFwUpdateApplyingVIMStrategyStage(TestFwUpdateState):
    def setUp(self):
        super().setUp()

        # set the next state in the chain (when this state is successful)
        self.on_success_state = consts.STRATEGY_STATE_FINISHING_FW_UPDATE
        self.current_state = consts.STRATEGY_STATE_APPLYING_FW_UPDATE_STRATEGY

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            self.subcloud.id, self.current_state
        )

    def test_applying_vim_strategy_success(self):
        """Test applying a VIM strategy that succeeds"""

        # first api query is before the apply
        # remaining api query results are after the apply is invoked
        self.vim_client.get_strategy.side_effect = [
            self._create_fake_strategy(vim.STATE_READY_TO_APPLY),
            self._create_fake_strategy(vim.STATE_APPLYING),
            self._create_fake_strategy(vim.STATE_APPLIED),
        ]

        # API calls acts as expected
        self.vim_client.apply_strategy.return_value = self._create_fake_strategy(
            vim.STATE_APPLYING
        )

        self._setup_and_assert(self.on_success_state)

    def test_applying_vim_strategy_raises_exception(self):
        """Test applying a VIM strategy that raises an exception"""

        # first api query is before the apply
        self.vim_client.get_strategy.return_value = self._create_fake_strategy(
            vim.STATE_READY_TO_APPLY
        )

        # raise an exception during apply_strategy
        error_message = "HTTPBadRequest: this is a fake exception"
        self.vim_client.apply_strategy.side_effect = Exception(error_message)

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(f"{self.current_state}: {error_message}")

    def test_applying_vim_strategy_fails_apply_immediately(self):
        """Test applying a VIM strategy that returns a failed result"""

        # first api query is before the apply
        self.vim_client.get_strategy.return_value = self._create_fake_strategy(
            vim.STATE_READY_TO_APPLY
        )

        # return a failed strategy
        self.vim_client.apply_strategy.return_value = self._create_fake_strategy(
            vim.STATE_APPLY_FAILED
        )

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.current_state}: VIM strategy apply failed - unexpected strategy "
            "state apply-failed"
        )

    def test_applying_vim_strategy_fails_apply_later(self):
        """Test applying a VIM strategy that starts to apply but then fails"""

        # first api query is before the apply
        mock_apply = mock.MagicMock()
        mock_apply.reason = "fake"

        strategies = [
            self._create_fake_strategy(vim.STATE_READY_TO_APPLY),
            self._create_fake_strategy(vim.STATE_APPLYING),
            self._create_fake_strategy(vim.STATE_APPLY_FAILED, apply_phase=mock_apply),
        ]
        self.vim_client.get_strategy.side_effect = strategies

        # API calls acts as expected
        self.vim_client.apply_strategy.return_value = self._create_fake_strategy(
            vim.STATE_APPLYING
        )

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.current_state}: Firmware strategy apply failed. "
            f"{strategies[2].state}. {strategies[2].apply_phase.reason}"
        )

    def test_applying_vim_strategy_timeout(self):
        """Test applying a VIM strategy that times out"""

        # first api query is before the apply
        # test where it never progresses past 'applying'
        self.vim_client.get_strategy.side_effect = itertools.chain(
            [
                self._create_fake_strategy(vim.STATE_READY_TO_APPLY),
            ],
            itertools.repeat(self._create_fake_strategy(vim.STATE_APPLYING)),
        )

        # API calls acts as expected
        self.vim_client.apply_strategy.return_value = self._create_fake_strategy(
            vim.STATE_APPLYING
        )

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(f"{self.current_state}: Timeout applying firmware strategy.")

        # verify the max number of queries was attempted (plus 1 before loop)
        self.assertEqual(
            applying_vim_strategy.DEFAULT_MAX_WAIT_ATTEMPTS + 1,
            self.vim_client.get_strategy.call_count,
        )

    def test_applying_vim_strategy_already_applying_and_completes(self):
        """Test applying a VIM strategy while one already is applying"""

        # first api query is what already exists in applying state
        # remainder are during the loop
        self.vim_client.get_strategy.side_effect = [
            self._create_fake_strategy(vim.STATE_APPLYING),
            self._create_fake_strategy(vim.STATE_APPLIED),
        ]

        self._setup_and_assert(self.on_success_state)

        # apply_strategy API call should never be invoked
        self.vim_client.apply_strategy.assert_not_called()

    def test_applying_vim_strategy_already_exists_and_is_broken(self):
        """Test applying a VIM strategy while a broken strategy exists"""

        # first api query is what already exists
        # remainder are during the loop
        self.vim_client.get_strategy.side_effect = [
            self._create_fake_strategy(vim.STATE_APPLY_FAILED),
        ]

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.current_state}: Timeout during recovery of apply firmware strategy."
        )

        # apply API call should never be invoked
        self.vim_client.apply_strategy.assert_not_called()

    def test_applying_vim_strategy_skips_without_subcloud_strategy(self):
        """Test applying a VIM strategy skips when there isn't a strategy to apply"""

        self.vim_client.get_strategy.return_value = None

        self._setup_and_assert(consts.STRATEGY_STATE_FINISHING_FW_UPDATE)
        self.vim_client.apply_strategy.assert_not_called()

    @mock.patch.object(BaseState, "stopped", return_value=True)
    def test_applying_vim_strategy_fails_when_strategy_stops(self, _):
        """Test applying a VIM strategy fails when strategy stops"""

        self.vim_client.get_strategy.side_effect = [
            self._create_fake_strategy(vim.STATE_READY_TO_APPLY)
        ]

        self.vim_client.apply_strategy.return_value = self._create_fake_strategy(
            vim.STATE_APPLYING
        )

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(f"{self.current_state}: Strategy has been stopped")

    def test_applying_vim_strategy_fails_on_max_failed_queries(self):
        """Test applying a VIM strategy fails when max_failed_queries is reached

        In this case, the DEFAULT_MAX_WAIT_ATTEMPTS must be greater than
        DEFAULT_MAX_FAILED_QUERIES in order to throw the correct exception
        """

        self.vim_client.get_strategy.side_effect = [
            self._create_fake_strategy(vim.STATE_READY_TO_APPLY),
            self._create_fake_strategy(vim.STATE_APPLYING),
            Exception(),
            Exception(),
            Exception(),
        ]

        self.vim_client.apply_strategy.return_value = self._create_fake_strategy(
            vim.STATE_APPLYING
        )

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.current_state}: Timeout during recovery of apply firmware strategy."
        )

    def test_applying_vim_strategy_fails_when_second_subcloud_strategy_is_none(self):
        """Test applying a VIM strategy fails without second subcloud strategy"""

        self.vim_client.get_strategy.side_effect = [
            self._create_fake_strategy(vim.STATE_READY_TO_APPLY),
            None,
        ]

        self.vim_client.apply_strategy.return_value = self._create_fake_strategy(
            vim.STATE_APPLYING
        )

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.current_state}: Firmware strategy disappeared while applying"
        )

    def test_applying_vim_strategy_fails_with_invalid_strategy(self):
        """Test applying a VIM strategy fails with an invalid strategy"""

        self.vim_client.get_strategy.side_effect = [
            self._create_fake_strategy(vim.STATE_READY_TO_APPLY),
            self._create_fake_strategy(vim.STATE_ABORTED),
        ]

        self.vim_client.apply_strategy.return_value = self._create_fake_strategy(
            vim.STATE_APPLYING
        )

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.current_state}: Firmware strategy apply failed. Unexpected State: "
            "aborted."
        )
