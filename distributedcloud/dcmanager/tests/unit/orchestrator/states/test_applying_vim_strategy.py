#
# Copyright (c) 2020-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import itertools

import mock

from dccommon.drivers.openstack import vim
from dccommon.exceptions import VIMClientException
from dcmanager.common import consts
from dcmanager.orchestrator.states import applying_vim_strategy
from dcmanager.orchestrator.states.base import BaseState
from dcmanager.tests.unit.fakes import FakeVimStrategy

STRATEGY_READY_TO_APPLY = FakeVimStrategy(state=vim.STATE_READY_TO_APPLY)
STRATEGY_APPLYING = FakeVimStrategy(state=vim.STATE_APPLYING)
STRATEGY_APPLIED = FakeVimStrategy(state=vim.STATE_APPLIED)
STRATEGY_APPLY_FAILED = FakeVimStrategy(state=vim.STATE_APPLY_FAILED)
STRATEGY_ABORTING = FakeVimStrategy(state=vim.STATE_ABORTING)


# Note: although the values of DEFAULT_MAX_WAIT_ATTEMPTS and WAIT_INTERVAL of
# "dcmanager.orchestrator.states.applying_vim_strategy" are patched in the lines
# below, the default values of parameters "wait_attempts" and "wait_interval" of
# method "ApplyingVIMStrategyState.__init__" don't change. To fix this, we patch
# these default values in "ApplyingVIMStrategyState.__init__.__defaults__".
@mock.patch.object(applying_vim_strategy, "DEFAULT_MAX_FAILED_QUERIES", 3)
@mock.patch.object(applying_vim_strategy, "DEFAULT_MAX_WAIT_ATTEMPTS", 3)
@mock.patch.object(applying_vim_strategy, "WAIT_INTERVAL", 1)
@mock.patch(
    "dcmanager.orchestrator.states.applying_vim_strategy."
    "ApplyingVIMStrategyState.__init__.__defaults__",
    (3, 1),
)
class ApplyingVIMStrategyMixin(object):
    def setup(self, state, success_state, strategy_type=None):
        # The kubernetes strategy require the strategy type to be updated to use the
        # strategy name instead
        self.strategy_name = strategy_type if strategy_type else self.strategy_type

        self.state = state
        self.on_success_state = success_state

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(self.subcloud.id, self.state)

    def test_applying_vim_strategy_success(self):
        """Test applying a VIM strategy that succeeds"""

        # first api query is before the apply
        # remaining api query results are after the apply is invoked
        strategy_states = [STRATEGY_READY_TO_APPLY, STRATEGY_APPLYING, STRATEGY_APPLIED]

        self.vim_client.get_strategy.side_effect = strategy_states
        # API calls acts as expected
        self.vim_client.apply_strategy.return_value = STRATEGY_APPLYING

        self._setup_and_assert(self.on_success_state)

        self.assertEqual(self.vim_client.get_strategy.call_count, len(strategy_states))
        self.vim_client.apply_strategy.assert_called_once()

    def test_applying_vim_strategy_success_and_applied(self):
        """Test applying a VIM strategy that succeeds and is applied"""

        # first api query is before the apply
        # remaining api query results are after the apply is invoked
        strategy_states = [STRATEGY_READY_TO_APPLY, STRATEGY_APPLYING, STRATEGY_APPLIED]

        self.vim_client.get_strategy.side_effect = strategy_states
        # API calls acts as expected
        self.vim_client.apply_strategy.return_value = STRATEGY_APPLIED

        self._setup_and_assert(self.on_success_state)

        self.assertEqual(self.vim_client.get_strategy.call_count, len(strategy_states))
        self.vim_client.apply_strategy.assert_called_once()

    def test_applying_vim_strategy_raises_exception(self):
        """Test applying a VIM strategy that raises an exception"""

        # first api query is before the apply
        self.vim_client.get_strategy.return_value = STRATEGY_READY_TO_APPLY

        # raise an exception during apply_strategy
        error_message = "HTTPBadRequest: this is a fake exception"
        self.vim_client.apply_strategy.side_effect = Exception(error_message)

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(f"{self.state}: {error_message}")

        self.vim_client.get_strategy.assert_called_once()
        self.vim_client.apply_strategy.assert_called_once()

    def test_applying_vim_strategy_fails_apply_immediately(self):
        """Test applying a VIM strategy that returns a failed result"""

        # first api query is before the apply
        self.vim_client.get_strategy.return_value = STRATEGY_READY_TO_APPLY

        # return a failed strategy
        fake_response = mock.MagicMock()
        fake_response.response = "fake"
        STRATEGY_APPLY_FAILED.apply_phase = fake_response
        self.vim_client.apply_strategy.return_value = STRATEGY_APPLY_FAILED

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.state}: Failed for subcloud {self.subcloud.name}: VIM strategy "
            f"apply failed: {STRATEGY_APPLY_FAILED.apply_phase.response} State: "
            f"apply-failed Strategy: {self.strategy_name}"
        )

        self.vim_client.get_strategy.assert_called_once()
        self.vim_client.apply_strategy.assert_called_once()

    def test_applying_vim_strategy_fails_with_unexpected_apply_state(self):
        """Test applying a vim strategy fails with an unexpected apply state"""

        self.vim_client.get_strategy.return_value = STRATEGY_READY_TO_APPLY

        fake_response = mock.MagicMock()
        fake_response.response = "fake"
        STRATEGY_ABORTING.apply_phase = fake_response
        self.vim_client.apply_strategy.return_value = STRATEGY_ABORTING

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.state}: Failed for subcloud {self.subcloud.name}: VIM strategy "
            f"unexpected apply state. State: {STRATEGY_ABORTING.state} Strategy: "
            f"{self.strategy_name}"
        )

        self.vim_client.get_strategy.assert_called_once()
        self.vim_client.apply_strategy.assert_called_once()

    def test_applying_vim_strategy_fails_apply_later(self):
        """Test applying a VIM strategy that starts to apply but then fails"""

        # first api query is before the apply
        strategy_states = [
            STRATEGY_READY_TO_APPLY,
            STRATEGY_APPLYING,
            STRATEGY_APPLY_FAILED,
        ]
        self.vim_client.get_strategy.side_effect = strategy_states

        # API calls acts as expected
        self.vim_client.apply_strategy.return_value = STRATEGY_APPLYING

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.state}: Failed for subcloud {self.subcloud.name}: VIM strategy "
            f"apply failed: fake State: apply-failed Strategy: {self.strategy_name}"
        )

        self.assertEqual(self.vim_client.get_strategy.call_count, len(strategy_states))
        self.vim_client.apply_strategy.assert_called_once()

    def test_applying_vim_strategy_timeout(self):
        """Test applying a VIM strategy that times out"""

        # first api query is before the apply
        # test where it never progresses past 'applying'
        self.vim_client.get_strategy.side_effect = itertools.chain(
            [STRATEGY_READY_TO_APPLY],
            itertools.repeat(STRATEGY_APPLYING),
        )

        # API calls acts as expected
        self.vim_client.apply_strategy.return_value = STRATEGY_APPLYING

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.state}: Failed for subcloud {self.subcloud.name}: Timeout waiting "
            f"for VIM strategy to apply. Strategy: {self.strategy_name}"
        )

        self.assertEqual(
            applying_vim_strategy.DEFAULT_MAX_WAIT_ATTEMPTS,
            self.vim_client.get_strategy.call_count,
        )
        self.vim_client.apply_strategy.assert_called_once()

    def test_applying_vim_strategy_already_applying_and_completes(self):
        """Test applying a VIM strategy while one already is applying"""

        # first api query is what already exists in applying state
        # remainder are during the loop
        strategy_states = [STRATEGY_APPLYING, STRATEGY_APPLIED]
        self.vim_client.get_strategy.side_effect = strategy_states
        self._setup_and_assert(self.on_success_state)

        # apply_strategy API call should never be invoked
        self.assertEqual(self.vim_client.get_strategy.call_count, len(strategy_states))
        self.vim_client.apply_strategy.assert_not_called()

    @mock.patch.object(BaseState, "stopped", return_value=True)
    def test_applying_vim_strategy_fails_when_strategy_stops(self, _):
        """Test applying a VIM strategy fails when strategy stops"""

        self.vim_client.get_strategy.side_effect = [STRATEGY_READY_TO_APPLY]
        self.vim_client.apply_strategy.return_value = STRATEGY_APPLYING

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(f"{self.state}: Strategy has been stopped")

        self.vim_client.get_strategy.assert_called_once()
        self.vim_client.apply_strategy.assert_called_once()

    def test_applying_vim_strategy_fails_with_vim_client_exception(self):
        """Test applying a VIM strategy fails with vim client exception"""

        mock_base_state = self._mock_object(BaseState, "get_vim_client")
        mock_base_state.side_effect = Exception("fake")

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.state}: Failed for subcloud {self.subcloud.name}: Failed to get "
            f"VIM client. Strategy: {self.strategy_name}"
        )

        self.vim_client.get_strategy.assert_not_called()
        self.vim_client.apply_strategy.assert_not_called()

    def test_applying_vim_strategy_fails_with_get_strategy_exception(self):
        """Test applying a VIM strategy fails with get strategy exception"""

        self.vim_client.get_strategy.side_effect = VIMClientException("fake")

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.state}: Failed for subcloud {self.subcloud.name}: Failed to get "
            f"VIM strategy. Strategy: {self.strategy_name}"
        )

        self.vim_client.get_strategy.assert_called_once()
        self.vim_client.apply_strategy.assert_not_called()

    def test_applying_vim_strategy_fails_with_apply_strategy_exception(self):
        """Test applying a VIM strategy fails with apply strategy exception"""

        self.vim_client.get_strategy.side_effect = [STRATEGY_READY_TO_APPLY]
        self.vim_client.apply_strategy.side_effect = VIMClientException("fake")

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.state}: Failed for subcloud {self.subcloud.name}: Failed to apply "
            f"VIM strategy. Strategy: {self.strategy_name}"
        )

        self.vim_client.get_strategy.assert_called_once()
        self.vim_client.apply_strategy.assert_called_once()

    def _test_applying_vim_strategy_fails_with_timeout(self):
        self.vim_client.get_strategy.side_effect = [
            STRATEGY_READY_TO_APPLY,
            STRATEGY_APPLYING,
            VIMClientException(),
            VIMClientException(),
            VIMClientException(),
        ]

        self.vim_client.apply_strategy.return_value = STRATEGY_APPLYING

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)

    def test_applying_vim_strategy_fails_on_max_wait_attempts(self):
        """Test applying a VIM strategy fails when the max wait_attempts is reached"""

        self._test_applying_vim_strategy_fails_with_timeout()
        self._assert_error(
            f"{self.state}: Failed for subcloud {self.subcloud.name}: Timeout waiting "
            f"for VIM strategy to apply. Strategy: {self.strategy_name}"
        )

    def test_applying_vim_strategy_fails_with_strategy_non_existent(self):
        self.vim_client.get_strategy.side_effect = [
            STRATEGY_READY_TO_APPLY,
            STRATEGY_APPLYING,
            None,
        ]

        self.vim_client.apply_strategy.return_value = STRATEGY_APPLYING

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.state}: Failed for subcloud {self.subcloud.name}: VIM Strategy no "
            f"longer exists. Strategy: {self.strategy_name}"
        )
