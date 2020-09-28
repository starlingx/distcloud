#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import itertools
import mock

from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.orchestrator.states import applying_vim_strategy

from dcmanager.tests.unit.fakes import FakeVimStrategy
from dcmanager.tests.unit.orchestrator.states.upgrade.test_base \
    import TestSwUpgradeState

STRATEGY_READY_TO_APPLY = FakeVimStrategy(state=vim.STATE_READY_TO_APPLY)
STRATEGY_APPLYING = FakeVimStrategy(state=vim.STATE_APPLYING)
STRATEGY_APPLIED = FakeVimStrategy(state=vim.STATE_APPLIED)
STRATEGY_APPLY_FAILED = FakeVimStrategy(vim.STATE_APPLY_FAILED)


@mock.patch("dcmanager.orchestrator.states.applying_vim_strategy."
            "DEFAULT_MAX_FAILED_QUERIES", 3)
@mock.patch("dcmanager.orchestrator.states.applying_vim_strategy."
            "DEFAULT_MAX_WAIT_ATTEMPTS", 3)
@mock.patch("dcmanager.orchestrator.states.applying_vim_strategy."
            "WAIT_INTERVAL", 1)
class TestSwUpgradeApplyingVIMStrategyStage(TestSwUpgradeState):

    def setUp(self):
        super(TestSwUpgradeApplyingVIMStrategyStage, self).setUp()

        # set the next state in the chain (when this state is successful)
        self.on_success_state = \
            consts.STRATEGY_STATE_SWACTING_TO_CONTROLLER_0

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            consts.STRATEGY_STATE_APPLYING_VIM_UPGRADE_STRATEGY)

        # Add mock API endpoints for client calls invcked by this state
        self.vim_client.get_strategy = mock.MagicMock()
        self.vim_client.apply_strategy = mock.MagicMock()

    def test_applying_vim_strategy_success(self):
        """Test applying a VIM strategy that succeeds"""

        # first api query is before the apply
        # remaining api query results are after the apply is invoked
        self.vim_client.get_strategy.side_effect = [
            STRATEGY_READY_TO_APPLY,
            STRATEGY_APPLYING,
            STRATEGY_APPLIED,
        ]

        # API calls acts as expected
        self.vim_client.apply_strategy.return_value = STRATEGY_APPLYING

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Successful promotion to next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_applying_vim_strategy_raises_exception(self):
        """Test applying a VIM strategy that raises an exception"""

        # first api query is before the apply
        self.vim_client.get_strategy.return_value = STRATEGY_READY_TO_APPLY

        # raise an exception during apply_strategy
        self.vim_client.apply_strategy.side_effect =\
            Exception("HTTPBadRequest: this is a fake exception")

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Failure case
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_applying_vim_strategy_fails_apply_immediately(self):
        """Test applying a VIM strategy that returns a failed result"""

        # first api query is before the apply
        self.vim_client.get_strategy.return_value = STRATEGY_READY_TO_APPLY

        # return a failed strategy
        self.vim_client.apply_strategy.return_value = STRATEGY_APPLY_FAILED

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Failure case
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_applying_vim_strategy_fails_apply_later(self):
        """Test applying a VIM strategy that starts to apply but then fails"""

        # first api query is before the apply
        self.vim_client.get_strategy.side_effect = [
            STRATEGY_READY_TO_APPLY,
            STRATEGY_APPLYING,
            STRATEGY_APPLY_FAILED,
        ]

        # API calls acts as expected
        self.vim_client.apply_strategy.return_value = STRATEGY_APPLYING

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Failure case
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_applying_vim_strategy_timeout(self):
        """Test applying a VIM strategy that times out"""

        # first api query is before the apply
        # test where it never progresses past 'applying'
        self.vim_client.get_strategy.side_effect = itertools.chain(
            [STRATEGY_READY_TO_APPLY, ], itertools.repeat(STRATEGY_APPLYING))

        # API calls acts as expected
        self.vim_client.apply_strategy.return_value = STRATEGY_APPLYING

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the max number of queries was attempted (plus 1 before loop)
        self.assertEqual(applying_vim_strategy.DEFAULT_MAX_WAIT_ATTEMPTS + 1,
                         self.vim_client.get_strategy.call_count)

        # Failure case
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_applying_vim_strategy_already_applying_and_completes(self):
        """Test applying a VIM strategy while one already is applying"""

        # first api query is what already exists in applying state
        # remainder are during the loop
        self.vim_client.get_strategy.side_effect = [
            STRATEGY_APPLYING,
            STRATEGY_APPLIED,
        ]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # apply_strategy API call should never be invoked
        self.vim_client.apply_strategy.assert_not_called()

        # SUCCESS case
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_applying_vim_strategy_already_exists_and_is_broken(self):
        """Test applying a VIM strategy while a broken strategy exists"""

        # first api query is what already exists
        # remainder are during the loop
        self.vim_client.get_strategy.side_effect = [
            STRATEGY_APPLY_FAILED,
        ]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # apply API call should never be invoked
        self.vim_client.apply_strategy.assert_not_called()

        # Failure case
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)
