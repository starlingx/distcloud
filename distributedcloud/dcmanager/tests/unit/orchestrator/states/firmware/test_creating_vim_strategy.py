#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import itertools
import mock


from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.orchestrator.states.firmware import creating_vim_strategy

from dcmanager.tests.unit.orchestrator.states.fakes import FakeVimStrategy
from dcmanager.tests.unit.orchestrator.states.firmware.test_base \
    import TestFwUpdateState

STRATEGY_BUILDING = FakeVimStrategy(state=vim.STATE_BUILDING)
STRATEGY_DONE_BUILDING = FakeVimStrategy(state=vim.STATE_READY_TO_APPLY)
STRATEGY_FAILED_BUILDING = FakeVimStrategy(vim.STATE_BUILD_FAILED)


@mock.patch("dcmanager.orchestrator.states.firmware.creating_vim_strategy."
            "DEFAULT_MAX_QUERIES", 3)
@mock.patch("dcmanager.orchestrator.states.firmware.creating_vim_strategy."
            "DEFAULT_SLEEP_DURATION", 1)
class TestFwUpdateCreatingVIMStrategyStage(TestFwUpdateState):

    def setUp(self):
        super(TestFwUpdateCreatingVIMStrategyStage, self).setUp()

        # set the next state in the chain (when this state is successful)
        self.on_success_state =\
            consts.STRATEGY_STATE_APPLYING_FW_UPDATE_STRATEGY

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            consts.STRATEGY_STATE_CREATING_FW_UPDATE_STRATEGY)

        # Add mock API endpoints for sysinv client calls invcked by this state
        self.vim_client.create_strategy = mock.MagicMock()
        self.vim_client.get_strategy = mock.MagicMock()

    def test_creating_vim_strategy_success(self):
        """Test creating a VIM strategy"""

        # first api query is before the create
        # remaining api query results are waiting for the strategy to build
        self.vim_client.get_strategy.side_effect = [
            None,
            STRATEGY_BUILDING,
            STRATEGY_DONE_BUILDING,
        ]

        # API calls acts as expected
        self.vim_client.create_strategy.return_value = STRATEGY_BUILDING

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Successful promotion to next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_creating_vim_strategy_raises_exception(self):
        """Test creating a VIM strategy that raises an exception"""

        # first api query is before the create
        self.vim_client.get_strategy.return_value = None

        # raise an exception during create_strategy
        self.vim_client.create_strategy.side_effect =\
            Exception("HTTPBadRequest: this is a fake exception")

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Failure case
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_creating_vim_strategy_fails_create_immediately(self):
        """Test creating a VIM strategy that returns a failed create"""

        # first api query is before the create
        self.vim_client.get_strategy.return_value = None

        # return a failed strategy
        self.vim_client.create_strategy.return_value = STRATEGY_FAILED_BUILDING

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Failure case
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_creating_vim_strategy_fails_create_later(self):
        """Test creating a VIM strategy that starts to build but then fails"""

        # first api query is before the create
        self.vim_client.get_strategy.side_effect = [
            None,
            STRATEGY_BUILDING,
            STRATEGY_FAILED_BUILDING,
        ]

        # API calls acts as expected
        self.vim_client.create_strategy.return_value = STRATEGY_BUILDING

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Failure case
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_creating_vim_strategy_timeout(self):
        """Test creating a VIM strategy that times out"""

        # first api query is before the create
        self.vim_client.get_strategy.side_effect = itertools.chain(
            [None, ], itertools.repeat(STRATEGY_BUILDING))

        # API calls acts as expected
        self.vim_client.create_strategy.return_value = STRATEGY_BUILDING

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the max number of queries was attempted (plus 1)
        self.assertEqual(creating_vim_strategy.DEFAULT_MAX_QUERIES + 1,
                         self.vim_client.get_strategy.call_count)

        # Failure case
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_creating_vim_strategy_already_exists_and_completes(self):
        """Test creating a VIM strategy while one already exists"""

        # first api query is what already exists
        # remainder are during the loop
        self.vim_client.get_strategy.side_effect = [
            STRATEGY_BUILDING,
            STRATEGY_DONE_BUILDING,
        ]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # create API call should never be invoked
        self.vim_client.create_strategy.assert_not_called()

        # SUCCESS case
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_creating_vim_strategy_already_exists_and_is_broken(self):
        """Test creating a VIM strategy while a broken strategy exists"""

        # first api query is what already exists
        # remainder are during the loop
        self.vim_client.get_strategy.side_effect = [
            STRATEGY_FAILED_BUILDING,
        ]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # create API call should never be invoked
        self.vim_client.create_strategy.assert_not_called()

        # Failure case
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)
