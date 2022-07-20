#
# Copyright (c) 2020-2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock

from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.common import exceptions as exception
from dcmanager.common import scheduler
from dcmanager.db.sqlalchemy import api as db_api
from dcmanager.orchestrator.orch_thread import OrchThread

from dcmanager.tests.unit.common import fake_strategy
from dcmanager.tests.unit.fakes import FakeVimClient
from dcmanager.tests.unit.fakes import FakeVimStrategy
from dcmanager.tests.unit.orchestrator.test_base import TestSwUpdate


# rather than invoke a thread, we invoke the function immediately
def non_threaded_start(some_function, some_arguments):
    some_function(some_arguments)


class TestFwOrchThread(TestSwUpdate):

    # Setting DEFAULT_STRATEGY_TYPE to firmware will setup the firmware
    # orchestration worker, and will mock away the other orch threads
    DEFAULT_STRATEGY_TYPE = consts.SW_UPDATE_TYPE_FIRMWARE

    def setUp(self):
        super(TestFwOrchThread, self).setUp()

        # Mock the vim client defined in the base state class
        self.vim_client = FakeVimClient()
        p = mock.patch.object(OrchThread, 'get_vim_client')
        self.mock_vim_client = p.start()
        self.mock_vim_client.return_value = self.vim_client
        self.addCleanup(p.stop)

        self.vim_client.create_strategy = mock.MagicMock()
        self.vim_client.delete_strategy = mock.MagicMock()
        self.vim_client.get_strategy = mock.MagicMock()

    def setup_strategy(self, state):
        return fake_strategy.create_fake_strategy(
            self.ctx,
            consts.SW_UPDATE_TYPE_FIRMWARE,
            state=state)

    def test_delete_strategy_no_steps(self):
        # The 'strategy'should be 'deleting'
        self.strategy = self.setup_strategy(
            state=consts.SW_UPDATE_STATE_DELETING)

        # invoke the strategy (not strategy step) operation on the orch thread
        self.worker.delete(self.strategy)

        # There are no strategy steps, so no vim api calls should be invoked
        self.vim_client.get_strategy.assert_not_called()

        # Verify the strategy was deleted
        self.assertRaises(exception.NotFound,
                          db_api.sw_update_strategy_get,
                          self.ctx,
                          consts.SW_UPDATE_TYPE_FIRMWARE)

    @mock.patch.object(scheduler.ThreadGroupManager, 'start')
    def test_delete_strategy_single_step_no_vim_strategy(self, mock_start):
        # The 'strategy' needs to be in 'deleting'
        self.strategy = self.setup_strategy(
            state=consts.SW_UPDATE_STATE_DELETING)

        self.subcloud = self.setup_subcloud()
        self.setup_strategy_step(
            self.subcloud.id, consts.STRATEGY_STATE_CREATING_FW_UPDATE_STRATEGY)

        # If the subcloud does not have a vim strategy, it raises an exception
        self.vim_client.get_strategy.side_effect = Exception

        mock_start.side_effect = non_threaded_start

        # invoke the strategy (not strategy step) operation on the orch thread
        self.worker.delete(self.strategy)

        # There is a step, so the vim strategy should be queried
        self.vim_client.get_strategy.assert_called()

        # Verify the strategy was deleted
        self.assertRaises(exception.NotFound,
                          db_api.sw_update_strategy_get,
                          self.ctx,
                          consts.SW_UPDATE_TYPE_FIRMWARE)

        # Verify the steps were deleted
        steps = db_api.strategy_step_get_all(self.ctx)
        self.assertEqual(steps, [])

    @mock.patch.object(scheduler.ThreadGroupManager, 'start')
    def test_delete_strategy_single_step_with_vim_strategy(self, mock_start):

        mock_start.side_effect = non_threaded_start

        # The 'strategy' needs to be in 'deleting'
        self.strategy = self.setup_strategy(
            state=consts.SW_UPDATE_STATE_DELETING)

        self.subcloud = self.setup_subcloud()
        self.setup_strategy_step(
            self.subcloud.id, consts.STRATEGY_STATE_CREATING_FW_UPDATE_STRATEGY)

        # the subcloud returns a vim strategy
        vim_strategy = FakeVimStrategy(state=vim.STATE_APPLIED)
        self.vim_client.get_strategy.return_value = vim_strategy

        # invoke the strategy (not strategy step) operation on the orch thread
        self.worker.delete(self.strategy)

        # There is a step, so the vim strategy should be queried and deleted
        self.vim_client.get_strategy.assert_called()
        self.vim_client.delete_strategy.assert_called()

        # Verify the strategy was deleted
        self.assertRaises(exception.NotFound,
                          db_api.sw_update_strategy_get,
                          self.ctx,
                          consts.SW_UPDATE_TYPE_FIRMWARE)

        # Verify the steps were deleted
        steps = db_api.strategy_step_get_all(self.ctx)
        self.assertEqual(steps, [])
