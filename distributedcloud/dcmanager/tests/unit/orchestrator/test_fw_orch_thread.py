#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import copy
import mock

from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.orchestrator.fw_update_orch_thread import FwUpdateOrchThread
from dcmanager.tests.unit.fakes import FakeVimClient
from dcmanager.tests.unit.fakes import FakeVimStrategy
from dcmanager.tests.unit.fakes import SwUpdateStrategy
from dcmanager.tests.unit.orchestrator.test_base import TestSwUpdate

FAKE_SW_UPDATE_DATA = {
    "type": consts.SW_UPDATE_TYPE_FIRMWARE,
    "subcloud-apply-type": consts.SUBCLOUD_APPLY_TYPE_PARALLEL,
    "max-parallel-subclouds": "2",
    "stop-on-failure": "true",
    "force": "false",
    "state": consts.SW_UPDATE_STATE_INITIAL
}


class TestFwOrchThread(TestSwUpdate):

    # Setting DEFAULT_STRATEGY_TYPE to firmware will setup the firmware
    # orchestration worker, and will mock away the other orch threads
    DEFAULT_STRATEGY_TYPE = consts.SW_UPDATE_TYPE_FIRMWARE

    def setUp(self):
        super(TestFwOrchThread, self).setUp()

        # Mock the vim client defined in the orch thread
        self.worker_vim_client = FakeVimClient()
        p = mock.patch.object(FwUpdateOrchThread, 'get_vim_client')
        self.mock_worker_vim_client = p.start()
        self.mock_worker_vim_client.return_value = self.worker_vim_client
        self.addCleanup(p.stop)

        self.worker_vim_client.create_strategy = mock.MagicMock()
        self.worker_vim_client.delete_strategy = mock.MagicMock()
        self.worker_vim_client.get_strategy = mock.MagicMock()

    def setup_strategy(self, state):
        data = copy.copy(FAKE_SW_UPDATE_DATA)
        data['state'] = state
        return SwUpdateStrategy(1, data=data)

    def test_delete_strategy_no_steps(self):
        # The 'strategy'should be 'deleting'
        self.strategy = self.setup_strategy(
            state=consts.SW_UPDATE_STATE_DELETING)

        self.mock_db_api.strategy_step_get_all.return_value = []

        # invoke the strategy (not strategy step) operation on the orch thread
        self.worker.delete(self.strategy)

        # Delete should get the steps and call delete_subcloud_strategy on each
        self.mock_db_api.strategy_step_get_all.assert_called()
        # There are no strategy steps, so no vim api calls should be invoked
        self.worker_vim_client.get_strategy.assert_not_called()

        self.mock_db_api.strategy_step_destroy_all.assert_called()
        self.mock_db_api.sw_update_strategy_destroy.assert_called()

    def test_delete_strategy_single_step_no_vim_strategy(self):
        # The 'strategy' needs to be in 'deleting'
        self.strategy = self.setup_strategy(
            state=consts.SW_UPDATE_STATE_DELETING)

        strategy_step = self.setup_strategy_step(
            consts.STRATEGY_STATE_CREATING_FW_UPDATE_STRATEGY)
        self.mock_db_api.strategy_step_get_all.return_value = [strategy_step, ]

        # If the subcloud does not have a vim strategy, it raises an exception
        self.worker_vim_client.get_strategy.side_effect = Exception

        # invoke the strategy (not strategy step) operation on the orch thread
        self.worker.delete(self.strategy)

        # Delete should get the steps and call delete_subcloud_strategy on each
        self.mock_db_api.strategy_step_get_all.assert_called()
        # There is a step, so the vim strategy should be queried
        self.worker_vim_client.get_strategy.assert_called()
        # delete should delete the streps from the DB and the strategy
        self.mock_db_api.strategy_step_destroy_all.assert_called()
        self.mock_db_api.sw_update_strategy_destroy.assert_called()

    def test_delete_strategy_single_step_with_vim_strategy(self):
        # The 'strategy' needs to be in 'deleting'
        self.strategy = self.setup_strategy(
            state=consts.SW_UPDATE_STATE_DELETING)

        strategy_step = self.setup_strategy_step(
            consts.STRATEGY_STATE_CREATING_FW_UPDATE_STRATEGY)
        self.mock_db_api.strategy_step_get_all.return_value = [strategy_step, ]

        # the subcloud returns a vim strategy
        vim_strategy = FakeVimStrategy(state=vim.STATE_APPLIED)
        self.worker_vim_client.get_strategy.return_value = vim_strategy

        # invoke the strategy (not strategy step) operation on the orch thread
        self.worker.delete(self.strategy)

        # Delete should get the steps and call delete_subcloud_strategy on each
        self.mock_db_api.strategy_step_get_all.assert_called()
        # There is a step, so the vim strategy should be queried and deleted
        self.worker_vim_client.get_strategy.assert_called()
        self.worker_vim_client.delete_strategy.assert_called()
        # delete should delete the streps from the DB and the strategy
        self.mock_db_api.strategy_step_destroy_all.assert_called()
        self.mock_db_api.sw_update_strategy_destroy.assert_called()
