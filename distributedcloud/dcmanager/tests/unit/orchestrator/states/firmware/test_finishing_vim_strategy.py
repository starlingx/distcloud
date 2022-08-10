#
# Copyright (c) 2020-2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock

from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.orchestrator.states.firmware import finishing_fw_update

from dcmanager.tests.unit.fakes import FakeVimStrategy
from dcmanager.tests.unit.orchestrator.states.firmware.test_base \
    import TestFwUpdateState

STRATEGY_APPLIED = FakeVimStrategy(state=vim.STATE_APPLIED)


@mock.patch("dcmanager.orchestrator.states.firmware.finishing_fw_update.DEFAULT_MAX_FAILED_QUERIES",
            3)
@mock.patch("dcmanager.orchestrator.states.firmware.finishing_fw_update.DEFAULT_FAILED_SLEEP", 1)
class TestFwUpdateFinishingFwUpdateStage(TestFwUpdateState):

    def setUp(self):
        super(TestFwUpdateFinishingFwUpdateStage, self).setUp()

        # set the next state in the chain (when this state is successful)
        self.on_success_state = consts.STRATEGY_STATE_COMPLETE

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            self.subcloud.id, consts.STRATEGY_STATE_FINISHING_FW_UPDATE)

        # Add mock API endpoints for sysinv client calls invcked by this state
        self.vim_client.get_strategy = mock.MagicMock()
        self.vim_client.delete_strategy = mock.MagicMock()
        self.sysinv_client.get_hosts = mock.MagicMock()
        self.sysinv_client.get_host_device_list = mock.MagicMock()

        p = mock.patch.object(finishing_fw_update.FinishingFwUpdateState, 'align_subcloud_status')
        self.mock_align = p.start()
        self.addCleanup(p.stop)

    def test_finishing_vim_strategy_success(self):
        """Test finishing the firmware update."""

        # this tests successful steps of:
        # - vim strategy exists on subcloud and can be deleted
        # - no device image states on the subcloud are 'failed'
        self.vim_client.get_strategy.return_value = STRATEGY_APPLIED

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Successful promotion to next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_finishing_vim_strategy_success_no_strategy(self):
        """Test finishing the firmware update.

        Finish the orchestration state when there is no subcloud vim strategy.
        """

        # this tests successful steps of:
        # - vim strategy does not exist for some reason
        # - no device image states on the subcloud are 'failed'
        self.vim_client.get_strategy.return_value = None

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # ensure that the delete was not called
        self.vim_client.delete_strategy.assert_not_called()

        # Successful promotion to next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_finishing_vim_strategy_failure_get_hosts(self):
        """Test finishing firmware update with communication error to subcloud"""

        # mock the get_host query fails and raises an exception
        self.sysinv_client.get_hosts.side_effect = \
            Exception("HTTP CommunicationError")

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the query was actually attempted
        self.sysinv_client.get_hosts.assert_called()

        # verified the query was tried max retries + 1
        self.assertEqual(finishing_fw_update.DEFAULT_MAX_FAILED_QUERIES + 1,
                         self.sysinv_client.get_hosts.call_count)

        # verify the subsequent sysinv command was never attempted
        self.sysinv_client.get_host_device_list.assert_not_called()

        # verify that the state moves to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)
