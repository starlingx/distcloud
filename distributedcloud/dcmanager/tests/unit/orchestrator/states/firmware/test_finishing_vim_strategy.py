#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock

from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.orchestrator.states.firmware.finishing_fw_update import FinishingFwUpdateState

from dcmanager.tests.unit.orchestrator.states.fakes import FakeVimStrategy
from dcmanager.tests.unit.orchestrator.states.firmware.test_base \
    import TestFwUpdateState

STRATEGY_APPLIED = FakeVimStrategy(state=vim.STATE_APPLIED)


class TestFwUpdateFinishingFwUpdateStage(TestFwUpdateState):

    def setUp(self):
        super(TestFwUpdateFinishingFwUpdateStage, self).setUp()

        # set the next state in the chain (when this state is successful)
        self.on_success_state = consts.STRATEGY_STATE_COMPLETE

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            consts.STRATEGY_STATE_FINISHING_FW_UPDATE)

        # Add mock API endpoints for sysinv client calls invcked by this state
        self.vim_client.get_strategy = mock.MagicMock()
        self.vim_client.delete_strategy = mock.MagicMock()
        self.sysinv_client.get_hosts = mock.MagicMock()

        p = mock.patch.object(FinishingFwUpdateState, 'align_subcloud_status')
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

        # ensure that the delete was called
        self.vim_client.delete_strategy.assert_called_once()

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
