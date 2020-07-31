#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock

from dcmanager.common import consts

from dcmanager.tests.unit.manager.states.firmware.test_base \
    import TestFwUpdateState


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

    def test_finishing_vim_strategy_success(self):
        """Test finishing the firmware update."""

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # todo(abailey): Add code to test this state

        # Successful promotion to next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)
