#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from dcmanager.common import consts
from dcmanager.orchestrator.states.patch.pre_check import IGNORED_ALARMS_IDS
from dcmanager.tests.unit.orchestrator.states.fakes import FakeAlarm
from dcmanager.tests.unit.orchestrator.states.patch.test_base import \
    TestPatchState


class TestPatchPreCheckStage(TestPatchState):
    def setUp(self):
        super(TestPatchPreCheckStage, self).setUp()

        self.success_state = consts.STRATEGY_STATE_UPDATING_PATCHES

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            self.subcloud.id, consts.STRATEGY_STATE_PRE_CHECK)

        self.fm_client.get_alarms = mock.MagicMock()

    def test_no_alarms(self):
        """Test pre check step where there are no alarms

        The pre-check should transition to the updating patches state
        """

        self.fm_client.get_alarms.return_value = []

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the get alarms API call was invoked
        self.fm_client.get_alarms.assert_called()

        # verify the expected next state happened
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.success_state)

    def test_no_management_affecting_alarm(self):
        """Test pre check step where there are no management affecting alarms

        The pre-check should transition to the updating patches state
        """

        self.fm_client.get_alarms.return_value = [FakeAlarm("100.114", "False")]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the get alarms API call was invoked
        self.fm_client.get_alarms.assert_called()

        # verify the expected next state happened
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.success_state)

    def test_management_affected_alarm(self):
        """Test pre check step where there is a management affecting alarm

        The pre-check should transition to the failed state
        """

        alarm_list = [FakeAlarm("100.001", "True"),
                      FakeAlarm("100.002", "True")]

        # also add ignored alarms
        for alarm_str in IGNORED_ALARMS_IDS:
            alarm_list.append(FakeAlarm(alarm_str, "True"))

        self.fm_client.get_alarms.return_value = alarm_list

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the get alarms API call was invoked
        self.fm_client.get_alarms.assert_called()

        # verify the expected next state happened
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_ignored_alarm(self):
        """Test pre check step where there is only a ignored alarm

        The pre-check should transition to the updating patches state
        """
        # add ignored alarms
        alarm_list = []
        for alarm_str in IGNORED_ALARMS_IDS:
            alarm_list.append(FakeAlarm(alarm_str, "True"))

        self.fm_client.get_alarms.return_value = alarm_list

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the get alarms API call was invoked
        self.fm_client.get_alarms.assert_called()

        # verify the expected next state happened
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.success_state)

    def test_get_alarms_unexpected_failure(self):
        """Test pre check step where fm-client get_alarms() fails

        The pre-check should transition to the failed state and the 'details'
        field should contain the correct message detailing the error
        """

        self.fm_client.get_alarms.side_effect = Exception('Test error message')

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the get alarms API call was invoked
        self.fm_client.get_alarms.assert_called()

        # verify the expected next state happened
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

        details = ("pre check: Failed to obtain subcloud alarm report due to:"
                   " (Test error message). Please see /var/log/dcmanager/orche"
                   "strator.log for details")
        self.assert_step_details(self.strategy_step.subcloud_id, details)
