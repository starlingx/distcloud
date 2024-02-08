#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock

from oslo_config import cfg

from dcmanager.common import consts
from dcmanager.orchestrator.states.software.finish_strategy import \
    FinishStrategyState
from dcmanager.tests.unit.orchestrator.states.software.test_base import \
    TestSoftwareOrchestrator


REGION_ONE_RELEASES = {"DC.1": {"sw_version": "20.12",
                                "state": "committed"},
                       "DC.2": {"sw_version": "20.12",
                                "state": "committed"},
                       "DC.3": {"sw_version": "20.12",
                                "state": "committed"},
                       "DC.8": {"sw_version": "20.12",
                                "state": "committed"}}

SUBCLOUD_RELEASES = {"DC.1": {"sw_version": "20.12",
                              "state": "committed"},
                     "DC.2": {"sw_version": "20.12",
                              "state": "committed"},
                     "DC.3": {"sw_version": "20.12",
                              "state": "deployed"},
                     "DC.9": {"sw_version": "20.12",
                              "state": "available"}}


class TestFinishStrategyState(TestSoftwareOrchestrator):
    def setUp(self):
        p = mock.patch.object(cfg.CONF, 'use_usm')
        self.mock_use_usm = p.start()
        self.mock_use_usm.return_value = True
        self.addCleanup(p.stop)
        super().setUp()

        self.on_success_state = consts.STRATEGY_STATE_COMPLETE

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            self.subcloud.id, consts.STRATEGY_STATE_SW_FINISH_STRATEGY)

        # Add mock API endpoints for software client calls
        # invoked by this state
        self.software_client.query = mock.MagicMock()
        self.software_client.delete = mock.MagicMock()
        self.software_client.commit_patch = mock.MagicMock()
        self._read_from_cache = mock.MagicMock()

    @mock.patch.object(FinishStrategyState, '_read_from_cache')
    def test_finish_strategy_success(self, mock_read_from_cache):
        """Test software finish strategy when the API call succeeds."""
        mock_read_from_cache.return_value = REGION_ONE_RELEASES

        self.software_client.query.side_effect = [SUBCLOUD_RELEASES]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        call_args, _ = self.software_client.delete.call_args_list[0]
        self.assertItemsEqual(['DC.9'], call_args[0])

        call_args, _ = self.software_client.commit_patch.call_args_list[0]
        self.assertItemsEqual(['DC.3'], call_args[0])

        # On success, the state should transition to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    @mock.patch.object(FinishStrategyState, '_read_from_cache')
    def test_finish_strategy_no_operation_required(self, mock_read_from_cache):
        """Test software finish strategy when no operation is required."""
        mock_read_from_cache.return_value = REGION_ONE_RELEASES

        self.software_client.query.side_effect = [REGION_ONE_RELEASES]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        self.software_client.delete.assert_not_called()

        self.software_client.commit_patch.assert_not_called()

        # On success, the state should transition to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)
