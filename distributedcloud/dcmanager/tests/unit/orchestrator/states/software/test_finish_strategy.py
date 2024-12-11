#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from dcmanager.common import consts
from dcmanager.orchestrator.states.base import BaseState
from dcmanager.orchestrator.states.software.finish_strategy import FinishStrategyState
from dcmanager.tests.unit.orchestrator.states.software.test_base import (
    TestSoftwareOrchestrator,
)
from dcorch.rpc import client as rpc_client


REGION_ONE_RELEASES = [
    {
        "release_id": "starlingx-9.0.0",
        "state": "deployed",
        "sw_version": "9.0.0",
    },
    {
        "release_id": "starlingx-9.0.1",
        "state": "deployed",
        "sw_version": "9.0.1",
    },
    {
        "release_id": "starlingx-9.0.2",
        "state": "deployed",
        "sw_version": "9.0.2",
    },
    {
        "release_id": "starlingx-9.0.3",
        "state": "deployed",
        "sw_version": "9.0.3",
    },
]

SUBCLOUD_RELEASES = [
    {
        "release_id": "starlingx-9.0.0",
        "state": "deployed",
        "sw_version": "9.0.0",
    },
    {
        "release_id": "starlingx-9.0.1",
        "state": "deployed",
        "sw_version": "9.0.1",
    },
    {
        "release_id": "starlingx-9.0.2",
        "state": "deployed",
        "sw_version": "9.0.2",
    },
    {
        "release_id": "starlingx-9.0.2",
        "state": "deploying",
        "sw_version": "9.0.3",
    },
    {
        "release_id": "starlingx-9.0.4",
        "state": "available",
        "sw_version": "9.0.4",
    },
]


class TestFinishStrategyState(TestSoftwareOrchestrator):
    def setUp(self):
        super().setUp()

        self.mock_read_from_cache = self._mock_object(
            FinishStrategyState, "_read_from_cache"
        )
        self._mock_object(rpc_client, "EngineWorkerClient")

        self.on_success_state = consts.STRATEGY_STATE_COMPLETE

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            self.subcloud.id, consts.STRATEGY_STATE_SW_FINISH_STRATEGY
        )
        self.mock_read_from_cache.return_value = REGION_ONE_RELEASES

        # Add mock API endpoints for software client calls
        # invoked by this state
        self.software_client.list = mock.MagicMock()
        self.software_client.delete = mock.MagicMock()
        self.software_client.commit_patch = mock.MagicMock()

    def test_finish_strategy_success(self):
        """Test software finish strategy when the API call succeeds."""

        self.software_client.list.side_effect = [SUBCLOUD_RELEASES]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        call_args, _ = self.software_client.delete.call_args_list[0]
        self.assertItemsEqual(["starlingx-9.0.4"], call_args[0])

        self.software_client.commit_patch.assert_not_called()

        # On success, the state should transition to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id, self.on_success_state)

    def test_finish_strategy_no_operation_required(self):
        """Test software finish strategy when no operation is required."""

        self.software_client.list.side_effect = [REGION_ONE_RELEASES]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        self.software_client.delete.assert_not_called()

        self.software_client.commit_patch.assert_not_called()

        # On success, the state should transition to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id, self.on_success_state)

    def test_finish_strategy_fails_when_query_exception(self):
        """Test finish strategy fails when software client query raises exception"""

        self.software_client.list.side_effect = Exception()

        self.worker.perform_state_action(self.strategy_step)

        self.assert_step_updated(
            self.strategy_step.subcloud_id, consts.STRATEGY_STATE_FAILED
        )

    def test_finish_strategy_fails_when_delete_exception(self):
        """Test finish strategy fails when software client delete raises exception"""

        self.software_client.list.side_effect = [SUBCLOUD_RELEASES]
        self.software_client.delete.side_effect = Exception()

        self.worker.perform_state_action(self.strategy_step)

        self.assert_step_updated(
            self.strategy_step.subcloud_id, consts.STRATEGY_STATE_FAILED
        )

    @mock.patch.object(BaseState, "stopped")
    def test_finish_strategy_fails_when_stopped(self, mock_base_stopped):
        """Test finish strategy fails when stopped"""

        self.software_client.list.side_effect = [SUBCLOUD_RELEASES]

        mock_base_stopped.return_value = True

        self.worker.perform_state_action(self.strategy_step)

        self.assert_step_updated(
            self.strategy_step.subcloud_id, consts.STRATEGY_STATE_FAILED
        )
