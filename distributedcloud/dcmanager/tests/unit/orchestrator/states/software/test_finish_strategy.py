#
# Copyright (c) 2023-2025 Wind River Systems, Inc.
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
    {"release_id": "starlingx-9.0.0", "state": "deployed", "sw_version": "9.0.0"},
    {"release_id": "starlingx-9.0.1", "state": "deployed", "sw_version": "9.0.1"},
    {"release_id": "starlingx-9.0.2", "state": "deployed", "sw_version": "9.0.2"},
    {"release_id": "starlingx-9.0.3", "state": "deployed", "sw_version": "9.0.3"},
]

SUBCLOUD_RELEASES = [
    {"release_id": "starlingx-9.0.0", "state": "deployed", "sw_version": "9.0.0"},
    {"release_id": "starlingx-9.0.1", "state": "deployed", "sw_version": "9.0.1"},
    {"release_id": "starlingx-9.0.2", "state": "deployed", "sw_version": "9.0.2"},
    {"release_id": "starlingx-9.0.2", "state": "deploying", "sw_version": "9.0.3"},
    {"release_id": "starlingx-9.0.4", "state": "available", "sw_version": "9.0.4"},
]

SUBCLOUD_WITHOUT_DEPLOYED_RELEASES = [
    {"release_id": "starlingx-9.0.0", "state": "available", "sw_version": "9.0.0"},
]


class TestFinishStrategyState(TestSoftwareOrchestrator):
    def setUp(self):
        super().setUp()

        self.mock_read_from_cache = self._mock_object(
            FinishStrategyState, "_read_from_cache"
        )
        self._mock_object(rpc_client, "EngineWorkerClient")

        self.on_success_state = consts.STRATEGY_STATE_COMPLETE
        self.current_state = consts.STRATEGY_STATE_SW_FINISH_STRATEGY

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            self.subcloud.id, self.current_state
        )
        self.mock_read_from_cache.return_value = REGION_ONE_RELEASES

    def test_finish_strategy_success(self):
        """Test software finish strategy when the API call succeeds."""

        self.software_client.list.side_effect = [SUBCLOUD_RELEASES]

        self._setup_and_assert(self.on_success_state)

        call_args, _ = self.software_client.delete.call_args_list[0]
        self.assertItemsEqual(["starlingx-9.0.4"], call_args[0])

        self.software_client.commit_patch.assert_not_called()

    def test_finish_strategy_success_without_subcloud_deployed_releases(self):
        """Test finish strategy success without subcloud deployed releases"""

        self.software_client.list.side_effect = [SUBCLOUD_WITHOUT_DEPLOYED_RELEASES]

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.current_state}: Failed for subcloud subcloud1: Unable to find a "
            "deployed release after deployment"
        )

    def test_finish_strategy_no_operation_required(self):
        """Test software finish strategy when no operation is required."""

        self.software_client.list.side_effect = [REGION_ONE_RELEASES]

        self._setup_and_assert(self.on_success_state)

        self.software_client.delete.assert_not_called()
        self.software_client.commit_patch.assert_not_called()

    def test_finish_strategy_fails_when_query_exception(self):
        """Test finish strategy fails when software client query raises exception"""

        self.software_client.list.side_effect = Exception()

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.current_state}: Failed for subcloud {self.subcloud.name}: Failed "
            "to retrieve necessary release information."
        )

    def test_finish_strategy_fails_when_delete_exception(self):
        """Test finish strategy fails when software client delete raises exception"""

        self.software_client.list.side_effect = [SUBCLOUD_RELEASES]
        self.software_client.delete.side_effect = Exception()

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.current_state}: Failed for subcloud {self.subcloud.name}: Cannot "
            "delete releases from subcloud."
        )

    @mock.patch.object(BaseState, "stopped")
    def test_finish_strategy_fails_when_stopped(self, mock_base_stopped):
        """Test finish strategy fails when stopped"""

        self.software_client.list.side_effect = [SUBCLOUD_RELEASES]

        mock_base_stopped.return_value = True

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(f"{self.current_state}: Strategy has been stopped")

    def test_handle_deploy_commit_is_not_implemented(self):
        """Test handle deploy commit is not implemented

        Because the releases to commit logic is not implemented, there is also no code
        execution for the _handle_deploy_commit method, which is unreacheable.
        """

        self.assertRaises(
            NotImplementedError,
            FinishStrategyState._handle_deploy_commit,
            None,
            None,
            None,
            None,
        )
