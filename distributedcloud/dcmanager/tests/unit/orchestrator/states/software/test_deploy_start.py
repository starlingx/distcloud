#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from dcmanager.common import consts
from dcmanager.orchestrator.states.software.deploy_start import DeployStartState
from dcmanager.tests.unit.orchestrator.states.fakes import FakeSystem
from dcmanager.tests.unit.orchestrator.states.software.test_base import \
    TestSoftwareOrchestrator

REGION_ONE_RR_RELEASES = {
    "stx_23.09.0": {
        "sw_version": "23.09.0",
        "state": "deployed",
        "reboot_required": "Y",
    },
    "stx_23.09.1": {
        "sw_version": "23.09.1",
        "state": "deployed",
        "reboot_required": "N",
    },
    "stx_23.09.2": {
        "sw_version": "23.09.1",
        "state": "deployed",
        "reboot_required": "N",
    },
}

REGION_ONE_NRR_RELEASES = {
    "stx_23.09.0": {
        "sw_version": "23.09.0",
        "state": "deployed",
        "reboot_required": "N",
    },
    "stx_23.09.1": {
        "sw_version": "23.09.1",
        "state": "deployed",
        "reboot_required": "N",
    },
}

SUBCLOUD_RR_RELEASES = {
    "stx_23.09.0": {
        "sw_version": "23.09.0",
        "state": "available",
        "reboot_required": "Y",
    },
    "stx_23.09.1": {
        "sw_version": "23.09.1",
        "state": "available",
        "reboot_required": "N",
    },
    "stx_23.09.2": {
        "sw_version": "23.09.1",
        "state": "available",
        "reboot_required": "N",
    },
}

SUBCLOUD_NRR_RELEASES = {
    "stx_23.09.0": {
        "sw_version": "23.09.0",
        "state": "available",
        "reboot_required": "N",
    },
    "stx_23.09.1": {
        "sw_version": "23.09.1",
        "state": "available",
        "reboot_required": "N",
    },
}


class TestDeployStartState(TestSoftwareOrchestrator):
    def setUp(self):
        super(TestDeployStartState, self).setUp()

        self.on_success_state = consts.STRATEGY_STATE_SW_DEPLOY_HOST
        self.on_success_lock_state = consts.STRATEGY_STATE_SW_LOCK_CONTROLLER

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            self.subcloud.id, consts.STRATEGY_STATE_SW_DEPLOY_START
        )

        # Add mock API endpoints for sysinv client calls invoked by this state
        self.sysinv_client.get_system = mock.MagicMock()
        system_values = FakeSystem()
        system_values.system_mode = consts.SYSTEM_MODE_SIMPLEX
        self.sysinv_client.get_system.return_value = system_values

        # Add mock API endpoints for software client calls invoked by this state
        self.software_client.query = mock.MagicMock()
        self.software_client.deploy_start = mock.MagicMock()

        self._read_from_cache = mock.MagicMock()

    @mock.patch.object(DeployStartState, "_read_from_cache")
    def test_deploy_start_nrr_success(self, mock_read_from_cache):
        """Test deploy start when the API call succeeds."""
        mock_read_from_cache.return_value = REGION_ONE_NRR_RELEASES
        self.software_client.query.side_effect = [SUBCLOUD_NRR_RELEASES]

        self.worker.perform_state_action(self.strategy_step)

        self.software_client.deploy_start.assert_called_once_with("stx_23.09.1")

        # On success, the state should transition to the next state
        self.assert_step_updated(
            self.strategy_step.subcloud_id, self.on_success_state
        )

    @mock.patch.object(DeployStartState, "_read_from_cache")
    def test_deploy_start_rr_success(self, mock_read_from_cache):
        """Test deploy start when the API call succeeds."""
        mock_read_from_cache.return_value = REGION_ONE_RR_RELEASES
        self.software_client.query.side_effect = [SUBCLOUD_RR_RELEASES]

        self.worker.perform_state_action(self.strategy_step)

        self.software_client.deploy_start.assert_called_once_with("stx_23.09.2")

        # On success, the state should transition to the next state
        self.assert_step_updated(
            self.strategy_step.subcloud_id, self.on_success_lock_state
        )
