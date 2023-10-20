#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dcmanager.common import consts
from dcmanager.tests.unit.orchestrator.states.software.test_base import \
    TestSoftwareOrchestrator


class TestUploadState(TestSoftwareOrchestrator):
    def setUp(self):
        super(TestUploadState, self).setUp()

        self.on_success_state = consts.STRATEGY_STATE_SW_DEPLOY_PRE_CHECK

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            self.subcloud.id, consts.STRATEGY_STATE_SW_UPLOAD)

    def test_upload_success(self):
        """Test upload when the API call succeeds."""

        self.worker.perform_state_action(self.strategy_step)

        # On success, the state should transition to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)
