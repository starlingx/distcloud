#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.tests.unit.common import fake_strategy
from dcmanager.tests.unit.fakes import FakeVimStrategy
from dcmanager.tests.unit.orchestrator.states.software.test_base import (
    TestSoftwareOrchestrator,
)

STRATEGY_BUILDING = FakeVimStrategy(state=vim.STATE_BUILDING)
STRATEGY_DONE_BUILDING = FakeVimStrategy(state=vim.STATE_READY_TO_APPLY)
RELEASE_ID = "starlingx-9.0.1"


class TestCreateVIMSoftwareStrategyState(TestSoftwareOrchestrator):
    def setUp(self):
        super().setUp()

        self.on_success_state = consts.STRATEGY_STATE_SW_APPLY_VIM_STRATEGY

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Create default strategy with release parameter
        extra_args = {"release_id": RELEASE_ID}
        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx, self.DEFAULT_STRATEGY_TYPE, extra_args=extra_args
        )

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            self.subcloud.id, consts.STRATEGY_STATE_SW_CREATE_VIM_STRATEGY
        )

        # Mock the API calls made by the state
        self.vim_client.create_strategy = mock.MagicMock()
        self.vim_client.delete_strategy = mock.MagicMock()
        self.vim_client.get_strategy = mock.MagicMock()

    def test_create_vim_software_strategy_success(self):
        """Test create vim software strategy when the API call succeeds."""

        self.vim_client.get_strategy.side_effect = [
            None,
            STRATEGY_BUILDING,
            STRATEGY_DONE_BUILDING,
        ]

        # API calls acts as expected
        self.vim_client.create_strategy.return_value = STRATEGY_BUILDING

        self.worker.perform_state_action(self.strategy_step)

        # Assert release parameter is passed to create_strategy
        self.vim_client.create_strategy.assert_called_with(
            "sw-upgrade",
            "parallel",
            "parallel",
            10,
            "migrate",
            "relaxed",
            release=RELEASE_ID,
            rollback=False,
        )

        # On success, the state should transition to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id, self.on_success_state)
