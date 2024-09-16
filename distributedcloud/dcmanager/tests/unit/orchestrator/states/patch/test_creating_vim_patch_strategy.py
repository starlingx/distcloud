#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from collections import namedtuple

import mock

from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.tests.unit.fakes import FakeVimStrategy
from dcmanager.tests.unit.orchestrator.states.patch.test_base import TestPatchState
from dcmanager.tests.unit.orchestrator.states.test_creating_vim_strategy import (
    CreatingVIMStrategyStageMixin,
)


BuildPhase = namedtuple("BuildPhase", "reason")


REASON = "no software patches need to be applied"
STRATEGY_BUILDING = FakeVimStrategy(state=vim.STATE_BUILDING)
STRATEGY_FAILED_BUILDING = FakeVimStrategy(
    state=vim.STATE_BUILD_FAILED, build_phase=BuildPhase(REASON)
)


@mock.patch(
    "dcmanager.orchestrator.states.patch.creating_vim_patch_strategy."
    "DEFAULT_MAX_QUERIES",
    3,
)
@mock.patch(
    "dcmanager.orchestrator.states.patch.creating_vim_patch_strategy."
    "DEFAULT_SLEEP_DURATION",
    1,
)
class TestCreatingVIMPatchStrategyStage(CreatingVIMStrategyStageMixin, TestPatchState):
    def setUp(self):
        super(TestCreatingVIMPatchStrategyStage, self).setUp()
        self.set_state(
            consts.STRATEGY_STATE_CREATING_VIM_PATCH_STRATEGY,
            consts.STRATEGY_STATE_APPLYING_VIM_PATCH_STRATEGY,
        )
        self.skip_state = consts.STRATEGY_STATE_COMPLETE

    def test_skip_if_not_needed(self):
        """Test creating VIM strategy when no patches need to be applied.

        When VIM returns 'no software patches need to be applied' the state
        should skip the 'applying VIM strategy' state, returning the 'finishing'
        state instead.
        """

        # first api query is before the create
        self.vim_client.get_strategy.side_effect = [
            None,
            STRATEGY_BUILDING,
            STRATEGY_FAILED_BUILDING,
        ]

        # API calls acts as expected
        self.vim_client.create_strategy.return_value = STRATEGY_BUILDING

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        self.assert_step_updated(self.strategy_step.subcloud_id, self.skip_state)
