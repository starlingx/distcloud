#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dcmanager.common import consts
from dcmanager.tests.unit.orchestrator.states.patch.test_base import \
    TestPatchState
from dcmanager.tests.unit.orchestrator.states.test_applying_vim_strategy import \
    ApplyingVIMStrategyMixin


class TestApplyingVIMPatchStrategyStage(ApplyingVIMStrategyMixin,
                                        TestPatchState):
    def setUp(self):
        super(TestApplyingVIMPatchStrategyStage, self).setUp()
        self.set_state(consts.STRATEGY_STATE_APPLYING_VIM_PATCH_STRATEGY,
                       consts.STRATEGY_STATE_FINISHING_PATCH_STRATEGY)
