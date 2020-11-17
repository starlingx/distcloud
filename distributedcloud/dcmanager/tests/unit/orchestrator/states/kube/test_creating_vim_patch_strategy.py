#
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dcmanager.common import consts
from dcmanager.tests.unit.orchestrator.states.kube.test_base \
    import TestKubeUpgradeState
from dcmanager.tests.unit.orchestrator.states.test_creating_vim_strategy \
    import CreatingVIMStrategyStageMixin


class TestCreatingVIMPatchStrategyStage(CreatingVIMStrategyStageMixin,
                                        TestKubeUpgradeState):
    """Test a VIM Patch Strategy during Kube upgrade orchestration"""

    def setUp(self):
        super(TestCreatingVIMPatchStrategyStage, self).setUp()
        self.set_state(
            consts.STRATEGY_STATE_KUBE_CREATING_VIM_PATCH_STRATEGY,
            consts.STRATEGY_STATE_KUBE_APPLYING_VIM_PATCH_STRATEGY)
