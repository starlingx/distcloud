#
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dcmanager.common import consts
from dcmanager.tests.unit.orchestrator.states.kube.test_base \
    import TestKubeUpgradeState
from dcmanager.tests.unit.orchestrator.states.test_applying_vim_strategy \
    import ApplyingVIMStrategyMixin


class TestApplyingVIMKubeUpgradeStrategyStage(ApplyingVIMStrategyMixin,
                                              TestKubeUpgradeState):
    """This test applies the 'kube' vim strategy during kube upgrade"""

    def setUp(self):
        super(TestApplyingVIMKubeUpgradeStrategyStage, self).setUp()
        self.set_state(
            consts.STRATEGY_STATE_KUBE_APPLYING_VIM_KUBE_UPGRADE_STRATEGY,
            consts.STRATEGY_STATE_COMPLETE)
