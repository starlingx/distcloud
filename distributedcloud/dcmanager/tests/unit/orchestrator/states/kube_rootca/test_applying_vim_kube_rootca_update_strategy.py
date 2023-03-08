#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock

from dcmanager.common import consts
from dcmanager.tests.unit.orchestrator.states.kube_rootca.test_base \
    import TestKubeRootCaUpgradeState
from dcmanager.tests.unit.orchestrator.states.test_applying_vim_strategy \
    import ApplyingVIMStrategyMixin


@mock.patch("dcmanager.orchestrator.states.kube_rootca.applying_vim_strategy."
            "KUBE_ROOTCA_UPDATE_MAX_WAIT_ATTEMPTS", 3)
@mock.patch("dcmanager.orchestrator.states.kube_rootca.applying_vim_strategy."
            "KUBE_ROOTCA_UPDATE_WAIT_INTERVAL", 1)
class TestApplyingVIMKubeRootCAUpgradeStrategyStage(ApplyingVIMStrategyMixin,
                                                    TestKubeRootCaUpgradeState):
    """Tests apply 'kube_rootca' vim strategy during kube rootca upgrade"""

    def setUp(self):
        super(TestApplyingVIMKubeRootCAUpgradeStrategyStage, self).setUp()
        self.set_state(
            consts.STRATEGY_STATE_APPLYING_VIM_KUBE_ROOTCA_UPDATE_STRATEGY,
            consts.STRATEGY_STATE_COMPLETE)
