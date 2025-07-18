#
# Copyright (c) 2021, 2024-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from dcmanager.common import consts
from dcmanager.orchestrator.states.kube_rootca import applying_vim_strategy
from dcmanager.tests.unit.orchestrator.states.kube_rootca.test_base import (
    TestKubeRootCaUpgradeState,
)
from dcmanager.tests.unit.orchestrator.states.test_applying_vim_strategy import (
    ApplyingVIMStrategyMixin,
)


@mock.patch.object(applying_vim_strategy, "KUBE_ROOTCA_UPDATE_MAX_WAIT_ATTEMPTS", 3)
@mock.patch.object(applying_vim_strategy, "KUBE_ROOTCA_UPDATE_WAIT_INTERVAL", 1)
class TestApplyingVIMKubeRootCAUpgradeStrategyStage(
    ApplyingVIMStrategyMixin, TestKubeRootCaUpgradeState
):
    """Tests apply 'kube_rootca' vim strategy during kube rootca upgrade"""

    def setUp(self):
        super().setUp()

        self.setup(
            consts.STRATEGY_STATE_APPLYING_VIM_KUBE_ROOTCA_UPDATE_STRATEGY,
            consts.STRATEGY_STATE_COMPLETE,
        )
