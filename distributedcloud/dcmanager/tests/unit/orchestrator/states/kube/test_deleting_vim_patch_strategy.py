#
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dcmanager.common import consts
from dcmanager.tests.unit.orchestrator.states.kube.test_base \
    import TestKubeUpgradeState


class TestKubeDeletingVimPatchStrategyStage(TestKubeUpgradeState):
    "Test deleting the vim patch strategy during kube orch."""

    def setUp(self):
        super(TestKubeDeletingVimPatchStrategyStage, self).setUp()

        self.strategy_step = self.setup_strategy_step(
            consts.STRATEGY_STATE_KUBE_DELETING_VIM_PATCH_STRATEGY)
        self.on_success_state = \
            consts.STRATEGY_STATE_KUBE_CREATING_VIM_KUBE_UPGRADE_STRATEGY

        self.subcloud = self.setup_subcloud()
