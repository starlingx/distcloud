#
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dcmanager.common import consts
from dcmanager.tests.unit.orchestrator.states.kube.test_base \
    import TestKubeUpgradeState


class TestKubeUpdatingPatchesStage(TestKubeUpgradeState):
    "Test uploading and applying the patces required for kube orch."""

    def setUp(self):
        super(TestKubeUpdatingPatchesStage, self).setUp()

        self.strategy_step = self.setup_strategy_step(
            consts.STRATEGY_STATE_KUBE_UPDATING_PATCHES)
        self.on_success_state = \
            consts.STRATEGY_STATE_KUBE_CREATING_VIM_PATCH_STRATEGY

        self.subcloud = self.setup_subcloud()
