#
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock

from dcmanager.common import consts
from dcmanager.tests.unit.orchestrator.states.fakes import FakeKubeVersion
from dcmanager.tests.unit.orchestrator.states.kube.test_base \
    import TestKubeUpgradeState
from dcmanager.tests.unit.orchestrator.states.test_creating_vim_strategy \
    import CreatingVIMStrategyStageMixin


class TestCreatingVIMKubeUpgradeStrategyStage(CreatingVIMStrategyStageMixin,
                                              TestKubeUpgradeState):
    """Test a vim kube upgrade strategy during kube orchestration"""

    def setUp(self):
        super(TestCreatingVIMKubeUpgradeStrategyStage, self).setUp()
        self.set_state(
            consts.STRATEGY_STATE_KUBE_CREATING_VIM_KUBE_UPGRADE_STRATEGY,
            consts.STRATEGY_STATE_KUBE_APPLYING_VIM_KUBE_UPGRADE_STRATEGY)

        self.sysinv_client.get_kube_versions = mock.MagicMock()
        self.sysinv_client.get_kube_versions.return_value = [
            FakeKubeVersion(),
        ]
