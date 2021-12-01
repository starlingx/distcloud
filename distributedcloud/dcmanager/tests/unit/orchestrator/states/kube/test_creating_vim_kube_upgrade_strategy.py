#
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock

from dcmanager.common import consts
from dcmanager.tests.unit.orchestrator.states.fakes import FakeKubeVersion
from dcmanager.tests.unit.orchestrator.states.fakes \
    import PREVIOUS_KUBE_VERSION
from dcmanager.tests.unit.orchestrator.states.fakes \
    import UPGRADED_KUBE_VERSION
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

        # creating the vim strategy checks if an existing upgrade exists
        self.sysinv_client.get_kube_upgrades = mock.MagicMock()
        self.sysinv_client.get_kube_upgrades.return_value = []

        # when no vim strategy exists, the available version is used
        self.sysinv_client.get_kube_versions = mock.MagicMock()
        self.sysinv_client.get_kube_versions.return_value = [
            FakeKubeVersion(obj_id=1,
                            version=PREVIOUS_KUBE_VERSION,
                            target=True,
                            state='active'),
            FakeKubeVersion(obj_id=2,
                            version=UPGRADED_KUBE_VERSION,
                            target=False,
                            state='available'),
        ]
