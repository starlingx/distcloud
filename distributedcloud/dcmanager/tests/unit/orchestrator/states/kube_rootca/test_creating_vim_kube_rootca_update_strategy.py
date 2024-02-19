#
# Copyright (c) 2021, 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dcmanager.common import consts
from dcmanager.tests.unit.common import fake_strategy
from dcmanager.tests.unit.orchestrator.states.kube_rootca.test_base \
    import TestKubeRootCaUpgradeState
from dcmanager.tests.unit.orchestrator.states.test_creating_vim_strategy \
    import CreatingVIMStrategyStageMixin


class TestCreatingVIMKubeRootCAUpgradeStrategyStage(
    CreatingVIMStrategyStageMixin, TestKubeRootCaUpgradeState
):
    """Test create vim kube rootca upgrade strategy during kube rootca orch"""

    def setUp(self):
        super().setUp()

        self.set_state(
            consts.STRATEGY_STATE_CREATING_VIM_KUBE_ROOTCA_UPDATE_STRATEGY,
            consts.STRATEGY_STATE_APPLYING_VIM_KUBE_ROOTCA_UPDATE_STRATEGY
        )

    def test_create_strategy_succeeds_with_extra_args(self):
        """Test create strategy succeeds with extra_args"""

        # Create a strategy with extra_args
        extra_args = {
            "expiry-date": "2020:01:31",
            "subject": "C=CA ST=ON L=OTT O=WR OU=STX CN=AL_RULES"
        }
        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx, self.DEFAULT_STRATEGY_TYPE, extra_args=extra_args
        )
        # Call the 'success' test
        self.test_creating_vim_strategy_success()

    def test_create_strategy_succeeds_without_extra_argst(self):
        """Test create strategy succeeds without extra_args"""

        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx, self.DEFAULT_STRATEGY_TYPE, extra_args=None
        )

        self.test_creating_vim_strategy_success()
