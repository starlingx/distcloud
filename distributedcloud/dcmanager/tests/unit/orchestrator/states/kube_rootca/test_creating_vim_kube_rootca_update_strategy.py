#
# Copyright (c) 2021, 2024-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.tests.unit.common import fake_strategy
from dcmanager.tests.unit.fakes import FakeVimStrategy
from dcmanager.tests.unit.orchestrator.states.kube_rootca.test_base import (
    TestKubeRootCaUpgradeState,
)
from dcmanager.tests.unit.orchestrator.states.test_creating_vim_strategy import (
    CreatingVIMStrategyStageMixin,
)

STRATEGY_BUILDING = FakeVimStrategy(state=vim.STATE_BUILDING)
STRATEGY_DONE_BUILDING = FakeVimStrategy(state=vim.STATE_READY_TO_APPLY)


class TestCreatingVIMKubeRootCAUpgradeStrategyStage(
    CreatingVIMStrategyStageMixin, TestKubeRootCaUpgradeState
):
    """Test create vim kube rootca upgrade strategy during kube rootca orch"""

    def setUp(self):
        super().setUp()

        self.set_state(
            consts.STRATEGY_STATE_CREATING_VIM_KUBE_ROOTCA_UPDATE_STRATEGY,
            consts.STRATEGY_STATE_APPLYING_VIM_KUBE_ROOTCA_UPDATE_STRATEGY,
        )

    def test_create_strategy_succeeds_with_extra_args(self):
        """Test create strategy succeeds with extra_args"""

        # Create a strategy with extra_args
        extra_args = {
            "expiry-date": "2020:01:31",
            "subject": "C=CA ST=ON L=OTT O=WR OU=STX CN=AL_RULES",
        }
        self.strategy = fake_strategy.update_fake_strategy(
            self.ctx, self.strategy_type, additional_args=extra_args
        )
        # Call the 'success' test
        self.test_creating_vim_strategy_success()

    def test_create_strategy_succeeds_without_extra_argst(self):
        """Test create strategy succeeds without extra_args"""

        self.test_creating_vim_strategy_success()

    def _create_strategy_and_get_vim_kwargs(self, extra_args):
        """Run the state with the extra_args and return the VIM create kwargs"""

        # first api query is before the create
        # remaining api query results are waiting for the strategy to build
        self.vim_client.get_strategy.side_effect = [
            None,
            STRATEGY_BUILDING,
            STRATEGY_DONE_BUILDING,
        ]
        self.strategy = fake_strategy.update_fake_strategy(
            self.ctx, self.strategy_type, additional_args=extra_args
        )

        # API calls acts as expected
        self.vim_client.create_strategy.return_value = STRATEGY_BUILDING

        self._setup_and_assert(self.on_success_state)

        return self.vim_client.create_strategy.call_args.kwargs

    def test_create_strategy_passes_algorithm_and_key_size_to_vim(self):
        """Test create strategy passes the algorithm and key size to the VIM"""

        kwargs = self._create_strategy_and_get_vim_kwargs(
            {"algorithm": "ECDSA", "key-size": 521}
        )

        self.assertEqual(kwargs["algorithm"], "ECDSA")
        self.assertEqual(kwargs["key_size"], 521)

    def test_create_strategy_without_algorithm_and_key_size_in_extra_args(self):
        """Test create strategy without algorithm and key size in the extra_args

        Strategies created before these parameters existed do not have them in the
        extra_args, so they must be passed to the VIM as None.
        """

        kwargs = self._create_strategy_and_get_vim_kwargs({"subject": "CN=AL_RULES"})

        self.assertIsNone(kwargs["algorithm"])
        self.assertIsNone(kwargs["key_size"])
