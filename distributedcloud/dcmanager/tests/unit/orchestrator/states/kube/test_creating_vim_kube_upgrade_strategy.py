#
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock

from dccommon.drivers.openstack import vim
from dcmanager.common import consts

from dcmanager.tests.unit.common import fake_strategy
from dcmanager.tests.unit.fakes import FakeVimStrategy
from dcmanager.tests.unit.orchestrator.states.fakes import FakeKubeVersion
from dcmanager.tests.unit.orchestrator.states.fakes \
    import PREVIOUS_KUBE_VERSION
from dcmanager.tests.unit.orchestrator.states.fakes \
    import UPGRADED_KUBE_VERSION
from dcmanager.tests.unit.orchestrator.states.kube.test_base \
    import TestKubeUpgradeState
from dcmanager.tests.unit.orchestrator.states.test_creating_vim_strategy \
    import CreatingVIMStrategyStageMixin

STRATEGY_BUILDING = FakeVimStrategy(state=vim.STATE_BUILDING)
STRATEGY_DONE_BUILDING = FakeVimStrategy(state=vim.STATE_READY_TO_APPLY)

KUBE_VERSION_LIST = [
    FakeKubeVersion(obj_id=1,
                    version='v1.2.3',
                    target=True,
                    state='active'),
    FakeKubeVersion(obj_id=2,
                    version='v1.2.4',
                    target=False,
                    state='available'),
    FakeKubeVersion(obj_id=3,
                    version='v1.2.5',
                    target=False,
                    state='available'),
    ]

KUBE_VERSION_LIST_SC = [
    FakeKubeVersion(obj_id=1,
                    version='v1.2.5',
                    target=True,
                    state='active')
    ]

KUBE_VERSION_LIST_SC_2 = [
    FakeKubeVersion(obj_id=1,
                    version='v1.2.4',
                    target=True,
                    state='active')
    ]


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

    def test_creating_vim_strategy_success_highest_kube_version(self):
        """Test creating a VIM strategy when selecting the highest kube version"""

        # first api query is before the create
        # remaining api query results are waiting for the strategy to build
        self.vim_client.get_strategy.side_effect = [
            None,
            STRATEGY_BUILDING,
            STRATEGY_DONE_BUILDING,
        ]

        self.sysinv_client.get_kube_versions.return_value = KUBE_VERSION_LIST

        extra_args = {"to-version": 'v1.2.5'}
        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx,
            self.DEFAULT_STRATEGY_TYPE,
            extra_args=extra_args)

        # API calls acts as expected
        self.vim_client.create_strategy.return_value = STRATEGY_BUILDING

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        self.vim_client.create_strategy.assert_called_with('kube-upgrade',
                                                           'parallel',
                                                           'parallel',
                                                           10,
                                                           'migrate',
                                                           'relaxed',
                                                           to_version='v1.2.5')

        # Successful promotion to next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_creating_vim_strategy_success_lowest_kube_version(self):
        """Test creating a VIM strategy when selecting the lowest kube version"""

        # first api query is before the create
        # remaining api query results are waiting for the strategy to build
        self.vim_client.get_strategy.side_effect = [
            None,
            STRATEGY_BUILDING,
            STRATEGY_DONE_BUILDING,
        ]

        self.sysinv_client.get_kube_versions.return_value = KUBE_VERSION_LIST

        extra_args = {"to-version": 'v1.2.4'}
        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx,
            self.DEFAULT_STRATEGY_TYPE,
            extra_args=extra_args)

        # API calls acts as expected
        self.vim_client.create_strategy.return_value = STRATEGY_BUILDING

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        self.vim_client.create_strategy.assert_called_with('kube-upgrade',
                                                           'parallel',
                                                           'parallel',
                                                           10,
                                                           'migrate',
                                                           'relaxed',
                                                           to_version='v1.2.4')

        # Successful promotion to next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_creating_vim_strategy_success_no_kube_version_selected(self):
        """Test creating a VIM strategy when --to-version is not provided"""

        # first api query is before the create
        # remaining api query results are waiting for the strategy to build
        self.vim_client.get_strategy.side_effect = [
            None,
            STRATEGY_BUILDING,
            STRATEGY_DONE_BUILDING,
        ]

        self.sysinv_client.get_kube_versions.side_effect = [KUBE_VERSION_LIST_SC,
                                                            KUBE_VERSION_LIST]

        # API calls acts as expectedlowest
        self.vim_client.create_strategy.return_value = STRATEGY_BUILDING

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        self.vim_client.create_strategy.assert_called_with('kube-upgrade',
                                                           'parallel',
                                                           'parallel',
                                                           10,
                                                           'migrate',
                                                           'relaxed',
                                                           to_version='v1.2.5')

        # Successful promotion to next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_creating_vim_strategy_when_SC_has_middle_version_active(self):
        """Test creating a VIM strategy when --to-version is not provided"""

        # first api query is before the create
        # remaining api query results are waiting for the strategy to build
        self.vim_client.get_strategy.side_effect = [
            None,
            STRATEGY_BUILDING,
            STRATEGY_DONE_BUILDING,
        ]

        self.sysinv_client.get_kube_versions.side_effect = [KUBE_VERSION_LIST_SC_2,
                                                            KUBE_VERSION_LIST]

        # API calls acts as expectedlowest
        self.vim_client.create_strategy.return_value = STRATEGY_BUILDING

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        self.vim_client.create_strategy.assert_called_with('kube-upgrade',
                                                           'parallel',
                                                           'parallel',
                                                           10,
                                                           'migrate',
                                                           'relaxed',
                                                           to_version='v1.2.4')

        # Successful promotion to next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)
