#
# Copyright (c) 2020-2021, 2024-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.orchestrator.states.base import BaseState
from dcmanager.tests.unit.common import fake_strategy
from dcmanager.tests.unit.fakes import FakeVimStrategy
from dcmanager.tests.unit.orchestrator.states.fakes import FakeKubeUpgrade
from dcmanager.tests.unit.orchestrator.states.fakes import FakeKubeVersion
from dcmanager.tests.unit.orchestrator.states.fakes import PREVIOUS_KUBE_VERSION
from dcmanager.tests.unit.orchestrator.states.fakes import UPGRADED_KUBE_VERSION
from dcmanager.tests.unit.orchestrator.states.kube.test_base import TestKubeUpgradeState
from dcmanager.tests.unit.orchestrator.states.test_creating_vim_strategy import (
    CreatingVIMStrategyStageMixin,
)

STRATEGY_BUILDING = FakeVimStrategy(state=vim.STATE_BUILDING)
STRATEGY_DONE_BUILDING = FakeVimStrategy(state=vim.STATE_READY_TO_APPLY)

KUBE_VERSION_LIST = [
    FakeKubeVersion(obj_id=1, version="v1.2.3", target=True, state="active"),
    FakeKubeVersion(obj_id=2, version="v1.2.4", target=False, state="available"),
    FakeKubeVersion(obj_id=3, version="v1.2.5", target=False, state="available"),
]

KUBE_VERSION_LIST_SC = [
    FakeKubeVersion(obj_id=1, version="v1.2.5", target=True, state="active")
]

KUBE_VERSION_LIST_SC_2 = [
    FakeKubeVersion(obj_id=1, version="v1.2.4", target=True, state="active")
]

KUBE_UPGRADE_LIST = [
    FakeKubeUpgrade(
        obj_id=1, to_version="v1.2.5", from_version="v1.2.4", state="active"
    )
]

KUBE_VERSION_LIST_WITHOUT_ACTIVE = [
    FakeKubeVersion(obj_id=1, version="v1.2.3", target=True, state="available")
]


@mock.patch(
    "dcmanager.orchestrator.states.creating_vim_strategy.DEFAULT_MAX_QUERIES", 3
)
@mock.patch(
    "dcmanager.orchestrator.states.creating_vim_strategy.DEFAULT_SLEEP_DURATION", 1
)
class TestCreatingVIMKubeUpgradeStrategyStage(
    CreatingVIMStrategyStageMixin, TestKubeUpgradeState
):
    """Test a vim kube upgrade strategy during kube orchestration"""

    def setUp(self):
        super().setUp()

        self.set_state(
            consts.STRATEGY_STATE_KUBE_CREATING_VIM_KUBE_UPGRADE_STRATEGY,
            consts.STRATEGY_STATE_KUBE_APPLYING_VIM_KUBE_UPGRADE_STRATEGY,
        )

        # creating the vim strategy checks if an existing upgrade exists
        self.sysinv_client.get_kube_upgrades = mock.MagicMock()
        self.sysinv_client.get_kube_upgrades.return_value = []

        # when no vim strategy exists, the available version is used
        self.sysinv_client.get_kube_versions = mock.MagicMock()
        self.sysinv_client.get_kube_versions.return_value = [
            FakeKubeVersion(
                obj_id=1, version=PREVIOUS_KUBE_VERSION, target=True, state="active"
            ),
            FakeKubeVersion(
                obj_id=2, version=UPGRADED_KUBE_VERSION, target=False, state="available"
            ),
        ]

        self.mock_read_from_cache = self._mock_object(BaseState, "_read_from_cache")
        self.mock_read_from_cache.return_value = [
            FakeKubeVersion(
                obj_id=1, version=PREVIOUS_KUBE_VERSION, target=True, state="active"
            ),
            FakeKubeVersion(
                obj_id=2, version=UPGRADED_KUBE_VERSION, target=False, state="available"
            ),
        ]
        self.vim_client.get_strategy = mock.MagicMock()
        self.vim_client.create_strategy = mock.MagicMock()

    def mock_and_assert_step_update(
        self, is_upgrade=False, kube_version=None, kube_version_list=None
    ):
        """Encapsulates the required arrangements to run the tests"""

        # first api query is before the create
        # remaining api query results are waiting for the strategy to build
        self.vim_client.get_strategy.side_effect = [
            None,
            STRATEGY_BUILDING,
            STRATEGY_DONE_BUILDING,
        ]
        self.sysinv_client.get_kube_versions.return_value = KUBE_VERSION_LIST
        self.mock_read_from_cache.return_value = KUBE_VERSION_LIST

        if is_upgrade:
            self.sysinv_client.get_kube_upgrades.return_value = kube_version_list
            kube_version = kube_version_list[0].to_version

        if kube_version:
            extra_args = {"to-version": kube_version}
            self.strategy = fake_strategy.create_fake_strategy(
                self.ctx, self.DEFAULT_STRATEGY_TYPE, extra_args=extra_args
            )
        else:
            kube_version = kube_version_list[0].version
            # Subcloud query
            self.sysinv_client.get_kube_versions.return_value = KUBE_VERSION_LIST
            # System controller query
            self.mock_read_from_cache.return_value = kube_version_list

        # API calls acts as expected
        self.vim_client.create_strategy.return_value = STRATEGY_BUILDING

        # invoke the strategy state operation on the orch thread
        self.worker._perform_state_action(
            self.DEFAULT_STRATEGY_TYPE, self.subcloud.region_name, self.strategy_step
        )

        self.vim_client.create_strategy.assert_called_with(
            "kube-upgrade",
            "parallel",
            "parallel",
            10,
            "migrate",
            "relaxed",
            to_version=kube_version,
        )

        # Successful promotion to next state
        self.assert_step_updated(self.strategy_step.subcloud_id, self.on_success_state)

    def test_strategy_succeeds_with_highest_kube_version(self):
        """Test strategy succeeds when selecting the highest kube version"""

        self.mock_and_assert_step_update(kube_version="v1.2.5")

    def test_strategy_succeeds_with_lowest_kube_version(self):
        """Test strategy succeeds when selecting the lowest kube version"""

        self.mock_and_assert_step_update(kube_version="v1.2.4")

    def test_strategy_succeeds_without_kube_version_selected(self):
        """Test strategy succeeds without a selected kube_version"""

        self.mock_and_assert_step_update(kube_version_list=KUBE_VERSION_LIST_SC)

    def test_strategy_succeeds_when_sc_has_middle_version_active(self):
        """Test strategy succeeds when sc has the middle version active"""

        self.mock_and_assert_step_update(kube_version_list=KUBE_VERSION_LIST_SC_2)

    def test_strategy_succeeds_with_subcloud_kube_upgrade(self):
        """Test strategy succeeds when there are subcloud kube upgrades"""

        self.mock_and_assert_step_update(
            is_upgrade=True, kube_version_list=KUBE_UPGRADE_LIST
        )

    def test_strategy_fails_without_active_version_to_upgrade(self):
        """Test upgrade fails without an active version to upgrade"""

        fake_strategy.create_fake_strategy(self.ctx, self.DEFAULT_STRATEGY_TYPE)

        self.sysinv_client.get_kube_versions.return_value = (
            KUBE_VERSION_LIST_WITHOUT_ACTIVE
        )
        self.mock_read_from_cache.return_value = KUBE_VERSION_LIST_WITHOUT_ACTIVE

        self.worker._perform_state_action(
            self.DEFAULT_STRATEGY_TYPE, self.subcloud.region_name, self.strategy_step
        )

        self.assert_step_updated(
            self.strategy_step.subcloud_id, consts.STRATEGY_STATE_FAILED
        )
