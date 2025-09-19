#
# Copyright (c) 2023-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.orchestrator.states import creating_vim_strategy
from dcmanager.orchestrator.validators import sw_deploy_validator
from dcmanager.tests.unit.common.consts import RELEASE_ID
from dcmanager.tests.unit.common import fake_strategy
from dcmanager.tests.unit import fakes
from dcmanager.tests.unit.orchestrator.states.software.test_base import (
    TestSoftwareOrchestrator,
)

STRATEGY_BUILDING = fakes.FakeVimStrategy(state=vim.STATE_BUILDING)
BUILD_PHASE_ERROR = fakes.FakeVimStrategyPhase(
    response="Installed license is valid: [FAIL]"
)
STRATEGY_BUILDING_FAILED = fakes.FakeVimStrategy(
    state=vim.STATE_BUILD_FAILED, build_phase=BUILD_PHASE_ERROR
)
STRATEGY_DONE_BUILDING = fakes.FakeVimStrategy(state=vim.STATE_READY_TO_APPLY)


@mock.patch.object(creating_vim_strategy, "DEFAULT_MAX_QUERIES", 3)
@mock.patch.object(creating_vim_strategy, "DEFAULT_SLEEP_DURATION", 1)
class TestCreateVIMSoftwareStrategyState(TestSoftwareOrchestrator):
    def setUp(self):
        super().setUp()

        self.on_success_state = consts.STRATEGY_STATE_SW_APPLY_VIM_STRATEGY
        self.current_state = consts.STRATEGY_STATE_SW_CREATE_VIM_STRATEGY

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            self.subcloud.id, self.current_state
        )

    def create_fake_software_strategy(self, payload=None):
        payload = payload or {}
        extra_args = (
            sw_deploy_validator.SoftwareDeployStrategyValidator().build_extra_args(
                payload
            )
        )
        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx, self.strategy_type, extra_args=extra_args
        )

    def base_create_vim_software_strategy_success(self, payload=None, **kwargs):
        """Creates a base vim software strategy testcase when the API call succeeds."""
        self.create_fake_software_strategy(payload)

        self.vim_client.get_strategy.side_effect = [
            None,
            STRATEGY_BUILDING,
            STRATEGY_DONE_BUILDING,
        ]

        # API calls acts as expected
        self.vim_client.create_strategy.return_value = STRATEGY_BUILDING

        self._setup_and_assert(self.on_success_state)

        # Assert correct extra args are passed to create_strategy
        self.vim_client.create_strategy.assert_called_with(
            "sw-upgrade",
            "parallel",
            "parallel",
            10,
            "migrate",
            "relaxed",
            **kwargs,
        )

    def test_create_vim_software_strategy_success_without_optional_extra_args(self):
        """Test create vim software strategy when the API call succeeds."""
        payload = {consts.EXTRA_ARGS_RELEASE_ID: RELEASE_ID}

        strategy_params = {
            "release": RELEASE_ID,
            "snapshot": False,
            "rollback": False,
            "delete": False,
        }
        self.base_create_vim_software_strategy_success(
            payload=payload,
            **strategy_params,
        )

    def test_create_vim_software_strategy_success_with_snapshot(self):
        """Test create vim software strategy with snapshot."""
        payload = {
            consts.EXTRA_ARGS_RELEASE_ID: RELEASE_ID,
            consts.EXTRA_ARGS_SNAPSHOT: True,
        }

        strategy_params = {
            "release": RELEASE_ID,
            "snapshot": True,
            "rollback": False,
            "delete": False,
        }

        self.base_create_vim_software_strategy_success(
            payload=payload,
            **strategy_params,
        )

    def test_create_vim_software_strategy_success_with_delete(self):
        """Test create vim software strategy with_delete."""
        payload = {
            consts.EXTRA_ARGS_RELEASE_ID: RELEASE_ID,
            consts.EXTRA_ARGS_WITH_DELETE: True,
        }

        strategy_params = {
            "release": RELEASE_ID,
            "snapshot": False,
            "rollback": False,
            "delete": True,
        }

        self.base_create_vim_software_strategy_success(
            payload=payload,
            **strategy_params,
        )

    def test_create_vim_software_strategy_success_with_delete_and_snapshot(self):
        """Test create vim software strategy with delete and snapshot."""
        payload = {
            consts.EXTRA_ARGS_RELEASE_ID: RELEASE_ID,
            consts.EXTRA_ARGS_SNAPSHOT: True,
            consts.EXTRA_ARGS_WITH_DELETE: True,
        }

        strategy_params = {
            "release": RELEASE_ID,
            "snapshot": True,
            "rollback": False,
            "delete": True,
        }

        self.base_create_vim_software_strategy_success(
            payload=payload,
            **strategy_params,
        )

    def test_create_vim_software_strategy_success_rollback(self):
        """Test create vim software strategy with rollback."""
        payload = {consts.EXTRA_ARGS_ROLLBACK: True}
        strategy_params = {
            "release": None,
            "snapshot": None,
            "rollback": True,
            "delete": None,
        }

        self.base_create_vim_software_strategy_success(
            payload=payload,
            **strategy_params,
        )

    @mock.patch.object(consts, "SNAPSHOT_SUPPORTED_VERSION", "25.09")
    def test_create_vim_software_strategy_success_with_snapshot_and_lower_release(self):
        """Test create vim software strategy with snapshot and lower release."""
        payload = {
            consts.EXTRA_ARGS_RELEASE_ID: RELEASE_ID,
            consts.EXTRA_ARGS_SNAPSHOT: True,
        }

        strategy_params = {
            "release": RELEASE_ID,
            "snapshot": True,
            "rollback": False,
            "delete": False,
        }

        self.base_create_vim_software_strategy_success(
            payload=payload,
            **strategy_params,
        )

    @mock.patch.object(consts, "SNAPSHOT_SUPPORTED_VERSION", "25.09")
    def test_create_vim_software_strategy_success_without_snapshot_and_lower_release(
        self,
    ):
        """Test create vim software strategy without snapshot and lower release."""
        payload = {
            consts.EXTRA_ARGS_RELEASE_ID: RELEASE_ID,
        }

        strategy_params = {
            "release": RELEASE_ID,
            "rollback": False,
            "delete": False,
        }

        self.base_create_vim_software_strategy_success(
            payload=payload,
            **strategy_params,
        )

    def test_create_vim_software_strategy_build_failed(self):
        """Test create vim software strategy build failed"""

        self.vim_client.get_strategy.side_effect = [
            None,
            STRATEGY_BUILDING_FAILED,
        ]

        # API calls acts as expected
        self.vim_client.create_strategy.return_value = STRATEGY_BUILDING

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.current_state}: Failed for subcloud subcloud1: VIM strategy build "
            "failed: Installed license is valid: [FAIL] State: build-failed Strategy: "
            "sw-upgrade"
        )
