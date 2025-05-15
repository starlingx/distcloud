#
# Copyright (c) 2023-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from os import path as os_path

import mock

from dcmanager.common import consts
from dcmanager.orchestrator.states.base import BaseState
from dcmanager.tests.unit.common import fake_strategy
from dcmanager.tests.unit.orchestrator.states.patch.test_base import TestPatchState

SUBCLOUD_NO_USM_PATCHES = {
    "stx-9.1": {
        "sw_version": "sxt-9.0",
        "repostate": "Available",
        "patchstate": "Partial-Remove",
    },
    "stx-9.2": {
        "sw_version": "sxt-9.0",
        "repostate": "Applied",
        "patchstate": "Partial-Apply",
    },
}

SUBCLOUD_USM_PATCHES = {
    "stx-9.1": {
        "sw_version": "stx-9.0",
        "repostate": "Available",
        "patchstate": "Available",
    },
    "stx-usm-9.2": {
        "sw_version": "stx-9.0",
        "repostate": "Available",
        "patchstate": "Partial-Remove",
    },
}

DC_VAULT_PATCH_DIR = "/opt/dc-vault/patches/22.12/"


@mock.patch(
    "dcmanager.orchestrator.states.patch.updating_patches.DEFAULT_MAX_QUERIES", 3
)
@mock.patch(
    "dcmanager.orchestrator.states.patch.updating_patches.DEFAULT_SLEEP_DURATION", 1
)
class TestUpdatingPatchesStage(TestPatchState):
    def setUp(self):
        super(TestUpdatingPatchesStage, self).setUp()

        self.success_state = consts.STRATEGY_STATE_CREATING_VIM_PATCH_STRATEGY

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            self.subcloud.id, consts.STRATEGY_STATE_UPDATING_PATCHES
        )

        # Add mock API endpoints for patching and sysinv client calls
        # invoked by this state
        self.patching_client.query = mock.MagicMock()
        self.patching_client.upload = mock.MagicMock()
        self.patching_client.apply = mock.MagicMock()
        self.patching_client.query_hosts = mock.MagicMock()

    def _create_fake_strategy(self, upload_only=False, patch_id=None):
        extra_args = {
            consts.EXTRA_ARGS_UPLOAD_ONLY: upload_only,
            consts.EXTRA_ARGS_PATCH_ID: patch_id,
        }
        return fake_strategy.create_fake_strategy(
            self.ctx, self.DEFAULT_STRATEGY_TYPE, extra_args=extra_args
        )

    @mock.patch.object(os_path, "isfile")
    def test_update_subcloud_patches_patch_id_success(self, mock_os_path_isfile):
        """Test update_patches where the API call succeeds with patch_id parameter."""

        mock_os_path_isfile.return_value = True

        self.patching_client.query.side_effect = [SUBCLOUD_NO_USM_PATCHES]

        self._create_fake_strategy(patch_id="stx-usm-9.2")

        # invoke the strategy state operation on the orch thread
        self.worker._perform_state_action(
            self.DEFAULT_STRATEGY_TYPE, self.subcloud.region_name, self.strategy_step
        )

        self.patching_client.upload.assert_called_with(
            [DC_VAULT_PATCH_DIR + "stx-usm-9.2.patch"]
        )

        call_args, _ = self.patching_client.apply.call_args_list[0]
        self.assertItemsEqual(["stx-usm-9.2"], call_args[0])

        # On success, the state should transition to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id, self.success_state)

        self.assert_step_details(self.strategy_step.subcloud_id, "")

    def test_update_subcloud_patches_patch_id_no_upload(self):
        """Test update_patches where the API using patch_id parameter isn't uploaded."""

        self.patching_client.query.side_effect = [SUBCLOUD_USM_PATCHES]

        self._create_fake_strategy(patch_id="stx-usm-9.2")

        # invoke the strategy state operation on the orch thread
        self.worker._perform_state_action(
            self.DEFAULT_STRATEGY_TYPE, self.subcloud.region_name, self.strategy_step
        )

        self.patching_client.upload.assert_not_called()

        call_args, _ = self.patching_client.apply.call_args_list[0]
        self.assertItemsEqual(["stx-usm-9.2"], call_args[0])

        # On success, the state should transition to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id, self.success_state)

        self.assert_step_details(self.strategy_step.subcloud_id, "")

    @mock.patch.object(os_path, "isfile")
    def test_update_subcloud_patches_patch_id_upload_only_success(
        self, mock_os_path_isfile
    ):
        """Test update_patches where the API call succeeds with patch_id/upload only."""

        mock_os_path_isfile.return_value = True

        self.patching_client.query.side_effect = [SUBCLOUD_NO_USM_PATCHES]

        self._create_fake_strategy(upload_only=True, patch_id="stx-usm-9.2")

        # invoke the strategy state operation on the orch thread
        self.worker._perform_state_action(
            self.DEFAULT_STRATEGY_TYPE, self.subcloud.region_name, self.strategy_step
        )

        self.patching_client.upload.assert_called_with(
            [DC_VAULT_PATCH_DIR + "stx-usm-9.2.patch"]
        )
        self.patching_client.apply.assert_not_called()

        self.assert_step_details(self.strategy_step.subcloud_id, "")

        # On success, the state should transition to the complete state
        self.assert_step_updated(
            self.strategy_step.subcloud_id, consts.STRATEGY_STATE_COMPLETE
        )

    @mock.patch.object(BaseState, "stopped")
    @mock.patch.object(os_path, "isfile")
    def test_updating_subcloud_patches_fails_when_stopped(
        self, mock_os_path_isfile, mock_base_stopped
    ):
        """Test update_patches state fails when stopped"""
        mock_os_path_isfile.return_value = True

        self.patching_client.query.side_effect = [SUBCLOUD_NO_USM_PATCHES]

        self._create_fake_strategy(upload_only=True, patch_id="stx-usm-9.2")

        mock_base_stopped.return_value = True

        self.worker._perform_state_action(
            self.DEFAULT_STRATEGY_TYPE, self.subcloud.region_name, self.strategy_step
        )

        self.assert_step_updated(
            self.strategy_step.subcloud_id, consts.STRATEGY_STATE_FAILED
        )
