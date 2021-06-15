#
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock
from os import path as os_path

from dcmanager.common import consts
from dcmanager.tests.unit.orchestrator.states.fakes import FakeKubeVersion
from dcmanager.tests.unit.orchestrator.states.fakes import FakeLoad
from dcmanager.tests.unit.orchestrator.states.kube.test_base \
    import TestKubeUpgradeState


FAKE_LOAD_VERSION = '12.34'
DIFFERENT_LOAD_VERSION = '12.35'


class TestKubeUpdatingPatchesStage(TestKubeUpgradeState):
    "Test uploading and applying the patces required for kube orch."""

    def setUp(self):
        super(TestKubeUpdatingPatchesStage, self).setUp()

        # next state after updating patches is creating a vim patch strategy
        self.on_success_state = \
            consts.STRATEGY_STATE_KUBE_CREATING_VIM_PATCH_STRATEGY

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            consts.STRATEGY_STATE_KUBE_UPDATING_PATCHES)

        # Add mock API endpoints for clients invoked by this state
        self.patching_client.query = mock.MagicMock()
        self.patching_client.query_hosts = mock.MagicMock()
        self.patching_client.upload = mock.MagicMock()
        self.patching_client.apply = mock.MagicMock()
        self.sysinv_client.get_loads = mock.MagicMock()
        self.sysinv_client.get_kube_version = mock.MagicMock()
        self.sysinv_client.get_kube_versions = mock.MagicMock()

        # Mock default results for APIs
        self.sysinv_client.get_loads.side_effect = [
            [FakeLoad(1,
                      software_version=FAKE_LOAD_VERSION,
                      state=consts.ACTIVE_LOAD_STATE)]
        ]

        self.sysinv_client.get_kube_version.return_value = FakeKubeVersion()
        self.sysinv_client.get_kube_versions.return_value = [
            FakeKubeVersion(),
        ]

    def test_success_no_patches(self):
        """Test behaviour when there are no region one patches.

        The state machine should simply skip to the next state.
        """

        REGION_ONE_PATCHES = {}
        SUBCLOUD_PATCHES = {}

        # patching client queries region one patches and then subcloud patches
        self.patching_client.query.side_effect = [
            REGION_ONE_PATCHES,
            SUBCLOUD_PATCHES,
        ]
        # hosts are queried to determine which patches are applied
        self.patching_client.query_hosts.return_value = [
        ]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # On success, the state should transition to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_success_no_patches_matching_load(self):
        """Test behaviour when no region one patches that match load.

        The state machine should simply skip to the next state.
        """

        REGION_ONE_PATCHES = {
            'DC.1': {'sw_version': DIFFERENT_LOAD_VERSION,
                     'repostate': 'Applied',
                     'patchstate': 'Applied'},
        }
        SUBCLOUD_PATCHES = {}

        # patching client queries region one patches and then subcloud patches
        self.patching_client.query.side_effect = [
            REGION_ONE_PATCHES,
            SUBCLOUD_PATCHES,
        ]
        # hosts are queried to determine which patches are applied
        self.patching_client.query_hosts.return_value = [
        ]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # On success, the state should transition to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    @mock.patch.object(os_path, 'isfile')
    def test_success_subcloud_needs_patch(self, mock_os_path_isfile):
        """Test behaviour when there is a region one patch not on subcloud.

        The state machine should upload and apply the patch and proceed
        to the next state.
        : param mock_os_path_isfile: Mocking the file existence check for
        the vault directory.
        """

        # Mock that the patch is checked into the vault on disk
        mock_os_path_isfile.return_value = True

        REGION_ONE_PATCHES = {
            'DC.1': {'sw_version': FAKE_LOAD_VERSION,
                     'repostate': 'Applied',
                     'patchstate': 'Applied'},
        }
        SUBCLOUD_PATCHES = {}

        # patching client queries region one patches and then subcloud patches
        self.patching_client.query.side_effect = [
            REGION_ONE_PATCHES,
            SUBCLOUD_PATCHES,
        ]

        # hosts are queried to determine which patches are applied
        self.patching_client.query_hosts.return_value = [
        ]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # On success, the state should transition to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    @mock.patch.object(os_path, 'isfile')
    def test_fail_subcloud_needs_patch_not_in_vault(self, mock_os_path_isfile):
        """Test behaviour when there is a region one patch not on subcloud.

        The state machine should upload and apply the patch and proceed
        to the next state.
        : param mock_os_path_isfile: Mocking the file existence check for
        the vault directory.
        """

        # Mock that the patch file is missing from the vault
        mock_os_path_isfile.return_value = False

        REGION_ONE_PATCHES = {
            'DC.1': {'sw_version': FAKE_LOAD_VERSION,
                     'repostate': 'Applied',
                     'patchstate': 'Applied'},
        }
        SUBCLOUD_PATCHES = {}

        # patching client queries region one patches and then subcloud patches
        self.patching_client.query.side_effect = [
            REGION_ONE_PATCHES,
            SUBCLOUD_PATCHES,
        ]

        # hosts are queried to determine which patches are applied
        self.patching_client.query_hosts.return_value = [
        ]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # A required patch was not in the vault. Fail this state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)
