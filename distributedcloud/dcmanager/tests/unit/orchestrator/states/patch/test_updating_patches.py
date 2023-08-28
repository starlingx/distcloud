#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from os import path as os_path

import mock

from dcmanager.common import consts
from dcmanager.orchestrator.orch_thread import OrchThread
from dcmanager.tests.unit.common import fake_strategy
from dcmanager.tests.unit.orchestrator.states.fakes import FakeLoad
from dcmanager.tests.unit.orchestrator.states.patch.test_base import \
    TestPatchState

REGION_ONE_PATCHES = {"DC.1": {"sw_version": "20.12",
                               "repostate": "Applied",
                               "patchstate": "Applied"},
                      "DC.2": {"sw_version": "20.12",
                               "repostate": "Applied",
                               "patchstate": "Applied"},
                      "DC.3": {"sw_version": "20.12",
                               "repostate": "Committed",
                               "patchstate": "Committed"},
                      "DC.4": {"sw_version": "20.12",
                               "repostate": "Available",
                               "patchstate": "Available"},
                      "DC.8": {"sw_version": "20.12",
                               "repostate": "Applied",
                               "patchstate": "Applied"}}

SUBCLOUD_PATCHES_SUCCESS = {"DC.1": {"sw_version": "20.12",
                                     "repostate": "Applied",
                                     "patchstate": "Applied"},
                            "DC.2": {"sw_version": "20.12",
                                     "repostate": "Available",
                                     "patchstate": "Available"},
                            "DC.3": {"sw_version": "20.12",
                                     "repostate": "Available",
                                     "patchstate": "Partial-Remove"},
                            "DC.5": {"sw_version": "20.12",
                                     "repostate": "Applied",
                                     "patchstate": "Applied"},
                            "DC.6": {"sw_version": "20.12",
                                     "repostate": "Applied",
                                     "patchstate": "Partial-Apply"}}

SUBCLOUD_PATCHES_BAD_COMMIT = {"DC.1": {"sw_version": "20.12",
                                        "repostate": "Applied",
                                        "patchstate": "Applied"},
                               "DC.2": {"sw_version": "20.12",
                                        "repostate": "Available",
                                        "patchstate": "Available"},
                               "DC.3": {"sw_version": "20.12",
                                        "repostate": "Available",
                                        "patchstate": "Partial-Remove"},
                               "DC.5": {"sw_version": "20.12",
                                        "repostate": "Committed",
                                        "patchstate": "Committed"},
                               "DC.6": {"sw_version": "20.12",
                                        "repostate": "Applied",
                                        "patchstate": "Partial-Apply"}}

SUBCLOUD_PATCHES_BAD_STATE = {"DC.1": {"sw_version": "20.12",
                                       "repostate": "Applied",
                                       "patchstate": "Applied"},
                              "DC.2": {"sw_version": "20.12",
                                       "repostate": "Available",
                                       "patchstate": "Available"},
                              "DC.3": {"sw_version": "20.12",
                                       "repostate": "Available",
                                       "patchstate": "Partial-Remove"},
                              "DC.5": {"sw_version": "20.12",
                                       "repostate": "Unknown",
                                       "patchstate": "Unknown"},
                              "DC.6": {"sw_version": "20.12",
                                       "repostate": "Applied",
                                       "patchstate": "Partial-Apply"}}


@mock.patch("dcmanager.orchestrator.states.patch.updating_patches."
            "DEFAULT_MAX_QUERIES", 3)
@mock.patch("dcmanager.orchestrator.states.patch.updating_patches"
            ".DEFAULT_SLEEP_DURATION", 1)
class TestUpdatingPatchesStage(TestPatchState):
    def setUp(self):
        super(TestUpdatingPatchesStage, self).setUp()

        self.success_state = consts.STRATEGY_STATE_CREATING_VIM_PATCH_STRATEGY

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            self.subcloud.id, consts.STRATEGY_STATE_UPDATING_PATCHES)

        # Add mock API endpoints for patching and sysinv client calls
        # invoked by this state
        self.patching_client.query = mock.MagicMock()
        self.sysinv_client.get_loads = mock.MagicMock()
        self.patching_client.remove = mock.MagicMock()
        self.patching_client.upload = mock.MagicMock()
        self.patching_client.apply = mock.MagicMock()
        self.patching_client.query_hosts = mock.MagicMock()

        # Mock OrchThread functions used by PatchJobData class
        p = mock.patch.object(OrchThread, "get_patching_client")
        self.mock_orch_patching_client = p.start()
        self.mock_orch_patching_client.return_value = self.patching_client
        self.addCleanup(p.stop)

        p = mock.patch.object(OrchThread, "get_sysinv_client")
        self.mock_orch_sysinv_client = p.start()
        self.mock_orch_sysinv_client.return_value = self.sysinv_client
        self.addCleanup(p.stop)

        self.fake_load = FakeLoad(1, software_version="20.12",
                                  state=consts.ACTIVE_LOAD_STATE)

    def _create_fake_strategy(self, upload_only=False):
        # setup extra_args used by PatchJobData
        extra_args = {consts.EXTRA_ARGS_UPLOAD_ONLY: upload_only}
        return fake_strategy.create_fake_strategy(self.ctx,
                                                  self.DEFAULT_STRATEGY_TYPE,
                                                  extra_args=extra_args)

    def test_set_job_data(self):
        """Test the 'set_job_data' method"""
        self.patching_client.query.side_effect = [REGION_ONE_PATCHES,
                                                  SUBCLOUD_PATCHES_SUCCESS]

        self.sysinv_client.get_loads.side_effect = [[self.fake_load]]

        self._create_fake_strategy()

        # invoke the pre apply setup to create the PatchJobData object
        self.worker.pre_apply_setup()

        # call determine_state_operator to invoke the set_job_data method
        state = self.worker.determine_state_operator(self.strategy_step)

        # Assert that the state has the proper region_one_patches and
        # region_one_applied_patch_ids attributes
        self.assertItemsEqual(REGION_ONE_PATCHES,
                              state.region_one_patches)
        self.assertItemsEqual(["DC.1", "DC.2", "DC.3", "DC.8"],
                              state.region_one_applied_patch_ids)

    @mock.patch.object(os_path, "isfile")
    def test_update_subcloud_patches_success(self, mock_os_path_isfile):
        """Test update_patches where the API call succeeds."""

        self.patching_client.query.side_effect = [REGION_ONE_PATCHES,
                                                  SUBCLOUD_PATCHES_SUCCESS]

        self.sysinv_client.get_loads.side_effect = [[self.fake_load]]

        mock_os_path_isfile.return_value = True

        self._create_fake_strategy()

        # invoke the pre apply setup to create the PatchJobData object
        self.worker.pre_apply_setup()

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        self.patching_client.upload.assert_called_with([consts.PATCH_VAULT_DIR +
                                                        "/20.12/DC.8.patch"])

        call_args, _ = self.patching_client.remove.call_args_list[0]
        self.assertItemsEqual(["DC.5", "DC.6"], call_args[0])

        call_args, _ = self.patching_client.apply.call_args_list[0]
        self.assertItemsEqual(["DC.2", "DC.3", "DC.8"], call_args[0])

        # On success, the state should transition to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.success_state)

        self.assert_step_details(self.strategy_step.subcloud_id, "")

    @mock.patch.object(os_path, "isfile")
    def test_update_subcloud_patches_bad_committed(self, mock_os_path_isfile):
        """Test update_patches where the API call fails.

        The update_patches call fails because the patch is 'committed' in
        the subcloud but not 'applied' in the System Controller.
        """

        self.patching_client.query.side_effect = [REGION_ONE_PATCHES,
                                                  SUBCLOUD_PATCHES_BAD_COMMIT]

        self.sysinv_client.get_loads.side_effect = [[self.fake_load]]

        mock_os_path_isfile.return_value = True

        self._create_fake_strategy()

        # invoke the pre apply setup to create the PatchJobData object
        self.worker.pre_apply_setup()

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        #  Verify it failed and moves to the next step
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

        self.assert_step_details(self.strategy_step.subcloud_id,
                                 "updating patches: Patch DC.5 is committed in "
                                 "subcloud but not applied in SystemController")

    @mock.patch.object(os_path, "isfile")
    def test_update_subcloud_patches_bad_state(self, mock_os_path_isfile):
        """Test update_patches where the API call fails.

        The update_patches call fails because the patch is 'unknown' in
        the subcloud which is not a valid state.
        """

        self.patching_client.query.side_effect = [REGION_ONE_PATCHES,
                                                  SUBCLOUD_PATCHES_BAD_STATE]

        self.sysinv_client.get_loads.side_effect = [[self.fake_load]]

        mock_os_path_isfile.return_value = True

        self._create_fake_strategy()

        # invoke the pre apply setup to create the PatchJobData object
        self.worker.pre_apply_setup()

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        #  Verify it failed and moves to the next step
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

        self.assert_step_details(self.strategy_step.subcloud_id,
                                 "updating patches: Patch DC.5 in subcloud is"
                                 " in an unexpected state: Unknown")

    @mock.patch.object(os_path, "isfile")
    def test_update_subcloud_patches_upload_only(self, mock_os_path_isfile):
        """Test update_patches with the upload-only option.

        It should only upload the patches, without applying or removing them,
        returning 'complete' as the next step.
        """

        self.patching_client.query.side_effect = [REGION_ONE_PATCHES,
                                                  SUBCLOUD_PATCHES_SUCCESS]

        self.sysinv_client.get_loads.side_effect = [[self.fake_load]]

        mock_os_path_isfile.return_value = True

        self._create_fake_strategy(upload_only=True)

        # invoke the pre apply setup to create the PatchJobData object
        self.worker.pre_apply_setup()

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        self.patching_client.upload.assert_called_with([consts.PATCH_VAULT_DIR +
                                                        "/20.12/DC.8.patch"])

        self.patching_client.remove.assert_not_called()
        self.patching_client.apply.assert_not_called()

        self.assert_step_details(self.strategy_step.subcloud_id, "")

        # On success, the state should transition to the complete state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_COMPLETE)
