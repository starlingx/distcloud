#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dcmanager.common import consts
from dcmanager.orchestrator.orch_thread import OrchThread
from dcmanager.tests.unit.orchestrator.states.fakes import FakeLoad
from dcmanager.tests.unit.orchestrator.states.patch.test_base import \
    TestPatchState
import mock

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
                               "repostate": "Committed",
                               "patchstate": "Committed"}}

SUBCLOUD_PATCHES = {"DC.1": {"sw_version": "20.12",
                             "repostate": "Applied",
                             "patchstate": "Applied"},
                    "DC.2": {"sw_version": "20.12",
                             "repostate": "Applied",
                             "patchstate": "Applied"},
                    "DC.3": {"sw_version": "20.12",
                             "repostate": "Applied",
                             "patchstate": "Applied"},
                    "DC.5": {"sw_version": "20.12",
                             "repostate": "Available",
                             "patchstate": "Available"},
                    "DC.8": {"sw_version": "20.12",
                             "repostate": "Committed",
                             "patchstate": "Committed"}}


class TestPatchFinishingStage(TestPatchState):
    def setUp(self):
        super(TestPatchFinishingStage, self).setUp()

        self.success_state = consts.STRATEGY_STATE_COMPLETE

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            self.subcloud.id, consts.STRATEGY_STATE_FINISHING_PATCH_STRATEGY)

        # Add mock API endpoints for patching and sysinv client calls
        # invoked by this state
        self.patching_client.query = mock.MagicMock()
        self.patching_client.delete = mock.MagicMock()
        self.patching_client.commit = mock.MagicMock()
        self.sysinv_client.get_loads = mock.MagicMock()

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

    def test_set_job_data(self):
        """Test the 'set_job_data' method"""
        self.patching_client.query.side_effect = [REGION_ONE_PATCHES,
                                                  SUBCLOUD_PATCHES]

        self.sysinv_client.get_loads.side_effect = [[self.fake_load]]

        # invoke the pre apply setup to create the PatchJobData object
        self.worker.pre_apply_setup()

        # call determine_state_operator to invoke the set_job_data method
        state = self.worker.determine_state_operator(self.strategy_step)

        # Assert that the state has the proper region_one_commited_patch_ids
        # attribute
        self.assertItemsEqual(["DC.3", "DC.8"],
                              state.region_one_commited_patch_ids)

    def test_finish(self):
        """Test whether the 'finishing' state completes successfully"""
        self.patching_client.query.side_effect = [REGION_ONE_PATCHES,
                                                  SUBCLOUD_PATCHES]

        self.sysinv_client.get_loads.side_effect = [[self.fake_load]]

        # invoke the pre apply setup to create the PatchJobData object
        self.worker.pre_apply_setup()

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        self.patching_client.delete.assert_called_with(["DC.5"])
        self.patching_client.commit.assert_called_with(["DC.3"])

        # On success, the state should transition to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.success_state)
