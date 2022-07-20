#
# Copyright (c) 2020, 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock
from os import path as os_path

from dcmanager.common import consts

from dcmanager.tests.unit.orchestrator.states.fakes import FakeLoad
from dcmanager.tests.unit.orchestrator.states.upgrade.test_base \
    import TestSwUpgradeState

REGION_ONE_PATCHES = {'DC.1': {'sw_version': '20.12',
                               'repostate': 'Applied',
                               'patchstate': 'Applied'},
                      'DC.2': {'sw_version': '20.12',
                               'repostate': 'Applied',
                               'patchstate': 'Applied'},
                      'DC.3': {'sw_version': '20.12',
                               'repostate': 'Committed',
                               'patchstate': 'Committed'},
                      'DC.4': {'sw_version': '20.12',
                               'repostate': 'Available',
                               'patchstate': 'Available'},
                      'DC.8': {'sw_version': '20.12',
                               'repostate': 'Applied',
                               'patchstate': 'Applied'},
                      }

SUBCLOUD_PATCHES_SUCCESS = {'DC.1': {'sw_version': '20.12',
                                     'repostate': 'Applied',
                                     'patchstate': 'Applied'},
                            'DC.2': {'sw_version': '20.12',
                                     'repostate': 'Available',
                                     'patchstate': 'Available'},
                            'DC.3': {'sw_version': '20.12',
                                     'repostate': 'Available',
                                     'patchstate': 'Partial-Remove'},
                            'DC.5': {'sw_version': '20.12',
                                     'repostate': 'Applied',
                                     'patchstate': 'Applied'},
                            'DC.6': {'sw_version': '20.12',
                                     'repostate': 'Applied',
                                     'patchstate': 'Partial-Apply'},
                            }

SUBCLOUD_PATCHES_BAD_COMMIT = {'DC.1': {'sw_version': '20.12',
                                        'repostate': 'Applied',
                                        'patchstate': 'Applied'},
                               'DC.2': {'sw_version': '20.12',
                                        'repostate': 'Available',
                                        'patchstate': 'Available'},
                               'DC.3': {'sw_version': '20.12',
                                        'repostate': 'Available',
                                        'patchstate': 'Partial-Remove'},
                               'DC.5': {'sw_version': '20.12',
                                        'repostate': 'Committed',
                                        'patchstate': 'Committed'},
                               'DC.6': {'sw_version': '20.12',
                                        'repostate': 'Applied',
                                        'patchstate': 'Partial-Apply'},
                               }

SUBCLOUD_PATCHES_BAD_STATE = {'DC.1': {'sw_version': '20.12',
                                       'repostate': 'Applied',
                                       'patchstate': 'Applied'},
                              'DC.2': {'sw_version': '20.12',
                                       'repostate': 'Available',
                                       'patchstate': 'Available'},
                              'DC.3': {'sw_version': '20.12',
                                       'repostate': 'Available',
                                       'patchstate': 'Partial-Remove'},
                              'DC.5': {'sw_version': '20.12',
                                       'repostate': 'Unknown',
                                       'patchstate': 'Unknown'},
                              'DC.6': {'sw_version': '20.12',
                                       'repostate': 'Applied',
                                       'patchstate': 'Partial-Apply'},
                              }


def compare_call_with_unsorted_list(call, unsorted_list):
    call_args, _ = call
    return call_args[0].sort() == unsorted_list.sort()


@mock.patch("dcmanager.orchestrator.states.upgrade.updating_patches"
            ".DEFAULT_MAX_QUERIES", 3)
@mock.patch("dcmanager.orchestrator.states.upgrade.updating_patches"
            ".DEFAULT_SLEEP_DURATION", 1)
class TestSwUpgradeUpdatingPatchesStage(TestSwUpgradeState):

    def setUp(self):
        super(TestSwUpgradeUpdatingPatchesStage, self).setUp()

        # next state after 'updating patches' is 'finishing patch strategy'
        self.on_success_state = consts.STRATEGY_STATE_FINISHING_PATCH_STRATEGY

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = \
            self.setup_strategy_step(self.subcloud.id, consts.STRATEGY_STATE_UPDATING_PATCHES)

        # Add mock API endpoints for patching and sysinv client calls invoked by this state
        self.patching_client.query = mock.MagicMock()
        self.sysinv_client.get_loads = mock.MagicMock()
        self.patching_client.remove = mock.MagicMock()
        self.patching_client.upload = mock.MagicMock()
        self.patching_client.apply = mock.MagicMock()
        self.patching_client.query_hosts = mock.MagicMock()

    @mock.patch.object(os_path, 'isfile')
    def test_update_subcloud_patches_success(self, mock_os_path_isfile):
        """Test update_patches where the API call succeeds."""

        self.patching_client.query.side_effect = [
            REGION_ONE_PATCHES,
            SUBCLOUD_PATCHES_SUCCESS,
        ]

        self.sysinv_client.get_loads.side_effect = [
            [FakeLoad(1,
                      software_version='20.12',
                      state=consts.ACTIVE_LOAD_STATE)]
        ]

        mock_os_path_isfile.return_value = True

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        self.patching_client.upload.assert_called_with(
            [consts.PATCH_VAULT_DIR + '/20.12/DC.8.patch'])

        assert(compare_call_with_unsorted_list(
            self.patching_client.remove.call_args_list[0],
            ['DC.5', 'DC.6']
        ))
        assert(compare_call_with_unsorted_list(
            self.patching_client.apply.call_args_list[0],
            ['DC.2', 'DC.3', 'DC.8']
        ))

        # On success, the state should transition to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    @mock.patch.object(os_path, 'isfile')
    def test_update_subcloud_patches_bad_committed(self, mock_os_path_isfile):
        """Test update_patches where the API call fails.

        The update_patches call fails because the patch is 'committed' in
        the subcloud but not 'applied' in the System Controller.
        """

        self.patching_client.query.side_effect = [
            REGION_ONE_PATCHES,
            SUBCLOUD_PATCHES_BAD_COMMIT,
        ]

        self.sysinv_client.get_loads.side_effect = [
            [FakeLoad(1,
                      software_version='20.12',
                      state=consts.ACTIVE_LOAD_STATE)]
        ]

        mock_os_path_isfile.return_value = True

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        #  Verify it failed and moves to the next step
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    @mock.patch.object(os_path, 'isfile')
    def test_update_subcloud_patches_bad_state(self, mock_os_path_isfile):
        """Test update_patches where the API call succeeds.

        The update_patches call fails because the patch is 'unknown' in
        the subcloud which is not a valid state.
        """

        self.patching_client.query.side_effect = [
            REGION_ONE_PATCHES,
            SUBCLOUD_PATCHES_BAD_STATE,
        ]

        self.sysinv_client.get_loads.side_effect = [
            [FakeLoad(1,
                      software_version='20.12',
                      state=consts.ACTIVE_LOAD_STATE)]
        ]

        mock_os_path_isfile.return_value = True

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        #  Verify it failed and moves to the next step
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)
