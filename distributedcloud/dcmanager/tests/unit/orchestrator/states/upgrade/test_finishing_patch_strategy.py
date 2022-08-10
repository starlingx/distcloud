#
# Copyright (c) 2020, 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock

from dcmanager.common import consts
from dcmanager.tests.unit.orchestrator.states.upgrade.test_base \
    import TestSwUpgradeState

REGION_ONE_PATCHES = {'DC.2': {'sw_version': '17.07',
                               'repostate': 'Committed',
                               'patchstate': 'Committed'},
                      'DC.3': {'sw_version': '17.07',
                               'repostate': 'Committed',
                               'patchstate': 'Committed'},
                      'DC.4': {'sw_version': '17.07',
                               'repostate': 'Committed',
                               'patchstate': 'Committed'},
                      }

SUBCLOUD_PATCHES = {'DC.1': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    'DC.2': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    'DC.3': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    'DC.4': {'sw_version': '17.07',
                             'repostate': 'Committed',
                             'patchstate': 'Committed'},
                    'DC.5': {'sw_version': '17.07',
                             'repostate': 'Available',
                             'patchstate': 'Available'},
                    'DC.6': {'sw_version': '17.07',
                             'repostate': 'Available',
                             'patchstate': 'Available'},
                    }


def compare_call_with_unsorted_list(call, unsorted_list):
    call_args, _ = call
    return call_args[0].sort() == unsorted_list.sort()


@mock.patch("dcmanager.orchestrator.states.upgrade.finishing_patch_strategy"
            ".DEFAULT_MAX_QUERIES", 3)
@mock.patch("dcmanager.orchestrator.states.upgrade.finishing_patch_strategy"
            ".DEFAULT_SLEEP_DURATION", 1)
class TestSwUpgradeFinishingPatchStrategyStage(TestSwUpgradeState):

    def setUp(self):
        super(TestSwUpgradeFinishingPatchStrategyStage, self).setUp()

        # next state after 'finishing patch strategy' is 'starting upgrade'
        self.on_success_state = consts.STRATEGY_STATE_STARTING_UPGRADE

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = \
            self.setup_strategy_step(self.subcloud.id, consts.STRATEGY_STATE_FINISHING_PATCH_STRATEGY)

        # Add mock API endpoints for patching client calls invoked by this state
        self.patching_client.query = mock.MagicMock()
        self.patching_client.delete = mock.MagicMock()
        self.patching_client.commit = mock.MagicMock()

    def test_finishing_patch_strategy_success(self):
        """Test finishing_patch_strategy where the API call succeeds."""

        self.patching_client.query.side_effect = [
            REGION_ONE_PATCHES,
            SUBCLOUD_PATCHES,
        ]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        assert(compare_call_with_unsorted_list(
            self.patching_client.delete.call_args_list[0],
            ['DC.5', 'DC.6']
        ))
        assert(compare_call_with_unsorted_list(
            self.patching_client.commit.call_args_list[0],
            ['DC.2', 'DC.3']
        ))

        # On success, the state should transition to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)
