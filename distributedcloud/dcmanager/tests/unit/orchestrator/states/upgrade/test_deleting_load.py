#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import itertools
import mock

from dcmanager.common import consts
from dcmanager.orchestrator.states.upgrade import deleting_load

from dcmanager.tests.unit.orchestrator.states.fakes import FakeLoad
from dcmanager.tests.unit.orchestrator.states.fakes import PREVIOUS_PREVIOUS_VERSION
from dcmanager.tests.unit.orchestrator.states.fakes import PREVIOUS_VERSION
from dcmanager.tests.unit.orchestrator.states.fakes import UPGRADED_VERSION
from dcmanager.tests.unit.orchestrator.states.upgrade.test_base  \
    import TestSwUpgradeState

PREVIOUS_LOAD = FakeLoad(1, software_version=PREVIOUS_VERSION,
                         state='imported')
UPGRADED_LOAD = FakeLoad(2, software_version=UPGRADED_VERSION,
                         state='active')

ONE_LOAD_RESPONSE = [UPGRADED_LOAD, ]
TWO_LOAD_RESPONSE = [PREVIOUS_LOAD, UPGRADED_LOAD, ]

SUCCESS_DELETE_RESPONSE = {
    'id': 0,
    'uuid': 'aaa4b4c6-8536-41f6-87ea-211d208a723b',
    'compatible_version': PREVIOUS_PREVIOUS_VERSION,
    'required_patches': '',
    'software_version': PREVIOUS_VERSION,
    'state': 'deleting',
    'created_at': '2020-06-01 12:12:12+00:00',
    'updated_at': None
}


@mock.patch("dcmanager.orchestrator.states.upgrade.deleting_load.DEFAULT_MAX_QUERIES",
            3)
@mock.patch("dcmanager.orchestrator.states.upgrade.deleting_load.DEFAULT_SLEEP_DURATION",
            1)
class TestSwUpgradeDeletingLoadStage(TestSwUpgradeState):

    def setUp(self):
        super(TestSwUpgradeDeletingLoadStage, self).setUp()

        # next state after 'importing load' is 'starting upgrade'
        self.on_success_state = consts.STRATEGY_STATE_COMPLETE

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = \
            self.setup_strategy_step(consts.STRATEGY_STATE_DELETING_LOAD)

        # Add mock API endpoints for sysinv client calls invoked by this state
        self.sysinv_client.get_loads = mock.MagicMock()
        self.sysinv_client.delete_load = mock.MagicMock()

    def test_upgrade_subcloud_deleting_N_load(self):
        """Test the deleting load step succeeds with deleting N load

        After the subcloud upgrade to N+1 release is complete, the N release
        load is removed.
        """

        # Mock get_loads API to return 2 loads in the first call and 1 load
        # in the subsequent call.
        self.sysinv_client.get_loads.side_effect = [
            TWO_LOAD_RESPONSE, ONE_LOAD_RESPONSE, ]

        # Simulate a delete_load API success on the subcloud.
        self.sysinv_client.delete_load.return_value = \
            SUCCESS_DELETE_RESPONSE

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the delete load API call was invoked
        self.sysinv_client.delete_load.assert_called()

        # On success, should have moved to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_upgrade_subcloud_deleting_load_timeout(self):
        """Test delete_load invoked and fails if times out

        The subcloud still has an N-1 load that needs to be removed before
        the N+1 load can be imported. The API call to delete this old load
        succeeds, however the state times out waiting for the load to be
        removed.
        """
        # Simulate the target load has not been imported yet on the subcloud
        self.sysinv_client.get_loads.return_value = TWO_LOAD_RESPONSE

        # Simulate a delete_load API success on the subcloud.
        self.sysinv_client.delete_load.return_value = \
            SUCCESS_DELETE_RESPONSE

        # mock the get_loads queries to return 2 loads
        self.sysinv_client.get_loads.side_effect = \
            itertools.repeat(TWO_LOAD_RESPONSE)

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the import load API call was invoked
        self.sysinv_client.delete_load.assert_called()

        # verify the get_loads query was invoked 1 + max_attempts times
        self.assertEqual(deleting_load.DEFAULT_MAX_QUERIES + 1,
                         self.sysinv_client.get_loads.call_count)

        # verify that state failed due to the delete load never finishing
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)
