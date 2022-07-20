#
# Copyright (c) 2020, 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import itertools
import mock

from dcmanager.common import consts
from dcmanager.orchestrator.states import unlock_host

from dcmanager.tests.unit.orchestrator.states.fakes import FakeController
from dcmanager.tests.unit.orchestrator.states.upgrade.test_base \
    import TestSwUpgradeState


@mock.patch("dcmanager.orchestrator.states.unlock_host.DEFAULT_MAX_API_QUERIES", 3)
@mock.patch("dcmanager.orchestrator.states.unlock_host.DEFAULT_MAX_FAILED_QUERIES",
            3)
@mock.patch("dcmanager.orchestrator.states.unlock_host.DEFAULT_MAX_UNLOCK_RETRIES",
            3)
@mock.patch("dcmanager.orchestrator.states.unlock_host.DEFAULT_API_SLEEP", 1)
@mock.patch("dcmanager.orchestrator.states.unlock_host.DEFAULT_FAILED_SLEEP", 1)
@mock.patch("dcmanager.orchestrator.states.unlock_host.DEFAULT_UNLOCK_SLEEP", 1)
class TestSwUpgradeUnlockSimplexStage(TestSwUpgradeState):

    state = consts.STRATEGY_STATE_UNLOCKING_CONTROLLER_0

    def setUp(self):
        super(TestSwUpgradeUnlockSimplexStage, self).setUp()

        # Add mock API endpoints for sysinv client calls invoked by this state
        self.sysinv_client.get_host = mock.MagicMock()
        self.sysinv_client.unlock_host = mock.MagicMock()

        # next state after a successful unlock is 'activating'
        self.on_success_state = consts.STRATEGY_STATE_ACTIVATING_UPGRADE

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(self.subcloud.id, self.state)

        self.setup_fake_controllers('controller-0')

    def setup_fake_controllers(self, host_name):
        self.CONTROLLER_UNLOCKED = \
            FakeController(hostname=host_name,
                           administrative=consts.ADMIN_UNLOCKED,
                           operational=consts.OPERATIONAL_ENABLED,
                           availability=consts.AVAILABILITY_AVAILABLE)
        self.CONTROLLER_LOCKED = \
            FakeController(hostname=host_name,
                           administrative=consts.ADMIN_LOCKED)
        self.CONTROLLER_UNLOCKING = \
            FakeController(hostname=host_name,
                           administrative=consts.ADMIN_LOCKED,
                           ihost_action='unlock',
                           task='Unlocking')
        self.CONTROLLER_UNLOCKING_FAILED = \
            FakeController(hostname=host_name,
                           administrative=consts.ADMIN_LOCKED,
                           ihost_action='force-swact',
                           task='Swacting')

    def test_unlock_success(self):
        """Test the unlock command returns a success"""

        # mock the get_host queries
        # first query is the starting state
        # query 2,3 are are during the unlock phase
        # query 4 : the host is now unlocked
        self.sysinv_client.get_host.side_effect = [self.CONTROLLER_LOCKED,
                                                   self.CONTROLLER_UNLOCKING,
                                                   self.CONTROLLER_UNLOCKING,
                                                   self.CONTROLLER_UNLOCKED, ]

        # mock the API call as failed on the subcloud
        self.sysinv_client.unlock_host.return_value = self.CONTROLLER_UNLOCKING

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the unlock command was actually attempted
        self.sysinv_client.unlock_host.assert_called()

        # verify that the API moved to the next state on success
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_unlock_skipped_when_already_unlocked(self):
        """Test the unlock command skips if host is already unlocked"""

        # mock the controller host query as being already unlocked
        self.sysinv_client.get_host.return_value = self.CONTROLLER_UNLOCKED

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the unlock command was never attempted
        self.sysinv_client.unlock_host.assert_not_called()

        # verify that the state moves to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_unlock_attempt_timeout(self):
        """Test unlock invoked handles timeout if unlocking takes too long"""

        # mock the get_host queries
        # first query is the starting state
        # all remaining queries, the host returns 'unlocking'
        self.sysinv_client.get_host.side_effect = itertools.chain(
            [self.CONTROLLER_LOCKED, ],
            itertools.repeat(self.CONTROLLER_UNLOCKING))

        # mock the API call as successful on the subcloud
        self.sysinv_client.unlock_host.return_value = self.CONTROLLER_UNLOCKING

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the lock command was actually attempted
        self.sysinv_client.unlock_host.assert_called()

        # verify the query was invoked: 1 + max_attempts times
        self.assertEqual(unlock_host.DEFAULT_MAX_API_QUERIES + 1,
                         self.sysinv_client.get_host.call_count)

        # verify that state failed due to subcloud never finishing the unlock
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_unlock_failure_sriov(self):
        """Test the unlock command returns an exception because of sriov failure"""

        # mock the get_host query
        self.sysinv_client.get_host.return_value = self.CONTROLLER_LOCKED

        # mock the API call as an unlock sriov failure
        self.sysinv_client.unlock_host.side_effect = \
            Exception("Expecting number of interface sriov_numvfs=32. Please"
                      " wait a few minutes for inventory update and retry"
                      " host-unlock.")

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the unlock command was actually attempted
        self.sysinv_client.unlock_host.assert_called()

        # verified the unlock was tried max retries + 1
        self.assertEqual(unlock_host.DEFAULT_MAX_UNLOCK_RETRIES + 1,
                         self.sysinv_client.unlock_host.call_count)

        # verify that state failed due to subcloud never finishing the unlock
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_unlock_attempt_due_sriov_failure(self):
        """Test the unlock attempts after sriov failure"""

        # mock the get_host query
        self.sysinv_client.get_host.return_value = self.CONTROLLER_LOCKED

        # mock the API call as an unlock sriov failure 2 times then a success
        self.sysinv_client.unlock_host.side_effect = \
            [Exception("Expecting number of interface sriov_numvfs=32. Please"
                       " wait a few minutes for inventory update and retry"
                       " host-unlock."),
             Exception("Expecting number of interface sriov_numvfs=32. Please"
                       " wait a few minutes for inventory update and retry"
                       " host-unlock."),
             self.CONTROLLER_UNLOCKING]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the unlock command was actually attempted
        self.sysinv_client.unlock_host.assert_called()

        # verify the unlock was called 3 times: 1st call + 2 retries
        self.assertEqual(3, self.sysinv_client.unlock_host.call_count)

        # verify that state failed because host did not get unlocked
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

        # now move to unlock the controller
        self.sysinv_client.get_host.return_value = self.CONTROLLER_UNLOCKED

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify that the state moves to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_unlock_failure(self):
        """Test the unlock command returns a failure"""

        # mock the get_host query
        self.sysinv_client.get_host.return_value = self.CONTROLLER_LOCKED

        # mock the API call as failed on the subcloud
        self.sysinv_client.unlock_host.return_value = \
            self.CONTROLLER_UNLOCKING_FAILED

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the unlock command was actually attempted
        self.sysinv_client.unlock_host.assert_called()

        # verify that the API error for the unlock leads to a failed state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_unlock_fails_when_host_query_fails(self):
        """Test the unlock command fails when it cannot get the controllers"""

        # mock the get_host query fails and raises an exception
        self.sysinv_client.get_host.side_effect = \
            Exception("Unable to find host controller-0")

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the unlock command was never attempted
        self.sysinv_client.unlock_host.assert_not_called()

        # verify that the state moves to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)


class TestSwUpgradeUnlockDuplexStage(TestSwUpgradeUnlockSimplexStage):
    """This subclasses Controller 0 Unlock, and overides some setup values"""

    def setUp(self):
        self.state = consts.STRATEGY_STATE_UNLOCKING_CONTROLLER_1
        super(TestSwUpgradeUnlockDuplexStage, self).setUp()
        # override some of the fields that were setup in the super class

        # next state after a successful unlock is 'creating vim strategy'
        self.on_success_state = consts.STRATEGY_STATE_SWACTING_TO_CONTROLLER_1

        self.setup_fake_controllers('controller-1')
