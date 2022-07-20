#
# Copyright (c) 2020, 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import itertools
import mock

from dcmanager.common import consts
from dcmanager.orchestrator.states import lock_host

from dcmanager.tests.unit.orchestrator.states.fakes import FakeController
from dcmanager.tests.unit.orchestrator.states.upgrade.test_base \
    import TestSwUpgradeState


@mock.patch("dcmanager.orchestrator.states.lock_host.DEFAULT_MAX_QUERIES", 3)
@mock.patch("dcmanager.orchestrator.states.lock_host.DEFAULT_SLEEP_DURATION", 1)
class TestSwUpgradeLockSimplexStage(TestSwUpgradeState):

    state = consts.STRATEGY_STATE_LOCKING_CONTROLLER_0

    def setUp(self):
        super(TestSwUpgradeLockSimplexStage, self).setUp()

        # next state after a successful lock is upgrading simplex
        self.on_success_state = consts.STRATEGY_STATE_UPGRADING_SIMPLEX

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(self.subcloud.id, self.state)

        # Add mock API endpoints for sysinv client calls invoked by this state
        self.sysinv_client.get_host = mock.MagicMock()
        self.sysinv_client.lock_host = mock.MagicMock()
        self.setup_fake_controllers('controller-0')

    def setup_fake_controllers(self, host_name):
        self.CONTROLLER_UNLOCKED = FakeController(hostname=host_name,
                                                  administrative=consts.ADMIN_UNLOCKED)
        self.CONTROLLER_LOCKED = FakeController(hostname=host_name,
                                                administrative=consts.ADMIN_LOCKED)
        self.CONTROLLER_LOCKING = FakeController(hostname=host_name,
                                                 administrative=consts.ADMIN_UNLOCKED,
                                                 ihost_action='lock',
                                                 task='Locking')
        self.CONTROLLER_LOCKING_FAILED = \
            FakeController(hostname=host_name,
                           administrative=consts.ADMIN_UNLOCKED,
                           ihost_action='force-swact',
                           task='Swacting')

    def test_lock_success(self):
        """Test the lock command returns a success"""

        # mock the controller host queries
        # first query is the starting state
        # query 2,3 are are during the lock phase
        # query 4 : the host is now locked
        self.sysinv_client.get_host.side_effect = [self.CONTROLLER_UNLOCKED,
                                                   self.CONTROLLER_LOCKING,
                                                   self.CONTROLLER_LOCKING,
                                                   self.CONTROLLER_LOCKED]

        # mock the API call as failed on the subcloud
        self.sysinv_client.lock_host.return_value = self.CONTROLLER_LOCKING

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the lock command was actually attempted
        self.sysinv_client.lock_host.assert_called()

        # verify that the API moved to the next state on success
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_lock_skipped_when_already_locked(self):
        """Test the lock command skips if host is already locked"""

        # mock the controller host query as being already locked
        self.sysinv_client.get_host.return_value = self.CONTROLLER_LOCKED

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the lock command was never attempted
        self.sysinv_client.lock_host.assert_not_called()

        # verify that the state moves to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_lock_attempt_timeout(self):
        """Test lock invoked and fails if timeout before host becomes locked"""

        # mock the get_host queries
        # first query is the starting state
        # all remaining queries, the host returns 'locking'
        self.sysinv_client.get_host.side_effect = itertools.chain(
            [self.CONTROLLER_UNLOCKED, ],
            itertools.repeat(self.CONTROLLER_LOCKING))

        # mock the API call as successful on the subcloud
        self.sysinv_client.lock_host.return_value = self.CONTROLLER_LOCKING

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the lock command was actually attempted
        self.sysinv_client.lock_host.assert_called()

        # verify the query was invoked: 1 + max_attempts times
        self.assertEqual(lock_host.DEFAULT_MAX_QUERIES + 1,
                         self.sysinv_client.get_host.call_count)

        # verify that state failed due to subcloud never finishing the lock
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_lock_failure(self):
        """Test the lock command returns a failure"""

        # mock the controller get_host query
        self.sysinv_client.get_host.return_value = self.CONTROLLER_UNLOCKED

        # mock the API call as failed on the subcloud
        self.sysinv_client.lock_host.return_value = self.CONTROLLER_LOCKING_FAILED

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the lock command was actually attempted
        self.sysinv_client.lock_host.assert_called()

        # verify that the API error for the lock leads to a failed state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_lock_fails_when_host_query_fails(self):
        """Test the lock command fails when it cannot get the controllers"""

        # mock the get_host query is empty and raises an exception
        self.sysinv_client.get_host.side_effect = \
            Exception("Unable to find host controller-0")

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the lock command was never attempted
        self.sysinv_client.lock_host.assert_not_called()

        # verify that the state moves to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)


class TestSwUpgradeLockDuplexStage(TestSwUpgradeLockSimplexStage):

    def setUp(self):
        self.state = consts.STRATEGY_STATE_LOCKING_CONTROLLER_1
        super(TestSwUpgradeLockDuplexStage, self).setUp()

        # next state after a successful lock is upgrading simplex
        self.on_success_state = consts.STRATEGY_STATE_UPGRADING_DUPLEX

        # Add mock API endpoints for sysinv client calls invoked by this state
        self.setup_fake_controllers('controller-1')
