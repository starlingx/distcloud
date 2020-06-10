#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import itertools
import mock

from dcmanager.common import consts
from dcmanager.manager.states.unlock_host import DEFAULT_MAX_QUERIES

from dcmanager.tests.unit.manager.states.upgrade.test_base \
    import FakeController
from dcmanager.tests.unit.manager.states.upgrade.test_base \
    import TestSwUpgradeState

CONTROLLER_0_UNLOCKED = FakeController(administrative=consts.ADMIN_UNLOCKED)
CONTROLLER_0_LOCKED = FakeController(administrative=consts.ADMIN_LOCKED)
CONTROLLER_0_UNLOCKING = FakeController(administrative=consts.ADMIN_LOCKED,
                                        ihost_action='unlock',
                                        task='Unlocking')
CONTROLLER_0_UNLOCKING_FAILED = \
    FakeController(administrative=consts.ADMIN_LOCKED,
                   ihost_action='force-swact',
                   task='Swacting')


class TestSwUpgradeUnlockControllerStage(TestSwUpgradeState):

    def setUp(self):
        super(TestSwUpgradeUnlockControllerStage, self).setUp()

        # next state after a successful unlock is 'activating'
        self.on_success_state = consts.STRATEGY_STATE_ACTIVATING_UPGRADE

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            consts.STRATEGY_STATE_UNLOCKING_CONTROLLER)

        # Add mock API endpoints for sysinv client calls invcked by this state
        self.sysinv_client.get_host = mock.MagicMock()
        self.sysinv_client.unlock_host = mock.MagicMock()

    def test_unlock_success(self):
        """Test the unlock command returns a success"""

        # mock the get_host queries
        # first query is the starting state
        # query 2,3 are are during the unlock phase
        # query 4 : the host is now unlocked
        self.sysinv_client.get_host.side_effect = [CONTROLLER_0_LOCKED,
                                                   CONTROLLER_0_UNLOCKING,
                                                   CONTROLLER_0_UNLOCKING,
                                                   CONTROLLER_0_UNLOCKED, ]

        # mock the API call as failed on the subcloud
        self.sysinv_client.unlock_host.return_value = CONTROLLER_0_UNLOCKING

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
        self.sysinv_client.get_host.return_value = CONTROLLER_0_UNLOCKED

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
            [CONTROLLER_0_LOCKED, ],
            itertools.repeat(CONTROLLER_0_UNLOCKING))

        # mock the API call as successful on the subcloud
        self.sysinv_client.unlock_host.return_value = CONTROLLER_0_UNLOCKING

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the lock command was actually attempted
        self.sysinv_client.unlock_host.assert_called()

        # verify the query was invoked: 1 + max_attempts times
        self.assertEqual(DEFAULT_MAX_QUERIES + 1,
                         self.sysinv_client.get_host.call_count)

        # verify that state failed due to subcloud never finishing the unlock
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_unlock_failure(self):
        """Test the unlock command returns a failure"""

        # mock the get_host query
        self.sysinv_client.get_host.return_value = CONTROLLER_0_LOCKED

        # mock the API call as failed on the subcloud
        self.sysinv_client.unlock_host.return_value = \
            CONTROLLER_0_UNLOCKING_FAILED

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
