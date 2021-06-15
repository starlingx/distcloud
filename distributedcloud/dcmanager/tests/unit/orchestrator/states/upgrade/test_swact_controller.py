#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import itertools
import mock

from dcmanager.common import consts
from dcmanager.orchestrator.states import swact_host

from dcmanager.tests.unit.orchestrator.states.fakes import FakeController
from dcmanager.tests.unit.orchestrator.states.upgrade.test_base \
    import TestSwUpgradeState


@mock.patch("dcmanager.orchestrator.states.swact_host.DEFAULT_MAX_QUERIES", 3)
@mock.patch("dcmanager.orchestrator.states.swact_host.DEFAULT_SLEEP_DURATION", 1)
class TestSwUpgradeSwactToController0Stage(TestSwUpgradeState):

    state = consts.STRATEGY_STATE_SWACTING_TO_CONTROLLER_0

    def setUp(self):
        super(TestSwUpgradeSwactToController0Stage, self).setUp()

        # next state after a successful swact is deleting load
        self.on_success_state = consts.STRATEGY_STATE_ACTIVATING_UPGRADE

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = \
            self.setup_strategy_step(self.state)

        # Add mock API endpoints for sysinv client calls invoked by this state
        self.sysinv_client.get_host = mock.MagicMock()
        self.sysinv_client.swact_host = mock.MagicMock()

        # In order to swact to controller-0, we run "system host-swact controller-1"
        self.setup_fake_controllers('controller-1')

    def setup_fake_controllers(self, host_name):
        self.CONTROLLER_ACTIVE = FakeController(hostname=host_name)
        self.CONTROLLER_STANDBY = FakeController(hostname=host_name,
                                                 capabilities={"Personality": "Controller-Standby"})
        self.CONTROLLER_SWACTING = FakeController(hostname=host_name,
                                                  task='Swacting')

    def test_swact_success(self):
        """Test the swact command returns a success"""

        # mock the controller host queries
        # first query is the starting state
        # query 2 is during the ongoing swact phase
        # query 3 is after successful host swact
        self.sysinv_client.get_host.side_effect = [self.CONTROLLER_STANDBY,
                                                   self.CONTROLLER_STANDBY,
                                                   self.CONTROLLER_ACTIVE]

        # mock the API call as failed on the subcloud
        self.sysinv_client.swact_host.return_value = self.CONTROLLER_SWACTING

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the swact command was actually attempted
        self.sysinv_client.swact_host.assert_called()

        # verify that the API moved to the next state on success
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_swact_skipped_when_already_active(self):
        """Test the swact command skips if host is already active controller"""

        # mock the controller host query as being already Controller-Active
        self.sysinv_client.get_host.return_value = self.CONTROLLER_ACTIVE

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the swact command was never attempted
        self.sysinv_client.swact_host.assert_not_called()

        # verify that the state moves to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_swact_attempt_timeout(self):
        """Test swact invoked and fails if timeout before host becomes active controller"""

        # mock the get_host queries
        # all remaining queries, the host returns 'Controller-Standby'
        self.sysinv_client.get_host.side_effect = itertools.chain(
            itertools.repeat(self.CONTROLLER_STANDBY))

        # mock the API call as successful on the subcloud
        self.sysinv_client.swact_host.return_value = self.CONTROLLER_SWACTING

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the swact command was actually attempted
        self.sysinv_client.swact_host.assert_called()

        # verify the query was invoked: 1 + max_attempts times
        self.assertEqual(swact_host.DEFAULT_MAX_QUERIES + 2,
                         self.sysinv_client.get_host.call_count)

        # verify that state failed due to subcloud never finishing the swact
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_swact_fails_when_host_query_fails(self):
        """Test the swact command fails when it cannot get the controllers"""

        # mock the get_host query is empty and raises an exception
        self.sysinv_client.get_host.side_effect = \
            Exception("Unable to find host controller-0")

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the swact command was never attempted
        self.sysinv_client.swact_host.assert_not_called()

        # verify that the state moves to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)


class TestSwUpgradeSwactToController1Stage(TestSwUpgradeSwactToController0Stage):

    def setUp(self):
        self.state = consts.STRATEGY_STATE_SWACTING_TO_CONTROLLER_1
        super(TestSwUpgradeSwactToController1Stage, self).setUp()

        # next state after a successful swact to comntroller-1 is creating VIM
        # upgrade strategy
        self.on_success_state = consts.STRATEGY_STATE_CREATING_VIM_UPGRADE_STRATEGY

        # In order to swact to controller-0, we run "system host-swact controller-0"
        self.setup_fake_controllers('controller-0')
