#
# Copyright (c) 2020, 2022, 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import itertools
import mock

from dcmanager.common import consts
from dcmanager.orchestrator.states.upgrade import starting_upgrade

from dcmanager.tests.unit.orchestrator.states.fakes import FakeSystem
from dcmanager.tests.unit.orchestrator.states.fakes import FakeUpgrade
from dcmanager.tests.unit.orchestrator.states.upgrade.test_base import \
    TestSwUpgradeState

UPGRADE_ABORTING = FakeUpgrade(state='aborting')
UPGRADE_STARTING = FakeUpgrade(state='starting')
UPGRADE_STARTED = FakeUpgrade(state='started')


@mock.patch("dcmanager.orchestrator.states.upgrade.starting_upgrade"
            ".DEFAULT_MAX_QUERIES", 3)
@mock.patch("dcmanager.orchestrator.states.upgrade.starting_upgrade"
            ".DEFAULT_SLEEP_DURATION", 1)
@mock.patch("dcmanager.orchestrator.states.upgrade.starting_upgrade"
            ".MAX_FAILED_RETRIES", 2)
class TestSwUpgradeSimplexStartingUpgradeStage(TestSwUpgradeState):

    def setUp(self):
        super(TestSwUpgradeSimplexStartingUpgradeStage, self).setUp()

        # next state after 'starting upgrade' is 'migrating data'
        self.on_success_state = consts.STRATEGY_STATE_TRANSFERRING_CA_CERTIFICATE

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            self.subcloud.id, consts.STRATEGY_STATE_STARTING_UPGRADE)

        # Add mock API endpoints for sysinv client calls invoked by this state
        self.sysinv_client.upgrade_start = mock.MagicMock()
        self.sysinv_client.get_upgrades = mock.MagicMock()
        self.sysinv_client.get_system = mock.MagicMock()
        system_values = FakeSystem()
        system_values.system_mode = consts.SYSTEM_MODE_SIMPLEX
        self.sysinv_client.get_system.return_value = system_values

    def test_upgrade_subcloud_upgrade_start_failure(self):
        """Test the upgrade_start where the API call fails.

        The upgrade_start call fails due to a validation check such as from
        the health-query check.
        """

        # No upgrades should yet exist in the DB / API
        self.sysinv_client.get_upgrades.return_value = []

        # Simulate an upgrade_start failure on the subcloud.
        # The API throws an exception rather than returning an error response
        self.sysinv_client.upgrade_start.side_effect = \
            Exception("HTTPBadRequest: upgrade-start rejected: "
                      "System is not in a valid state for upgrades. "
                      "Run system health-query-upgrade for more details.")

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the API call that failed was invoked
        self.sysinv_client.upgrade_start.assert_called()

        # Verify the API failure leads to a state failure
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_upgrade_subcloud_upgrade_start_success(self):
        """Test upgrade_start where the API call succeeds.

        This will result in an upgrade being created with the appropriate
        state.
        """

        # No upgrades should yet exist in the initial DB / API
        # the subsequent call should indicate it is started
        self.sysinv_client.get_upgrades.side_effect = [
            [],
            [UPGRADE_STARTING, ],
            [UPGRADE_STARTED, ],
        ]

        # Simulate an upgrade_start succeeds on the subcloud
        self.sysinv_client.upgrade_start.return_value = UPGRADE_STARTING

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the API call that succeeded was actually invoked
        self.sysinv_client.upgrade_start.assert_called()

        # verify default alarm-restriction-type (relaxed) is treated as 'force'
        self.sysinv_client.upgrade_start.assert_called_with(force=True)

        # On success, the state should transition to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_upgrade_subcloud_upgrade_start_skip_already_started(self):
        """Test upgrade_start where the upgrade is already started."""

        # An already started upgrade exists in the DB"""
        self.sysinv_client.get_upgrades.return_value = [UPGRADE_STARTED, ]

        # upgrade_start should not be invoked, so can be mocked as 'failed'
        # by raising an exception
        self.sysinv_client.upgrade_start.side_effect = \
            Exception("HTTPBadRequest: this is a fake exception")

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # upgrade_start API call should not have been attempted due to the
        # existing upgrade already in started state.
        self.sysinv_client.upgrade_start.assert_not_called()

        # On success, the state should transition to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_upgrade_subcloud_upgrade_start_fails_bad_existing_upgrade(self):
        """Test the upgrade_start fails due to a bad existing upgrade."""

        # An already started upgrade exists in the DB but is in bad shape."""
        self.sysinv_client.get_upgrades.return_value = [UPGRADE_ABORTING, ]

        # upgrade_start will NOT be invoked. No need to mock it.

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # upgrade_start API call should not have been attempted due to the
        # invalid existing upgrade that needs to be cleaned up.
        self.sysinv_client.upgrade_start.assert_not_called()

        # Verify it failed and moves to the next step
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_upgrade_subcloud_upgrade_start_retry(self):
        """Test upgrade_start where HTTP error occurs after successful API call."""

        # Simulate an HTTP exception thrown after upgrade start
        self.sysinv_client.get_upgrades.side_effect = itertools.chain(
            [[], ],
            itertools.repeat(Exception("HTTPBadRequest: this is a fake exception")))

        self.sysinv_client.upgrade_start.return_value = UPGRADE_STARTING

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the API call that succeeded was actually invoked
        self.sysinv_client.upgrade_start.assert_called()

        # verify default alarm-restriction-type (relaxed) is treated as 'force'
        self.sysinv_client.upgrade_start.assert_called_with(force=True)

        # verify the get_upgrades query was invoked: 1 + max_failed_retries times
        self.assertEqual(starting_upgrade.MAX_FAILED_RETRIES + 1,
                         self.sysinv_client.get_upgrades.call_count)

        # Verify the timeout leads to a state failure
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_upgrade_subcloud_upgrade_start_timeout(self):
        """Test upgrade_start where the API call succeeds but times out."""

        # No upgrades should yet exist in the initial DB / API
        # the subsequent calls indicate 'starting' instead of 'started'
        # which eventually leads to the timeout
        self.sysinv_client.get_upgrades.side_effect = itertools.chain(
            [[], ],
            itertools.repeat([UPGRADE_STARTING, ]))

        # Simulate an upgrade_start succeeds on the subcloud
        self.sysinv_client.upgrade_start.return_value = UPGRADE_STARTING

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the API call that succeeded was actually invoked
        self.sysinv_client.upgrade_start.assert_called()

        # verify default alarm-restriction-type (relaxed) is treated as 'force'
        self.sysinv_client.upgrade_start.assert_called_with(force=True)

        # verify the get_upgrades query was invoked: 1 + max_attempts times
        self.assertEqual(starting_upgrade.DEFAULT_MAX_QUERIES + 1,
                         self.sysinv_client.get_upgrades.call_count)

        # Verify the timeout leads to a state failure
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)


@mock.patch("dcmanager.orchestrator.states.upgrade.starting_upgrade"
            ".DEFAULT_MAX_QUERIES", 3)
@mock.patch("dcmanager.orchestrator.states.upgrade.starting_upgrade"
            ".DEFAULT_SLEEP_DURATION", 1)
class TestSwUpgradeDuplexStartingUpgradeStage(
        TestSwUpgradeSimplexStartingUpgradeStage):

    def setUp(self):
        super(TestSwUpgradeDuplexStartingUpgradeStage, self).setUp()

        # next state after 'starting upgrade' is 'migrating data'
        self.on_success_state = consts.STRATEGY_STATE_TRANSFERRING_CA_CERTIFICATE

        # Add mock API endpoints for sysinv client calls invoked by this state
        system_values = FakeSystem()
        system_values.system_mode = consts.SYSTEM_MODE_DUPLEX
        self.sysinv_client.get_system.return_value = system_values
