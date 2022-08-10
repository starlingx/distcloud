#
# Copyright (c) 2020, 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import itertools
import mock

from dcmanager.common import consts
from dcmanager.orchestrator.states.upgrade import upgrading_duplex

from dcmanager.tests.unit.orchestrator.states.fakes import FakeUpgrade
from dcmanager.tests.unit.orchestrator.states.upgrade.test_base \
    import TestSwUpgradeState

UPGRADE_ABORTING = FakeUpgrade(state='aborting')
UPGRADE_STARTED = FakeUpgrade(state='started')
UPGRADE_COMPLETE = FakeUpgrade(state='data-migration-complete')
UPGRADE_FAILED = FakeUpgrade(state='data-migration-failed')


@mock.patch("dcmanager.orchestrator.states.upgrade.upgrading_duplex"
            ".DEFAULT_MAX_QUERIES", 3)
@mock.patch("dcmanager.orchestrator.states.upgrade.upgrading_duplex"
            ".DEFAULT_SLEEP_DURATION", 1)
class TestSwUpgradeUpgradingDuplexStage(TestSwUpgradeState):

    def setUp(self):
        super(TestSwUpgradeUpgradingDuplexStage, self).setUp()

        # next state after 'upgrading duplex' is 'unlocking controller 1'
        self.on_success_state = consts.STRATEGY_STATE_UNLOCKING_CONTROLLER_1

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = \
            self.setup_strategy_step(self.subcloud.id, consts.STRATEGY_STATE_UPGRADING_DUPLEX)

        # Add mock API endpoints for sysinv client calls invoked by this state
        self.sysinv_client.get_host = mock.MagicMock()
        self.sysinv_client.upgrade_host = mock.MagicMock()
        self.sysinv_client.get_upgrades = mock.MagicMock()

    def test_subcloud_duplex_upgrade_success(self):
        """Test upgrading_duplex where the API call succeeds."""

        # A successfully completed upgrade exists in the DB"""
        self.sysinv_client.get_upgrades.return_value = [UPGRADE_COMPLETE, ]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the get_upgrades query was invoked: 1 + max_attempts times
        self.assertEqual(self.sysinv_client.get_upgrades.call_count, 2)

        # On success, the state should transition to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_subcloud_duplex_upgrade_fails(self):
        """Test the upgrading_duplex fails as data migration fails."""

        self.sysinv_client.get_upgrades.return_value = [UPGRADE_FAILED, ]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the get_upgrades query was invoked: 1 + max_attempts times
        self.assertEqual(self.sysinv_client.get_upgrades.call_count, 2)

        # Verify it failed and moves to the next step
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_subcloud_duplex_upgrade_timeout(self):
        """Test upgrading_duplex where the API call succeeds but times out."""
        # Upgrades state is stuck at 'started' state which eventually
        # leads to the timeout
        self.sysinv_client.get_upgrades.side_effect = itertools.chain(
            itertools.repeat([UPGRADE_STARTED, ]))

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the API call that succeeded was actually invoked
        self.sysinv_client.upgrade_host.assert_called()

        # verify the get_upgrades query was invoked: 1 + max_attempts times
        self.assertEqual(upgrading_duplex.DEFAULT_MAX_QUERIES,
                         self.sysinv_client.get_upgrades.call_count)

        # Verify the timeout leads to a state failure
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)
