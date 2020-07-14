#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock

from dcmanager.common import consts
from dcmanager.manager.states.upgrade import completing

from dcmanager.tests.unit.manager.states.upgrade.test_base import FakeSystem
from dcmanager.tests.unit.manager.states.upgrade.test_base import FakeUpgrade
from dcmanager.tests.unit.manager.states.upgrade.test_base \
    import TestSwUpgradeState

VALID_UPGRADE = FakeUpgrade(state='activation-complete')
INVALID_UPGRADE = FakeUpgrade(state='aborting')
UPGRADE_COMPLETING = FakeUpgrade(state='completing')


@mock.patch("dcmanager.manager.states.upgrade.completing.DEFAULT_MAX_QUERIES",
            3)
@mock.patch("dcmanager.manager.states.upgrade.completing.DEFAULT_SLEEP_DURATION",
            1)
class TestSwUpgradeCompletingStage(TestSwUpgradeState):

    def setUp(self):
        super(TestSwUpgradeCompletingStage, self).setUp()

        # next state after completing an upgrade is 'complete'
        self.on_success_state = consts.STRATEGY_STATE_COMPLETE

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = \
            self.setup_strategy_step(consts.STRATEGY_STATE_COMPLETING_UPGRADE)

        # Add mock API endpoints for sysinv client calls invoked by this state
        self.sysinv_client.upgrade_complete = mock.MagicMock()
        self.sysinv_client.get_upgrades = mock.MagicMock()
        self.sysinv_client.get_system = mock.MagicMock()
        self.sysinv_client.get_system.return_value = FakeSystem()
        self.sysinv_client.get_system = mock.MagicMock()

    def test_upgrade_subcloud_completing_upgrade_failure(self):
        """Test the completing upgrade API call fails."""

        # upgrade_complete will only be called if an appropriate upgrade exists
        self.sysinv_client.get_upgrades.return_value = [VALID_UPGRADE, ]

        # API call raises an exception when it is rejected
        self.sysinv_client.upgrade_complete.side_effect = \
            Exception("upgrade complete failed for some reason")

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the expected API call was invoked
        self.sysinv_client.upgrade_complete.assert_called()

        # Verify the state moves to 'failed'
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_upgrade_subcloud_completing_upgrade_success(self):
        """Test the completing upgrade step succeeds."""

        # upgrade_complete will only be called if an appropriate upgrade exists
        # it will be re-queried until no upgrade exists
        self.sysinv_client.get_upgrades.side_effect = [
            [VALID_UPGRADE, ],
            []
        ]

        # API call will not raise an exception. It will delete the upgrade
        self.sysinv_client.upgrade_complete.return_value = UPGRADE_COMPLETING

        # Mock the db API call
        p = mock.patch('dcmanager.db.api.subcloud_update')
        self.mock_db_update = p.start()
        self.addCleanup(p.stop)

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the API call was invoked
        self.sysinv_client.upgrade_complete.assert_called()

        # verify the DB update was invoked
        self.mock_db_update.assert_called()

        # On success, the state should be updated to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_upgrade_subcloud_completing_upgrade_skip_already_completed(self):
        """Test the completing upgrade step skipped if already completed."""

        # upgrade_complete will only be called if an appropriate upgrade exists
        # If the upgrade has been deleted, there is nothing to complete
        self.sysinv_client.get_upgrades.return_value = []

        # API call will not be invoked, so no need to mock it

        # Mock the db API call
        p = mock.patch('dcmanager.db.api.subcloud_update')
        self.mock_db_update = p.start()
        self.addCleanup(p.stop)

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # upgrade is already in one of the completing states so skip completing
        self.sysinv_client.upgrade_complete.assert_not_called()

        # verify the DB update was invoked
        self.mock_db_update.assert_called()

        # On success, the state is set to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_upgrade_subcloud_completing_upgrade_timeout(self):
        """Test the completing upgrade step succeeds but times out."""

        # upgrade_complete will only be called if an appropriate upgrade exists
        self.sysinv_client.get_upgrades.return_value = [VALID_UPGRADE, ]

        # API call will not raise an exception. It will delete the upgrade
        self.sysinv_client.upgrade_complete.return_value = UPGRADE_COMPLETING

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the API call was invoked
        self.sysinv_client.upgrade_complete.assert_called()

        # verify the get_upgrades query was invoked: 1 + max_attempts times
        self.assertEqual(completing.DEFAULT_MAX_QUERIES + 1,
                         self.sysinv_client.get_upgrades.call_count)

        # Verify the state moves to 'failed' due to the timeout
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)
