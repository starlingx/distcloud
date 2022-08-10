#
# Copyright (c) 2020, 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import itertools
import mock

from dcmanager.common import consts
from dcmanager.orchestrator.states.upgrade import activating

from dcmanager.tests.unit.orchestrator.states.fakes import FakeUpgrade
from dcmanager.tests.unit.orchestrator.states.upgrade.test_base \
    import TestSwUpgradeState

VALID_UPGRADE = FakeUpgrade(state='imported')
ACTIVATING_UPGRADE = FakeUpgrade(state='activation-requested')
ACTIVATING_FAILED = FakeUpgrade(state='activation-failed')
ALREADY_ACTIVATED_UPGRADE = FakeUpgrade(state='activation-complete')


@mock.patch("dcmanager.orchestrator.states.upgrade.activating.DEFAULT_MAX_QUERIES",
            5)
@mock.patch("dcmanager.orchestrator.states.upgrade.activating.DEFAULT_SLEEP_DURATION",
            1)
@mock.patch("dcmanager.orchestrator.states.upgrade.activating.MAX_FAILED_RETRIES",
            3)
class TestSwUpgradeActivatingStage(TestSwUpgradeState):

    def setUp(self):
        super(TestSwUpgradeActivatingStage, self).setUp()

        # next state after activating an upgrade is 'completing'
        self.on_success_state = consts.STRATEGY_STATE_COMPLETING_UPGRADE

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = \
            self.setup_strategy_step(self.subcloud.id, consts.STRATEGY_STATE_ACTIVATING_UPGRADE)

        # Add mock API endpoints for sysinv client calls invoked by this state
        self.sysinv_client.upgrade_activate = mock.MagicMock()
        self.sysinv_client.get_upgrades = mock.MagicMock()

    def test_upgrade_subcloud_activating_upgrade_failure(self):
        """Test the activating upgrade API call fails."""

        # upgrade_activate will only be called if an appropriate upgrade exists
        self.sysinv_client.get_upgrades.return_value = [VALID_UPGRADE, ]

        # API call raises an exception when it is rejected
        self.sysinv_client.upgrade_activate.side_effect = \
            Exception("upgrade activate failed for some reason")

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the expected API call was invoked
        self.sysinv_client.upgrade_activate.assert_called()

        # Verify the state moves to 'failed'
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_upgrade_subcloud_activating_upgrade_success(self):
        """Test the activating upgrade step succeeds."""

        # upgrade_activate will only be called if an appropriate upgrade exists
        # first call is before the API call
        # loops once waiting for activating to complete
        # final query is the activation having completed
        self.sysinv_client.get_upgrades.side_effect = [
            [VALID_UPGRADE, ],
            [ACTIVATING_UPGRADE, ],
            [ALREADY_ACTIVATED_UPGRADE], ]

        # API call will not raise an exception, and will return an upgrade
        self.sysinv_client.upgrade_activate.return_value = ACTIVATING_UPGRADE

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the API call was invoked
        self.sysinv_client.upgrade_activate.assert_called()

        # On success, the state should be updated to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_upgrade_subcloud_activating_upgrade_skip_already_activated(self):
        """Test the activating upgrade step skipped if already activated."""

        # upgrade_activate will only be called if an appropriate upgrade exists
        self.sysinv_client.get_upgrades.return_value = \
            [ALREADY_ACTIVATED_UPGRADE, ]

        # API call will not be invoked, so no need to mock it

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # upgrade is already in one of the activating states so skip activating
        self.sysinv_client.upgrade_activate.assert_not_called()

        # On success, the state is set to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_upgrade_subcloud_activating_upgrade_times_out(self):
        """Test the activating upgrade step should succeed but times out."""

        # upgrade_activate will only be called if an appropriate upgrade exists
        # first call is before the API call
        # remaining loops are wating for the activation to complete
        self.sysinv_client.get_upgrades.side_effect = itertools.chain(
            [[VALID_UPGRADE, ], ],
            itertools.repeat([ACTIVATING_UPGRADE, ]))

        # API call will not raise an exception, and will return an upgrade
        self.sysinv_client.upgrade_activate.return_value = ACTIVATING_UPGRADE

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the API call was invoked
        self.sysinv_client.upgrade_activate.assert_called()

        # verify the get_upgrades query was invoked: 1 + max_attempts times
        self.assertEqual(activating.DEFAULT_MAX_QUERIES + 1,
                         self.sysinv_client.get_upgrades.call_count)

        # Times out. state goes to failed
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_upgrade_subcloud_activating_upgrade_retries(self):
        """Test the activating upgrade step fails but succeeds on retry."""

        # upgrade_activate will only be called if an appropriate upgrade exists
        # first call is before the API call
        # then goes to activating
        # then activating fails which triggers a retry
        # then goes to activating
        # then goes to success
        self.sysinv_client.get_upgrades.side_effect = [
            [VALID_UPGRADE, ],
            [ACTIVATING_UPGRADE, ],
            [ACTIVATING_FAILED, ],
            [ACTIVATING_UPGRADE, ],
            [ALREADY_ACTIVATED_UPGRADE, ]
        ]

        # API call will not raise an exception, and will return an upgrade
        self.sysinv_client.upgrade_activate.return_value = ACTIVATING_UPGRADE

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the API call was invoked twice
        self.assertEqual(2, self.sysinv_client.upgrade_activate.call_count)

        # Even though it failed once, the retry passed
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_upgrade_subcloud_activating_upgrade_exceed_max_retries(self):
        """Test the activating upgrade step should succeed but times out."""

        # upgrade_activate will only be called if an appropriate upgrade exists
        # first call is before the API call
        # remaining loops are retrying due to the activationg fails
        # the get_upgrades query is invoked less than max query limit
        self.sysinv_client.get_upgrades.side_effect = itertools.chain(
            [[VALID_UPGRADE, ], ],
            itertools.repeat([ACTIVATING_FAILED, ]))

        # API call will not raise an exception, and will return an upgrade
        self.sysinv_client.upgrade_activate.return_value = ACTIVATING_UPGRADE

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the API call was invoked: 1 + MAX_FAILED_RETRIES times
        self.assertEqual(activating.MAX_FAILED_RETRIES + 1,
                         self.sysinv_client.upgrade_activate.call_count)

        # verify get_upgrades query was invoked: 1 + MAX_FAILED_RETRIES times
        self.assertEqual(activating.MAX_FAILED_RETRIES + 1,
                         self.sysinv_client.get_upgrades.call_count)

        # Exceeds maximum retries. state goes to failed
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_upgrade_subcloud_activating_retries_until_times_out(self):
        """Test the activating upgrade fails due to reaches the max retries."""

        # upgrade_activate will only be called if an appropriate upgrade exists
        # first call is before the API call
        # then goes to three times of activating
        # remaining loops are activate failed
        # the API call is invoked less than the maxmium retries + 1
        # the states goes to failed due to times out rather than max retries
        self.sysinv_client.get_upgrades.side_effect = itertools.chain(
            [[VALID_UPGRADE, ],
             [ACTIVATING_UPGRADE, ],
             [ACTIVATING_UPGRADE, ],
             [ACTIVATING_UPGRADE, ], ],
            itertools.repeat([ACTIVATING_FAILED, ]))

        # API call will not raise an exception, and will return an upgrade
        self.sysinv_client.upgrade_activate.return_value = ACTIVATING_UPGRADE

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the API call was invoked was invoked:
        # max_attempts + 1 - 3 times, 3 times for the in progress status
        self.assertEqual(activating.DEFAULT_MAX_QUERIES - 2,
                         self.sysinv_client.upgrade_activate.call_count)

        # verify the get_upgrades query was invoked: 2 + max_attempts times
        self.assertEqual(activating.DEFAULT_MAX_QUERIES + 1,
                         self.sysinv_client.get_upgrades.call_count)

        # Times out. state goes to failed
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)
