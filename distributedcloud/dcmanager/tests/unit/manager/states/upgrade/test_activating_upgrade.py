#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import itertools
import mock

from dcmanager.common import consts

from dcmanager.tests.unit.manager.states.upgrade.test_base import FakeUpgrade
from dcmanager.tests.unit.manager.states.upgrade.test_base \
    import TestSwUpgradeState

VALID_UPGRADE = FakeUpgrade(state='imported')
ACTIVATING_UPGRADE = FakeUpgrade(state='activation-requested')
ALREADY_ACTIVATED_UPGRADE = FakeUpgrade(state='activation-complete')


@mock.patch("dcmanager.manager.states.upgrade.activating.DEFAULT_MAX_QUERIES",
            3)
@mock.patch("dcmanager.manager.states.upgrade.activating.DEFAULT_SLEEP_DURATION",
            1)
class TestSwUpgradeActivatingStage(TestSwUpgradeState):

    def setUp(self):
        super(TestSwUpgradeActivatingStage, self).setUp()

        # next state after activating an upgrade is 'completing'
        self.on_success_state = consts.STRATEGY_STATE_COMPLETING_UPGRADE

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = \
            self.setup_strategy_step(consts.STRATEGY_STATE_ACTIVATING_UPGRADE)

        # Add mock API endpoints for sysinv client calls invcked by this state
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

        # verify the API cvall was invoked
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

        # verify the API cvall was invoked
        self.sysinv_client.upgrade_activate.assert_called()

        # Times out. state goes to failed
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)
