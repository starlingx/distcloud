#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock

from dcmanager.common import consts

from dcmanager.tests.unit.manager.states.upgrade.test_base import FakeSubcloud
from dcmanager.tests.unit.manager.states.upgrade.test_base \
    import TestSwUpgradeState


class TestSwUpgradePreCheckStage(TestSwUpgradeState):

    def setUp(self):
        super(TestSwUpgradePreCheckStage, self).setUp()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = \
            self.setup_strategy_step(consts.STRATEGY_STATE_PRE_CHECK)

        # Mock the db API call. Each test will override the return value
        p = mock.patch('dcmanager.db.api.subcloud_get')
        self.mock_db_query = p.start()
        self.addCleanup(p.stop)

    def test_upgrade_pre_check_subcloud_online(self):
        """Test pre check step where the subcloud is online.

        The pre-check should transition in this scenario to the first state
        of a normal upgrade orchestation which is 'installing license'.
        """

        # subcloud is online
        self.mock_db_query.return_value = \
            FakeSubcloud(availability_status=consts.AVAILABILITY_ONLINE)

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the DB query was invoked
        self.mock_db_query.assert_called()

        # Verify the expected next state happened (installing license)
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_INSTALLING_LICENSE)

    def test_upgrade_pre_check_subcloud_jumps_to_migrating(self):
        """Test pre check step which jumps to the migrating data state

        The pre-check should transition in this scenario to the migrating data
        state if the subcloud is now offline, and the deploy status can be
        handled by that state.
        """

        # subcloud is offline but deploy_state of 'installed' should allow
        # the upgrade to resume at the 'migrating data' state
        self.mock_db_query.return_value = FakeSubcloud(
            availability_status=consts.AVAILABILITY_OFFLINE,
            deploy_status=consts.DEPLOY_STATE_INSTALLED)

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the DB query was invoked
        self.mock_db_query.assert_called()

        # Verify the expected next state happened (migrating data)
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_MIGRATING_DATA)

    def test_upgrade_pre_check_subcloud_jumps_to_upgrading(self):
        """Test pre check step which jumps to the upgrading state

        The pre-check should transition in this scenario to the upgrading
        state if the subcloud is now offline, and the deploy status can be
        handled by that state.
        """

        # subcloud is offline but deploy_status of 'migration failed'
        # should be recoverable by an upgrade
        self.mock_db_query.return_value = FakeSubcloud(
            availability_status=consts.AVAILABILITY_OFFLINE,
            deploy_status=consts.DEPLOY_STATE_DATA_MIGRATION_FAILED)

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the DB query was invoked
        self.mock_db_query.assert_called()

        # Verify the expected next state happened (upgrading)
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_UPGRADING_SIMPLEX)

    def test_upgrade_pre_check_subcloud_cannot_proceed(self):
        """Test pre check step which requires manual intervention to proceed

        The pre-check should raise an exception and transition to the failed
        state when an offline subcloud is not in a deploy_status that has a
        known recovery route.
        """

        # subcloud is offline and there does not appear to be a way to revover
        self.mock_db_query.return_value = FakeSubcloud(
            availability_status=consts.AVAILABILITY_OFFLINE,
            deploy_status=consts.DEPLOY_STATE_BOOTSTRAP_FAILED)

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the DB query was invoked
        self.mock_db_query.assert_called()

        # Verify the exception caused the state to go to failed
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)
