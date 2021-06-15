#
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock

from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.tests.unit.fakes import FakeVimStrategy
from dcmanager.tests.unit.orchestrator.states.kube.test_base \
    import TestKubeUpgradeState

# We permit deleting a strategy that has completed or failed its action
DELETABLE_STRATEGY = FakeVimStrategy(state=vim.STATE_APPLIED)

# Not permitted to delete a strategy while it is partway through its action:
# 'BUILDING, APPLYING, ABORTING
UNDELETABLE_STRATEGY = FakeVimStrategy(state=vim.STATE_APPLYING)


class TestKubeDeletingVimPatchStrategyStage(TestKubeUpgradeState):
    "Test deleting the vim patch strategy during kube orch."""

    def setUp(self):
        super(TestKubeDeletingVimPatchStrategyStage, self).setUp()

        self.on_success_state = \
            consts.STRATEGY_STATE_KUBE_CREATING_VIM_KUBE_UPGRADE_STRATEGY

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            consts.STRATEGY_STATE_KUBE_DELETING_VIM_PATCH_STRATEGY)

        # Add mock API endpoints for client calls invcked by this state
        self.vim_client.get_strategy = mock.MagicMock()
        self.vim_client.delete_strategy = mock.MagicMock()

    def test_success_no_strategy_exists(self):
        """If there is no vim strategy, success. Skip to next state"""

        # Mock that there is no strategy to delete
        self.vim_client.get_strategy.return_value = None

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the vim strategy delete was never invoked
        self.vim_client.delete_strategy.assert_not_called()

        # On success it should proceed to next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_success_strategy_exists(self):
        """If there is a deletable strategy, delete and go to next state"""

        # Mock that there is a strategy to delete
        self.vim_client.get_strategy.return_value = DELETABLE_STRATEGY

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the vim strategy delete was invoked
        self.vim_client.delete_strategy.assert_called()

        # On success it should proceed to next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_failure_strategy_undeletable(self):
        """If there is a strategy that is in progress, cannot delete. Fail"""

        # Mock that there is a strategy to delete that is still running
        self.vim_client.get_strategy.return_value = UNDELETABLE_STRATEGY

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the vim strategy delete was not invoked
        self.vim_client.delete_strategy.assert_not_called()

        # The strategy was in an un-deletable state, so this should have failed
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_failure_vim_api_failure(self):
        """If delete strategy raises an exception, Fail."""

        # Mock that there is a strategy to delete
        self.vim_client.get_strategy.return_value = DELETABLE_STRATEGY

        # Mock that the delete API call raises an exception
        self.vim_client.delete_strategy.side_effect = \
            Exception("vim delete strategy failed for some reason")

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # The strategy was in an un-deletable state, so this should have failed
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)
