#
# Copyright (c) 2021-2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dcmanager.common.consts \
    import STRATEGY_STATE_CREATING_VIM_KUBE_ROOTCA_UPDATE_STRATEGY
from dcmanager.common.consts import STRATEGY_STATE_KUBE_ROOTCA_UPDATE_PRE_CHECK
from dcmanager.common.consts import STRATEGY_STATE_KUBE_ROOTCA_UPDATE_START

from dcmanager.tests.unit.common import fake_strategy
from dcmanager.tests.unit.orchestrator.states.kube_rootca.test_base \
    import TestKubeRootCaUpgradeState


class TestPreCheckStage(TestKubeRootCaUpgradeState):

    def setUp(self):
        super(TestPreCheckStage, self).setUp()

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            self.subcloud.id, STRATEGY_STATE_KUBE_ROOTCA_UPDATE_PRE_CHECK)

    def test_pre_check_no_extra_args(self):
        """Test pre check step where there are no extra args

        The pre-check should transition to the create vim strategy state
        """
        # Create a strategy with no extra_args
        extra_args = None
        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx,
            self.DEFAULT_STRATEGY_TYPE,
            extra_args=extra_args)

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Verify the expected next state happened
        self.assert_step_updated(
            self.strategy_step.subcloud_id,
            STRATEGY_STATE_CREATING_VIM_KUBE_ROOTCA_UPDATE_STRATEGY)

    def test_pre_check_extra_args_no_cert_file(self):
        """Test pre check step where extra args exist, but no cert-file entry

        The pre-check should transition to the create vim strategy state
        """
        extra_args = {
            "expiry-date": "2020:01:31",
            "subject": "C=CA ST=ON L=OTT O=WR OU=STX CN=AL_RULES"
        }
        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx,
            self.DEFAULT_STRATEGY_TYPE,
            extra_args=extra_args)
        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Verify the expected next state happened
        self.assert_step_updated(
            self.strategy_step.subcloud_id,
            STRATEGY_STATE_CREATING_VIM_KUBE_ROOTCA_UPDATE_STRATEGY)

    def test_pre_check_cert_file_extra_args_detected(self):
        """Test pre check step where extra args cert-file exists

        There are currently no checks in pre-check to short circuit based on
        pre-existing kube rootca update state.
        The unit test should transition to the start-update state.
        """

        extra_args = {
            "cert-file": "some_fake_cert_file"
        }
        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx,
            self.DEFAULT_STRATEGY_TYPE,
            extra_args=extra_args)
        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Verify the expected next state happened
        self.assert_step_updated(
            self.strategy_step.subcloud_id,
            STRATEGY_STATE_KUBE_ROOTCA_UPDATE_START)
