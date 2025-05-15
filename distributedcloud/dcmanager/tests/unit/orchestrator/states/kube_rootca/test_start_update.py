#
# Copyright (c) 2021-2022, 2024-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from dcmanager.common.consts import (
    STRATEGY_STATE_CREATING_VIM_KUBE_ROOTCA_UPDATE_STRATEGY,
)
from dcmanager.common.consts import STRATEGY_STATE_KUBE_ROOTCA_UPDATE_START
from dcmanager.common.consts import STRATEGY_STATE_KUBE_ROOTCA_UPDATE_UPLOAD_CERT
from dcmanager.tests.unit.orchestrator.states.fakes import FakeKubeRootCaUpdate
from dcmanager.tests.unit.orchestrator.states.kube_rootca.test_base import (
    TestKubeRootCaUpgradeState,
)

KUBE_ROOTCA_UPDATE_STARTED = FakeKubeRootCaUpdate(state="update-started")
KUBE_ROOTCA_UPDATE_ABORTED = FakeKubeRootCaUpdate(state="update-aborted")
KUBE_ROOTCA_UPDATE_CERT_UPLOADED = FakeKubeRootCaUpdate(
    state="update-new-rootca-cert-uploaded"
)


class TestStartUpdateStage(TestKubeRootCaUpgradeState):

    def setUp(self):
        super(TestStartUpdateStage, self).setUp()

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            self.subcloud.id, STRATEGY_STATE_KUBE_ROOTCA_UPDATE_START
        )

        self.sysinv_client.kube_rootca_update_start = mock.MagicMock()
        self.sysinv_client.get_kube_rootca_updates = mock.MagicMock()

    def test_no_existing_update(self):
        """Test start update when there is no existing update object

        The start update operation should be invoked, and move to upload cert
        """
        self.sysinv_client.get_kube_rootca_updates.return_value = []
        self.sysinv_client.kube_rootca_update_start.return_value = (
            KUBE_ROOTCA_UPDATE_STARTED
        )
        # invoke the strategy state operation on the orch thread
        self.worker._perform_state_action(
            self.DEFAULT_STRATEGY_TYPE, self.subcloud.region_name, self.strategy_step
        )

        # Verify the expected next state happened (upload cert)
        self.assert_step_updated(
            self.strategy_step.subcloud_id,
            STRATEGY_STATE_KUBE_ROOTCA_UPDATE_UPLOAD_CERT,
        )

    def test_existing_update_started(self):
        """Test start update when there is an update in started state

        The start update operation should be skipped, and move to upload cert
        """
        self.sysinv_client.get_kube_rootca_updates.return_value = [
            KUBE_ROOTCA_UPDATE_STARTED
        ]
        # invoke the strategy state operation on the orch thread
        self.worker._perform_state_action(
            self.DEFAULT_STRATEGY_TYPE, self.subcloud.region_name, self.strategy_step
        )

        # Verify the expected next state happened (upload cert)
        self.assert_step_updated(
            self.strategy_step.subcloud_id,
            STRATEGY_STATE_KUBE_ROOTCA_UPDATE_UPLOAD_CERT,
        )

    def test_existing_update_aborted(self):
        """Test start update when there is an update in aborted state

        The start update operation should be invoked, and move to upload cert
        """
        self.sysinv_client.get_kube_rootca_updates.return_value = [
            KUBE_ROOTCA_UPDATE_ABORTED
        ]
        self.sysinv_client.kube_rootca_update_start.return_value = (
            KUBE_ROOTCA_UPDATE_STARTED
        )
        # invoke the strategy state operation on the orch thread
        self.worker._perform_state_action(
            self.DEFAULT_STRATEGY_TYPE, self.subcloud.region_name, self.strategy_step
        )

        # Verify the expected next state happened (upload cert)
        self.assert_step_updated(
            self.strategy_step.subcloud_id,
            STRATEGY_STATE_KUBE_ROOTCA_UPDATE_UPLOAD_CERT,
        )

    def test_existing_update_other_state(self):
        """Test start update if there is an update in an other state.

        If an update exists that is not in started or aborted state, the upload
        cert step will be skipped, and transition to the vim creation state.
        """
        self.sysinv_client.get_kube_rootca_updates.return_value = [
            KUBE_ROOTCA_UPDATE_CERT_UPLOADED
        ]
        # invoke the strategy state operation on the orch thread
        self.worker._perform_state_action(
            self.DEFAULT_STRATEGY_TYPE, self.subcloud.region_name, self.strategy_step
        )

        # Verify the expected next state happened (upload cert)
        self.assert_step_updated(
            self.strategy_step.subcloud_id,
            STRATEGY_STATE_CREATING_VIM_KUBE_ROOTCA_UPDATE_STRATEGY,
        )
