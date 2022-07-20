#
# Copyright (c) 2021-2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock

from dcmanager.common.consts \
    import STRATEGY_STATE_CREATING_VIM_KUBE_ROOTCA_UPDATE_STRATEGY
from dcmanager.common.consts import STRATEGY_STATE_FAILED
from dcmanager.common.consts \
    import STRATEGY_STATE_KUBE_ROOTCA_UPDATE_UPLOAD_CERT

from dcmanager.tests.unit.common import fake_strategy
from dcmanager.tests.unit.orchestrator.states.kube_rootca.test_base \
    import TestKubeRootCaUpgradeState

# Only the 'error' field is error checked on upload_cert
ERROR_UPLOADING_CERT = {"error": "File not found"}
SUCCESS_UPLOADING_CERT = {"success": "Success Upload"}

FAKE_CERT_FILE = "some_fake_cert_file.pem"


class TestUploadCertStage(TestKubeRootCaUpgradeState):

    def setUp(self):
        super(TestUploadCertStage, self).setUp()

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            self.subcloud.id, STRATEGY_STATE_KUBE_ROOTCA_UPDATE_UPLOAD_CERT)

        self.sysinv_client.kube_rootca_update_upload_cert = mock.MagicMock()

        # Mock the strategy with a reference to a cert-file in extra_args
        extra_args = {
            "cert-file": FAKE_CERT_FILE
        }
        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx,
            self.DEFAULT_STRATEGY_TYPE,
            extra_args=extra_args)

    def test_upload_cert_fails(self):
        """Test upload cert failed the sysinv operation

        The state should fail
        """
        self.sysinv_client.kube_rootca_update_upload_cert.return_value = \
            ERROR_UPLOADING_CERT

        mock_open = mock.mock_open(read_data='test')
        with mock.patch('six.moves.builtins.open', mock_open):
            # invoke the strategy state operation on the orch thread
            self.worker.perform_state_action(self.strategy_step)

        # verify we attempted to call the mocked upload method
        self.sysinv_client.kube_rootca_update_upload_cert.assert_called()

        # Verify the strategy failed
        self.assert_step_updated(
            self.strategy_step.subcloud_id,
            STRATEGY_STATE_FAILED)

    def test_upload_cert_pass(self):
        """Test upload cert passes the sysinv operation

        The state should transition to the vim creation state
        """
        self.sysinv_client.kube_rootca_update_upload_cert.return_value = \
            SUCCESS_UPLOADING_CERT

        mock_open = mock.mock_open(read_data='test')
        with mock.patch('six.moves.builtins.open', mock_open):
            # invoke the strategy state operation on the orch thread
            self.worker.perform_state_action(self.strategy_step)

        # verify we attempted to call the mocked upload method
        self.sysinv_client.kube_rootca_update_upload_cert.assert_called()

        # Verify the expected next state happened
        self.assert_step_updated(
            self.strategy_step.subcloud_id,
            STRATEGY_STATE_CREATING_VIM_KUBE_ROOTCA_UPDATE_STRATEGY)
