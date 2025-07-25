#
# Copyright (c) 2021-2022, 2024-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from dcmanager.common.consts import (
    STRATEGY_STATE_CREATING_VIM_KUBE_ROOTCA_UPDATE_STRATEGY,
)
from dcmanager.common.consts import STRATEGY_STATE_FAILED
from dcmanager.common.consts import STRATEGY_STATE_KUBE_ROOTCA_UPDATE_UPLOAD_CERT
from dcmanager.db import api as db_api
from dcmanager.tests.unit.common import fake_strategy
from dcmanager.tests.unit.orchestrator.states.kube_rootca.test_base import (
    TestKubeRootCaUpgradeState,
)

# Only the 'error' field is checked on upload_cert
ERROR_UPLOADING_CERT = {"error": "fake error"}
SUCCESS_UPLOADING_CERT = {"success": "Success Upload"}

FAKE_CERT_FILE = "some_fake_cert_file.pem"


class TestUploadCertStage(TestKubeRootCaUpgradeState):
    def setUp(self):
        super().setUp()

        self.on_success_state = STRATEGY_STATE_CREATING_VIM_KUBE_ROOTCA_UPDATE_STRATEGY
        self.current_state = STRATEGY_STATE_KUBE_ROOTCA_UPDATE_UPLOAD_CERT

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            self.subcloud.id, self.current_state
        )

        # Mock the strategy with a reference to a cert-file in extra_args
        extra_args = {"cert-file": FAKE_CERT_FILE}
        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx, self.strategy_type, extra_args=extra_args
        )

    def test_upload_cert_fails(self):
        """Test upload cert failed the sysinv operation

        The state should fail
        """

        self.sysinv_client.kube_rootca_update_upload_cert.return_value = (
            ERROR_UPLOADING_CERT
        )

        mock_open = mock.mock_open(read_data="test")
        with mock.patch("builtins.open", mock_open):
            self._setup_and_assert(STRATEGY_STATE_FAILED)
            self._assert_error(
                f"{self.current_state}: Error while uploading rootca certificate. "
                "fake error"
            )

        # verify we attempted to call the mocked upload method
        self.sysinv_client.kube_rootca_update_upload_cert.assert_called()

    def test_upload_cert_pass(self):
        """Test upload cert passes the sysinv operation

        The state should transition to the vim creation state
        """

        self.sysinv_client.kube_rootca_update_upload_cert.return_value = (
            SUCCESS_UPLOADING_CERT
        )

        mock_open = mock.mock_open(read_data="test")
        with mock.patch("builtins.open", mock_open):
            self._setup_and_assert(self.on_success_state)

        # verify we attempted to call the mocked upload method
        self.sysinv_client.kube_rootca_update_upload_cert.assert_called()

    def test_upload_cert_pass_without_extra_args(self):
        """Test upload cert passes the sysinv operation without extra args

        The state should transition to the vim creation state
        """

        db_api.sw_update_strategy_destroy(self.ctx)
        self.strategy = fake_strategy.create_fake_strategy(self.ctx, self.strategy_type)

        self.sysinv_client.kube_rootca_update_upload_cert.return_value = (
            SUCCESS_UPLOADING_CERT
        )

        self._setup_and_assert(self.on_success_state)

        self.sysinv_client.kube_rootca_update_upload_cert.assert_not_called()
