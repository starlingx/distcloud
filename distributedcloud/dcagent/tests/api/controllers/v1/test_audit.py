#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import http.client
import json

import mock

from dcagent.common import utils
from dcagent.tests.api.test_root_controller import DCAgentApiTest
from dccommon import consts as dccommon_consts
from dcmanager.audit.alarm_aggregation import AlarmAggregation
from dcmanager.audit import base_audit
from dcmanager.audit.firmware_audit import FirmwareAudit
from dcmanager.audit.kube_rootca_update_audit import KubeRootcaUpdateAudit
from dcmanager.audit.kubernetes_audit import KubernetesAudit
from dcmanager.audit.software_audit import SoftwareAudit


class BaseTestAudit(DCAgentApiTest):
    def setUp(self):
        super().setUp()

        self.url = "/v1/dcaudit"
        self.method = self.app.patch_json

        self._mock_object(utils, "CachedSysinvClient")
        self._mock_object(utils, "CachedFmClient")
        self._mock_object(utils, "KeystoneCache")
        self._mock_object(utils, "CachedSoftwareClient")


class TestAuditController(BaseTestAudit):
    """Test class for Audit Controller"""

    def setUp(self):
        super().setUp()

    def test_unmapped_method(self):
        """Test requesting an unmapped method results in success with null content"""

        self.method = self.app.put

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(response.text, "null")


class TestAuditPatch(BaseTestAudit):
    def setUp(self):
        super().setUp()

    @mock.patch.object(json, "loads")
    def test_patch_audit_bad_request_on_decoding_error(self, mock_json_loads):
        self.params = "{bad json"
        mock_json_loads.side_effect = ValueError()
        response = self._send_request()
        error_msg = "Request body decoding error"
        self._assert_pecan_and_response(response, http.client.BAD_REQUEST, error_msg)

    def test_patch_audit_bad_request_on_empty_body(self):
        self.params = {}
        response = self._send_request()
        error_msg = "Body required"
        self._assert_pecan_and_response(response, http.client.BAD_REQUEST, error_msg)

    @mock.patch("dcagent.common.audit_manager.RequestedAudit.get_sync_status")
    def test_patch_audit_internal_server_error_on_exception(self, mock_get_sync_status):
        exception_msg = "Test Error"
        mock_get_sync_status.side_effect = Exception(exception_msg)
        error_response = f"Unable to get audit info: {exception_msg}"
        self.params = {"use_cache": True}
        response = self._send_request()
        self._assert_pecan_and_response(
            response, http.client.INTERNAL_SERVER_ERROR, error_response
        )


class TestRequestedAudit(BaseTestAudit):
    def setUp(self):
        super().setUp()

        mock_availability = self._mock_object(
            base_audit, "get_subcloud_availability_status"
        )
        mock_alarm_aggregation = self._mock_object(
            AlarmAggregation, "get_alarm_summary"
        )
        mock_software_audit = self._mock_object(
            SoftwareAudit, "get_subcloud_sync_status"
        )
        mock_firmware_audit = self._mock_object(
            FirmwareAudit, "get_subcloud_sync_status"
        )
        mock_kubernetes_audit = self._mock_object(
            KubernetesAudit, "get_subcloud_sync_status"
        )
        mock_kube_rootca_audit = self._mock_object(
            KubeRootcaUpdateAudit, "get_subcloud_sync_status"
        )

        # Mock responses for the external dependencies
        mock_availability.return_value = ["online", []]
        mock_alarm_aggregation.return_value = "test_alarm_summary"
        mock_software_audit.return_value = "software_audit_response"
        mock_firmware_audit.return_value = "firmware_audit_response"
        mock_kubernetes_audit.return_value = "kubernetes_audit_response"
        mock_kube_rootca_audit.return_value = "kube_rootca_audit_response"

    def test_get_sync_status(self):
        self.params = {
            dccommon_consts.BASE_AUDIT: "",
            dccommon_consts.FIRMWARE_AUDIT: "regionone_data_firmware",
            dccommon_consts.KUBE_ROOTCA_AUDIT: "regionone_data_kube_rootca",
            dccommon_consts.KUBERNETES_AUDIT: "regionone_data_kubernetes",
            dccommon_consts.SOFTWARE_AUDIT: "regionone_data_software",
        }

        response = self._send_request()

        # Verify results
        expected_result = {
            dccommon_consts.BASE_AUDIT: {
                "availability": "online",
                "inactive_sg": [],
                "alarms": "test_alarm_summary",
            },
            dccommon_consts.FIRMWARE_AUDIT: "firmware_audit_response",
            dccommon_consts.KUBE_ROOTCA_AUDIT: "kube_rootca_audit_response",
            dccommon_consts.KUBERNETES_AUDIT: "kubernetes_audit_response",
            dccommon_consts.SOFTWARE_AUDIT: "software_audit_response",
        }
        self._assert_response(
            response,
            expected_response_text=json.dumps(expected_result, sort_keys=False),
        )

    def test_get_sync_status_unsuported_audit(self):
        self.params = {"fake_audit": ""}
        error_msg = "Requested audit fake_audit is not supported."
        response = self._send_request()
        self._assert_pecan_and_response(response, http.client.BAD_REQUEST, error_msg)
