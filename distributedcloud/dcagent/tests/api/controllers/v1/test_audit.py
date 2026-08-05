#
# Copyright (c) 2024-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import http.client
import json
import socket

import mock

from dcagent.api.controllers.v1.audit import AuditController
from dcagent.common import utils
from dcagent.tests.api.test_root_controller import DCAgentApiTest
from dccommon import consts as dccommon_consts
from dccommon.endpoint_cache import EndpointCache
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
        self._mock_object(utils, "CachedSoftwareClient")
        self._mock_object(EndpointCache, "get_admin_session")


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


class TestSyncOidcLoginConfig(BaseTestAudit):
    """Test class for OIDC login config sync via audit."""

    def setUp(self):
        super().setUp()

        mock_availability = self._mock_object(
            base_audit, "get_subcloud_availability_status"
        )
        mock_alarm_aggregation = self._mock_object(
            AlarmAggregation, "get_alarm_summary"
        )
        mock_availability.return_value = ["online", []]
        mock_alarm_aggregation.return_value = "test_alarm_summary"

    @mock.patch.object(AuditController, "_sync_oidc_login_config")
    def test_patch_audit_syncs_oidc_config_from_extra_args(self, mock_sync):
        """Test that OIDC config is extracted from extra_args and synced."""
        self.params = {
            dccommon_consts.BASE_AUDIT: "",
            "extra_args": {"oidc_login_config": "oidc-config-content"},
        }
        self._send_request()
        mock_sync.assert_called_once_with("oidc-config-content")

    @mock.patch.object(AuditController, "_sync_oidc_login_config")
    def test_patch_audit_no_oidc_config_in_extra_args(self, mock_sync):
        """Test that _sync_oidc_login_config is not called without config."""
        self.params = {
            dccommon_consts.BASE_AUDIT: "",
            "extra_args": {},
        }
        self._send_request()
        mock_sync.assert_not_called()

    @mock.patch.object(AuditController, "_sync_oidc_login_config")
    def test_patch_audit_no_extra_args(self, mock_sync):
        """Test that missing extra_args does not break the audit."""
        self.params = {
            dccommon_consts.BASE_AUDIT: "",
        }
        self._send_request()
        mock_sync.assert_not_called()

    @mock.patch("os.rename")
    @mock.patch("os.chmod")
    @mock.patch("builtins.open", mock.mock_open())
    @mock.patch("os.path.isfile", return_value=False)
    def test_sync_oidc_login_config_writes_new_file(
        self, mock_isfile, mock_chmod, mock_rename
    ):
        """Test writing OIDC config when file does not exist."""
        AuditController._sync_oidc_login_config("new-content")
        mock_chmod.assert_called_once_with(
            dccommon_consts.OIDC_LOGIN_CONFIG_PATH + ".tmp", 0o644
        )
        mock_rename.assert_called_once_with(
            dccommon_consts.OIDC_LOGIN_CONFIG_PATH + ".tmp",
            dccommon_consts.OIDC_LOGIN_CONFIG_PATH,
        )

    @mock.patch("os.rename")
    @mock.patch("os.chmod")
    @mock.patch("builtins.open", mock.mock_open(read_data="existing-content"))
    @mock.patch("os.path.isfile", return_value=True)
    def test_sync_oidc_login_config_skips_when_unchanged(
        self, mock_isfile, mock_chmod, mock_rename
    ):
        """Test that file is not written when content is unchanged."""
        AuditController._sync_oidc_login_config("existing-content")
        mock_chmod.assert_not_called()
        mock_rename.assert_not_called()

    @mock.patch("os.rename")
    @mock.patch("os.chmod")
    @mock.patch("builtins.open", mock.mock_open(read_data="old-content"))
    @mock.patch("os.path.isfile", return_value=True)
    def test_sync_oidc_login_config_writes_when_changed(
        self, mock_isfile, mock_chmod, mock_rename
    ):
        """Test that file is written when content has changed."""
        AuditController._sync_oidc_login_config("new-content")
        mock_chmod.assert_called_once_with(
            dccommon_consts.OIDC_LOGIN_CONFIG_PATH + ".tmp", 0o644
        )
        mock_rename.assert_called_once_with(
            dccommon_consts.OIDC_LOGIN_CONFIG_PATH + ".tmp",
            dccommon_consts.OIDC_LOGIN_CONFIG_PATH,
        )

    @mock.patch("os.rename")
    @mock.patch("os.chmod")
    @mock.patch(
        "socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.10.10.1", 0))],
    )
    @mock.patch(
        "builtins.open",
        mock.mock_open(
            read_data="oidc-client-id: stx-oidc-client-app\n"
            "oidc-issuer-url: https://10.10.10.1:30556/dex\n"
        ),
    )
    @mock.patch("os.path.isfile", return_value=True)
    def test_sync_oidc_login_config_skips_when_local_oidc_app(
        self, mock_isfile, mock_getaddrinfo, mock_chmod, mock_rename
    ):
        """Test that file is not overwritten when subcloud has local oidc-auth-apps.

        If the existing config's oidc-issuer-url points to the local OAM IP,
        it was generated by a locally-applied oidc-auth-apps and must not be
        overwritten by the system controller's config.
        """
        incoming_content = (
            "oidc-client-id: stx-oidc-client-app\n"
            "oidc-issuer-url: https://10.99.99.1:30556/dex\n"
        )
        AuditController._sync_oidc_login_config(incoming_content)
        mock_getaddrinfo.assert_called_once_with("oamcontroller", None)
        mock_chmod.assert_not_called()
        mock_rename.assert_not_called()

    @mock.patch("os.rename")
    @mock.patch("os.chmod")
    @mock.patch(
        "socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.10.10.1", 0))],
    )
    @mock.patch(
        "builtins.open",
        mock.mock_open(
            read_data="oidc-client-id: stx-oidc-client-app\n"
            "oidc-issuer-url: https://10.99.99.1:30556/dex\n"
        ),
    )
    @mock.patch("os.path.isfile", return_value=True)
    def test_sync_oidc_login_config_writes_when_not_local_oidc_app(
        self, mock_isfile, mock_getaddrinfo, mock_chmod, mock_rename
    ):
        """Test that file is overwritten when existing config points to remote host.

        If the existing config's oidc-issuer-url does NOT point to the local
        OAM IP (e.g., it was previously synced from the system controller),
        it should be updated with the new content.
        """
        incoming_content = (
            "oidc-client-id: stx-oidc-client-app\n"
            "oidc-issuer-url: https://10.99.99.2:30556/dex\n"
        )
        AuditController._sync_oidc_login_config(incoming_content)
        mock_chmod.assert_called_once_with(
            dccommon_consts.OIDC_LOGIN_CONFIG_PATH + ".tmp", 0o644
        )
        mock_rename.assert_called_once_with(
            dccommon_consts.OIDC_LOGIN_CONFIG_PATH + ".tmp",
            dccommon_consts.OIDC_LOGIN_CONFIG_PATH,
        )

    @mock.patch("os.rename")
    @mock.patch("os.chmod")
    @mock.patch(
        "socket.getaddrinfo",
        return_value=[
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                0,
                "",
                ("2620:10a:a001:aa0c::54", 0, 0, 0),
            )
        ],
    )
    @mock.patch(
        "builtins.open",
        mock.mock_open(
            read_data="oidc-client-id: stx-oidc-client-app\n"
            "oidc-issuer-url: https://[2620:10a:a001:aa0c::54]:30556/dex\n"
        ),
    )
    @mock.patch("os.path.isfile", return_value=True)
    def test_sync_oidc_login_config_skips_when_local_oidc_app_ipv6(
        self, mock_isfile, mock_getaddrinfo, mock_chmod, mock_rename
    ):
        """Test skip logic works with IPv6 addresses.

        urlparse strips brackets from IPv6 URLs, and getaddrinfo returns
        the bare address. The comparison must handle both forms correctly.
        """
        incoming_content = (
            "oidc-client-id: stx-oidc-client-app\n"
            "oidc-issuer-url: https://[2620:10a:a001:bb0d::99]:30556/dex\n"
        )
        AuditController._sync_oidc_login_config(incoming_content)
        mock_getaddrinfo.assert_called_once_with("oamcontroller", None)
        mock_chmod.assert_not_called()
        mock_rename.assert_not_called()

    @mock.patch("os.rename")
    @mock.patch("os.chmod")
    @mock.patch(
        "socket.getaddrinfo",
        return_value=[
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                0,
                "",
                ("2620:10a:a001:aa0c::54", 0, 0, 0),
            )
        ],
    )
    @mock.patch(
        "builtins.open",
        mock.mock_open(
            read_data="oidc-client-id: stx-oidc-client-app\n"
            "oidc-issuer-url: https://[2620:10a:a001:bb0d::99]:30556/dex\n"
        ),
    )
    @mock.patch("os.path.isfile", return_value=True)
    def test_sync_oidc_login_config_writes_when_not_local_oidc_app_ipv6(
        self, mock_isfile, mock_getaddrinfo, mock_chmod, mock_rename
    ):
        """Test that file is overwritten when IPv6 issuer-url is not local OAM."""
        incoming_content = (
            "oidc-client-id: stx-oidc-client-app\n"
            "oidc-issuer-url: https://[2620:10a:a001:cc0e::11]:30556/dex\n"
        )
        AuditController._sync_oidc_login_config(incoming_content)
        mock_chmod.assert_called_once_with(
            dccommon_consts.OIDC_LOGIN_CONFIG_PATH + ".tmp", 0o644
        )
        mock_rename.assert_called_once_with(
            dccommon_consts.OIDC_LOGIN_CONFIG_PATH + ".tmp",
            dccommon_consts.OIDC_LOGIN_CONFIG_PATH,
        )

    @mock.patch("os.rename")
    @mock.patch("os.chmod")
    @mock.patch(
        "socket.getaddrinfo",
        return_value=[
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                0,
                "",
                ("2620:10a:a001:aa0c:0:0:0:54", 0, 0, 0),
            )
        ],
    )
    @mock.patch(
        "builtins.open",
        mock.mock_open(
            read_data="oidc-client-id: stx-oidc-client-app\n"
            "oidc-issuer-url: https://[2620:10a:a001:aa0c::54]:30556/dex\n"
        ),
    )
    @mock.patch("os.path.isfile", return_value=True)
    def test_sync_oidc_login_config_skips_ipv6_equivalent_representations(
        self, mock_isfile, mock_getaddrinfo, mock_chmod, mock_rename
    ):
        """Test that equivalent IPv6 representations are matched correctly.

        The config file may use '2620:10a:a001:aa0c::54' (compressed) while
        getaddrinfo returns '2620:10a:a001:aa0c:0:0:0:54' (expanded).
        These must be recognized as the same address.
        """
        incoming_content = (
            "oidc-client-id: stx-oidc-client-app\n"
            "oidc-issuer-url: https://[2620:10a:a001:bb0d::99]:30556/dex\n"
        )
        AuditController._sync_oidc_login_config(incoming_content)
        mock_getaddrinfo.assert_called_once_with("oamcontroller", None)
        mock_chmod.assert_not_called()
        mock_rename.assert_not_called()
