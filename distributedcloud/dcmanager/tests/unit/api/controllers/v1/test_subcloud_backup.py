#
# Copyright (c) 2022-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import http.client
import json
import os
import time

import mock
from oslo_messaging import RemoteError

from dccommon import consts as dccommon_consts
from dccommon.endpoint_cache import EndpointCache
from dcmanager.common import consts
import dcmanager.common.utils
from dcmanager.db import api as db_api
from dcmanager.rpc import client as rpc_client
from dcmanager.tests import base
from dcmanager.tests.unit.api.test_root_controller import DCManagerApiTest
from dcmanager.tests.unit.common import fake_subcloud

FAKE_GOOD_SYSTEM_HEALTH = (
    "System Health:\n"
    "All hosts are provisioned: [OK]\n"
    "All hosts are unlocked/enabled: [OK]\n"
    "All hosts have current configurations: [OK]\n"
    "All hosts are patch current: [OK]\n"
    "No alarms: [Fail]\n"
    "[1] alarms found, [0] of which are management affecting\n"
    "All kubernetes nodes are ready: [OK]\n"
    "All kubernetes control plane pods are ready: [OK]\n"
)
FAKE_GOOD_SYSTEM_HEALTH_NO_ALARMS = (
    "System Health:"
    "All hosts are provisioned: [OK]"
    "All hosts are unlocked/enabled: [OK]"
    "All hosts have current configurations: [OK]"
    "All hosts are patch current: [OK]"
    "No alarms: [OK]"
    "All kubernetes nodes are ready: [OK]"
    "All kubernetes control plane pods are ready: [OK]"
)
FAKE_SYSTEM_HEALTH_CEPH_FAIL = (
    "System Health:\n"
    "All hosts are provisioned: [OK]\n"
    "All hosts are unlocked/enabled: [OK]\n"
    "All hosts have current configurations: [OK]\n"
    "All hosts are patch current: [OK]\n"
    "Ceph Storage Healthy: [Fail]\n"
    "No alarms: [Fail]\n"
    "[2] alarms found, [2] of which are management affecting\n"
    "All kubernetes nodes are ready: [OK]\n"
    "All kubernetes control plane pods are ready: [OK]\n"
)
FAKE_SYSTEM_HEALTH_MGMT_ALARM = (
    "System Health:\n"
    "All hosts are provisioned: [OK]\n"
    "All hosts are unlocked/enabled: [OK]\n"
    "All hosts have current configurations: [OK]\n"
    "All hosts are patch current: [OK]\n"
    "Ceph Storage Healthy: [Fail]\n"
    "No alarms: [Fail]\n"
    "[2] alarms found, [2] of which are management affecting\n"
    "All kubernetes nodes are ready: [OK]\n"
    "All kubernetes control plane pods are ready: [OK]\n"
)
FAKE_SYSTEM_HEALTH_K8S_FAIL = (
    "System Health:\n"
    "All hosts are provisioned: [OK]\n"
    "All hosts are unlocked/enabled: [OK]\n"
    "All hosts have current configurations: [OK]\n"
    "All hosts are patch current: [OK]\n"
    "Ceph Storage Healthy: [Fail]\n"
    "No alarms: [Fail]\n"
    "[2] alarms found, [2] of which are management affecting\n"
    "All kubernetes nodes are ready: [OK]\n"
    "All kubernetes control plane pods are ready: [OK]\n"
)
FAKE_RESTORE_VALUES_INVALID_IP = {"bootstrap_address": {"subcloud1": "10.10.20.12.22"}}
FAKE_RESTORE_VALUES_VALID_IP = {"bootstrap_address": {"subcloud1": "10.10.20.12"}}


class BaseTestSubcloudBackupController(DCManagerApiTest):
    """Base class for testing the SubcloudBackupController"""

    def setUp(self):
        super().setUp()

        self.url = "/v1.0/subcloud-backup"
        self.subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        self.mock_rpc_client = self._mock_object(rpc_client, "ManagerClient")
        self._mock_object(rpc_client, "SubcloudStateClient")
        self._mock_object(EndpointCache, "get_admin_session")
        self.mock_sysinv_client = self._mock_object(
            dcmanager.common.utils, "SysinvClient"
        )

    def _update_subcloud(
        self,
        availability_status=dccommon_consts.AVAILABILITY_ONLINE,
        management_state=dccommon_consts.MANAGEMENT_MANAGED,
        deploy_status=consts.DEPLOY_STATE_DONE,
        backup_datetime=None,
        backup_status=consts.BACKUP_STATE_UNKNOWN,
        data_install=None,
        group_id=None,
    ):
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            availability_status=availability_status,
            management_state=management_state,
            backup_datetime=backup_datetime,
            backup_status=backup_status,
            deploy_status=deploy_status,
            data_install=data_install,
            group_id=group_id,
        )


class TestSubcloudBackupController(BaseTestSubcloudBackupController):
    """Test class for SubcloudBackupController"""

    def setUp(self):
        super().setUp()

    def test_unmapped_method(self):
        """Test requesting an unmapped method results in success with null content"""

        self.method = self.app.put

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(response.text, "null")


class BaseTestSubcloudBackupPost(BaseTestSubcloudBackupController):
    """Base test class for post requests"""

    def setUp(self):
        super().setUp()

        self.method = self.app.post


class TestSubcloudBackupPost(BaseTestSubcloudBackupPost):
    """Test class for post requests"""

    def setUp(self):
        super().setUp()

    def test_post_fails_with_invalid_payload(self):
        """Test post fails with invalid payload"""

        self.params = '[{"key": "value"}]'

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Invalid request body format"
        )

    def test_post_fails_with_unexpected_parameter(self):
        """Test post fails with unexpected parameter

        Even though the restore_values is a parameter accepted by the
        _get_multipart_payload, it isn't valid for POST requests, which leads to
        the failure.
        """

        fake_restore_values = json.dumps(FAKE_RESTORE_VALUES_VALID_IP).encode()
        self.upload_files = [
            ("restore_values", "fake_restore_values", fake_restore_values)
        ]

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Unexpected parameter received"
        )

    def test_post_fails_without_sysadmin_password_in_multipart_payload(self):
        """Test post fails without sysadmin password in multipart payload"""

        self.params = {
            "subcloud": str(self.subcloud.id),
        }

        fake_restore_values = json.dumps(FAKE_RESTORE_VALUES_VALID_IP).encode()
        self.upload_files = [
            ("backup_values", "fake_backup_values", fake_restore_values)
        ]

        self._update_subcloud()

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "subcloud sysadmin_password required"
        )

    def test_post_fails_with_invalid_password(self):
        """Test post fails with invalid password"""

        self.params = f'{{"sysadmin_password": "{"keyword".encode("utf-8")}"}}'

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Failed to decode subcloud sysadmin_password, "
            "verify the password is base64 encoded",
        )

    def test_post_fails_with_subcloud_and_group(self):
        """Test post fails with subcloud and group"""

        self.params = (
            f'{{"sysadmin_password": "{self._create_password()}",'
            f'"subcloud": "{self.subcloud.id}", "group": {self.subcloud.id}}}'
        )

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "'subcloud' and 'group' parameters should not be given at the same time",
        )

    def test_post_fails_without_subcloud_and_group(self):
        """Test post fails without subcloud and group"""

        self.params = f'{{"sysadmin_password": "{self._create_password()}"}}'

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "'subcloud' or 'group' parameter is required",
        )


class TestSubcloudBackupPostSubcloud(BaseTestSubcloudBackupPost):
    """Test class for post requests for subcloud resource"""

    def setUp(self):
        super().setUp()

        self.params = (
            f'{{"sysadmin_password": "{self._create_password()}",'
            f'"subcloud": "{self.subcloud.id}"}}'
        )

    def test_post_subcloud_succeeds(self):
        """Test post subcloud succeeds"""

        good_health_states = [
            FAKE_GOOD_SYSTEM_HEALTH,
            FAKE_GOOD_SYSTEM_HEALTH_NO_ALARMS,
        ]

        for system_health in good_health_states:
            self._update_subcloud()
            self.mock_sysinv_client().get_system_health.return_value = system_health

            response = self._send_request()

            self._assert_response(response)

    def test_post_subcloud_fails_with_bad_system_health(self):
        """Test post subcloud fails with bad system health"""

        bad_health_states = [
            FAKE_SYSTEM_HEALTH_MGMT_ALARM,
            FAKE_SYSTEM_HEALTH_CEPH_FAIL,
            FAKE_SYSTEM_HEALTH_K8S_FAIL,
        ]

        for index, system_health in enumerate(bad_health_states, start=1):
            self._update_subcloud()
            self.mock_sysinv_client().get_system_health.return_value = system_health

            response = self._send_request()

            self._assert_pecan_and_response(
                response,
                http.client.BAD_REQUEST,
                f"Subcloud {self.subcloud.name} must be in good health for "
                "subcloud-backup create.",
                index,
            )

    def test_post_subcloud_fails_with_unknown_subcloud(self):
        """Test post subcloud fails with unknown subcloud"""

        self.params = (
            f'{{"sysadmin_password": "{self._create_password()}","subcloud": "123"}}'
        )

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Subcloud not found"
        )

    def test_post_subcloud_fails_with_subcloud_offline(self):
        """Test post subcloud fails with subcloud offline"""

        self._update_subcloud(availability_status=dccommon_consts.AVAILABILITY_OFFLINE)

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"Subcloud {self.subcloud.name} must be deployed, online and managed "
            "for the subcloud-backup create operation.",
        )

    def test_post_subcloud_fails_with_unmanaged_subcloud(self):
        """Test post subcloud fails with unmanaged subcloud"""

        self._update_subcloud(management_state=dccommon_consts.MANAGEMENT_UNMANAGED)

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"Subcloud {self.subcloud.name} must be deployed, online and managed "
            "for the subcloud-backup create operation.",
        )

    def test_post_subcloud_fails_with_subcloud_in_invalid_deploy_state(self):
        """Test post subcloud fails with subcloud in invalid deploy state"""

        self._update_subcloud(deploy_status=consts.DEPLOY_STATE_BOOTSTRAPPING)

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"Subcloud {self.subcloud.name} must be deployed, online and managed "
            "for the subcloud-backup create operation.",
        )

    def test_post_subcloud_succeeds_with_backup_values(self):
        """Test post subcloud succeeds with backup values"""

        self.params = (
            f'{{"sysadmin_password": "{self._create_password()}",'
            f'"subcloud": "{self.subcloud.id}","backup_values": "TestFileDirectory"}}'
        )

        self._update_subcloud()

        self.mock_sysinv_client().get_system_health.return_value = (
            FAKE_GOOD_SYSTEM_HEALTH
        )

        response = self._send_request()

        self._assert_response(response)

    def test_post_subcloud_fails_without_password(self):
        """Test post subcloud fails without password"""

        self.params = f'{{"subcloud": "{self.subcloud.id}"}}'

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "subcloud sysadmin_password required"
        )

    def test_post_subcloud_succeeds_with_local_only(self):
        """Test post subcloud succeeds with local only"""

        self.params = (
            f'{{"sysadmin_password": "{self._create_password()}",'
            f'"subcloud": "{self.subcloud.id}", "local_only": "True"}}'
        )

        self._update_subcloud()

        self.mock_sysinv_client().get_system_health.return_value = (
            FAKE_GOOD_SYSTEM_HEALTH
        )

        response = self._send_request()

        self._assert_response(response)

    def test_post_subcloud_fails_with_invalid_local_only(self):
        """Test post subcloud fails with invalid local only"""

        self.params = (
            f'{{"sysadmin_password": "{self._create_password()}",'
            f'"subcloud": "{self.subcloud.id}", "local_only": "fake"}}'
        )

        self._update_subcloud()

        self.mock_sysinv_client().get_system_health.return_value = (
            FAKE_GOOD_SYSTEM_HEALTH
        )

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Invalid local_only value, should be boolean",
        )

    def test_post_subcloud_succeeds_with_local_only_and_registry_images(self):
        """Test post subcloud succeeds with local only and registry images"""

        self.params = (
            f'{{"sysadmin_password": "{self._create_password()}",'
            f'"subcloud": "{self.subcloud.id}", "local_only": "True", '
            f'"registry_images": "True"}}'
        )

        self._update_subcloud()

        self.mock_sysinv_client().get_system_health.return_value = (
            FAKE_GOOD_SYSTEM_HEALTH
        )

        response = self._send_request()

        self._assert_response(response)

    def test_post_subcloud_fails_with_registry_images(self):
        """Test post subcloud fails with registry images"""

        self.params = (
            f'{{"sysadmin_password": "{self._create_password()}",'
            f'"subcloud": "{self.subcloud.id}", "registry_images": "True"}}'
        )

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Option registry_images can not be used without local_only option.",
        )

    def test_post_subcloud_fails_with_unknown_parameter(self):
        """Test post subcloud fails with unknown parameter"""

        self.params = (
            f'{{"sysadmin_password": "{self._create_password()}",'
            f'"subcloud": "{self.subcloud.id}", "unknown_parameter": "fake"}}'
        )

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Unexpected parameter received"
        )

    def test_post_subcloud_fails_with_invalid_payload(self):
        """Test post subcloud fails with invalid payload"""

        self.params = "payload"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Request body is malformed."
        )

    def test_post_subcloud_succeeds_with_final_backup_states(self):
        """Test post subcloud succeeds with final backup states"""

        self.mock_sysinv_client().get_system_health.return_value = (
            FAKE_GOOD_SYSTEM_HEALTH
        )

        final_backup_states = [
            consts.BACKUP_STATE_VALIDATE_FAILED,
            consts.BACKUP_STATE_PREP_FAILED,
            consts.BACKUP_STATE_FAILED,
            consts.BACKUP_STATE_UNKNOWN,
            consts.BACKUP_STATE_COMPLETE_CENTRAL,
            consts.BACKUP_STATE_COMPLETE_LOCAL,
        ]

        for backup_state in final_backup_states:
            self._update_subcloud(backup_status=backup_state)

            response = self._send_request()

            self._assert_response(response)

    def test_post_subcloud_fails_with_ongoing_backup_states(self):
        """Test post subcloud fails with ongoing backup states"""

        self.mock_sysinv_client().get_system_health.return_value = (
            FAKE_GOOD_SYSTEM_HEALTH
        )

        for index, state in enumerate(consts.TRANSITORY_BACKUP_STATES, start=1):
            self._update_subcloud(backup_status=state)

            response = self._send_request()

            operation_in_progress = f"backup_status is '{state}'"
            error_message = (
                "Cannot perform subcloud-backup create operation: "
                f"Subcloud {self.subcloud.name} current {operation_in_progress}. "
                "Please wait until it finishes before running this operation."
            )

            self._assert_pecan_and_response(
                response,
                http.client.BAD_REQUEST,
                error_message,
                call_count=index,
            )


class TestSubcloudBackupPostGroup(BaseTestSubcloudBackupPost):
    """Test class for post requests for group resource"""

    def setUp(self):
        super().setUp()

        self.params = (
            f'{{"sysadmin_password": "{self._create_password()}",'
            f'"group": "{self.subcloud.id}"}}'
        )

    def test_post_group_succeeds(self):
        """Test post group succeeds"""

        self._update_subcloud()

        response = self._send_request()

        self._assert_response(response)

    def test_post_group_fails_with_unknown_group(self):
        """Test post group fails with unknown group"""

        self.params = (
            f'{{"sysadmin_password": "{self._create_password()}","group": "123"}}'
        )

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.NOT_FOUND, "Group not found"
        )

    def test_post_group_fails_with_subcloud_offline(self):
        """Test post group fails with subcloud offline"""

        self._update_subcloud(availability_status=dccommon_consts.AVAILABILITY_OFFLINE)

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"None of the subclouds in group {self.subcloud.id} are in "
            "a valid state for subcloud-backup create",
        )

    def test_post_group_fails_with_unmanaged_subcloud(self):
        """Test post group fails with unmanaged subcloud"""

        self._update_subcloud(management_state=dccommon_consts.MANAGEMENT_UNMANAGED)

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"None of the subclouds in group {self.subcloud.id} are in "
            "a valid state for subcloud-backup create",
        )

    def test_post_group_fails_with_subcloud_in_invalid_deploy_state(self):
        """Test post group fails with subcloud in invalid deploy state"""

        self._update_subcloud(deploy_status=consts.DEPLOY_STATE_BOOTSTRAPPING)

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"None of the subclouds in group {self.subcloud.id} are in "
            "a valid state for subcloud-backup create",
        )

    def test_post_group_fails_with_rpc_client_remote_error(self):
        """Test post group fails with rpc client remote error"""

        self._update_subcloud()

        self.mock_rpc_client().backup_subclouds.side_effect = RemoteError(
            "msg", "value"
        )

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.UNPROCESSABLE_ENTITY, "value"
        )

    def test_post_group_fails_with_rpc_client_generic_exception(self):
        """Test post group fails with rpc client generic exception"""

        self._update_subcloud()

        self.mock_rpc_client().backup_subclouds.side_effect = Exception()

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.INTERNAL_SERVER_ERROR, "Unable to backup subcloud"
        )


class BaseTestSubcloudBackupPatch(BaseTestSubcloudBackupController):
    """Base test class for patch requests"""

    def setUp(self):
        super().setUp()

        self.method = self.app.patch_json


class TestSubcloudBackupPatch(BaseTestSubcloudBackupPatch):
    """Test class for patch requests"""

    def test_patch_fails_with_invalid_verb(self):
        """Test patch fails with invalid verb"""

        self.url = f"{self.url}/fake"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Unexpected verb received"
        )

    def test_patch_fails_with_existing_verb(self):
        """Test patch fails with existing verb

        When performing a request to the endpoint, the payload is verified for
        specific verbs, i.e. create, delete and restore. Because of that, for the
        patch request to reach the Invalid request error it is necessary to use a
        verb mapped in the _get_payload method but that isn't mapped in the patch
        endpoint
        """

        self.url = f"{self.url}/create"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Invalid request"
        )


class BaseTestSubcloudBackupPatchDelete(BaseTestSubcloudBackupPatch):
    """Base test class for patch requests with delete verb"""

    def setUp(self):
        super().setUp()

        self.url = f"{self.url}/delete/22.12"

        self.mock_rpc_client().delete_subcloud_backups.return_value = (
            "delete_subcloud_backups",
            {"release_version": "22.12"},
        )


class TestSubcloudBackupPatchDelete(BaseTestSubcloudBackupPatchDelete):
    """Test class for patch requests with delete verb"""

    def setUp(self):
        super().setUp()

    def test_patch_delete_fails_with_subcloud_and_group(self):
        """Test patch delete fails with subcloud and group"""

        self.params = {
            "sysadmin_password": self._create_password(),
            "subcloud": str(self.subcloud.id),
            "group": str(self.subcloud.id),
        }

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "'subcloud' and 'group' parameters should not be given at the same time",
        )

    def test_patch_delete_fails_without_subcloud_and_group(self):
        """Test patch delete fails without subcloud and group"""

        self.params = {"sysadmin_password": self._create_password()}

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "'subcloud' or 'group' parameter is required",
        )

    def test_patch_delete_fails_without_release_version(self):
        """Test patch delete fails without release version"""

        self.url = "/v1.0/subcloud-backup/delete"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Release version required"
        )


class TestSubcloudBackupPatchDeleteSubcloud(BaseTestSubcloudBackupPatchDelete):
    """Test class for patch requests with delete verb for subcloud resource"""

    def setUp(self):
        super().setUp()

        self.params = {
            "sysadmin_password": self._create_password(),
            "subcloud": str(self.subcloud.id),
        }

    def test_patch_delete_subcloud_succeeds(self):
        """Test patch delete subcloud succeeds"""

        response = self._send_request()

        self._assert_response(response, http.client.MULTI_STATUS)

    def test_patch_delete_subcloud_succeeds_with_no_content(self):
        """Test patch delete subcloud succeeds with no content"""

        self.mock_rpc_client().delete_subcloud_backups.return_value = None

        response = self._send_request()

        self._assert_response(response, http.client.NO_CONTENT, None)

    def test_patch_delete_subcloud_succeeds_with_local_only(self):
        """Test patch delete subcloud succeeds with local only"""

        self.params["local_only"] = "True"

        self._update_subcloud()

        response = self._send_request()

        self._assert_response(response, http.client.MULTI_STATUS)

    def test_patch_delete_subcloud_succeeds_with_false_local_only(self):
        """Test patch delete subcloud succeeds with false local only"""

        self.params["local_only"] = "False"

        response = self._send_request()

        self._assert_response(response, http.client.MULTI_STATUS)

    def test_patch_delete_subcloud_fails_with_invalid_local_only(self):
        """Test patch delete subcloud fails with invalid local only"""

        self.params["local_only"] = "fake"

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Invalid local_only value, should be boolean",
        )

    def test_patch_delete_subcloud_fails_with_unknown_subcloud(self):
        """Test patch delete subcloud fails with unknown subcloud"""

        self.params["subcloud"] = "999"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Subcloud not found"
        )

    def test_patch_delete_subcloud_fails_with_rpc_client_remote_error(self):
        """Test patch delete subcloud fails with rpc client remote error"""

        self.mock_rpc_client().delete_subcloud_backups.side_effect = RemoteError(
            "msg", "value"
        )

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.UNPROCESSABLE_ENTITY, "value"
        )

    def test_patch_delete_subcloud_fails_with_rpc_client_generic_exception(self):
        """Test patch delete subcloud fails with rpc client generic exception"""

        self.mock_rpc_client().delete_subcloud_backups.side_effect = Exception()

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.INTERNAL_SERVER_ERROR,
            "Unable to delete subcloud backups",
        )

    def test_patch_delete_subcloud_fails_with_backup_index_and_local_only(self):
        """Test that backup_index cannot be combined with local_only"""

        self.params["backup_index"] = "latest"
        self.params["local_only"] = "True"

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "backup_index parameter cannot be used with "
            "local_only. Index-based deletion is only supported "
            "for centralized backups.",
        )

    def test_patch_delete_subcloud_fails_with_negative_backup_index(self):
        """Test that a negative backup_index value is rejected"""

        self.params["backup_index"] = "-1"

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "backup_index must be non-negative",
        )

    def test_patch_delete_subcloud_fails_with_invalid_backup_index_string(self):
        """Test that a non-numeric, non-alias backup_index string is rejected"""

        self.params["backup_index"] = "bad_value"

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Invalid backup_index. Must be a non-negative integer, "
            f"'{consts.BACKUP_INDEX_LATEST}', or '{consts.BACKUP_INDEX_OLDEST}'",
        )

    def test_patch_delete_subcloud_succeeds_with_backup_index_latest(self):
        """Test that backup_index='latest' is accepted and the archive is resolved"""

        archive = db_api.subcloud_backup_archive_create(
            self.ctx,
            backup_id="test-backup-latest",
            subcloud_id=self.subcloud.id,
            release_version="22.12",
            storage_location=consts.BACKUP_STORAGE_DC_VAULT,
            storage_path="/opt/dc-vault/backups/subcloud1/22.12/backup.tgz",
        )
        self.params["backup_index"] = "latest"

        response = self._send_request()

        self._assert_response(response, http.client.MULTI_STATUS)
        call_payload = self.mock_rpc_client().delete_subcloud_backups.call_args[0][2]
        self.assertEqual(call_payload["backup_id"], archive.backup_id)

    def test_patch_delete_subcloud_succeeds_with_backup_index_oldest(self):
        """Test that backup_index='oldest' resolves to the single archive"""

        archive = db_api.subcloud_backup_archive_create(
            self.ctx,
            backup_id="test-backup-oldest",
            subcloud_id=self.subcloud.id,
            release_version="22.12",
            storage_location=consts.BACKUP_STORAGE_DC_VAULT,
            storage_path="/opt/dc-vault/backups/subcloud1/22.12/backup.tgz",
        )
        self.params["backup_index"] = "oldest"

        response = self._send_request()

        self._assert_response(response, http.client.MULTI_STATUS)
        call_payload = self.mock_rpc_client().delete_subcloud_backups.call_args[0][2]
        self.assertEqual(call_payload["backup_id"], archive.backup_id)

    def test_patch_delete_subcloud_succeeds_with_numeric_backup_index(self):
        """Test that a numeric backup_index resolves to the correct archive"""

        archive = db_api.subcloud_backup_archive_create(
            self.ctx,
            backup_id="test-backup-0",
            subcloud_id=self.subcloud.id,
            release_version="22.12",
            storage_location=consts.BACKUP_STORAGE_DC_VAULT,
            storage_path="/opt/dc-vault/backups/subcloud1/22.12/backup.tgz",
        )
        self.params["backup_index"] = "0"

        response = self._send_request()

        self._assert_response(response, http.client.MULTI_STATUS)
        call_payload = self.mock_rpc_client().delete_subcloud_backups.call_args[0][2]
        self.assertEqual(call_payload["backup_id"], archive.backup_id)

    def test_patch_delete_subcloud_fails_with_backup_index_not_found(self):
        """Test that 404 is returned when no backup exists at the requested index"""

        self.params["backup_index"] = "0"
        subcloud_ref = str(self.subcloud.id)

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.NOT_FOUND,
            f"No backup found at index '0' for "
            f"subcloud '{subcloud_ref}' and release '22.12'",
        )

    def test_patch_delete_subcloud_returns_500_on_backup_index_resolve_error(self):
        """Test that it fails when resolving backup_index raises an unexpected error"""

        self.params["backup_index"] = "0"

        with mock.patch(
            "dcmanager.db.api.subcloud_backup_archive_get_all",
            side_effect=Exception("DB failure"),
        ):
            response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.INTERNAL_SERVER_ERROR,
            "Failed to resolve backup index",
        )


class TestSubcloudBackupPatchGroup(BaseTestSubcloudBackupPatchDelete):
    """Test class for patch requests with delete verb for group resource"""

    def setUp(self):
        super().setUp()

        self.params = {
            "sysadmin_password": self._create_password(),
            "group": str(self.subcloud.id),
        }

    def test_patch_delete_group_succeeds(self):
        """Test patch delete group succeeds"""

        response = self._send_request()

        self._assert_response(response, http.client.MULTI_STATUS)

    def test_patch_delete_group_fails_with_unknown_group(self):
        """Test patch delete group fails with unknown group"""

        self._update_subcloud(availability_status=dccommon_consts.AVAILABILITY_OFFLINE)

        self.params["group"] = "999"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.NOT_FOUND, "Group not found"
        )

    def test_patch_delete_group_fails_with_unmanaged_subcloud(self):
        """Test patch delete group fails with unmanaged subcloud

        The subclouds in a group are only validated when the local_only parameter
        is sent in the request. Otherwise, the validation is skipped.
        """

        self.params["local_only"] = "True"

        self._update_subcloud(management_state=dccommon_consts.MANAGEMENT_UNMANAGED)

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"None of the subclouds in group {self.subcloud.id} are in "
            "a valid state for subcloud-backup delete",
        )


class BaseTestSubcloudBackupPatchRestore(BaseTestSubcloudBackupPatch):
    """Base test class for patch requests with restore verb"""

    def setUp(self):
        super().setUp()

        self.url = f"{self.url}/restore"

    def _assert_on_site_incompatible_with(self, param=None):
        """Assert that on_site is rejected when combined with an incompatible param."""
        self.params["on_site"] = "True"
        if param is not None:
            self.params[param] = "True"

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Option on_site cannot be used with any of the following "
            "options: with_install, factory, auto or group",
        )


class TestSubcloudBackupPatchRestore(BaseTestSubcloudBackupPatchRestore):
    """Test class for patch requests with restore verb"""

    def setUp(self):
        super().setUp()

    def test_patch_restore_fails_without_params(self):
        """Test patch restore fails without params"""

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Body required"
        )

    def test_patch_restore_fails_with_subcloud_and_group(self):
        """Test patch restore fails with subcloud and group"""

        self.params = {
            "sysadmin_password": self._create_password(),
            "subcloud": str(self.subcloud.id),
            "group": str(self.subcloud.id),
        }

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "'subcloud' and 'group' parameters should not be given at the same time",
        )

    def test_patch_restore_fails_without_subcloud_and_group(self):
        """Test patch restore fails without subcloud and group"""

        self.params = {"sysadmin_password": self._create_password()}

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "'subcloud' or 'group' parameter is required",
        )


class TestSubcloudBackupPatchRestoreSubcloud(BaseTestSubcloudBackupPatchRestore):
    """Test class for patch requests with restore verb for subcloud resource"""

    def setUp(self):
        super().setUp()

        self.params = {
            "sysadmin_password": self._create_password(),
            "subcloud": str(self.subcloud.id),
        }

        self.mock_os_listdir = self._mock_object(os, "listdir")
        self.mock_os_path_isdir = self._mock_object(os.path, "isdir")

        self.mock_os_listdir.return_value = ["test.iso", "test.sig"]
        self.mock_os_path_isdir.return_value = True

        self.default_archive = self._create_restore_archive()

    def _create_restore_archive(self, backup_id="test-restore-backup"):
        return db_api.subcloud_backup_archive_create(
            self.ctx,
            backup_id=backup_id,
            subcloud_id=self.subcloud.id,
            release_version="TEST.SW.VERSION",
            storage_location=consts.BACKUP_STORAGE_DC_VAULT,
            storage_path=(
                f"/opt/dc-vault/backups/{self.subcloud.name}/"
                f"TEST.SW.VERSION/{backup_id}.tgz"
            ),
        )

    def test_patch_restore_subcloud_succeeds(self):
        """Test patch restore subcloud succeeds"""

        response = self._send_request()

        self._assert_response(response)

    def test_patch_restore_subcloud_succeeds_with_restore_values(self):
        """Test patch restore subcloud succeeds with restore values"""

        self.params["restore_values"] = FAKE_RESTORE_VALUES_VALID_IP

        response = self._send_request()

        self._assert_response(response)

    def test_patch_restore_subcloud_fails_with_invalid_ip_in_restore_values(self):
        """Test patch restore subcloud fails with invalid ip in restore values"""

        self.params["restore_values"] = FAKE_RESTORE_VALUES_INVALID_IP

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"Subcloud {self.subcloud.name} must "
            "have a valid bootstrap address: 10.10.20.12.22",
        )

    def test_patch_restore_subcloud_fails_with_invalid_restore_values(self):
        """Test patch restore subcloud fails with invalid restore values"""

        self.params["restore_values"] = {"bootstrap_address": "fake"}

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "The bootstrap_address provided in restore_values is in invalid format.",
        )

    def test_patch_restore_subcloud_fails_with_unknown_subcloud(self):
        """Test patch restore subcloud succeeds with invalid restore values"""

        self.params["subcloud"] = "999"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Subcloud not found"
        )

    def test_patch_restore_subcloud_fails_with_registry_images_only(self):
        """Test patch restore subcloud fails with registry images only"""

        self.params["registry_images"] = "True"

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Option registry_images cannot be used without local_only option.",
        )

    def test_patch_restore_subcloud_fails_with_managed_subcloud(self):
        """Test patch restore subcloud fails with managed subcloud"""

        self._update_subcloud()

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"Subcloud {self.subcloud.name} must be unmanaged and in a valid "
            "deploy state for the subcloud-backup restore operation.",
        )

    def test_patch_restore_subcloud_fails_with_subcloud_in_invalid_state(self):
        """Test patch restore subcloud fails with subcloud in invalid state"""

        for index, status in enumerate(
            consts.INVALID_DEPLOY_STATES_FOR_RESTORE, start=1
        ):
            self._update_subcloud(deploy_status=status)

            response = self._send_request()

            self._assert_pecan_and_response(
                response,
                http.client.BAD_REQUEST,
                f"Subcloud {self.subcloud.name} must be unmanaged and in a valid "
                "deploy state for the subcloud-backup restore operation.",
                call_count=index,
            )

    def test_patch_restore_subcloud_succeeds_with_install_without_release(self):
        """Test patch restore subcloud succeeds with install without release"""

        self.params["with_install"] = "True"

        data_install = str(fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES).replace("/", '"')
        self._update_subcloud(
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
            data_install=data_install,
        )

        response = self._send_request()

        self._assert_response(response)

    def test_patch_restore_subcloud_succeeds_with_install_and_release(self):
        """Test patch restore subcloud succeeds with install and release"""

        self.params["with_install"] = "True"
        self.params["release"] = "TEST.SW.VERSION"

        data_install = str(fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES).replace("/", '"')
        self._update_subcloud(
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
            data_install=data_install,
        )

        with mock.patch(
            "builtins.open",
            mock.mock_open(read_data=fake_subcloud.FAKE_UPGRADES_METADATA),
        ):
            response = self._send_request()

        self._assert_response(response)

    def test_patch_restore_subcloud_fails_with_release_without_with_install(self):
        """Test patch restore subcloud fails with release without with install"""

        self.params["release"] = "22.12"

        data_install = str(fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES).replace("/", '"')
        self._update_subcloud(
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
            data_install=data_install,
        )

        with mock.patch(
            "builtins.open",
            mock.mock_open(read_data=fake_subcloud.FAKE_UPGRADES_METADATA),
        ):
            response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Option release cannot be used without 'with_install' or "
            "'factory' options.",
        )

    def test_patch_restore_subcloud_fails_with_install_without_install_values(self):
        """Test patch restore subcloud fails with install without install values"""

        self.params["with_install"] = "True"

        self._update_subcloud(
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED, data_install=""
        )

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "The restore operation was requested with with_install, auto or "
            "factory, but the following subcloud(s) does not contain install "
            f"values: {self.subcloud.name}",
        )

    def test_patch_restore_subcloud_fails_with_install_without_matching_iso(self):
        """Test patch restore subcloud fails with install without matching iso"""

        self.params["with_install"] = "True"

        self._update_subcloud(management_state=dccommon_consts.MANAGEMENT_UNMANAGED)

        self.mock_os_listdir.return_value = ["test.sig"]

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "No matching: .iso found in vault: "
            f"{dccommon_consts.SOFTWARE_VAULT_DIR}/TEST.SW.VERSION/",
        )

    def test_patch_restore_subcloud_fails_with_install_without_matching_sig(self):
        """Test patch restore subcloud fails with install without matching sig"""

        self.params["with_install"] = "True"

        self._update_subcloud(management_state=dccommon_consts.MANAGEMENT_UNMANAGED)

        self.mock_os_listdir.return_value = ["test.iso"]

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "No matching: .sig found in vault: "
            f"{dccommon_consts.SOFTWARE_VAULT_DIR}/TEST.SW.VERSION/",
        )

    @mock.patch("dcmanager.common.utils.get_matching_iso")
    def test_patch_restore_subcloud_fails_with_invalid_release(self, matching_iso):
        """Test patch restore subcloud fails with invalid release"""

        self.params["with_install"] = "True"
        self.params["release"] = "00.00"

        matching_iso.return_value = [None, True]

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.NOT_FOUND,
            "No backup found at index 'latest' for subcloud '1' and release '00.00'",
        )

    @mock.patch("dcmanager.common.utils.get_bootstrap_values")
    def test_patch_restore_subcloud_auto_restore_fails_with_duplex(
        self, mock_get_bootstrap_values
    ):
        """Test patch restore subcloud auto-restore fails for a duplex subcloud"""

        self.params["auto"] = "True"

        mock_get_bootstrap_values.return_value = {
            "system_mode": consts.SYSTEM_MODE_DUPLEX
        }

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"{self.subcloud.name} is a {consts.SYSTEM_MODE_DUPLEX} subcloud. "
            f"Auto restore is only supported for {consts.SYSTEM_MODE_SIMPLEX} "
            "subclouds.",
        )

    @mock.patch("dcmanager.common.utils.get_bootstrap_values")
    def test_patch_restore_subcloud_auto_restore_succeeds_with_simplex(
        self, mock_get_bootstrap_values
    ):
        """Test patch restore subcloud auto-restore succeeds for a simplex subcloud"""

        self.params["auto"] = "True"

        mock_get_bootstrap_values.return_value = {
            "system_mode": consts.SYSTEM_MODE_SIMPLEX
        }

        response = self._send_request()

        self._assert_response(response)

    @mock.patch("dcmanager.common.utils.get_bootstrap_values")
    def test_patch_restore_subcloud_auto_restore_fails_with_unsupported_release(
        self, mock_get_bootstrap_values
    ):
        """Test patch subcloud auto-restore fails with an unsupported release"""

        self.params["auto"] = "True"
        self.params["with_install"] = "True"
        self.params["release"] = "22.12"

        mock_get_bootstrap_values.return_value = {
            "system_mode": consts.SYSTEM_MODE_SIMPLEX
        }

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Auto-restore and factory restore are not supported for releases "
            f"earlier than {consts.MINIMUM_AUTO_RESTORE_RELEASE}.",
        )

    @mock.patch("dcmanager.common.utils.get_bootstrap_values")
    def test_patch_restore_subcloud_factory_restore_fails_with_unsupported_release(
        self, mock_get_bootstrap_values
    ):
        """Test patch subcloud factory-restore fails with an unsupported release"""

        self.params["factory"] = "True"
        self.params["release"] = "22.12"

        mock_get_bootstrap_values.return_value = {
            "system_mode": consts.SYSTEM_MODE_SIMPLEX
        }

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Auto-restore and factory restore are not supported for releases "
            f"earlier than {consts.MINIMUM_AUTO_RESTORE_RELEASE}.",
        )

    def test_patch_restore_subcloud_fails_with_backup_index_and_local_only(self):
        """Test that backup_index cannot be combined with local_only"""

        self.params["backup_index"] = "latest"
        self.params["local_only"] = "True"

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "backup_index parameter cannot be used with local_only. Index-based "
            "restore is only supported for centralized backups.",
        )

    def test_patch_restore_subcloud_fails_with_backup_index_and_factory(self):
        """Test that backup_index cannot be combined with factory restore"""

        self.params["backup_index"] = "latest"
        self.params["factory"] = "True"

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "backup_index parameter cannot be used with factory restore. "
            "Factory restore always uses pre-installed local backup.",
        )

    def test_patch_restore_subcloud_fails_with_negative_backup_index(self):
        """Test that a negative backup_index value is rejected"""

        self.params["backup_index"] = "-1"

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "backup_index must be non-negative",
        )

    def test_patch_restore_subcloud_fails_with_invalid_backup_index_string(self):
        """Test that a non-numeric, non-alias backup_index string is rejected"""

        self.params["backup_index"] = "bad_value"

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Invalid backup_index. Must be a non-negative integer, "
            f"'{consts.BACKUP_INDEX_LATEST}', or '{consts.BACKUP_INDEX_OLDEST}'",
        )

    def test_patch_restore_subcloud_succeeds_with_backup_index_latest(self):
        """Test that backup_index='latest' resolves the correct archive"""
        latest_archive = self._create_restore_archive(backup_id="latest-backup")

        self.params["backup_index"] = "latest"

        response = self._send_request()

        self._assert_response(response)
        call_payload = self.mock_rpc_client().restore_subcloud_backups.call_args[0][1]
        self.assertEqual(call_payload["backup_id"], latest_archive.backup_id)

    def test_patch_restore_subcloud_succeeds_with_backup_index_oldest(self):
        """Test that backup_index='oldest' resolves to the single archive"""
        self._create_restore_archive(backup_id="latest-backup")

        self.params["backup_index"] = "oldest"

        response = self._send_request()

        self._assert_response(response)
        call_payload = self.mock_rpc_client().restore_subcloud_backups.call_args[0][1]
        self.assertEqual(call_payload["backup_id"], self.default_archive.backup_id)

    def test_patch_restore_subcloud_succeeds_with_numeric_backup_index(self):
        """Test that a numeric backup_index resolves to the correct archive"""
        latest_archive = self._create_restore_archive(backup_id="latest-backup")

        self.params["backup_index"] = "0"

        response = self._send_request()

        self._assert_response(response)
        call_payload = self.mock_rpc_client().restore_subcloud_backups.call_args[0][1]
        self.assertEqual(call_payload["backup_id"], latest_archive.backup_id)

    def test_patch_restore_subcloud_fails_with_backup_index_not_found(self):
        """Test that 404 is returned when no backup exists at the requested index"""

        # setUp creates exactly 1 archive (index 0); index 1 does not exist
        self.params["backup_index"] = "1"

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.NOT_FOUND,
            f"No backup found at index '1' for "
            f"subcloud '{self.params['subcloud']}' and release 'TEST.SW.VERSION'",
        )

    def test_patch_restore_subcloud_returns_500_on_backup_index_resolve_error(self):
        """Test that 500 is returned when resolving backup_index raises an error"""

        self.params["backup_index"] = "0"

        with mock.patch(
            "dcmanager.db.api.subcloud_backup_archive_get_all",
            side_effect=Exception("Mocked DB failure"),
        ):
            response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.INTERNAL_SERVER_ERROR,
            "Failed to resolve backup index",
        )

    def test_patch_restore_subcloud_defaults_to_latest_for_centralized(self):
        """Test that backup_index defaults to 'latest' when not specified"""
        latest_archive = self._create_restore_archive(backup_id="latest-backup")

        response = self._send_request()

        self._assert_response(response)
        call_payload = self.mock_rpc_client().restore_subcloud_backups.call_args[0][1]
        self.assertEqual(call_payload["backup_index"], consts.BACKUP_INDEX_LATEST)
        self.assertEqual(call_payload["backup_id"], latest_archive.backup_id)

    def test_patch_restore_local_only_does_not_default_backup_index(self):
        """Test that backup_index is NOT defaulted for local-only restore"""

        self.params["local_only"] = "True"

        response = self._send_request()

        self._assert_response(response)
        call_payload = self.mock_rpc_client().restore_subcloud_backups.call_args[0][1]
        self.assertNotIn("backup_index", call_payload)

    def test_patch_restore_factory_does_not_default_backup_index(self):
        """Test that backup_index is NOT defaulted for factory restore"""

        self.params["factory"] = "True"
        self.params["restore_values"] = FAKE_RESTORE_VALUES_VALID_IP

        response = self._send_request()

        self._assert_response(response)
        call_payload = self.mock_rpc_client().restore_subcloud_backups.call_args[0][1]
        self.assertNotIn("backup_index", call_payload)

    def test_patch_restore_on_site_local_only_succeeds(self):
        """Test on_site restore with local_only succeeds"""

        self.params["on_site"] = "True"
        self.params["local_only"] = "True"

        response = self._send_request()

        self._assert_response(response)
        call_payload = self.mock_rpc_client().restore_subcloud_backups.call_args[0][1]
        self.assertTrue(call_payload["on_site"])
        self.assertTrue(call_payload["local_only"])

    def test_patch_restore_on_site_succeeds(self):
        """Test on_site restore without local_only succeeds"""

        self.params["on_site"] = "True"

        response = self._send_request()

        self._assert_response(response)
        call_payload = self.mock_rpc_client().restore_subcloud_backups.call_args[0][1]
        self.assertTrue(call_payload["on_site"])

    def test_patch_restore_on_site_succeeds_with_restore_values(self):
        """Test on_site restore succeeds when combined with restore_values"""

        self.params["on_site"] = "True"
        self.params["restore_values"] = FAKE_RESTORE_VALUES_VALID_IP

        response = self._send_request()

        self._assert_response(response)

    def test_patch_restore_on_site_fails_with_with_install(self):
        """Test on_site restore fails when combined with with_install"""
        self._assert_on_site_incompatible_with("with_install")

    def test_patch_restore_on_site_fails_with_factory(self):
        """Test on_site restore fails when combined with factory"""
        self._assert_on_site_incompatible_with("factory")

    def test_patch_restore_on_site_fails_with_auto(self):
        """Test on_site restore fails when combined with auto"""
        self._assert_on_site_incompatible_with("auto")


class TestSubcloudBackupPatchRestoreGroup(BaseTestSubcloudBackupPatchRestore):
    """Test class for patch requests with restore verb for group resource"""

    def setUp(self):
        super().setUp()

        self.params = {
            "sysadmin_password": self._create_password(),
            "group": str(self.subcloud.id),
        }

    def test_patch_restore_group_succeeds(self):
        """Test patch restore group succeeds"""

        response = self._send_request()

        self._assert_response(response)

    def test_patch_restore_group_succeeds_with_multiple_subclouds(self):
        """Test patch restore group succeeds with multiple subclouds

        The subcloud, when created, starts with the management_state as UNMANAGED.
        Because of that, there'll be an invalid and a valid subcloud in the group.
        """

        fake_subcloud.create_fake_subcloud(
            self.ctx,
            group_id=self.subcloud.id,
            name=base.SUBCLOUD_2["name"],
            region_name=base.SUBCLOUD_2["region_name"],
        )

        self._update_subcloud()

        response = self._send_request()

        self._assert_response(response)

    def test_patch_restore_group_fails_with_unknown_group(self):
        """Test patch restore group fails with unknown group"""

        self.params["group"] = "999"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.NOT_FOUND, "Group not found"
        )

    def test_patch_restore_group_without_subclouds_in_group(self):
        """Test patch restore group without subclouds in group"""

        self._update_subcloud(group_id=999)

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "No subclouds present in group"
        )

    def test_patch_restore_fails_with_rpc_client_remote_error(self):
        """Test patch restore fails when rpc client raises a remote error"""

        self.mock_rpc_client().restore_subcloud_backups.side_effect = RemoteError(
            "msg", "value"
        )

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.UNPROCESSABLE_ENTITY, "value"
        )

    def test_patch_restore_fails_with_rpc_client_generic_exception(self):
        """Test patch restore fails when rpc client raises a generic exception"""

        self.mock_rpc_client().restore_subcloud_backups.side_effect = Exception()

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.INTERNAL_SERVER_ERROR, "Unable to restore subcloud"
        )

    def test_patch_restore_on_site_fails_with_group(self):
        """Test on_site restore fails when combined with group"""
        # group is already set in self.params by setUp
        self._assert_on_site_incompatible_with()


class TestSubcloudBackupGet(BaseTestSubcloudBackupController):
    """Test class for get (backup list) requests"""

    def setUp(self):
        super().setUp()
        self.method = self.app.get

    def _create_backup_archive(
        self,
        backup_id,
        subcloud_id=None,
        release_version="25.09",
        storage_location="dc-vault",
        size_bytes=10000,
    ):
        return db_api.subcloud_backup_archive_create(
            self.ctx,
            backup_id=backup_id,
            subcloud_id=subcloud_id or self.subcloud.id,
            release_version=release_version,
            storage_location=storage_location,
            size_bytes=size_bytes,
            storage_path=f"/path/to/backup_{backup_id}",
        )

    def _create_subcloud_and_group(self):
        group = fake_subcloud.create_fake_subcloud_group(self.ctx, name="new-group")
        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx,
            name="new-subcloud",
            region_name="new-region",
            group_id=group.id,
        )
        return subcloud, group

    def test_get_succeeds_with_no_filters(self):
        """Test get succeeds with no filters"""
        self._create_backup_archive("backup-1")
        self._create_backup_archive("backup-2")

        response = self._send_request()

        self._assert_response(response)
        response_data = json.loads(response.text)
        self.assertIn("backups", response_data)
        self.assertEqual(len(response_data["backups"]), 2)

    def test_get_succeeds_with_subcloud_filter(self):
        """Test get succeeds with subcloud filter"""
        self._create_backup_archive("backup-1")

        new_subcloud, _ = self._create_subcloud_and_group()
        self._create_backup_archive("backup-2", new_subcloud.id)

        for subcloud_ref in (self.subcloud.name, self.subcloud.id):
            self.params = {"subcloud": str(subcloud_ref)}

            response = self._send_request()

            self._assert_response(response)
            response_data = json.loads(response.text)
            self.assertEqual(len(response_data["backups"]), 1)
            self.assertEqual(
                response_data["backups"][0]["subcloud"], self.subcloud.name
            )

    def test_get_succeeds_with_group_filter(self):
        """Test get succeeds with group filter"""
        group = fake_subcloud.create_fake_subcloud_group(self.ctx)
        self._update_subcloud(group_id=group.id)
        self._create_backup_archive("backup-1")

        self._create_subcloud_and_group()

        for group_ref in (group.name, group.id):
            self.params = {"group": str(group_ref)}

            response = self._send_request()

            self._assert_response(response)
            response_data = json.loads(response.text)
            self.assertEqual(
                response_data["backups"][0]["subcloud"], self.subcloud.name
            )
            self.assertEqual(len(response_data["backups"]), 1)

    def test_get_succeeds_with_release_filter(self):
        """Test get succeeds with release filter"""
        self._create_backup_archive("backup-1", release_version="22.12")
        self._create_backup_archive("backup-2", release_version="25.09")

        self.params = {"release": "22.12"}

        response = self._send_request()

        self._assert_response(response)
        response_data = json.loads(response.text)
        self.assertEqual(len(response_data["backups"]), 1)
        self.assertEqual(response_data["backups"][0]["release"], "22.12")

    def test_get_succeeds_with_storage_filter(self):
        """Test get succeeds with storage filter"""
        self._create_backup_archive("backup-1", storage_location="dc-vault")
        self._create_backup_archive("backup-2", storage_location="seaweedfs")

        self.params = {"storage": "seaweedfs"}

        response = self._send_request()

        self._assert_response(response)
        response_data = json.loads(response.text)
        self.assertEqual(len(response_data["backups"]), 1)
        self.assertEqual(response_data["backups"][0]["storage"], "seaweedfs")

    def test_get_fails_with_invalid_storage_filter(self):
        """Test get fails with invalid storage filter"""
        self.params = {"storage": "invalid-storage"}

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Invalid location filter, must be one of ['dc-vault', 'seaweedfs']",
        )

    def test_get_fails_with_unknown_subcloud(self):
        """Test get returns empty list with unknown subcloud"""
        self._create_backup_archive("backup-1")
        self.params = {"subcloud": "unknown-subcloud"}

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.NOT_FOUND,
            "Subcloud backup filter 'unknown-subcloud' not found",
        )

    def test_get_fails_with_unknown_group(self):
        """Test get returns empty list with unknown group"""
        self._create_backup_archive("backup-1")
        self.params = {"group": "unknown-group"}

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.NOT_FOUND,
            "Group backup filter 'unknown-group' not found",
        )

    def test_get_fails_with_subcloud_and_group_filters(self):
        """Test get fails when using both the group and subcloud filters"""
        self._create_backup_archive("backup-1")
        _, group = self._create_subcloud_and_group()

        self.params = {"subcloud": self.subcloud.name, "group": group.name}

        response = self._send_request()
        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "The 'subcloud' and 'group' parameters are mutually exclusive",
        )

    def test_get_formats_backup_indices_correctly(self):
        """Test get formats backup indices correctly based on creation time"""
        subcloud2 = fake_subcloud.create_fake_subcloud(
            self.ctx, name="subcloud2", region_name="region2"
        )

        self._create_backup_archive("old", release_version="22.12")
        time.sleep(0.1)  # Just to make sure the created-at timestamp will be different
        self._create_backup_archive("new", release_version="22.12")
        self._create_backup_archive("single", release_version="23.09")
        self._create_backup_archive("other", subcloud2.id, release_version="22.12")

        response = self._send_request()

        self._assert_response(response)
        response_data = json.loads(response.text)

        self.assertEqual(len(response_data["backups"]), 4)

        backups_by_id = {b["backup_id"]: b for b in response_data["backups"]}

        # For subcloud1 + 22.12: backup "new" should have index 0,
        # backup "old" should have index 1
        self.assertEqual(backups_by_id["new"]["backup_index"], 0)
        self.assertEqual(backups_by_id["old"]["backup_index"], 1)

        # Single backups should have index 0
        self.assertEqual(backups_by_id["single"]["backup_index"], 0)
        self.assertEqual(backups_by_id["other"]["backup_index"], 0)


@mock.patch("dcmanager.api.controllers.v1.subcloud_backup.policy.authorize")
class TestSubcloudBackupPolicy(BaseTestSubcloudBackupController):
    """Test class for policy enforcement"""

    def test_get_enforces_policy(self, mock_authorize):
        """Test GET request enforces policy"""

        self.method = self.app.get
        self._send_request()

        mock_authorize.assert_called_once()
        self.assertIn("list", mock_authorize.call_args[0][0])
