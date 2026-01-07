#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import http.client

import mock

from dcmanager.api.controllers.v1 import subcloud_backup_config
from dcmanager.common import consts
from dcmanager.db import api as db_api
from dcmanager.db.sqlalchemy.api import get_session
from dcmanager.db.sqlalchemy import models
from dcmanager.tests.unit.api.controllers.v1.mixins import APIMixin
from dcmanager.tests.unit.api.test_root_controller import DCManagerApiTest


def create_backup_config():
    # There's no DB API method to create the backup config, so we
    # do it manually to support the unit tests.
    with db_api.get_engine().begin():
        backup_config = models.SubcloudBackupConfig()
        backup_config.storage_location = consts.BACKUP_STORAGE_DC_VAULT
        backup_config.retention_count = consts.DEFAULT_BACKUP_RETENTION_COUNT
        session = get_session()
        session.add(backup_config)
        session.flush()


class BaseTestSubcloudBackupConfigController(DCManagerApiTest, APIMixin):
    """Base test class for SubcloudBackupConfigController"""

    API_PREFIX = "/v1.0/subcloud-backup-config"
    RESULT_KEY = "subcloud_backup_config"
    EXPECTED_FIELDS = ["storage_location", "retention_count", "updated_at"]

    def setUp(self):
        super().setUp()

        self.url = self.API_PREFIX

        # Ensure the backup config record exists for tests
        create_backup_config()

    def _get_backup_config(self):
        return db_api.subcloud_backup_config_get(self.ctx)

    # The following methods are required for subclasses of APIMixin
    def get_api_prefix(self):
        return self.API_PREFIX

    def get_result_key(self):
        return self.RESULT_KEY

    def get_expected_api_fields(self):
        return self.EXPECTED_FIELDS

    def get_omitted_api_fields(self):
        return []

    def _create_db_object(self, context, **kw):
        # For backup config, we update the existing record rather than
        # create a new one.
        values = {}
        if "storage_location" in kw:
            values["storage_location"] = kw["storage_location"]
        if "retention_count" in kw:
            values["retention_count"] = kw["retention_count"]

        if values:
            return db_api.subcloud_backup_config_update(context, values)
        return db_api.subcloud_backup_config_get(context)

    def get_post_object(self):
        # Backup config doesn't support POST, only GET and PATCH
        return {}

    def get_update_object(self):
        return {"retention_count": 5}


class TestSubcloudBackupConfigController(BaseTestSubcloudBackupConfigController):
    """Test class for SubcloudBackupConfigController"""

    def test_unmapped_method(self):
        """Test requesting an unmapped method results in success with null content"""

        self.method = self.app.put

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(response.text, "null")


class TestSubcloudBackupConfigGet(BaseTestSubcloudBackupConfigController):
    """Test class for get requests"""

    def setUp(self):
        super().setUp()

        self.method = self.app.get

    def test_get_succeeds_with_default_config(self):
        """Test get succeeds with default backup configuration"""

        response = self._send_request()

        self._assert_response(response)

        # Verify the response contains expected fields
        config = response.json
        self.assertIn("storage_location", config)
        self.assertIn("retention_count", config)
        self.assertIn("updated_at", config)

        # Verify default values
        self.assertEqual(config["storage_location"], consts.BACKUP_STORAGE_DC_VAULT)
        self.assertEqual(
            config["retention_count"], consts.DEFAULT_BACKUP_RETENTION_COUNT
        )

    @mock.patch("dcmanager.db.api.subcloud_backup_config_get")
    def test_get_fails_on_db_error(self, mock_db_get):
        """Test get fails when database error occurs"""

        mock_db_get.side_effect = Exception("Database error")

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.INTERNAL_SERVER_ERROR,
            "Failed to retrieve backup configuration",
        )


class TestSubcloudBackupConfigPatch(BaseTestSubcloudBackupConfigController):
    """Test class for patch requests"""

    def setUp(self):
        super().setUp()

        self.method = self.app.patch_json

    def test_patch_fails_with_empty_body(self):
        """Test patch fails when request body is empty"""

        self.params = {}

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Body required"
        )

    def test_patch_fails_with_invalid_json(self):
        """Test patch fails when request body is not valid JSON"""

        self.params = "invalid json"

        response = self._send_request()

        # The controller calls pecan.abort twice in the exception chain
        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Request body must be valid JSON",
            call_count=2,
        )

    def test_patch_fails_with_no_parameters(self):
        """Test patch fails when no valid parameters provided"""

        self.params = {"invalid_param": "value"}

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "At least one parameter must be provided",
        )

    def test_patch_succeeds_with_storage_location(self):
        """Test patch succeeds with valid storage location"""

        self.params = {"storage_location": consts.BACKUP_STORAGE_SEAWEEDFS}

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(
            response.json["storage_location"], consts.BACKUP_STORAGE_SEAWEEDFS
        )

        # Verify database was updated
        config = self._get_backup_config()
        self.assertEqual(config.storage_location, consts.BACKUP_STORAGE_SEAWEEDFS)

    def test_patch_succeeds_with_retention_count(self):
        """Test patch succeeds with valid retention count"""

        self.params = {"retention_count": 7}

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(response.json["retention_count"], 7)

        # Verify database was updated
        config = self._get_backup_config()
        self.assertEqual(config.retention_count, 7)

    def test_patch_succeeds_with_both_parameters(self):
        """Test patch succeeds with both storage location and retention count"""

        self.params = {
            "storage_location": consts.BACKUP_STORAGE_SEAWEEDFS,
            "retention_count": 10,
        }

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(
            response.json["storage_location"], consts.BACKUP_STORAGE_SEAWEEDFS
        )
        self.assertEqual(response.json["retention_count"], 10)

        # Verify database was updated
        config = self._get_backup_config()
        self.assertEqual(config.storage_location, consts.BACKUP_STORAGE_SEAWEEDFS)
        self.assertEqual(config.retention_count, 10)

    def test_patch_fails_with_invalid_storage_location(self):
        """Test patch fails with invalid storage location"""

        self.params = {"storage_location": "invalid-location"}

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Invalid storage_location. Must be one of: dc-vault, seaweedfs",
        )

    def test_patch_accepts_case_insensitive_storage_location(self):
        """Test patch accepts case insensitive storage location"""

        self.params = {"storage_location": "DC-VAULT"}

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(
            response.json["storage_location"], consts.BACKUP_STORAGE_DC_VAULT
        )

    def test_patch_accepts_all_valid_storage_locations(self):
        """Test patch accepts all valid storage locations"""

        for location in consts.BACKUP_STORAGE_LOCATIONS:
            self.params = {"storage_location": location}

            response = self._send_request()

            self._assert_response(response)
            self.assertEqual(response.json["storage_location"], location.lower())

    def test_patch_fails_with_retention_count_below_minimum(self):
        """Test patch fails with retention count below minimum"""

        self.params = {"retention_count": consts.MIN_BACKUP_RETENTION_COUNT - 1}

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"retention_count must be between "
            f"{consts.MIN_BACKUP_RETENTION_COUNT} and "
            f"{consts.MAX_BACKUP_RETENTION_COUNT}",
        )

    def test_patch_fails_with_retention_count_above_maximum(self):
        """Test patch fails with retention count above maximum"""

        self.params = {"retention_count": consts.MAX_BACKUP_RETENTION_COUNT + 1}

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"retention_count must be between "
            f"{consts.MIN_BACKUP_RETENTION_COUNT} and "
            f"{consts.MAX_BACKUP_RETENTION_COUNT}",
        )

    def test_patch_accepts_retention_count_boundary_values(self):
        """Test patch accepts retention count at minimum and maximum boundaries"""

        # Minimum boundary
        self.params = {"retention_count": consts.MIN_BACKUP_RETENTION_COUNT}
        response = self._send_request()
        self._assert_response(response)
        self.assertEqual(
            response.json["retention_count"], consts.MIN_BACKUP_RETENTION_COUNT
        )

        # Maximum boundary
        self.params = {"retention_count": consts.MAX_BACKUP_RETENTION_COUNT}
        response = self._send_request()
        self._assert_response(response)
        self.assertEqual(
            response.json["retention_count"], consts.MAX_BACKUP_RETENTION_COUNT
        )

    def test_patch_fails_with_retention_count_zero(self):
        """Test patch fails with retention count of zero"""

        self.params = {"retention_count": 0}

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"retention_count must be between "
            f"{consts.MIN_BACKUP_RETENTION_COUNT} and "
            f"{consts.MAX_BACKUP_RETENTION_COUNT}",
        )

    def test_patch_fails_with_retention_count_negative(self):
        """Test patch fails with negative retention count"""

        self.params = {"retention_count": -1}

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "retention_count must be a positive integer",
        )

    def test_patch_fails_with_retention_count_non_integer_string(self):
        """Test patch fails with non-integer string for retention count"""

        self.params = {"retention_count": "not-a-number"}

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "retention_count must be a positive integer",
        )

    def test_patch_accepts_retention_count_as_string(self):
        """Test patch accepts string representation of valid retention count"""

        valid_count = 5
        self.params = {"retention_count": str(valid_count)}

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(response.json["retention_count"], valid_count)

    def test_patch_fails_retention_count_as_float(self):
        """Test patch fails with a float for retention count"""

        self.params = {"retention_count": 5.5}

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "retention_count must be a positive integer",
        )

    @mock.patch.object(
        subcloud_backup_config.SubcloudBackupConfigController,
        "_validate_seaweedfs_state",
    )
    def test_patch_validates_seaweedfs_when_switching_to_seaweedfs(
        self, mock_validate_seaweedfs
    ):
        """Test patch validates SeaweedFS state when switching to SeaweedFS"""

        self.params = {"storage_location": consts.BACKUP_STORAGE_SEAWEEDFS}

        response = self._send_request()

        self._assert_response(response)
        mock_validate_seaweedfs.assert_called_once()

    @mock.patch.object(
        subcloud_backup_config.SubcloudBackupConfigController,
        "_validate_seaweedfs_state",
    )
    def test_patch_does_not_validate_seaweedfs_for_dcvault(
        self, mock_validate_seaweedfs
    ):
        """Test patch does not validate SeaweedFS when using dc-vault"""

        self.params = {"storage_location": consts.BACKUP_STORAGE_DC_VAULT}

        response = self._send_request()

        self._assert_response(response)
        mock_validate_seaweedfs.assert_not_called()

    @mock.patch.object(subcloud_backup_config, "LOG")
    def test_patch_fails_when_seaweedfs_validation_fails(self, mock_log):
        """Test patch fails when SeaweedFS validation fails"""

        # TODO(gherzmann): Update this unit test when support for SeaweedFS is added
        mock_log.info.side_effect = Exception("SeaweedFS not available")
        self.params = {"storage_location": consts.BACKUP_STORAGE_SEAWEEDFS}

        response = self._send_request()

        # The exception should be caught and converted to a 400 error
        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Cannot switch to SeaweedFS: service not available",
        )
        mock_log.info.assert_called_once()

    @mock.patch("dcmanager.db.api.subcloud_backup_config_update")
    def test_patch_fails_on_db_update_error(self, mock_db_update):
        """Test patch fails when database update fails"""

        mock_db_update.side_effect = Exception("Database error")
        self.params = {"retention_count": 5}

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.INTERNAL_SERVER_ERROR,
            "Failed to update backup configuration",
        )

    def test_patch_returns_updated_timestamp(self):
        """Test patch returns updated timestamp in response"""

        self.params = {"retention_count": 3}

        response = self._send_request()

        self._assert_response(response)
        self.assertIsNotNone(response.json.get("updated_at"))

    def test_patch_preserves_unchanged_values(self):
        """Test patch preserves values that are not being updated"""

        # Update only retention_count
        self.params = {"retention_count": 9}
        response = self._send_request()

        self._assert_response(response)
        # Storage location should remain unchanged (default value)
        self.assertEqual(
            response.json["storage_location"], consts.BACKUP_STORAGE_DC_VAULT
        )
        # Retention count should be updated
        self.assertEqual(response.json["retention_count"], 9)


class TestSubcloudBackupConfigPolicy(BaseTestSubcloudBackupConfigController):
    """Test class for policy enforcement"""

    @mock.patch("dcmanager.api.controllers.v1.subcloud_backup_config.policy.authorize")
    def test_get_enforces_policy(self, mock_authorize):
        """Test GET request enforces policy"""

        self.method = self.app.get
        self._send_request()

        mock_authorize.assert_called_once()
        self.assertIn("get", mock_authorize.call_args[0][0])

    @mock.patch("dcmanager.api.controllers.v1.subcloud_backup_config.policy.authorize")
    def test_patch_enforces_policy(self, mock_authorize):
        """Test PATCH request enforces policy"""

        self.method = self.app.patch
        self.params = {"retention_count": 5}
        self._send_request()

        mock_authorize.assert_called_once()
        self.assertIn("modify", mock_authorize.call_args[0][0])
