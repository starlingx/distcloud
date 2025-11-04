# Copyright (c) 2020-2024 Wind River Systems, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

import builtins
import http.client
import os

import mock
from tsconfig.tsconfig import SW_VERSION
import webtest

from dcmanager.api.controllers.v1 import subcloud_deploy
from dcmanager.common import consts
from dcmanager.common import utils as dutils
from dcmanager.tests.base import FakeException
from dcmanager.tests.unit.api.test_root_controller import DCManagerApiTest
from dcmanager.tests.unit.common import fake_subcloud

FAKE_SOFTWARE_VERSION = "22.12"
FAKE_DEPLOY_PLAYBOOK_FILE = "deployment-manager.yaml"
FAKE_DEPLOY_OVERRIDES_FILE = "deployment-manager-overrides-subcloud.yaml"
FAKE_DEPLOY_CHART_FILE = "deployment-manager.tgz"
FAKE_DEPLOY_FILES = {
    f"{consts.DEPLOY_PLAYBOOK}_": FAKE_DEPLOY_PLAYBOOK_FILE,
    f"{consts.DEPLOY_OVERRIDES}_": FAKE_DEPLOY_OVERRIDES_FILE,
    f"{consts.DEPLOY_CHART}_": FAKE_DEPLOY_CHART_FILE,
}


class BaseTestSubcloudDeployController(DCManagerApiTest):
    """Base class for testing the SubcloudDeployController"""

    def setUp(self):
        super().setUp()

        self.url = "/v1.0/subcloud-deploy"

        self.mock_os_path_isdir = self._mock_object(os.path, "isdir")
        self.mock_os_remove = self._mock_object(os, "remove")
        self._mock_object(os, "mkdir")
        self.mock_os_open = self._mock_object(os, "open")
        self._mock_object(os, "write")
        self.mock_builtins_open = self._mock_object(builtins, "open")
        self.mock_get_filename_by_prefix = self._mock_object(
            dutils, "get_filename_by_prefix"
        )
        self._setup_get_filename_by_prefix()

    def _setup_get_filename_by_prefix(self):
        self.mock_get_filename_by_prefix.side_effect = (
            self._mock_get_filename_by_prefix_side_effect
        )

    def _mock_get_filename_by_prefix_side_effect(self, _, prefix):
        filename = FAKE_DEPLOY_FILES.get(prefix)

        return f"{prefix}{filename}" if filename else None

    def _create_fake_fields(self, file_options=None, is_file_upload=True):
        file_options = file_options or consts.DEPLOY_COMMON_FILE_OPTIONS
        fields = []

        for file_option in file_options:
            fake_name = f"{file_option}_fake"
            fake_content = "fake content".encode("utf-8")

            if is_file_upload:
                fields.append([file_option, webtest.Upload(fake_name, fake_content)])
            else:
                fields.append([file_option, fake_name, fake_content])

        return fields


class TestSubcloudDeployController(BaseTestSubcloudDeployController):
    """Test class for SubcloudDeployController"""

    def setUp(self):
        super().setUp()

    def test_unmapped_method(self):
        """Test requesting an unmapped method results in success with null content"""

        self.method = self.app.put

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(response.text, "null")


class TestSubcloudDeployPost(BaseTestSubcloudDeployController):
    """Test class for post requests"""

    def setUp(self):
        super().setUp()

        self.method = self.app.post
        self.upload_files = self._create_fake_fields(is_file_upload=False)

        self.mock_builtins_open.side_effect = mock.mock_open(
            read_data=fake_subcloud.FAKE_UPGRADES_METADATA
        )

    def test_post_succeeds_with_params(self):
        """Test post succeeds with params"""

        self.params = [("release", FAKE_SOFTWARE_VERSION)]
        self.params += self._create_fake_fields()
        self.upload_files = None

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(FAKE_SOFTWARE_VERSION, response.json["software_version"])
        self.assertEqual(self.mock_builtins_open.call_count, len(self.params))

    def test_post_succeeds_without_release(self):
        """Test post succeeds without release"""

        response = self._send_request()

        self._assert_response(response)
        # Verify the active release will be returned if release isn't present
        self.assertEqual(SW_VERSION, response.json["software_version"])
        self.assertEqual(self.mock_builtins_open.call_count, 4)

    def test_post_fails_with_missing_deploy_chart(self):
        """Test post fails with missing deploy chart"""

        file_options = [
            consts.DEPLOY_PLAYBOOK,
            consts.DEPLOY_OVERRIDES,
            consts.DEPLOY_PRESTAGE,
        ]
        self.upload_files = self._create_fake_fields(file_options, False)

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"error: argument --{consts.DEPLOY_CHART} is required",
        )

    def test_post_fails_with_missing_deploy_chart_and_deploy_prestage(self):
        """Test post fails with missing deploy chart and deploy prestage"""

        file_options = [consts.DEPLOY_PLAYBOOK, consts.DEPLOY_OVERRIDES]
        self.upload_files = self._create_fake_fields(file_options, False)

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"error: argument --{consts.DEPLOY_CHART} is required",
        )

    def test_post_fails_with_missing_deploy_playbook(self):
        """Test post fails with missing deploy playbook"""

        file_options = [
            consts.DEPLOY_CHART,
            consts.DEPLOY_OVERRIDES,
            consts.DEPLOY_PRESTAGE,
        ]
        self.upload_files = self._create_fake_fields(file_options, False)

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"error: argument --{consts.DEPLOY_PLAYBOOK} is required",
        )

    def test_post_succeeds_with_missing_deploy_prestage(self):
        """Test post succeeds with missing deploy prestage"""

        file_options = [
            consts.DEPLOY_PLAYBOOK,
            consts.DEPLOY_OVERRIDES,
            consts.DEPLOY_CHART,
        ]
        self.upload_files = self._create_fake_fields(file_options, False)

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(self.mock_builtins_open.call_count, len(self.upload_files))

    def test_post_succeeds_with_empty_dir_path(self):
        """Test post succeeds with empty dir_path"""

        self.mock_os_path_isdir.return_value = False

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(self.mock_builtins_open.call_count, 4)

    def test_post_succeeds_with_deploy_prestage(self):
        """Test post succeeds with deploy prestage"""

        file_options = [consts.DEPLOY_PRESTAGE]
        self.upload_files = self._create_fake_fields(file_options, False)

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(self.mock_builtins_open.call_count, 1)

    def test_post_fails_for_subcloud_deploy_missing_file_name(self):
        """Test post fails when a file option has an empty name is missing"""

        self.upload_files = self._create_fake_fields(is_file_upload=False)
        self.upload_files[0][1] = ""

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"No {consts.DEPLOY_PLAYBOOK} file uploaded",
        )

    def test_post_fails_with_internal_server_error(self):
        """Test post fails with internal server error"""

        self.mock_os_remove.side_effect = FakeException("fake file name")

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.INTERNAL_SERVER_ERROR,
            f"Failed to upload {consts.DEPLOY_PLAYBOOK} file: fake file name",
        )


class TestSubcloudDeployGet(BaseTestSubcloudDeployController):
    """Test class for get requests"""

    def setUp(self):
        super().setUp()

        self.url = f"{self.url}/{FAKE_SOFTWARE_VERSION}"
        self.method = self.app.get

        self.mock_builtins_open.side_effect = mock.mock_open(
            read_data=fake_subcloud.FAKE_UPGRADES_METADATA
        )

    def test_get_succeeds_with_release(self):
        """Test get succeeds with release"""

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(
            FAKE_SOFTWARE_VERSION, response.json["subcloud_deploy"]["software_version"]
        )
        self.assertEqual(
            FAKE_DEPLOY_PLAYBOOK_FILE,
            response.json["subcloud_deploy"][consts.DEPLOY_PLAYBOOK],
        )
        self.assertEqual(
            FAKE_DEPLOY_OVERRIDES_FILE,
            response.json["subcloud_deploy"][consts.DEPLOY_OVERRIDES],
        )
        self.assertEqual(
            FAKE_DEPLOY_CHART_FILE,
            response.json["subcloud_deploy"][consts.DEPLOY_CHART],
        )
        self.assertEqual(None, response.json["subcloud_deploy"][consts.DEPLOY_PRESTAGE])

    def test_get_succeeds_without_release(self):
        """Test get succeeds without release"""

        self.mock_os_path_isdir.return_value = True

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(
            FAKE_SOFTWARE_VERSION, response.json["subcloud_deploy"]["software_version"]
        )
        self.assertEqual(
            FAKE_DEPLOY_PLAYBOOK_FILE,
            response.json["subcloud_deploy"][consts.DEPLOY_PLAYBOOK],
        )
        self.assertEqual(
            FAKE_DEPLOY_OVERRIDES_FILE,
            response.json["subcloud_deploy"][consts.DEPLOY_OVERRIDES],
        )
        self.assertEqual(
            FAKE_DEPLOY_CHART_FILE,
            response.json["subcloud_deploy"][consts.DEPLOY_CHART],
        )
        self.assertEqual(None, response.json["subcloud_deploy"][consts.DEPLOY_PRESTAGE])


class TestSubcloudDeployDelete(BaseTestSubcloudDeployController):
    """Test class for delete requests"""

    def setUp(self):
        super().setUp()

        self.method = self.app.delete

        self.mock_log = self._mock_object(subcloud_deploy, "LOG")
        self.mock_get_sw_version = self._mock_object(dutils, "get_sw_version")

        self.sw_version_directory = "/opt/platform/deploy/"
        self.version = FAKE_SOFTWARE_VERSION

        self.mock_get_sw_version.return_value = self.version
        self.mock_os_path_isdir.side_effect = self._mock_os_path_isdir_side_effect
        self.mock_os_remove.return_value = None

    def _mock_os_path_isdir_side_effect(self, dir_path):
        return dir_path == f"{self.sw_version_directory}{self.version}"

    def test_delete_succeeds_with_release(self):
        """Test delete succeeds with release"""

        self.url = (
            f"{self.url}/{self.version}?prestage_images=False&deployment_files=False"
        )

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(self.mock_os_remove.call_count, 3)

    def test_delete_succeeds_with_deployment_files(self):
        """Test delete succeeds with deployment files"""

        self.url = f"{self.url}?prestage_images=False&deployment_files=True"

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(self.mock_os_remove.call_count, 3)

    def test_delete_succeeds_with_prestage_images(self):
        """Test delete succeeds with prestage images"""

        self.url = f"{self.url}?prestage_images=True&deployment_files=False"

        response = self._send_request()

        self._assert_response(response)
        self.mock_log.warning.assert_called_with("prestage_images file not present")

    def test_delete_succeeds_with_prestage_images_and_deployment_files(self):
        """Test delete succeeds with prestage images and deployment files"""

        self.url = f"{self.url}?prestage_images=True&deployment_files=True"

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(self.mock_os_remove.call_count, 3)

    def test_delete_fails_with_directory_not_found(self):
        """Test delete fails with directory not found"""

        self.url = f"{self.url}?prestage_images=False&deployment_files=False"

        version = "21.12"
        self.mock_get_sw_version.return_value = version

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.NOT_FOUND,
            f"Directory not found: {self.sw_version_directory}{version}",
        )

    def test_delete_fails_with_internal_server_error(self):
        """Test delete fails with internal server error"""

        self.mock_os_remove.side_effect = FakeException("fake file name")

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.INTERNAL_SERVER_ERROR,
            "Failed to delete file: fake file name",
        )
