# Copyright (c) 2020-2023 Wind River Systems, Inc.
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
import os
from os import path as os_path

import mock
import six
from six.moves import http_client
import webtest

from dccommon import consts as dccommon_consts
from dcmanager.api.controllers.v1 import subcloud_deploy
from dcmanager.common import consts
from dcmanager.common import phased_subcloud_deploy as psd_common
from dcmanager.common import utils as dutils
from dcmanager.tests.unit.api import test_root_controller as testroot
from dcmanager.tests.unit.common import fake_subcloud
from dcmanager.tests import utils

from tsconfig.tsconfig import SW_VERSION

FAKE_SOFTWARE_VERSION = '22.12'
FAKE_TENANT = utils.UUID1
FAKE_ID = '1'
FAKE_URL = '/v1.0/subcloud-deploy'
FAKE_HEADERS = {'X-Tenant-Id': FAKE_TENANT, 'X_ROLE': 'admin,member,reader',
                'X-Identity-Status': 'Confirmed', 'X-Project-Name': 'admin'}

FAKE_DEPLOY_PLAYBOOK_PREFIX = consts.DEPLOY_PLAYBOOK + '_'
FAKE_DEPLOY_OVERRIDES_PREFIX = consts.DEPLOY_OVERRIDES + '_'
FAKE_DEPLOY_CHART_PREFIX = consts.DEPLOY_CHART + '_'
FAKE_PRESTAGE_IMAGES_PREFIX = consts.DEPLOY_PRESTAGE + '_'
FAKE_DEPLOY_PLAYBOOK_FILE = 'deployment-manager.yaml'
FAKE_DEPLOY_OVERRIDES_FILE = 'deployment-manager-overrides-subcloud.yaml'
FAKE_DEPLOY_CHART_FILE = 'deployment-manager.tgz'
FAKE_DEPLOY_FILES = {
    FAKE_DEPLOY_PLAYBOOK_PREFIX: FAKE_DEPLOY_PLAYBOOK_FILE,
    FAKE_DEPLOY_OVERRIDES_PREFIX: FAKE_DEPLOY_OVERRIDES_FILE,
    FAKE_DEPLOY_CHART_PREFIX: FAKE_DEPLOY_CHART_FILE,
}
FAKE_DEPLOY_DELETE_FILES = {
    FAKE_DEPLOY_PLAYBOOK_PREFIX: '/opt/platform/deploy/22.12/deployment-manager.yaml',
    FAKE_DEPLOY_OVERRIDES_PREFIX:
        '/opt/platform/deploy/22.12/deployment-manager-overrides-subcloud.yaml',
    FAKE_DEPLOY_CHART_PREFIX: '/opt/platform/deploy/22.12/deployment-manager.tgz',
    FAKE_PRESTAGE_IMAGES_PREFIX: '/opt/platform/deploy/22.12/prestage_images.yml'
}


def get_filename_by_prefix_side_effect(dir_path, prefix):
    filename = FAKE_DEPLOY_FILES.get(prefix)
    if filename:
        return prefix + FAKE_DEPLOY_FILES.get(prefix)
    else:
        return None


class TestSubcloudDeploy(testroot.DCManagerApiTest):
    def setUp(self):
        super(TestSubcloudDeploy, self).setUp()
        self.ctx = utils.dummy_context()

    @mock.patch.object(subcloud_deploy.SubcloudDeployController,
                       '_upload_files')
    def test_post_subcloud_deploy(self, mock_upload_files):
        params = [('release', FAKE_SOFTWARE_VERSION)]
        fields = list()
        for opt in consts.DEPLOY_COMMON_FILE_OPTIONS:
            fake_name = opt + "_fake"
            fake_content = "fake content".encode('utf-8')
            fields.append((opt, webtest.Upload(fake_name, fake_content)))
        mock_upload_files.return_value = True
        params += fields

        with mock.patch('builtins.open',
                        mock.mock_open(read_data=fake_subcloud.FAKE_UPGRADES_METADATA)):
            response = self.app.post(FAKE_URL,
                                     headers=FAKE_HEADERS,
                                     params=params)

        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual(FAKE_SOFTWARE_VERSION, response.json['software_version'])

    @mock.patch.object(subcloud_deploy.SubcloudDeployController,
                       '_upload_files')
    def test_post_subcloud_deploy_without_release(self, mock_upload_files):
        fields = list()
        for opt in consts.DEPLOY_COMMON_FILE_OPTIONS:
            fake_name = opt + "_fake"
            fake_content = "fake content".encode('utf-8')
            fields.append((opt, fake_name, fake_content))
        mock_upload_files.return_value = True
        response = self.app.post(FAKE_URL,
                                 headers=FAKE_HEADERS,
                                 upload_files=fields)
        self.assertEqual(response.status_code, http_client.OK)
        # Verify the active release will be returned if release doesn't present
        self.assertEqual(SW_VERSION, response.json['software_version'])

    @mock.patch.object(subcloud_deploy.SubcloudDeployController,
                       '_upload_files')
    def test_post_subcloud_deploy_missing_chart(self, mock_upload_files):
        opts = [consts.DEPLOY_PLAYBOOK, consts.DEPLOY_OVERRIDES, consts.DEPLOY_PRESTAGE]
        fields = list()
        for opt in opts:
            fake_name = opt + "_fake"
            fake_content = "fake content".encode('utf-8')
            fields.append((opt, fake_name, fake_content))
        mock_upload_files.return_value = True
        response = self.app.post(FAKE_URL,
                                 headers=FAKE_HEADERS,
                                 upload_files=fields,
                                 expect_errors=True)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    @mock.patch.object(subcloud_deploy.SubcloudDeployController,
                       '_upload_files')
    def test_post_subcloud_deploy_missing_chart_prestages(self, mock_upload_files):
        opts = [consts.DEPLOY_PLAYBOOK, consts.DEPLOY_OVERRIDES]
        fields = list()
        for opt in opts:
            fake_name = opt + "_fake"
            fake_content = "fake content".encode('utf-8')
            fields.append((opt, fake_name, fake_content))
        mock_upload_files.return_value = True
        response = self.app.post(FAKE_URL,
                                 headers=FAKE_HEADERS,
                                 upload_files=fields,
                                 expect_errors=True)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    @mock.patch.object(subcloud_deploy.SubcloudDeployController,
                       '_upload_files')
    def test_post_subcloud_deploy_missing_playbook_overrides(self, mock_upload_files):
        opts = [consts.DEPLOY_CHART, consts.DEPLOY_PRESTAGE]
        fields = list()
        for opt in opts:
            fake_name = opt + "_fake"
            fake_content = "fake content".encode('utf-8')
            fields.append((opt, fake_name, fake_content))
        mock_upload_files.return_value = True
        response = self.app.post(FAKE_URL,
                                 headers=FAKE_HEADERS,
                                 upload_files=fields,
                                 expect_errors=True)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    @mock.patch.object(subcloud_deploy.SubcloudDeployController,
                       '_upload_files')
    def test_post_subcloud_deploy_missing_prestage(self, mock_upload_files):
        opts = [consts.DEPLOY_PLAYBOOK, consts.DEPLOY_OVERRIDES, consts.DEPLOY_CHART]
        fields = list()
        for opt in opts:
            fake_name = opt + "_fake"
            fake_content = "fake content".encode('utf-8')
            fields.append((opt, fake_name, fake_content))
        mock_upload_files.return_value = True
        response = self.app.post(FAKE_URL,
                                 headers=FAKE_HEADERS,
                                 upload_files=fields)
        self.assertEqual(response.status_code, http_client.OK)

    @mock.patch.object(subcloud_deploy.SubcloudDeployController,
                       '_upload_files')
    def test_post_subcloud_deploy_all_input(self, mock_upload_files):
        opts = [consts.DEPLOY_PLAYBOOK, consts.DEPLOY_OVERRIDES,
                consts.DEPLOY_CHART, consts.DEPLOY_PRESTAGE]
        fields = list()
        for opt in opts:
            fake_name = opt + "_fake"
            fake_content = "fake content".encode('utf-8')
            fields.append((opt, fake_name, fake_content))
        mock_upload_files.return_value = True
        response = self.app.post(FAKE_URL,
                                 headers=FAKE_HEADERS,
                                 upload_files=fields)
        self.assertEqual(response.status_code, http_client.OK)

    @mock.patch.object(subcloud_deploy.SubcloudDeployController,
                       '_upload_files')
    def test_post_subcloud_deploy_prestage(self, mock_upload_files):
        opts = [consts.DEPLOY_PRESTAGE]
        fields = list()
        for opt in opts:
            fake_name = opt + "_fake"
            fake_content = "fake content".encode('utf-8')
            fields.append((opt, fake_name, fake_content))
        mock_upload_files.return_value = True
        response = self.app.post(FAKE_URL,
                                 headers=FAKE_HEADERS,
                                 upload_files=fields)
        self.assertEqual(response.status_code, http_client.OK)

    @mock.patch.object(subcloud_deploy.SubcloudDeployController,
                       '_upload_files')
    def test_post_subcloud_deploy_missing_file_name(self, mock_upload_files):
        fields = list()
        for opt in consts.DEPLOY_COMMON_FILE_OPTIONS:
            fake_content = "fake content".encode('utf-8')
            fields.append((opt, "", fake_content))
        mock_upload_files.return_value = True
        response = self.app.post(FAKE_URL,
                                 headers=FAKE_HEADERS,
                                 upload_files=fields,
                                 expect_errors=True)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    @mock.patch.object(dutils, 'get_filename_by_prefix')
    def test_get_subcloud_deploy_with_release(self, mock_get_filename_by_prefix):

        def get_filename_by_prefix_side_effect(dir_path, prefix):
            filename = FAKE_DEPLOY_FILES.get(prefix)
            if filename:
                return prefix + FAKE_DEPLOY_FILES.get(prefix)
            else:
                return None

        os.path.isdir = mock.Mock(return_value=True)
        mock_get_filename_by_prefix.side_effect = \
            get_filename_by_prefix_side_effect
        url = FAKE_URL + '/' + FAKE_SOFTWARE_VERSION

        with mock.patch('builtins.open',
                        mock.mock_open(read_data=fake_subcloud.FAKE_UPGRADES_METADATA)):
            response = self.app.get(url, headers=FAKE_HEADERS)

        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual(FAKE_SOFTWARE_VERSION,
                         response.json['subcloud_deploy']['software_version'])
        self.assertEqual(FAKE_DEPLOY_PLAYBOOK_FILE,
                         response.json['subcloud_deploy'][consts.DEPLOY_PLAYBOOK])
        self.assertEqual(FAKE_DEPLOY_OVERRIDES_FILE,
                         response.json['subcloud_deploy'][consts.DEPLOY_OVERRIDES])
        self.assertEqual(FAKE_DEPLOY_CHART_FILE,
                         response.json['subcloud_deploy'][consts.DEPLOY_CHART])
        self.assertEqual(None,
                         response.json['subcloud_deploy'][consts.DEPLOY_PRESTAGE])

    @mock.patch.object(dutils, 'get_filename_by_prefix')
    def test_get_subcloud_deploy_without_release(self, mock_get_filename_by_prefix):

        def get_filename_by_prefix_side_effect(dir_path, prefix):
            filename = FAKE_DEPLOY_FILES.get(prefix)
            if filename:
                return prefix + FAKE_DEPLOY_FILES.get(prefix)
            else:
                return None

        os.path.isdir = mock.Mock(return_value=True)
        mock_get_filename_by_prefix.side_effect = \
            get_filename_by_prefix_side_effect
        response = self.app.get(FAKE_URL, headers=FAKE_HEADERS)
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual(SW_VERSION,
                         response.json['subcloud_deploy']['software_version'])
        self.assertEqual(FAKE_DEPLOY_PLAYBOOK_FILE,
                         response.json['subcloud_deploy'][consts.DEPLOY_PLAYBOOK])
        self.assertEqual(FAKE_DEPLOY_OVERRIDES_FILE,
                         response.json['subcloud_deploy'][consts.DEPLOY_OVERRIDES])
        self.assertEqual(FAKE_DEPLOY_CHART_FILE,
                         response.json['subcloud_deploy'][consts.DEPLOY_CHART])
        self.assertEqual(None,
                         response.json['subcloud_deploy'][consts.DEPLOY_PRESTAGE])

    def test_get_config_file_path(self):
        bootstrap_file = psd_common.get_config_file_path("subcloud1")
        install_values = psd_common.get_config_file_path("subcloud1",
                                                         consts.INSTALL_VALUES)
        deploy_config = psd_common.get_config_file_path("subcloud1",
                                                        consts.DEPLOY_CONFIG)
        self.assertEqual(bootstrap_file,
                         f'{dccommon_consts.ANSIBLE_OVERRIDES_PATH}/subcloud1.yml')
        self.assertEqual(install_values,
                         f'{dccommon_consts.ANSIBLE_OVERRIDES_PATH}/subcloud1/install_values.yml')
        self.assertEqual(deploy_config,
                         f'{dccommon_consts.ANSIBLE_OVERRIDES_PATH}/subcloud1_deploy_config.yml')

    @mock.patch.object(os_path, 'isdir')
    @mock.patch.object(dutils, 'get_sw_version')
    def test_subcloud_deploy_delete_directory_not_found(self,
                                                        mock_get_sw_version,
                                                        mock_path_isdir):

        mock_get_sw_version.return_value = '21.12'
        url = FAKE_URL + '?prestage_images=' + \
            str(False) + '&deployment_files=' + str(False)
        mock_path_isdir.side_effect = lambda x: True \
            if x == '/opt/platform/deploy/22.12' else False
        six.assertRaisesRegex(self, webtest.app.AppError, "404 *",
                              self.app.delete, url,
                              headers=FAKE_HEADERS)

    @mock.patch.object(os_path, 'isdir')
    @mock.patch.object(dutils, 'get_sw_version')
    def test_subcloud_deploy_delete_internal_server_error(self,
                                                          mock_get_sw_version,
                                                          mock_path_isdir):

        mock_get_sw_version.return_value = '22.12'
        mock_path_isdir.side_effect = lambda x: True \
            if x == '/opt/platform/deploy/22.12' else False
        six.assertRaisesRegex(self, webtest.app.AppError, "500 *",
                              self.app.delete, FAKE_URL,
                              headers=FAKE_HEADERS)

    @mock.patch.object(os_path, 'isdir')
    @mock.patch.object(dutils, 'get_sw_version')
    @mock.patch.object(dutils, 'get_filename_by_prefix')
    @mock.patch.object(os, 'remove')
    def test_subcloud_deploy_delete_with_release(self, mock_os_remove,
                                                 mock_get_filename_by_prefix,
                                                 mock_get_sw_version,
                                                 mock_path_isdir):

        mock_os_remove.return_value = None
        mock_get_sw_version.return_value = '22.12'

        mock_get_filename_by_prefix.side_effect = \
            get_filename_by_prefix_side_effect
        mock_path_isdir.return_value = True
        url = FAKE_URL + '/' + FAKE_SOFTWARE_VERSION + \
            '?prestage_images=' + str(False) + '&deployment_files=' + str(False)
        response = self.app.delete(url, headers=FAKE_HEADERS)
        self.assertEqual(response.status_code, http_client.OK)

    @mock.patch.object(os_path, 'isdir')
    @mock.patch.object(dutils, 'get_sw_version')
    @mock.patch.object(dutils, 'get_filename_by_prefix')
    @mock.patch.object(os, 'remove')
    def test_subcloud_deploy_delete_without_release(self, mock_os_remove,
                                                    mock_get_filename_by_prefix,
                                                    mock_get_sw_version,
                                                    mock_path_isdir):

        mock_os_remove.return_value = None
        mock_get_sw_version.return_value = '22.12'
        url = FAKE_URL + '?prestage_images=' + \
            str(True) + '&deployment_files=' + str(True)
        mock_get_filename_by_prefix.side_effect = \
            get_filename_by_prefix_side_effect
        mock_path_isdir.return_value = True
        response = self.app.delete(url, headers=FAKE_HEADERS)
        self.assertEqual(response.status_code, http_client.OK)

    @mock.patch.object(os_path, 'isdir')
    @mock.patch.object(dutils, 'get_sw_version')
    @mock.patch.object(dutils, 'get_filename_by_prefix')
    @mock.patch.object(os, 'remove')
    def test_subcloud_deploy_delete_deployment_files(self, mock_os_remove,
                                                     mock_get_filename_by_prefix,
                                                     mock_get_sw_version,
                                                     mock_path_isdir):
        mock_os_remove.return_value = None
        mock_get_sw_version.return_value = '22.12'
        url = FAKE_URL + '?prestage_images=' + \
            str(False) + '&deployment_files=' + str(True)
        mock_get_filename_by_prefix.side_effect = \
            get_filename_by_prefix_side_effect
        mock_path_isdir.side_effect = lambda x: True \
            if x == '/opt/platform/deploy/22.12' else False
        response = self.app.delete(url, headers=FAKE_HEADERS)
        self.assertEqual(response.status_code, http_client.OK)

    @mock.patch.object(os_path, 'isdir')
    @mock.patch.object(dutils, 'get_sw_version')
    @mock.patch.object(dutils, 'get_filename_by_prefix')
    @mock.patch.object(os, 'remove')
    def test_subcloud_deploy_delete_prestage_images(self, mock_os_remove,
                                                    mock_get_filename_by_prefix,
                                                    mock_get_sw_version,
                                                    mock_path_isdir):
        mock_os_remove.return_value = None
        mock_get_sw_version.return_value = '22.12'
        url = FAKE_URL + '?prestage_images=' + \
            str(True) + '&deployment_files=' + str(False)
        mock_get_filename_by_prefix.side_effect = \
            get_filename_by_prefix_side_effect
        mock_path_isdir.side_effect = lambda x: True \
            if x == '/opt/platform/deploy/22.12' else False
        response = self.app.delete(url, headers=FAKE_HEADERS)
        self.assertEqual(response.status_code, http_client.OK)

    @mock.patch.object(os_path, 'isdir')
    @mock.patch.object(dutils, 'get_sw_version')
    @mock.patch.object(dutils, 'get_filename_by_prefix')
    @mock.patch.object(os, 'remove')
    def test_subcloud_deploy_delete_with_both_parameters(self, mock_os_remove,
                                                         mock_get_filename_by_prefix,
                                                         mock_get_sw_version,
                                                         mock_path_isdir):
        mock_os_remove.return_value = None
        mock_get_sw_version.return_value = '22.12'
        url = FAKE_URL + '?prestage_images=' + \
            str(True) + '&deployment_files=' + str(True)
        mock_get_filename_by_prefix.side_effect = \
            get_filename_by_prefix_side_effect
        mock_path_isdir.side_effect = lambda x: True \
            if x == '/opt/platform/deploy/22.12' else False
        response = self.app.delete(url, headers=FAKE_HEADERS)
        self.assertEqual(response.status_code, http_client.OK)
