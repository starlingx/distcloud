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
# Copyright (c) 2020 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

import mock
from six.moves import http_client

from dcmanager.api.controllers.v1 import subcloud_deploy
from dcmanager.common import consts
from dcmanager.tests.unit.api import test_root_controller as testroot
from dcmanager.tests import utils

FAKE_TENANT = utils.UUID1
FAKE_ID = '1'
FAKE_URL = '/v1.0/subcloud-deploy'
FAKE_HEADERS = {'X-Tenant-Id': FAKE_TENANT, 'X_ROLE': 'admin',
                'X-Identity-Status': 'Confirmed'}


class TestSubcloudDeploy(testroot.DCManagerApiTest):
    def setUp(self):
        super(TestSubcloudDeploy, self).setUp()
        self.ctx = utils.dummy_context()

    @mock.patch.object(subcloud_deploy.SubcloudDeployController,
                       '_upload_files')
    def test_post_subcloud_deploy(self, mock_upload_files):
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

    @mock.patch.object(subcloud_deploy.SubcloudDeployController,
                       '_upload_files')
    def test_post_subcloud_deploy_missing_file(self, mock_upload_files):
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
