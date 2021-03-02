# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

import json
import mock
from six.moves import http_client

from dcmanager.audit import rpcapi as audit_rpc_client
from dcmanager.tests.unit.api import test_root_controller as testroot
from dcmanager.tests import utils

FAKE_URL = '/v1.0/notifications'
FAKE_TENANT = utils.UUID1
FAKE_HEADERS = {'X-Tenant-Id': FAKE_TENANT, 'X_ROLE': 'admin',
                'X-Identity-Status': 'Confirmed'}


class TestNotificationsController(testroot.DCManagerApiTest):
    def setUp(self):
        super(TestNotificationsController, self).setUp()
        self.ctx = utils.dummy_context()

    @mock.patch.object(audit_rpc_client, 'ManagerAuditClient')
    def test_post(self, mock_audit_rpc_client):
        mock_audit_rpc_client().trigger_load_audit.return_value = None
        post_url = FAKE_URL
        params = json.dumps({'events': ['platform-upgrade-completed']})
        response = self.app.post(post_url, params=params, headers=FAKE_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        mock_audit_rpc_client().trigger_load_audit.assert_called_once_with(
            mock.ANY)
