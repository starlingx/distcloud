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
# Copyright (c) 2020 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

import mock
from six.moves import http_client

from dcmanager.api.controllers.v1 import alarm_manager
from dcmanager.tests.unit.api import test_root_controller as testroot
from dcmanager.tests import utils

FAKE_URL = '/v1.0/alarms'
FAKE_TENANT = utils.UUID1
FAKE_ID = '1'
FAKE_HEADERS = {'X-Tenant-Id': FAKE_TENANT, 'X_ROLE': 'admin',
                'X-Identity-Status': 'Confirmed'}


class TestSubcloudAlarmController(testroot.DCManagerApiTest):
    def setUp(self):
        super(TestSubcloudAlarmController, self).setUp()
        self.ctx = utils.dummy_context()

    @mock.patch.object(alarm_manager, 'db_api')
    def test_get_alarms(self, mock_db_api):
        get_url = FAKE_URL
        alarms_from_db = [{'name': 'subcloud1',
                           'uuid': utils.UUID2,
                           'critical_alarms': 1,
                           'major_alarms': 2,
                           'minor_alarms': 3,
                           'warnings': 0,
                           'cloud_status': 'critical'},
                          {'name': 'subcloud2',
                           'uuid': utils.UUID3,
                           'critical_alarms': 0,
                           'major_alarms': 2,
                           'minor_alarms': 3,
                           'warnings': 4,
                           'cloud_status': 'degraded'}]
        subcloud_summary = [{'region_name': 'subcloud1',
                             'uuid': utils.UUID2,
                             'critical_alarms': 1,
                             'major_alarms': 2,
                             'minor_alarms': 3,
                             'warnings': 0,
                             'cloud_status': 'critical'},
                            {'region_name': 'subcloud2',
                             'uuid': utils.UUID3,
                             'critical_alarms': 0,
                             'major_alarms': 2,
                             'minor_alarms': 3,
                             'warnings': 4,
                             'cloud_status': 'degraded'}]
        mock_db_api.subcloud_alarms_get_all.return_value = alarms_from_db
        response = self.app.get(get_url, headers=FAKE_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual(subcloud_summary, response.json.get('alarm_summary'))
