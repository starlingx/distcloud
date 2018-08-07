# Copyright (c) 2017 Ericsson AB
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
# Copyright (c) 2017 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

import copy
import mock
import webtest

from dcmanager.api.controllers.v1 import subclouds
from dcmanager.common import consts
from dcmanager.rpc import client as rpc_client
from dcmanager.tests.unit.api import test_root_controller as testroot
from dcmanager.tests import utils

FAKE_TENANT = utils.UUID1
FAKE_ID = '1'
FAKE_URL = '/v1.0/subclouds'
WRONG_URL = '/v1.0/wrong'
FAKE_HEADERS = {'X-Tenant-Id': FAKE_TENANT, 'X_ROLE': 'admin',
                'X-Identity-Status': 'Confirmed'}

FAKE_SUBCLOUD_DATA = {"name": "subcloud1",
                      "description": "subcloud1 description",
                      "location": "subcloud1 location",
                      "management-subnet": "192.168.101.0/24",
                      "management-start-ip": "192.168.101.2",
                      "management-end-ip": "192.168.101.50",
                      "management-gateway-ip": "192.168.101.1",
                      "systemcontroller-gateway-ip": "192.168.204.101",
                      "availability-status": "disabled"}


class FakeAddressPool(object):
    def __init__(self, pool_network, pool_prefix, pool_start, pool_end):
        self.network = pool_network
        self.prefix = pool_prefix
        range = list()
        range.append(pool_start)
        range.append(pool_end)
        self.ranges = list()
        self.ranges.append(range)


class TestSubclouds(testroot.DCManagerApiTest):
    def setUp(self):
        super(TestSubclouds, self).setUp()
        self.ctx = utils.dummy_context()

    @mock.patch.object(subclouds.SubcloudsController,
                       '_get_management_address_pool')
    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_post_subcloud(self, mock_db_api, mock_rpc_client,
                           mock_get_management_address_pool):
        data = FAKE_SUBCLOUD_DATA
        management_address_pool = FakeAddressPool('192.168.204.0', 24,
                                                  '192.168.204.2',
                                                  '192.168.204.100')
        mock_get_management_address_pool.return_value = management_address_pool
        mock_rpc_client().add_subcloud.return_value = True
        response = self.app.post_json(FAKE_URL,
                                      headers=FAKE_HEADERS,
                                      params=data)
        mock_rpc_client().add_subcloud.assert_called_once_with(
            mock.ANY,
            data)
        self.assertEqual(response.status_int, 200)

    @mock.patch.object(subclouds.SubcloudsController,
                       '_get_management_address_pool')
    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_post_subcloud_bad_gateway(self, mock_db_api, mock_rpc_client,
                                       mock_get_management_address_pool):
        data = copy.copy(FAKE_SUBCLOUD_DATA)
        data["systemcontroller-gateway-ip"] = "192.168.205.101"
        management_address_pool = FakeAddressPool('192.168.204.0', 24,
                                                  '192.168.204.2',
                                                  '192.168.204.100')
        mock_get_management_address_pool.return_value = management_address_pool
        self.assertRaisesRegexp(webtest.app.AppError, "400 *",
                                self.app.post_json, FAKE_URL,
                                headers=FAKE_HEADERS, params=data)

    @mock.patch.object(subclouds.SubcloudsController,
                       '_get_management_address_pool')
    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_post_subcloud_bad_gateway2(self, mock_db_api, mock_rpc_client,
                                        mock_get_management_address_pool):
        data = copy.copy(FAKE_SUBCLOUD_DATA)
        management_address_pool = FakeAddressPool('192.168.204.0', 24,
                                                  '192.168.204.2',
                                                  '192.168.204.254')
        mock_get_management_address_pool.return_value = management_address_pool
        self.assertRaisesRegexp(webtest.app.AppError, "400 *",
                                self.app.post_json, FAKE_URL,
                                headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_post_subcloud_bad_subnet(self, mock_db_api, mock_rpc_client):
        data = copy.copy(FAKE_SUBCLOUD_DATA)
        data["management-subnet"] = "192.168.101.0/32"
        self.assertRaisesRegexp(webtest.app.AppError, "400 *",
                                self.app.post_json, FAKE_URL,
                                headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_post_subcloud_bad_start_ip(self, mock_db_api, mock_rpc_client):
        data = copy.copy(FAKE_SUBCLOUD_DATA)
        data["management-subnet"] = "192.168.101.0/24"
        data["management-start-ip"] = "192.168.100.2"
        data["management-end-ip"] = "192.168.100.50"
        self.assertRaisesRegexp(webtest.app.AppError, "400 *",
                                self.app.post_json, FAKE_URL,
                                headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_post_subcloud_bad_end_ip(self, mock_db_api, mock_rpc_client):
        data = copy.copy(FAKE_SUBCLOUD_DATA)
        data["management-start-ip"] = "192.168.101.2"
        data["management-end-ip"] = "192.168.100.100"
        self.assertRaisesRegexp(webtest.app.AppError, "400 *",
                                self.app.post_json, FAKE_URL,
                                headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_post_subcloud_short_ip_range(self, mock_db_api, mock_rpc_client):
        data = copy.copy(FAKE_SUBCLOUD_DATA)
        data["management-start-ip"] = "192.168.101.2"
        data["management-end-ip"] = "192.168.101.4"
        self.assertRaisesRegexp(webtest.app.AppError, "400 *",
                                self.app.post_json, FAKE_URL,
                                headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_post_subcloud_invert_ip_range(self, mock_db_api, mock_rpc_client):
        data = copy.copy(FAKE_SUBCLOUD_DATA)
        data["management-start-ip"] = "192.168.101.20"
        data["management-end-ip"] = "192.168.101.4"
        self.assertRaisesRegexp(webtest.app.AppError, "400 *",
                                self.app.post_json, FAKE_URL,
                                headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_post_subcloud_wrong_url(self, mock_rpc_client):
        data = FAKE_SUBCLOUD_DATA
        self.assertRaisesRegexp(webtest.app.AppError, "404 *",
                                self.app.post_json, WRONG_URL,
                                headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_post_no_body(self, mock_rpc_client):
        data = {}
        self.assertRaisesRegexp(webtest.app.AppError, "400 *",
                                self.app.post_json, FAKE_URL,
                                headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_post_no_name(self, mock_rpc_client):
        data = dict(FAKE_SUBCLOUD_DATA)
        del data['name']
        self.assertRaisesRegexp(webtest.app.AppError, "400 *",
                                self.app.post_json, FAKE_URL,
                                headers=FAKE_HEADERS, params=data)

    @mock.patch.object(subclouds.SubcloudsController,
                       '_create_subcloud_config_file')
    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_post_subcloud_config(self, mock_db_api, mock_rpc_client,
                                  mock_create_config):
        mock_create_config.return_value = "Some\n long multiline config data"
        post_url = FAKE_URL + '/' + FAKE_ID + '/config'
        self.app.post(post_url, headers=FAKE_HEADERS)
        self.assertEqual(1, mock_db_api.subcloud_get.call_count)
        self.assertEqual(1, mock_create_config.call_count)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_delete_subcloud(self, mock_db_api, mock_rpc_client):
        delete_url = FAKE_URL + '/' + FAKE_ID
        mock_rpc_client().delete_subcloud.return_value = True
        response = self.app.delete_json(delete_url, headers=FAKE_HEADERS)
        mock_rpc_client().delete_subcloud.assert_called_once_with(
            mock.ANY, mock.ANY)
        self.assertEqual(response.status_int, 200)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_delete_wrong_request(self, mock_rpc_client):
        delete_url = WRONG_URL + '/' + FAKE_ID
        self.assertRaisesRegex(webtest.app.AppError, "404 *",
                               self.app.delete_json, delete_url,
                               headers=FAKE_HEADERS)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_get_subcloud(self, mock_db_api, mock_rpc_client):
        get_url = FAKE_URL + '/' + FAKE_ID
        self.app.get(get_url, headers=FAKE_HEADERS)
        self.assertEqual(1, mock_db_api.subcloud_get_with_status.call_count)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_get_wrong_request(self, mock_db_api, mock_rpc_client):
        get_url = WRONG_URL + '/' + FAKE_ID
        self.assertRaisesRegex(webtest.app.AppError, "404 *",
                               self.app.get, get_url,
                               headers=FAKE_HEADERS)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_get_subcloud_all(self, mock_db_api, mock_rpc_client):
        get_url = FAKE_URL
        self.app.get(get_url, headers=FAKE_HEADERS)
        self.assertEqual(1,
                         mock_db_api.subcloud_get_all_with_status.call_count)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_patch_subcloud(self, mock_db_api, mock_rpc_client):
        data = {'management-state': consts.MANAGEMENT_UNMANAGED}
        mock_rpc_client().update_subcloud.return_value = True
        response = self.app.patch_json(FAKE_URL + '/' + FAKE_ID,
                                       headers=FAKE_HEADERS,
                                       params=data)
        mock_rpc_client().update_subcloud.assert_called_once_with(
            mock.ANY,
            mock.ANY,
            management_state=consts.MANAGEMENT_UNMANAGED,
            description=None,
            location=None)
        self.assertEqual(response.status_int, 200)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_patch_subcloud_no_body(self, mock_rpc_client):
        data = {}
        self.assertRaisesRegexp(webtest.app.AppError, "400 *",
                                self.app.patch_json, FAKE_URL + '/' + FAKE_ID,
                                headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_patch_subcloud_bad_status(self, mock_db_api, mock_rpc_client):
        data = {'management-state': 'bad-status'}
        self.assertRaisesRegex(webtest.app.AppError, "400 *",
                               self.app.patch_json, FAKE_URL + '/' + FAKE_ID,
                               headers=FAKE_HEADERS, params=data)
