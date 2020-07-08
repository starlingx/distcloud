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
# Copyright (c) 2017-2020 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

from oslo_utils import timeutils

import base64
import copy
import json
import mock
import six
from six.moves import http_client
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

FAKE_SUBCLOUD_DATA = {"id": FAKE_ID,
                      "name": "subcloud1",
                      "description": "subcloud1 description",
                      "location": "subcloud1 location",
                      "system_mode": "duplex",
                      "management_subnet": "192.168.101.0/24",
                      "management_start_address": "192.168.101.2",
                      "management_end_address": "192.168.101.50",
                      "management_gateway_address": "192.168.101.1",
                      "systemcontroller_gateway_address": "192.168.204.101",
                      "deploy_status": consts.DEPLOY_STATE_DONE,
                      "external_oam_subnet": "10.10.10.0/24",
                      "external_oam_gateway_address": "10.10.10.1",
                      "external_oam_floating_address": "10.10.10.12",
                      "availability-status": "disabled"}

FAKE_SUBCLOUD_INSTALL_VALUES = {
    "image": "http://192.168.101.2:8080/iso/bootimage.iso",
    "software_version": "12.34",
    "bootstrap_interface": "eno1",
    "bootstrap_address": "128.224.151.183",
    "bootstrap_address_prefix": 23,
    "bmc_address": "128.224.64.180",
    "bmc_username": "root",
    "nexthop_gateway": "128.224.150.1",
    "network_address": "128.224.144.0",
    "network_mask": "255.255.254.0",
    "install_type": 3,
    "console_type": "tty0",
    "bootstrap_vlan": 128,
    "rootfs_device": "/dev/disk/by-path/pci-0000:5c:00.0-scsi-0:1:0:0",
    "boot_device": "/dev/disk/by-path/pci-0000:5c:00.0-scsi-0:1:0:0"
}

FAKE_BOOTSTRAP_VALUE = {
    'bootstrap-address': '10.10.10.12',
    'sysadmin_password': base64.b64encode('testpass'.encode("utf-8"))
}


class Subcloud(object):
    def __init__(self, data, is_online):
        self.id = data['id']
        self.name = data['name']
        self.description = data['description']
        self.location = data['location']
        self.management_state = consts.MANAGEMENT_UNMANAGED
        if is_online:
            self.availability_status = consts.AVAILABILITY_ONLINE
        else:
            self.availability_status = consts.AVAILABILITY_OFFLINE
        self.deploy_status = data['deploy_status']
        self.management_subnet = data['management_subnet']
        self.management_gateway_ip = data['management_gateway_address']
        self.management_start_ip = data['management_start_address']
        self.management_end_ip = data['management_end_address']
        self.external_oam_subnet = data['external_oam_subnet']
        self.external_oam_gateway_address = \
            data['external_oam_gateway_address']
        self.external_oam_floating_address = \
            data['external_oam_floating_address']
        self.systemcontroller_gateway_ip = \
            data['systemcontroller_gateway_address']
        self.created_at = timeutils.utcnow()
        self.updated_at = timeutils.utcnow()


class FakeAddressPool(object):
    def __init__(self, pool_network, pool_prefix, pool_start, pool_end):
        self.network = pool_network
        self.prefix = pool_prefix
        range = list()
        range.append(pool_start)
        range.append(pool_end)
        self.ranges = list()
        self.ranges.append(range)


class FakeOAMAddressPool(object):
    def __init__(self, oam_subnet, oam_start_ip,
                 oam_end_ip, oam_c1_ip,
                 oam_c0_ip, oam_gateway_ip,
                 oam_floating_ip):
        self.oam_start_ip = oam_start_ip
        self.oam_end_ip = oam_end_ip
        self.oam_c1_ip = oam_c1_ip
        self.oam_c0_ip = oam_c0_ip
        self.oam_subnet = oam_subnet
        self.oam_gateway_ip = oam_gateway_ip
        self.oam_floating_ip = oam_floating_ip


class TestSubclouds(testroot.DCManagerApiTest):
    def setUp(self):
        super(TestSubclouds, self).setUp()
        self.ctx = utils.dummy_context()

    @mock.patch.object(subclouds.SubcloudsController,
                       '_add_subcloud_to_database')
    @mock.patch.object(subclouds.SubcloudsController,
                       '_upload_deploy_config_file')
    @mock.patch.object(subclouds.SubcloudsController,
                       '_get_request_data')
    @mock.patch.object(subclouds.SubcloudsController,
                       '_get_management_address_pool')
    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_post_subcloud(self, mock_db_api, mock_rpc_client,
                           mock_get_management_address_pool,
                           mock_get_request_data,
                           mock_upload_deploy_config_file,
                           mock_add_subcloud_to_database):
        management_address_pool = FakeAddressPool('192.168.204.0', 24,
                                                  '192.168.204.2',
                                                  '192.168.204.100')
        mock_get_management_address_pool.return_value = management_address_pool
        mock_rpc_client().add_subcloud.return_value = True
        fields = list()
        for f in subclouds.SUBCLOUD_ADD_MANDATORY_FILE:
            fake_name = f + "_fake"
            fake_content = "fake content".encode("utf-8")
            fields.append((f, fake_name, fake_content))
        data = copy.copy(FAKE_SUBCLOUD_DATA)
        data.update(FAKE_BOOTSTRAP_VALUE)
        mock_get_request_data.return_value = data
        mock_upload_deploy_config_file.return_value = True
        mock_db_api.subcloud_db_model_to_dict.return_value = data
        response = self.app.post(FAKE_URL,
                                 headers=FAKE_HEADERS,
                                 params=FAKE_BOOTSTRAP_VALUE,
                                 upload_files=fields)
        mock_add_subcloud_to_database.assert_called_once()
        mock_rpc_client().add_subcloud.assert_called_once_with(
            mock.ANY,
            data)
        self.assertEqual(response.status_int, 200)

    @mock.patch.object(subclouds.SubcloudsController,
                       '_add_subcloud_to_database')
    @mock.patch.object(subclouds.SubcloudsController,
                       '_upload_deploy_config_file')
    @mock.patch.object(subclouds.SubcloudsController,
                       '_get_request_data')
    @mock.patch.object(subclouds.SubcloudsController,
                       '_get_management_address_pool')
    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_post_subcloud_with_install_values(
            self, mock_db_api, mock_rpc_client,
            mock_get_management_address_pool,
            mock_get_request_data,
            mock_upload_deploy_config_file,
            mock_add_subcloud_to_database):
        data = copy.copy(FAKE_SUBCLOUD_DATA)
        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)
        data.update({'install_values': install_data})
        management_address_pool = FakeAddressPool('192.168.204.0', 24,
                                                  '192.168.204.2',
                                                  '192.168.204.100')
        mock_get_management_address_pool.return_value = management_address_pool
        mock_rpc_client().add_subcloud.return_value = True
        fields = list()
        for f in subclouds.SUBCLOUD_ADD_GET_FILE_CONTENTS:
            fake_name = f + "_fake"
            fake_content = "fake content".encode("utf-8")
            fields.append((f, fake_name, fake_content))
        params = copy.copy(FAKE_BOOTSTRAP_VALUE)
        params.update(
            {'bmc_password':
             (base64.b64encode('bmc_password'.encode("utf-8"))).decode("utf-8")})
        data.update(params)
        mock_get_request_data.return_value = data
        mock_upload_deploy_config_file.return_value = True
        mock_db_api.subcloud_db_model_to_dict.return_value = data
        response = self.app.post(FAKE_URL,
                                 headers=FAKE_HEADERS,
                                 params=params,
                                 upload_files=fields)
        mock_add_subcloud_to_database.assert_called_once()
        self.assertEqual(response.status_int, 200)

    @mock.patch.object(subclouds.SubcloudsController,
                       '_get_management_address_pool')
    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_post_subcloud_bad_gateway(self, mock_db_api, mock_rpc_client,
                                       mock_get_management_address_pool):
        data = copy.copy(FAKE_SUBCLOUD_DATA)
        data["systemcontroller_gateway_address"] = "192.168.205.101"
        management_address_pool = FakeAddressPool('192.168.204.0', 24,
                                                  '192.168.204.2',
                                                  '192.168.204.100')
        mock_get_management_address_pool.return_value = management_address_pool
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
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
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.post_json, FAKE_URL,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_post_subcloud_bad_subnet(self, mock_db_api, mock_rpc_client):
        data = copy.copy(FAKE_SUBCLOUD_DATA)
        data["management_subnet"] = "192.168.101.0/32"
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.post_json, FAKE_URL,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_post_subcloud_bad_start_ip(self, mock_db_api, mock_rpc_client):
        data = copy.copy(FAKE_SUBCLOUD_DATA)
        data["management_subnet"] = "192.168.101.0/24"
        data["management_start_address"] = "192.168.100.2"
        data["management_end_address"] = "192.168.100.50"
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.post_json, FAKE_URL,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_post_subcloud_bad_end_ip(self, mock_db_api, mock_rpc_client):
        data = copy.copy(FAKE_SUBCLOUD_DATA)
        data["management_start_address"] = "192.168.101.2"
        data["management_end_address"] = "192.168.100.100"
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.post_json, FAKE_URL,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_post_subcloud_short_ip_range(self, mock_db_api, mock_rpc_client):
        data = copy.copy(FAKE_SUBCLOUD_DATA)
        data["management_start_address"] = "192.168.101.2"
        data["management_end_address"] = "192.168.101.4"
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.post_json, FAKE_URL,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_post_subcloud_invert_ip_range(self, mock_db_api, mock_rpc_client):
        data = copy.copy(FAKE_SUBCLOUD_DATA)
        data["management_start_address"] = "192.168.101.20"
        data["management_end_address"] = "192.168.101.4"
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.post_json, FAKE_URL,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_post_subcloud_wrong_url(self, mock_rpc_client):
        data = FAKE_SUBCLOUD_DATA
        six.assertRaisesRegex(self, webtest.app.AppError, "404 *",
                              self.app.post_json, WRONG_URL,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(subclouds.SubcloudsController,
                       '_get_management_address_pool')
    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_post_subcloud_install_no_bmc_password(
            self, mock_db_api, mock_rpc_client,
            mock_get_management_address_pool):
        data = copy.copy(FAKE_SUBCLOUD_DATA)
        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)
        data.update({'install_values': install_data})
        management_address_pool = FakeAddressPool('192.168.204.0', 24,
                                                  '192.168.204.2',
                                                  '192.168.204.100')
        mock_get_management_address_pool.return_value = management_address_pool
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.post_json, FAKE_URL,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(subclouds.SubcloudsController,
                       '_get_management_address_pool')
    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_post_subcloud_install_missing_mandatory_values(
            self, mock_db_api, mock_rpc_client,
            mock_get_management_address_pool):
        data = copy.copy(FAKE_SUBCLOUD_DATA)
        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)
        del install_data['image']
        data.update({'install_values': install_data})
        management_address_pool = FakeAddressPool('192.168.204.0', 24,
                                                  '192.168.204.2',
                                                  '192.168.204.100')
        mock_get_management_address_pool.return_value = management_address_pool
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.post_json, FAKE_URL,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(subclouds.SubcloudsController,
                       '_get_management_address_pool')
    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_post_subcloud_install_invalid_type(
            self, mock_db_api, mock_rpc_client,
            mock_get_management_address_pool):
        data = copy.copy(FAKE_SUBCLOUD_DATA)
        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)
        install_data['install_type'] = 10
        data.update({'install_values': install_data})
        management_address_pool = FakeAddressPool('192.168.204.0', 24,
                                                  '192.168.204.2',
                                                  '192.168.204.100')
        mock_get_management_address_pool.return_value = management_address_pool
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.post_json, FAKE_URL,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(subclouds.SubcloudsController,
                       '_get_management_address_pool')
    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_post_subcloud_install_bad_bootstrap_ip(
            self, mock_db_api, mock_rpc_client,
            mock_get_management_address_pool):
        data = copy.copy(FAKE_SUBCLOUD_DATA)
        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)
        install_data['bootstrap_address'] = '192.168.1.256'
        data.update({'install_values': install_data})
        management_address_pool = FakeAddressPool('192.168.204.0', 24,
                                                  '192.168.204.2',
                                                  '192.168.204.100')
        mock_get_management_address_pool.return_value = management_address_pool
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.post_json, FAKE_URL,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(subclouds.SubcloudsController,
                       '_get_management_address_pool')
    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_post_subcloud_install_bad_bmc_ip(
            self, mock_db_api, mock_rpc_client,
            mock_get_management_address_pool):
        data = copy.copy(FAKE_SUBCLOUD_DATA)
        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)
        install_data['bmc_address'] = '128.224.64.280'
        data.update({'install_values': install_data})
        management_address_pool = FakeAddressPool('192.168.204.0', 24,
                                                  '192.168.204.2',
                                                  '192.168.204.100')
        mock_get_management_address_pool.return_value = management_address_pool
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.post_json, FAKE_URL,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(subclouds.SubcloudsController,
                       '_get_management_address_pool')
    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_post_subcloud_install_different_ip_version(
            self, mock_db_api, mock_rpc_client,
            mock_get_management_address_pool):
        data = copy.copy(FAKE_SUBCLOUD_DATA)
        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)
        install_data['nexthop_gateway'] = '192.168.1.2'
        install_data['network_address'] = 'fd01:6::0'
        install_data['bmc_address'] = 'fd01:6::7'
        data.update({'install_values': install_data})
        management_address_pool = FakeAddressPool('192.168.204.0', 24,
                                                  '192.168.204.2',
                                                  '192.168.204.100')
        mock_get_management_address_pool.return_value = management_address_pool
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.post_json, FAKE_URL,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(subclouds.SubcloudsController,
                       '_get_management_address_pool')
    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_post_subcloud_install_missing_network_gateway(
            self, mock_db_api, mock_rpc_client,
            mock_get_management_address_pool):
        data = copy.copy(FAKE_SUBCLOUD_DATA)
        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)
        del install_data['nexthop_gateway']
        data.update({'install_values': install_data})
        management_address_pool = FakeAddressPool('192.168.204.0', 24,
                                                  '192.168.204.2',
                                                  '192.168.204.100')
        mock_get_management_address_pool.return_value = management_address_pool
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.post_json, FAKE_URL,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(subclouds.SubcloudsController,
                       '_get_management_address_pool')
    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_post_subcloud_install_bad_network_address(
            self, mock_db_api, mock_rpc_client,
            mock_get_management_address_pool):
        data = copy.copy(FAKE_SUBCLOUD_DATA)
        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)
        install_data['network_address'] = 'fd01:6::0'
        install_data['network_mask'] = '63'
        data.update({'install_values': install_data})
        management_address_pool = FakeAddressPool('192.168.204.0', 24,
                                                  '192.168.204.2',
                                                  '192.168.204.100')
        mock_get_management_address_pool.return_value = management_address_pool
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.post_json, FAKE_URL,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_post_no_body(self, mock_rpc_client):
        data = {}
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.post_json, FAKE_URL,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_post_no_name(self, mock_rpc_client):
        data = dict(FAKE_SUBCLOUD_DATA)
        del data['name']
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.post_json, FAKE_URL,
                              headers=FAKE_HEADERS, params=data)

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
        six.assertRaisesRegex(self, webtest.app.AppError, "404 *",
                              self.app.delete_json, delete_url,
                              headers=FAKE_HEADERS)

    @mock.patch.object(subclouds.SubcloudsController,
                       '_get_oam_addresses')
    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_get_subcloud(self,
                          mock_db_api,
                          mock_rpc_client,
                          mock_get_oam_addresses):
        get_url = FAKE_URL + '/' + FAKE_ID
        response = self.app.get(get_url, headers=FAKE_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual(response.json.get('oam_floating_ip', None), None)
        self.assertEqual(1, mock_db_api.subcloud_get_with_status.call_count)

    @mock.patch.object(subclouds.SubcloudsController,
                       '_get_oam_addresses')
    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_get_subcloud_with_additional_detail(self,
                                                 mock_db_api,
                                                 mock_rpc_client,
                                                 mock_get_oam_addresses):
        get_url = FAKE_URL + '/' + FAKE_ID + '/detail'
        oam_addresses = FakeOAMAddressPool('10.10.10.254',
                                           '10.10.10.1',
                                           '10.10.10.254',
                                           '10.10.10.4',
                                           '10.10.10.3',
                                           '10.10.10.1',
                                           '10.10.10.2')
        mock_get_oam_addresses.return_value = oam_addresses
        response = self.app.get(get_url, headers=FAKE_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual('10.10.10.2', response.json['oam_floating_ip'])

    @mock.patch.object(subclouds.SubcloudsController,
                       '_get_oam_addresses')
    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_subcloud_oam_ip_unavailable(self,
                                         mock_db_api,
                                         mock_rpc_client,
                                         mock_get_oam_addresses):
        get_url = FAKE_URL + '/' + FAKE_ID + '/detail'
        mock_get_oam_addresses.return_value = None
        response = self.app.get(get_url, headers=FAKE_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual('unavailable', response.json['oam_floating_ip'])

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    def test_get_wrong_request(self, mock_db_api, mock_rpc_client):
        get_url = WRONG_URL + '/' + FAKE_ID
        six.assertRaisesRegex(self, webtest.app.AppError, "404 *",
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
    @mock.patch.object(subclouds.SubcloudsController, '_get_patch_data')
    def test_patch_subcloud(self, mock_get_patch_data, mock_db_api,
                            mock_rpc_client):
        data = {'management-state': consts.MANAGEMENT_UNMANAGED}
        mock_rpc_client().update_subcloud.return_value = True
        mock_get_patch_data.return_value = data
        response = self.app.patch_json(FAKE_URL + '/' + FAKE_ID,
                                       headers=FAKE_HEADERS,
                                       params=data)
        mock_rpc_client().update_subcloud.assert_called_once_with(
            mock.ANY,
            mock.ANY,
            management_state=consts.MANAGEMENT_UNMANAGED,
            description=None,
            location=None,
            group_id=None,
            data_install=None)
        self.assertEqual(response.status_int, 200)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    @mock.patch.object(subclouds.SubcloudsController, '_get_patch_data')
    def test_patch_subcloud_install_values(self, mock_get_patch_data,
                                           mock_db_api, mock_rpc_client):
        payload = {}
        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)
        encoded_password = base64.b64encode(
            'bmc_password'.encode("utf-8")).decode('utf-8')
        data = {'bmc_password': encoded_password}
        payload.update({'install_values': install_data})
        payload.update(data)
        mock_rpc_client().update_subcloud.return_value = True
        mock_get_patch_data.return_value = payload

        # Return a fake subcloud database object
        fake_subcloud = Subcloud(FAKE_SUBCLOUD_DATA, False)
        mock_db_api.subcloud_get.return_value = fake_subcloud
        fake_content = "fake content".encode("utf-8")
        response = self.app.patch(FAKE_URL + '/' + FAKE_ID,
                                  headers=FAKE_HEADERS,
                                  params=data,
                                  upload_files=[("install_values",
                                                 "fake_name",
                                                 fake_content)])
        install_data.update({'bmc_password': encoded_password})
        mock_rpc_client().update_subcloud.assert_called_once_with(
            mock.ANY,
            FAKE_ID,
            management_state=None,
            description=None,
            location=None,
            group_id=None,
            data_install=json.dumps(install_data))
        self.assertEqual(response.status_int, 200)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    @mock.patch.object(subclouds.SubcloudsController, '_get_patch_data')
    def test_patch_subcloud_no_body(self, mock_get_patch_data, mock_db_api,
                                    mock_rpc_client):
        data = {}
        mock_get_patch_data.return_value = data
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' + FAKE_ID,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    @mock.patch.object(subclouds.SubcloudsController, '_get_patch_data')
    def test_patch_subcloud_bad_status(self, mock_get_patch_data, mock_db_api,
                                       mock_rpc_client):
        data = {'management-state': 'bad-status'}
        mock_get_patch_data.return_value = data
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' + FAKE_ID,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    @mock.patch.object(subclouds.SubcloudsController, '_get_reconfig_payload')
    def test_reconfigure_subcloud(self, mock_get_reconfig_payload,
                                  mock_db_api, mock_rpc_client):
        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password}

        mock_rpc_client().reconfigure_subcloud.return_value = True
        mock_get_reconfig_payload.return_value = data

        # Return a fake subcloud database object
        fake_subcloud = Subcloud(FAKE_SUBCLOUD_DATA, False)
        mock_db_api.subcloud_get.return_value = fake_subcloud

        response = self.app.patch_json(FAKE_URL + '/' + FAKE_ID +
                                       '/reconfigure',
                                       headers=FAKE_HEADERS,
                                       params=data)
        mock_rpc_client().reconfigure_subcloud.assert_called_once_with(
            mock.ANY,
            FAKE_ID,
            mock.ANY)
        self.assertEqual(response.status_int, 200)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    @mock.patch.object(subclouds.SubcloudsController, '_get_reconfig_payload')
    def test_reconfigure_subcloud_no_body(self, mock_get_reconfig_payload,
                                          mock_db_api, mock_rpc_client):
        # Pass an empty request body
        data = {}
        mock_get_reconfig_payload.return_value = data
        mock_rpc_client().reconfigure_subcloud.return_value = True

        # Return a fake subcloud database object
        fake_subcloud = Subcloud(FAKE_SUBCLOUD_DATA, False)
        mock_db_api.subcloud_get.return_value = fake_subcloud

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              FAKE_ID + '/reconfigure',
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    @mock.patch.object(subclouds.SubcloudsController, '_get_reconfig_payload')
    def test_reconfigure_subcloud_bad_password(self, mock_get_reconfig_payload,
                                               mock_db_api, mock_rpc_client):
        # Pass a sysadmin_password which is not base64 encoded
        data = {'sysadmin_password': 'not_base64'}
        mock_get_reconfig_payload.return_value = data
        mock_rpc_client().reconfigure_subcloud.return_value = True

        # Return a fake subcloud database object
        fake_subcloud = Subcloud(FAKE_SUBCLOUD_DATA, False)
        mock_db_api.subcloud_get.return_value = fake_subcloud

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              FAKE_ID + '/reconfigure',
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    @mock.patch.object(subclouds.SubcloudsController, '_get_reconfig_payload')
    def test_reconfigure_invalid_deploy_status(self,
                                               mock_get_reconfig_payload,
                                               mock_db_api,
                                               mock_rpc_client):
        fake_password = base64.b64encode('testpass'.encode("utf-8")).decode("utf-8")
        data = {'sysadmin_password': fake_password}
        # Update the deploy status to bootstrap-failed
        FAKE_SUBCLOUD_DATA_NEW = copy.copy(FAKE_SUBCLOUD_DATA)
        FAKE_SUBCLOUD_DATA_NEW["deploy_status"] = \
            consts.DEPLOY_STATE_BOOTSTRAP_FAILED
        mock_get_reconfig_payload.return_value = data
        mock_rpc_client().reconfigure_subcloud.return_value = True

        # Return a fake subcloud database object
        fake_subcloud = Subcloud(FAKE_SUBCLOUD_DATA_NEW, False)
        mock_db_api.subcloud_get.return_value = fake_subcloud

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              FAKE_ID + '/reconfigure',
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    @mock.patch.object(subclouds.SubcloudsController, '_get_updatestatus_payload')
    def test_subcloud_updatestatus(self, mock_get_updatestatus_payload,
                                   mock_db_api,
                                   mock_rpc_client):
        data = {'endpoint': 'dc-cert', 'status': 'in-sync'}
        mock_get_updatestatus_payload.return_value = data

        FAKE_SUBCLOUD_DATA_NEW = copy.copy(FAKE_SUBCLOUD_DATA)
        fake_subcloud = Subcloud(FAKE_SUBCLOUD_DATA_NEW, False)
        mock_db_api.subcloud_get.return_value = fake_subcloud
        mock_rpc_client().update_subcloud_endpoint_status.return_value = True
        response = self.app.patch_json(FAKE_URL + '/' + FAKE_ID + '/update_status',
                                       data, headers=FAKE_HEADERS)

        mock_rpc_client().update_subcloud_endpoint_status.assert_called_once_with(
            mock.ANY,
            fake_subcloud.name,
            'dc-cert',
            'in-sync')

        self.assertEqual(response.status_int, 200)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    @mock.patch.object(subclouds.SubcloudsController, '_get_updatestatus_payload')
    def test_subcloud_updatestatus_invalid_endpoint(
            self, mock_get_updatestatus_payload,
            mock_db_api,
            mock_rpc_client):
        data = {'endpoint': 'any-other-endpoint', 'status': 'in-sync'}
        mock_get_updatestatus_payload.return_value = data

        FAKE_SUBCLOUD_DATA_NEW = copy.copy(FAKE_SUBCLOUD_DATA)
        fake_subcloud = Subcloud(FAKE_SUBCLOUD_DATA_NEW, False)
        mock_db_api.subcloud_get.return_value = fake_subcloud
        mock_rpc_client().update_subcloud_endpoint_status.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              FAKE_ID + '/update_status',
                              headers=FAKE_HEADERS, params=data)
        mock_rpc_client().update_subcloud_endpoint_status.assert_not_called()

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds, 'db_api')
    @mock.patch.object(subclouds.SubcloudsController, '_get_updatestatus_payload')
    def test_subcloud_updatestatus_invalid_status(
            self, mock_get_updatestatus_payload,
            mock_db_api,
            mock_rpc_client):
        data = {'endpoint': 'dc-cert', 'status': 'not-sure'}
        mock_get_updatestatus_payload.return_value = data

        FAKE_SUBCLOUD_DATA_NEW = copy.copy(FAKE_SUBCLOUD_DATA)
        fake_subcloud = Subcloud(FAKE_SUBCLOUD_DATA_NEW, False)
        mock_db_api.subcloud_get.return_value = fake_subcloud
        mock_rpc_client().update_subcloud_endpoint_status.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              FAKE_ID + '/update_status',
                              headers=FAKE_HEADERS, params=data)
        mock_rpc_client().update_subcloud_endpoint_status.assert_not_called()
