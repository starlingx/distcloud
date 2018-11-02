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
# Copyright (c) 2017 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

import mock

from oslo_config import cfg
from oslo_utils import timeutils

import sys
sys.modules['fm_core'] = mock.Mock()

from dcorch.rpc import client as dcorch_rpc_client

from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.manager import subcloud_manager
from dcmanager.tests import base
from dcmanager.tests import utils

from ddt import ddt
from ddt import file_data

CONF = cfg.CONF
FAKE_ID = '1'
FAKE_SUBCLOUD_DATA = {"name": "subcloud1",
                      "description": "subcloud1 description",
                      "location": "subcloud1 location",
                      "management-subnet": "192.168.101.0/24",
                      "management-start-ip": "192.168.101.3",
                      "management-end-ip": "192.168.101.4",
                      "management-gateway-ip": "192.168.101.1",
                      "systemcontroller-gateway-ip": "192.168.204.101"}


class Controller(object):
    def __init__(self, hostname):
        self.hostname = hostname


class Service(object):
    def __init__(self, type, id):
        self.type = type
        self.id = id


class Subcloud(object):
    def __init__(self, data, is_online):
        self.id = data['id']
        self.name = data['name']
        self.description = data['description']
        self.location = data['location']
        self.software_version = data['software-version']
        self.management_state = consts.MANAGEMENT_UNMANAGED
        if is_online:
            self.availability_status = consts.AVAILABILITY_ONLINE
        else:
            self.availability_status = consts.AVAILABILITY_OFFLINE

        self.management_subnet = data['management-subnet']
        self.management_gateway_ip = data['management-gateway-ip']
        self.management_start_ip = data['management-start-ip']
        self.management_end_ip = data['management-end-ip']
        self.systemcontroller_gateway_ip = data['systemcontroller-gateway-ip']
        self.created_at = timeutils.utcnow()
        self.updated_at = timeutils.utcnow()


@ddt
class TestSubcloudManager(base.DCManagerTestCase):
    def setUp(self):
        super(TestSubcloudManager, self).setUp()
        self.ctxt = utils.dummy_context()

    @mock.patch.object(dcorch_rpc_client, 'EngineClient')
    @mock.patch.object(subcloud_manager, 'KeystoneClient')
    @mock.patch.object(subcloud_manager, 'context')
    def test_init(self, mock_context, mock_endpoint, mock_dcorch_rpc_client):
        mock_context.get_admin_context.return_value = self.ctxt
        am = subcloud_manager.SubcloudManager()
        self.assertIsNotNone(am)
        self.assertEqual('subcloud_manager', am.service_name)
        self.assertEqual('localhost', am.host)
        self.assertEqual(self.ctxt, am.context)

    @file_data(utils.get_data_filepath('dcmanager', 'subclouds'))
    @mock.patch.object(dcorch_rpc_client, 'EngineClient')
    @mock.patch.object(subcloud_manager, 'context')
    @mock.patch.object(subcloud_manager, 'KeystoneClient')
    @mock.patch.object(subcloud_manager, 'db_api')
    @mock.patch.object(subcloud_manager, 'SysinvClient')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_create_addn_hosts_dc')
    def test_add_subcloud(self, value,
                          mock_create_addn_hosts, mock_sysinv_client,
                          mock_db_api, mock_keystone_client, mock_context,
                          mock_dcorch_rpc_client):
        value = utils.create_subcloud_dict(value)
        controllers = [Controller('controller-0'), Controller('controller-1')]
        services = [Service('identity', '1234')]
        mock_context.get_admin_context.return_value = self.ctxt
        mock_db_api.subcloud_get_by_name.side_effect = \
            exceptions.SubcloudNameNotFound()

        mock_sysinv_client().get_controller_hosts.return_value = controllers
        mock_keystone_client().services_list = services

        sm = subcloud_manager.SubcloudManager()
        sm.add_subcloud(self.ctxt, payload=value)
        mock_db_api.subcloud_create.assert_called_once()
        mock_db_api.subcloud_status_create.assert_called()
        mock_sysinv_client().create_route.assert_called()
        mock_dcorch_rpc_client().add_subcloud.assert_called_once()
        mock_create_addn_hosts.assert_called_once()

    @file_data(utils.get_data_filepath('dcmanager', 'subclouds'))
    @mock.patch.object(dcorch_rpc_client, 'EngineClient')
    @mock.patch.object(subcloud_manager, 'context')
    @mock.patch.object(subcloud_manager, 'db_api')
    @mock.patch.object(subcloud_manager, 'SysinvClient')
    @mock.patch.object(subcloud_manager, 'KeystoneClient')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_create_addn_hosts_dc')
    def test_delete_subcloud(self, value, mock_create_addn_hosts,
                             mock_keystone_client,
                             mock_sysinv_client,
                             mock_db_api,
                             mock_context,
                             mock_dcorch_rpc_client):
        controllers = [Controller('controller-0'), Controller('controller-1')]
        mock_context.get_admin_context.return_value = self.ctxt
        data = utils.create_subcloud_dict(value)
        fake_subcloud = Subcloud(data, False)
        mock_db_api.subcloud_get.return_value = fake_subcloud
        mock_sysinv_client().get_controller_hosts.return_value = controllers
        sm = subcloud_manager.SubcloudManager()
        sm.delete_subcloud(self.ctxt, subcloud_id=data['id'])
        mock_sysinv_client().delete_route.assert_called()
        mock_keystone_client().delete_region.assert_called_once()
        mock_db_api.subcloud_destroy.assert_called_once()
        mock_create_addn_hosts.assert_called_once()

    @file_data(utils.get_data_filepath('dcmanager', 'subclouds'))
    @mock.patch.object(dcorch_rpc_client, 'EngineClient')
    @mock.patch.object(subcloud_manager, 'context')
    @mock.patch.object(subcloud_manager, 'KeystoneClient')
    @mock.patch.object(subcloud_manager, 'db_api')
    def test_update_subcloud(self, value, mock_db_api,
                             mock_endpoint, mock_context,
                             mock_dcorch_rpc_client):
        mock_context.get_admin_context.return_value = self.ctxt
        data = utils.create_subcloud_dict(value)
        subcloud_result = Subcloud(data, True)
        mock_db_api.subcloud_get.return_value = subcloud_result
        mock_db_api.subcloud_update.return_value = subcloud_result
        sm = subcloud_manager.SubcloudManager()
        sm.update_subcloud(self.ctxt, data['id'],
                           management_state=consts.MANAGEMENT_MANAGED,
                           description="subcloud new description",
                           location="subcloud new location")
        mock_db_api.subcloud_update.assert_called_once_with(
            mock.ANY,
            data['id'],
            management_state=consts.MANAGEMENT_MANAGED,
            description="subcloud new description",
            location="subcloud new location")
