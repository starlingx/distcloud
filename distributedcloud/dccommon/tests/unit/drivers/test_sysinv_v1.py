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
# Copyright (c) 2017-2020 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

import mock

from dccommon.drivers.openstack import sysinv_v1
from dccommon.tests import base
from dccommon.tests import utils
from dcmanager.common import consts
from dcmanager.tests import utils as dcmanager_utils

from ddt import ddt
from ddt import file_data


class FakeInterface(object):
    def __init__(self, ifname, uuid):
        self.ifname = ifname
        self.uuid = uuid


class FakeInterfaceNetwork(object):
    def __init__(self, network_type, interface):
        self.network_type = network_type
        self.interface = interface


class FakeNetwork(object):
    def __init__(self, type, pool_uuid):
        self.type = type
        self.pool_uuid = pool_uuid


class FakeAddressPool(object):
    def __init__(self, pool_uuid):
        self.pool_uuid = pool_uuid


class FakeRoute(object):
    def __init__(self, data):
        self.uuid = data['uuid']
        self.network = data['network']
        self.prefix = data['prefix']
        self.gateway = data['gateway']
        self.metric = data['metric']


@ddt
class TestSysinvClient(base.DCCommonTestCase):
    def setUp(self):
        super(TestSysinvClient, self).setUp()
        self.ctx = utils.dummy_context()

    @mock.patch.object(sysinv_v1.SysinvClient, '__init__')
    def test_get_controller_hosts(self, mock_sysinvclient_init):
        controller_list = ['controller-0', 'controller-1']
        mock_sysinvclient_init.return_value = None
        sysinv_client = sysinv_v1.SysinvClient(consts.DEFAULT_REGION_NAME,
                                               None)
        sysinv_client.sysinv_client = mock.MagicMock()
        sysinv_client.sysinv_client.ihost.list_personality = mock.MagicMock()
        sysinv_client.sysinv_client.ihost.list_personality.return_value = \
            controller_list
        controllers = sysinv_client.get_controller_hosts()
        self.assertEqual(controller_list, controllers)

    @mock.patch.object(sysinv_v1.SysinvClient, '__init__')
    def test_get_management_interface(self, mock_sysinvclient_init):
        interface = FakeInterface('interface', 'uuid')
        interface_network = FakeInterfaceNetwork('mgmt', 'interface')
        mock_sysinvclient_init.return_value = None
        sysinv_client = sysinv_v1.SysinvClient(consts.DEFAULT_REGION_NAME,
                                               None)
        sysinv_client.sysinv_client = mock.MagicMock()
        sysinv_client.sysinv_client.iinterface.list = mock.MagicMock()
        sysinv_client.sysinv_client.iinterface.list.return_value = [interface]
        sysinv_client.sysinv_client.interface_network.list_by_interface.\
            return_value = [interface_network]
        management_interface = sysinv_client.get_management_interface(
            'hostname')
        self.assertEqual(interface, management_interface)

    @mock.patch.object(sysinv_v1.SysinvClient, '__init__')
    def test_get_management_address_pool(self, mock_sysinvclient_init):
        network = FakeNetwork('mgmt', 'uuid')
        pool = FakeAddressPool('uuid')
        mock_sysinvclient_init.return_value = None
        sysinv_client = sysinv_v1.SysinvClient(consts.DEFAULT_REGION_NAME,
                                               None)
        sysinv_client.sysinv_client = mock.MagicMock()
        sysinv_client.sysinv_client.network.list = mock.MagicMock()
        sysinv_client.sysinv_client.network.list.return_value = [network]
        sysinv_client.sysinv_client.address_pool.get = mock.MagicMock()
        sysinv_client.sysinv_client.address_pool.get.return_value = pool
        management_pool = sysinv_client.get_management_address_pool()
        self.assertEqual(pool, management_pool)

    @file_data(dcmanager_utils.get_data_filepath('sysinv', 'routes'))
    @mock.patch.object(sysinv_v1.SysinvClient, '__init__')
    def test_create_route(self, value, mock_sysinvclient_init):
        fake_route = utils.create_route_dict(value)
        mock_sysinvclient_init.return_value = None
        sysinv_client = sysinv_v1.SysinvClient(consts.DEFAULT_REGION_NAME,
                                               None)
        sysinv_client.sysinv_client = mock.MagicMock()
        sysinv_client.sysinv_client.route.create = mock.MagicMock()
        sysinv_client.create_route(fake_route['uuid'],
                                   fake_route['network'],
                                   fake_route['prefix'],
                                   fake_route['gateway'],
                                   fake_route['metric'])
        sysinv_client.sysinv_client.route.create.assert_called_with(
            interface_uuid=fake_route['uuid'],
            network=fake_route['network'], prefix=fake_route['prefix'],
            gateway=fake_route['gateway'], metric=fake_route['metric'])

    @file_data(dcmanager_utils.get_data_filepath('sysinv', 'routes'))
    @mock.patch.object(sysinv_v1.SysinvClient, '__init__')
    def test_delete_route(self, value, mock_sysinvclient_init):
        # fake_route = utils.create_route_dict(value)
        mock_sysinvclient_init.return_value = None
