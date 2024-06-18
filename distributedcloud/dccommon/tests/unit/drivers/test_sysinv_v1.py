# Copyright (c) 2017-2024 Wind River Systems, Inc.
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

import mock

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack import sysinv_v1
from dccommon.tests import base
from dccommon.tests import utils


class FakeInterface(object):
    def __init__(self, ifname, uuid):
        self.ifname = ifname
        self.uuid = uuid


class FakeInterfaceNetwork(object):
    def __init__(self, network_type, interface):
        self.network_type = network_type
        self.interface = interface


class FakeNetwork(object):
    def __init__(self, uuid, type, pool_uuid):
        self.uuid = uuid
        self.type = type
        self.pool_uuid = pool_uuid


class FakeAddressPool(object):
    def __init__(self, pool_uuid):
        self.pool_uuid = pool_uuid


class FakeNetworkAddrPool(object):
    def __init__(self, network_uuid, address_pool_uuid):
        self.network_uuid = network_uuid
        self.address_pool_uuid = address_pool_uuid


class FakeRoute(object):
    def __init__(self, data):
        self.uuid = data["uuid"]
        self.network = data["network"]
        self.prefix = data["prefix"]
        self.gateway = data["gateway"]
        self.metric = data["metric"]


class TestSysinvClient(base.DCCommonTestCase):
    def setUp(self):
        super(TestSysinvClient, self).setUp()
        self.ctx = utils.dummy_context()

    @mock.patch.object(sysinv_v1.SysinvClient, "__init__")
    def test_get_controller_hosts(self, mock_sysinvclient_init):
        controller_list = ["controller-0", "controller-1"]
        mock_sysinvclient_init.return_value = None
        sysinv_client = sysinv_v1.SysinvClient(
            dccommon_consts.DEFAULT_REGION_NAME, None
        )
        sysinv_client.sysinv_client = mock.MagicMock()
        sysinv_client.sysinv_client.ihost.list_personality = mock.MagicMock()
        sysinv_client.sysinv_client.ihost.list_personality.return_value = (
            controller_list
        )
        controllers = sysinv_client.get_controller_hosts()
        self.assertEqual(controller_list, controllers)

    @mock.patch.object(sysinv_v1.SysinvClient, "__init__")
    def test_get_management_interface(self, mock_sysinvclient_init):
        interface = FakeInterface("interface", "uuid")
        interface_network = FakeInterfaceNetwork("mgmt", "interface")
        mock_sysinvclient_init.return_value = None
        sysinv_client = sysinv_v1.SysinvClient(
            dccommon_consts.DEFAULT_REGION_NAME, None
        )
        sysinv_client.sysinv_client = mock.MagicMock()
        sysinv_client.sysinv_client.iinterface.list = mock.MagicMock()
        sysinv_client.sysinv_client.iinterface.list.return_value = [interface]
        sysinv_client.sysinv_client.interface_network.list_by_interface.return_value = [
            interface_network
        ]
        management_interface = sysinv_client.get_management_interface("hostname")
        self.assertEqual(interface, management_interface)

    @mock.patch.object(sysinv_v1.SysinvClient, "__init__")
    def test_get_management_address_pools(self, mock_sysinvclient_init):
        network = FakeNetwork("network-uuid", "mgmt", "pool-uuid")
        pool = FakeAddressPool("pool-uuid")
        network_addrpool = FakeNetworkAddrPool("network-uuid", "pool-uuid")
        mock_sysinvclient_init.return_value = None
        sysinv_client = sysinv_v1.SysinvClient(
            dccommon_consts.DEFAULT_REGION_NAME, None
        )
        sysinv_client.sysinv_client = mock.MagicMock()
        sysinv_client.sysinv_client.network.list = mock.MagicMock()
        sysinv_client.sysinv_client.network.list.return_value = [network]
        sysinv_client.sysinv_client.network_addrpool.list = mock.MagicMock()
        sysinv_client.sysinv_client.network_addrpool.list.return_value = [
            network_addrpool
        ]
        sysinv_client.sysinv_client.address_pool.get = mock.MagicMock()
        sysinv_client.sysinv_client.address_pool.get.return_value = pool
        management_pools = sysinv_client.get_management_address_pools()
        self.assertEqual([pool], management_pools)

    def _get_address_pool(self, pool_uuid):
        return self.addr_pools[pool_uuid]

    @mock.patch.object(sysinv_v1.SysinvClient, "__init__")
    def test_dual_stack_get_management_address_pools(self, mock_sysinvclient_init):
        network = FakeNetwork("network-uuid", "mgmt", "pool-uuid-1")
        pool_1 = FakeAddressPool("pool-uuid-1")
        network_addrpool_1 = FakeNetworkAddrPool("network-uuid", "pool-uuid-1")
        pool_2 = FakeAddressPool("pool-uuid-2")
        network_addrpool_2 = FakeNetworkAddrPool("network-uuid", "pool-uuid-2")
        mock_sysinvclient_init.return_value = None
        sysinv_client = sysinv_v1.SysinvClient(
            dccommon_consts.DEFAULT_REGION_NAME, None
        )
        sysinv_client.sysinv_client = mock.MagicMock()
        sysinv_client.sysinv_client.network.list = mock.MagicMock()
        sysinv_client.sysinv_client.network.list.return_value = [network]
        sysinv_client.sysinv_client.network_addrpool.list = mock.MagicMock()
        sysinv_client.sysinv_client.network_addrpool.list.return_value = [
            network_addrpool_1,
            network_addrpool_2,
        ]
        self.addr_pools = {"pool-uuid-1": pool_1, "pool-uuid-2": pool_2}
        sysinv_client.sysinv_client.address_pool.get.side_effect = (
            self._get_address_pool
        )
        management_pools = sysinv_client.get_management_address_pools()
        self.assertEqual([pool_1, pool_2], management_pools)

    @mock.patch.object(sysinv_v1.SysinvClient, "__init__")
    def test_dual_stack_get_oam_address_pools(self, mock_sysinvclient_init):
        network = FakeNetwork("network-uuid", "oam", "pool-uuid-1")
        pool_1 = FakeAddressPool("pool-uuid-1")
        network_addrpool_1 = FakeNetworkAddrPool("network-uuid", "pool-uuid-1")
        pool_2 = FakeAddressPool("pool-uuid-2")
        network_addrpool_2 = FakeNetworkAddrPool("network-uuid", "pool-uuid-2")
        mock_sysinvclient_init.return_value = None
        sysinv_client = sysinv_v1.SysinvClient(
            dccommon_consts.DEFAULT_REGION_NAME, None
        )
        sysinv_client.sysinv_client = mock.MagicMock()
        sysinv_client.sysinv_client.network.list = mock.MagicMock()
        sysinv_client.sysinv_client.network.list.return_value = [network]
        sysinv_client.sysinv_client.network_addrpool.list = mock.MagicMock()
        sysinv_client.sysinv_client.network_addrpool.list.return_value = [
            network_addrpool_1,
            network_addrpool_2,
        ]
        self.addr_pools = {"pool-uuid-1": pool_1, "pool-uuid-2": pool_2}
        sysinv_client.sysinv_client.address_pool.get.side_effect = (
            self._get_address_pool
        )
        oam_pools = sysinv_client.get_oam_address_pools()
        self.assertEqual([pool_1, pool_2], oam_pools)

    @mock.patch.object(sysinv_v1.SysinvClient, "__init__")
    def test_get_admin_interface(self, mock_sysinvclient_init):
        interface = FakeInterface("interface", "uuid")
        interface_network = FakeInterfaceNetwork("admin", "interface")
        mock_sysinvclient_init.return_value = None
        sysinv_client = sysinv_v1.SysinvClient(
            dccommon_consts.DEFAULT_REGION_NAME, None
        )
        sysinv_client.sysinv_client = mock.MagicMock()
        sysinv_client.sysinv_client.iinterface.list = mock.MagicMock()
        sysinv_client.sysinv_client.iinterface.list.return_value = [interface]
        sysinv_client.sysinv_client.interface_network.list_by_interface.return_value = [
            interface_network
        ]
        admin_interface = sysinv_client.get_admin_interface("hostname")
        self.assertEqual(interface, admin_interface)

    @mock.patch.object(sysinv_v1.SysinvClient, "__init__")
    def test_get_admin_address_pools(self, mock_sysinvclient_init):
        network = FakeNetwork("network-uuid", "admin", "pool-uuid")
        pool = FakeAddressPool("pool-uuid")
        network_addrpool = FakeNetworkAddrPool("network-uuid", "pool-uuid")
        mock_sysinvclient_init.return_value = None
        sysinv_client = sysinv_v1.SysinvClient(
            dccommon_consts.DEFAULT_REGION_NAME, None
        )
        sysinv_client.sysinv_client = mock.MagicMock()
        sysinv_client.sysinv_client.network.list = mock.MagicMock()
        sysinv_client.sysinv_client.network.list.return_value = [network]
        sysinv_client.sysinv_client.network_addrpool.list = mock.MagicMock()
        sysinv_client.sysinv_client.network_addrpool.list.return_value = [
            network_addrpool
        ]
        sysinv_client.sysinv_client.address_pool.get = mock.MagicMock()
        sysinv_client.sysinv_client.address_pool.get.return_value = pool
        admin_pools = sysinv_client.get_admin_address_pools()
        self.assertEqual([pool], admin_pools)

    @mock.patch.object(sysinv_v1.SysinvClient, "__init__")
    def test_create_route(self, mock_sysinvclient_init):
        fake_route = utils.create_route_dict(base.ROUTE_0)
        mock_sysinvclient_init.return_value = None
        sysinv_client = sysinv_v1.SysinvClient(
            dccommon_consts.DEFAULT_REGION_NAME, None
        )
        sysinv_client.sysinv_client = mock.MagicMock()
        sysinv_client.sysinv_client.route.create = mock.MagicMock()
        sysinv_client.create_route(
            fake_route["uuid"],
            fake_route["network"],
            fake_route["prefix"],
            fake_route["gateway"],
            fake_route["metric"],
        )
        sysinv_client.sysinv_client.route.create.assert_called_with(
            interface_uuid=fake_route["uuid"],
            network=fake_route["network"],
            prefix=fake_route["prefix"],
            gateway=fake_route["gateway"],
            metric=fake_route["metric"],
        )

    @mock.patch.object(sysinv_v1.SysinvClient, "__init__")
    def test_delete_route(self, mock_sysinvclient_init):
        fake_route = utils.create_route_dict(base.ROUTE_0)
        mock_sysinvclient_init.return_value = None
        sysinv_client = sysinv_v1.SysinvClient(
            dccommon_consts.DEFAULT_REGION_NAME, None
        )
        sysinv_client.sysinv_client = mock.MagicMock()
        sysinv_client.sysinv_client.route.delete = mock.MagicMock()
        sysinv_client.sysinv_client.route.list_by_interface = mock.MagicMock()
        existing_route_0 = FakeRoute(utils.create_route_dict(base.ROUTE_0))
        existing_route_1 = FakeRoute(utils.create_route_dict(base.ROUTE_1))
        sysinv_client.sysinv_client.route.list_by_interface.return_value = [
            existing_route_0,
            existing_route_1,
        ]
        sysinv_client.delete_route(
            fake_route["uuid"],
            fake_route["network"],
            fake_route["prefix"],
            fake_route["gateway"],
            fake_route["metric"],
        )
        sysinv_client.sysinv_client.route.delete.assert_called_with(
            existing_route_0.uuid
        )

    @mock.patch.object(sysinv_v1.SysinvClient, "__init__")
    def test_delete_route_not_exist(self, mock_sysinvclient_init):
        fake_route = utils.create_route_dict(base.ROUTE_0)
        mock_sysinvclient_init.return_value = None
        sysinv_client = sysinv_v1.SysinvClient(
            dccommon_consts.DEFAULT_REGION_NAME, None
        )
        sysinv_client.sysinv_client = mock.MagicMock()
        sysinv_client.sysinv_client.route.delete = mock.MagicMock()
        sysinv_client.sysinv_client.route.list_by_interface = mock.MagicMock()
        existing_route_1 = FakeRoute(utils.create_route_dict(base.ROUTE_1))
        sysinv_client.sysinv_client.route.list_by_interface.return_value = [
            existing_route_1
        ]
        sysinv_client.delete_route(
            fake_route["uuid"],
            fake_route["network"],
            fake_route["prefix"],
            fake_route["gateway"],
            fake_route["metric"],
        )
        sysinv_client.sysinv_client.route.delete.assert_not_called()
