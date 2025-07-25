# Copyright (c) 2017-2021, 2024-2025 Wind River Systems, Inc.
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

from dccommon.drivers.openstack import keystone_v3
from dccommon.tests import base
from dccommon.tests import utils

FAKE_SERVICE = ["endpoint_volume", "endpoint_network"]


class Project(object):
    def __init__(self, proj_name, id, enabled=True):
        self.proj_name = proj_name
        self.id = id
        self.enabled = enabled


class User(object):
    def __init__(self, user_name, id, enabled=True):
        self.user_name = user_name
        self.id = id
        self.enabled = enabled


class FakeEndpoint(object):
    def __init__(self, endpoint_name, region):
        self.endpoint_name = endpoint_name
        self.region = region


class TestKeystoneClient(base.DCCommonTestCase):
    def setUp(self):
        super(TestKeystoneClient, self).setUp()
        self.ctx = utils.dummy_context()

    @mock.patch.object(keystone_v3, "EndpointCache")
    def test_get_enabled_projects(self, mock_endpoint_cache):
        p1 = Project("proj1", "123")
        p2 = Project("proj2", "456", False)
        key_client = keystone_v3.KeystoneClient()
        mock_endpoint_cache().keystone_client.projects.list.return_value = [p1, p2]
        project_list = key_client.get_enabled_projects()
        self.assertIn(p1.id, project_list)
        self.assertNotIn(p2.id, project_list)

    @mock.patch.object(keystone_v3, "EndpointCache")
    def test_get_enabled_users(self, mock_endpoint_cache):
        u1 = User("user1", "123")
        u2 = User("user2", "456", False)
        key_client = keystone_v3.KeystoneClient()
        mock_endpoint_cache().keystone_client.users.list.return_value = [u1, u2]
        users_list = key_client.get_enabled_users()
        self.assertIn(u1.id, users_list)
        self.assertNotIn(u2.id, users_list)

    @mock.patch.object(keystone_v3.endpoint_filter, "EndpointFilterManager")
    @mock.patch.object(keystone_v3, "EndpointCache")
    def test_get_filtered_region(
        self, mock_endpoint_cache, mock_endpoint_filter_manager
    ):
        endpoint_1 = FakeEndpoint("endpoint1", "regionOne")
        endpoint_2 = FakeEndpoint("endpoint2", "regionTwo")
        key_client = keystone_v3.KeystoneClient()
        mock_endpoint_filter_manager().list_endpoints_for_project.return_value = [
            endpoint_1,
            endpoint_2,
        ]
        region_list = key_client.get_filtered_region("fake_project")
        self.assertIn("regionOne", region_list)
        self.assertIn("regionTwo", region_list)

    @mock.patch.object(keystone_v3, "EndpointCache")
    def test_delete_endpoints(self, mock_endpoint_cache):
        endpoint_1 = FakeEndpoint("endpoint1", "regionOne")
        mock_endpoint_cache().keystone_client.endpoints.list.return_value = [endpoint_1]
        key_client = keystone_v3.KeystoneClient()
        key_client.delete_endpoints("regionOne")
        mock_endpoint_cache().keystone_client.endpoints.delete.assert_called_with(
            endpoint_1
        )

    @mock.patch.object(keystone_v3, "EndpointCache")
    def test_delete_region(self, mock_endpoint_cache):
        key_client = keystone_v3.KeystoneClient()
        key_client.delete_region("regionOne")
        mock_endpoint_cache().keystone_client.regions.delete.assert_called_with(
            "regionOne"
        )
