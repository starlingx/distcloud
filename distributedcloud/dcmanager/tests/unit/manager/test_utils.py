# Copyright (c) 2023 Wind River Systems, Inc.
# All Rights Reserved
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

from dcmanager.common import utils
from dcmanager.tests import base
from dcmanager.tests.unit.common import fake_subcloud
from dcmanager.tests import utils as test_utils


class TestUtils(base.DCManagerTestCase):
    def setUp(self):
        super(TestUtils, self).setUp()
        self.ctx = test_utils.dummy_context()

    def test_has_network_reconfig_same_values(self):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        payload = {"management_subnet": "192.168.101.0/24",
                   "management_gateway_address": "192.168.101.1",
                   "management_start_address": "192.168.101.2",
                   "management_end_address": "192.168.101.50",
                   "systemcontroller_gateway_address": "192.168.204.101"}
        result = utils.has_network_reconfig(payload, subcloud)
        self.assertFalse(result)

    def test_has_network_reconfig_different_subnet(self):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        payload = {"management_subnet": "192.168.102.0/24",
                   "management_gateway_address": "192.168.102.1",
                   "management_start_address": "192.168.102.2",
                   "management_end_address": "192.168.102.50"}
        result = utils.has_network_reconfig(payload, subcloud)
        self.assertTrue(result)

    def test_has_network_reconfig_different_start_address(self):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        payload = {"management_subnet": "192.168.101.0/24",
                   "management_gateway_address": "192.168.101.5",
                   "management_start_address": "192.168.101.7",
                   "management_end_address": "192.168.101.50"}
        result = utils.has_network_reconfig(payload, subcloud)
        self.assertTrue(result)

    def test_has_network_reconfig_different_sc_gateway(self):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        payload = {"management_subnet": "192.168.101.0/24",
                   "management_gateway_address": "192.168.101.1",
                   "management_start_address": "192.168.101.2",
                   "management_end_address": "192.168.101.50",
                   "systemcontroller_gateway_address": "192.168.204.102"}
        result = utils.has_network_reconfig(payload, subcloud)
        self.assertTrue(result)
