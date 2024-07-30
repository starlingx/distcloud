# Copyright 2016 Ericsson AB
# Copyright (c) 2017, 2019, 2021, 2024 Wind River Systems, Inc.
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


class TestUtils(base.DCManagerTestCase):
    def setUp(self):
        super(TestUtils, self).setUp()

    def test_get_management_subnet(self):
        payload = {"management_subnet": "192.168.204.0/24"}
        self.assertEqual(
            utils.get_management_subnet(payload), payload["management_subnet"]
        )

    def test_get_management_subnet_return_admin(self):
        payload = {
            "admin_subnet": "192.168.205.0/24",
            "management_subnet": "192.168.204.0/24",
        }
        self.assertEqual(utils.get_management_subnet(payload), payload["admin_subnet"])

    def test_get_management_start_address(self):
        payload = {"management_start_address": "192.168.204.2"}
        self.assertEqual(
            utils.get_management_start_address(payload),
            payload["management_start_address"],
        )

    def test_get_management_start_address_return_admin(self):
        payload = {
            "admin_start_address": "192.168.205.2",
            "management_start_address": "192.168.204.2",
        }
        self.assertEqual(
            utils.get_management_start_address(payload),
            payload["admin_start_address"],
        )

    def test_get_management_end_address(self):
        payload = {"management_end_address": "192.168.204.50"}
        self.assertEqual(
            utils.get_management_end_address(payload),
            payload["management_end_address"],
        )

    def test_get_management_end_address_return_admin(self):
        payload = {
            "admin_end_address": "192.168.205.50",
            "management_end_address": "192.168.204.50",
        }
        self.assertEqual(
            utils.get_management_end_address(payload), payload["admin_end_address"]
        )

    def test_get_management_gateway_address(self):
        payload = {"management_gateway_address": "192.168.204.1"}
        self.assertEqual(
            utils.get_management_gateway_address(payload),
            payload["management_gateway_address"],
        )

    def test_get_management_gateway_address_return_admin(self):
        payload = {
            "admin_gateway_address": "192.168.205.1",
            "management_gateway_address": "192.168.204.1",
        }
        self.assertEqual(
            utils.get_management_gateway_address(payload),
            payload["admin_gateway_address"],
        )
