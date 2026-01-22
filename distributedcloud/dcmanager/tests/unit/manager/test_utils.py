# Copyright (c) 2023-2024, 2026 Wind River Systems, Inc.
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

import json
import mock

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
        payload = {
            "management_subnet": "192.168.101.0/24",
            "management_gateway_address": "192.168.101.1",
            "management_start_address": "192.168.101.2",
            "management_end_address": "192.168.101.50",
            "systemcontroller_gateway_address": "192.168.204.101",
        }
        result = utils.has_network_reconfig(payload, subcloud)
        self.assertFalse(result)

    def test_has_network_reconfig_different_subnet(self):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        payload = {
            "management_subnet": "192.168.102.0/24",
            "management_gateway_address": "192.168.102.1",
            "management_start_address": "192.168.102.2",
            "management_end_address": "192.168.102.50",
        }
        result = utils.has_network_reconfig(payload, subcloud)
        self.assertTrue(result)

    def test_has_network_reconfig_different_start_address(self):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        payload = {
            "management_subnet": "192.168.101.0/24",
            "management_gateway_address": "192.168.101.5",
            "management_start_address": "192.168.101.7",
            "management_end_address": "192.168.101.50",
        }
        result = utils.has_network_reconfig(payload, subcloud)
        self.assertTrue(result)

    def test_has_network_reconfig_different_sc_gateway(self):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        payload = {
            "management_subnet": "192.168.101.0/24",
            "management_gateway_address": "192.168.101.1",
            "management_start_address": "192.168.101.2",
            "management_end_address": "192.168.101.50",
            "systemcontroller_gateway_address": "192.168.204.102",
        }
        result = utils.has_network_reconfig(payload, subcloud)
        self.assertTrue(result)

    def test_format_ipv4_address(self):
        # Test a valid IPv4 address
        ipv4_address = "192.168.1.1"
        expected = "192.168.1.1"
        result = utils.format_address(ipv4_address)
        self.assertEqual(result, expected)

    def test_format_ipv6_address(self):
        # Test a valid IPv6 address
        ipv6_address = "2620:10a:a001:aa0c::128"
        expected = "[2620:10a:a001:aa0c::128]"
        result = utils.format_address(ipv6_address)
        self.assertEqual(result, expected)

    @mock.patch("dcmanager.common.utils.subprocess.run")
    def test_get_last_sel_event_id_success(self, mock_run):
        mock_run.return_value = mock.Mock(
            stdout=json.dumps({"last_event_id": "12345"}),
            returncode=0,
        )
        install_values = {
            "bmc_address": "10.64.8.246",
            "bmc_username": "sysadmin",
            "bmc_password": "secret",
        }

        result = utils.get_last_sel_event_id(install_values)

        self.assertEqual(result, "12345")
        mock_run.assert_called_once_with(
            [
                "/usr/local/bin/ipmi_sel_event_monitor.py",
                "--bmc-address",
                "10.64.8.246",
                "--bmc-username",
                "sysadmin",
                "--bmc-password",
                "secret",
                "--get-last-event",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    @mock.patch("dcmanager.common.utils.subprocess.run")
    def test_get_last_sel_event_id_failure(self, mock_run):
        mock_run.return_value = mock.Mock(
            stdout="",
            stderr="Connection refused",
            returncode=1,
        )
        install_values = {
            "bmc_address": "10.64.8.246",
            "bmc_username": "sysadmin",
            "bmc_password": "secret",
        }

        exc = self.assertRaises(
            RuntimeError,
            utils.get_last_sel_event_id,
            install_values,
        )
        self.assertNotIn("secret", str(exc))
