#
# Copyright (c) 2023-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import base64
import copy
import json
import os

from oslo_utils import timeutils

from dccommon import consts as dccommon_consts
from dcmanager.common import consts
from dcmanager.common import phased_subcloud_deploy as psd_common
from dcmanager.tests.base import DCManagerTestCase
from dcmanager.tests.unit.common import fake_subcloud


class Subcloud(object):
    def __init__(self, data, is_online):
        self.id = data["id"]
        self.name = data["name"]
        self.description = data["description"]
        self.location = data["location"]
        self.management_state = dccommon_consts.MANAGEMENT_UNMANAGED
        if is_online:
            self.availability_status = dccommon_consts.AVAILABILITY_ONLINE
        else:
            self.availability_status = dccommon_consts.AVAILABILITY_OFFLINE
        self.deploy_status = data["deploy_status"]
        self.management_subnet = data["management_subnet"]
        self.management_gateway_ip = data["management_gateway_address"]
        self.management_start_ip = data["management_start_address"]
        self.management_end_ip = data["management_end_address"]
        self.external_oam_subnet = data["external_oam_subnet"]
        self.external_oam_gateway_address = data["external_oam_gateway_address"]
        self.external_oam_floating_address = data["external_oam_floating_address"]
        self.systemcontroller_gateway_ip = data["systemcontroller_gateway_address"]
        self.created_at = timeutils.utcnow()
        self.updated_at = timeutils.utcnow()
        self.data_install = ""
        self.data_upgrade = ""


class TestCommonPhasedSubcloudDeploy(DCManagerTestCase):
    def setUp(self):
        super().setUp()
        self.mock_os_path_isdir = self._mock_object(os.path, "isdir")
        self.mock_os_listdir = self._mock_object(os, "listdir")

    def test_check_deploy_files_alternate_location_with_all_file_exists(self):
        payload = {}
        self.mock_os_path_isdir.return_value = True
        self.mock_os_listdir.return_value = [
            "deploy-chart-fake-deployment-manager.tgz",
            "deploy-overrides-fake-overrides-subcloud.yaml",
            "deploy-playbook-fake-deployment-manager.yaml",
        ]

        response = psd_common.check_deploy_files_in_alternate_location(payload)
        self.assertEqual(response, True)

    def test_check_deploy_files_alternate_location_with_chart_exists(self):
        payload = {}
        self.mock_os_path_isdir.return_value = True
        self.mock_os_listdir.return_value = [
            "deploy-chart-fake.tgz",
            "deploy-overrides-fake-overrides-subcloud.yaml",
            "deploy-playbook-fake-deployment-manager.yaml",
        ]

        response = psd_common.check_deploy_files_in_alternate_location(payload)
        self.assertEqual(response, True)

    def test_check_deploy_files_deploy_overrides_not_exists(self):
        payload = {}
        self.mock_os_path_isdir.return_value = True
        self.mock_os_listdir.return_value = [
            "deploy-chart-fake-deployment-manager.tgz",
            "deploy-overrides.yaml",
            "deploy-playbook-fake-deployment-manager.yaml",
        ]

        response = psd_common.check_deploy_files_in_alternate_location(payload)
        self.assertEqual(response, False)

    def test_check_deploy_files_deploy_playbook_not_exists(self):
        payload = {}
        self.mock_os_path_isdir.return_value = True
        self.mock_os_listdir.return_value = [
            "deploy-chart-fake-deployment-manager.tgz",
            "deploy-overrides-fake-overrides-subcloud.yaml",
            "deploy-playbook.yaml",
        ]

        response = psd_common.check_deploy_files_in_alternate_location(payload)
        self.assertEqual(response, False)

    def test_get_config_file_path(self):
        bootstrap_file = psd_common.get_config_file_path("subcloud1")
        install_values = psd_common.get_config_file_path("subcloud1", "install_values")
        deploy_config = psd_common.get_config_file_path(
            "subcloud1", consts.DEPLOY_CONFIG
        )

        self.assertEqual(
            bootstrap_file, f"{dccommon_consts.ANSIBLE_OVERRIDES_PATH}/subcloud1.yml"
        )
        self.assertEqual(
            install_values,
            f"{dccommon_consts.ANSIBLE_OVERRIDES_PATH}/subcloud1/install_values.yml",
        )
        self.assertEqual(
            deploy_config,
            f"{dccommon_consts.ANSIBLE_OVERRIDES_PATH}/subcloud1_deploy_config.yml",
        )

    def test_format_ip_address(self):
        fake_payload = {}
        good_values = {
            "10.10.10.3": "10.10.10.3",
            "2620:10a:a001:a103::1135": "2620:10a:a001:a103::1135",
            "2620:10A:A001:A103::1135": "2620:10a:a001:a103::1135",
            "2620:010a:a001:a103::1135": "2620:10a:a001:a103::1135",
            "2620:10a:a001:a103:0000::1135": "2620:10a:a001:a103::1135",
        }

        for k, v in good_values.items():
            fake_payload["bootstrap-address"] = k
            psd_common.format_ip_address(fake_payload)
            self.assertEqual(fake_payload["bootstrap-address"], v)

            fake_payload[consts.INSTALL_VALUES] = {}
            for k, v in good_values.items():
                fake_payload[consts.INSTALL_VALUES]["bmc_address"] = k
                psd_common.format_ip_address(fake_payload)
                self.assertEqual(fake_payload[consts.INSTALL_VALUES]["bmc_address"], v)

            fake_payload["othervalues1"] = "othervalues1"
            fake_payload[consts.INSTALL_VALUES]["othervalues2"] = "othervalues2"
            psd_common.format_ip_address(fake_payload)
            self.assertEqual(fake_payload["othervalues1"], "othervalues1")
            self.assertEqual(
                fake_payload[consts.INSTALL_VALUES]["othervalues2"], "othervalues2"
            )

    def test_get_subcloud_db_install_values(self):
        install_data = copy.copy(fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES)
        encoded_password = base64.b64encode("bmc_password".encode("utf-8")).decode(
            "utf-8"
        )
        install_data["bmc_password"] = encoded_password
        test_subcloud = copy.copy(fake_subcloud.FAKE_SUBCLOUD_DATA)
        subcloud_info = Subcloud(test_subcloud, False)
        subcloud_info.data_install = json.dumps(install_data)

        actual_result = psd_common.get_subcloud_db_install_values(subcloud_info)

        self.assertEqual(
            json.loads(json.dumps(install_data)), json.loads(json.dumps(actual_result))
        )

    def test_validate_admin_config_range(self):
        admin_subnet = "fd02::/64"
        admin_start_address = "fd02::2"
        admin_end_address = "fd02::ffff:ffff:ffff:ffff"
        admin_gateway_address = "fd02::1"

        try:
            psd_common.validate_admin_network_config(
                admin_subnet,
                admin_start_address,
                admin_end_address,
                admin_gateway_address,
                existing_networks=None,
                operation=None,
            )
        except Exception:
            self.fail("validate_admin_network_config raised an exception unexpectedly!")

    def test_validate_admin_config_subnet_small(self):
        admin_subnet = "192.168.205.0/32"
        admin_start_address = "192.168.205.2"
        admin_end_address = "192.168.205.50"
        admin_gateway_address = "192.168.205.1"

        with self.assertRaisesRegex(Exception, "Subnet too small*"):
            psd_common.validate_admin_network_config(
                admin_subnet,
                admin_start_address,
                admin_end_address,
                admin_gateway_address,
                existing_networks=None,
                operation=None,
            )

    def test_validate_admin_config_start_address_outOfSubnet(self):
        admin_subnet = "192.168.205.0/28"
        admin_start_address = "192.168.205.200"
        admin_end_address = "192.168.205.50"
        admin_gateway_address = "192.168.205.1"

        with self.assertRaisesRegex(Exception, "Address must be in subnet*"):
            psd_common.validate_admin_network_config(
                admin_subnet,
                admin_start_address,
                admin_end_address,
                admin_gateway_address,
                existing_networks=None,
                operation=None,
            )

    def test_validate_admin_config_end_address_outOfSubnet(self):
        admin_subnet = "192.168.205.0/28"
        admin_start_address = "192.168.205.1"
        admin_end_address = "192.168.205.50"
        admin_gateway_address = "192.168.205.1"

        with self.assertRaisesRegex(Exception, "Address must be in subnet*"):
            psd_common.validate_admin_network_config(
                admin_subnet,
                admin_start_address,
                admin_end_address,
                admin_gateway_address,
                existing_networks=None,
                operation=None,
            )

        admin_end_address = "192.168.205.12"
        admin_gateway_address = "192.168.205.50"

        with self.assertRaisesRegex(Exception, "Address must be in subnet*"):
            psd_common.validate_admin_network_config(
                admin_subnet,
                admin_start_address,
                admin_end_address,
                admin_gateway_address,
                existing_networks=None,
                operation=None,
            )

    def test_validate_admin_config_end_address_broadcast(self):
        admin_subnet = "192.168.205.0/24"
        admin_start_address = "192.168.205.1"
        admin_end_address = "192.168.205.255"
        admin_gateway_address = "192.168.205.1"

        with self.assertRaisesRegex(Exception, "Cannot use broadcast address"):
            psd_common.validate_admin_network_config(
                admin_subnet,
                admin_start_address,
                admin_end_address,
                admin_gateway_address,
                existing_networks=None,
                operation=None,
            )
