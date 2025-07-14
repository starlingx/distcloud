#
# Copyright (c) 2023-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import base64
import builtins
import copy
import io
import json
import os
import tarfile
import tempfile

from oslo_utils import timeutils

from dccommon import consts as dccommon_consts
from dccommon.endpoint_cache import EndpointCache
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
        self._mock_object(EndpointCache, "get_admin_session")

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
        cloud_init_config = psd_common.get_config_file_path(
            "subcloud1", dccommon_consts.CLOUD_INIT_CONFIG
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
        self.assertEqual(
            cloud_init_config,
            f"{dccommon_consts.ANSIBLE_OVERRIDES_PATH}/subcloud1_cloud_init_config.tar",
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
            )
        except Exception:
            self.fail("validate_admin_network_config raised an exception unexpectedly!")

    def test_validate_admin_config_overlap(self):
        admin_subnet = "fd02::/64"
        admin_start_address = "fd02::2"
        admin_end_address = "fd02::ffff:ffff:ffff:ffff"
        admin_gateway_address = "fd02::1"

        class fake_subcloud_db(object):
            name = "subcloud1"
            management_start_ip = "fd02::2"
            management_end_ip = "fd02::ffff:ffff:ffff:ffff"

        subcloud1 = fake_subcloud_db()
        subclouds = [subcloud1]
        with self.assertRaisesRegex(
            Exception, "Admin address range overlaps with that of subcloud *"
        ):
            psd_common.validate_admin_network_config(
                admin_subnet,
                admin_start_address,
                admin_end_address,
                admin_gateway_address,
                existing_subclouds=subclouds,
            )

    def test_validate_admin_config_no_overlap(self):
        admin_subnet = "fd02::/64"
        admin_start_address = "fd02::2"
        admin_end_address = "fd02::ffff:ffff:ffff:ffff"
        admin_gateway_address = "fd02::1"

        class fake_subcloud_db(object):
            name = "subcloud1"
            management_start_ip = "fd03::2"
            management_end_ip = "fd03::ffff:ffff:ffff:ffff"

        subcloud1 = fake_subcloud_db()
        subclouds = [subcloud1]
        try:
            psd_common.validate_admin_network_config(
                admin_subnet,
                admin_start_address,
                admin_end_address,
                admin_gateway_address,
                existing_subclouds=subclouds,
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
            )

        admin_end_address = "192.168.205.12"
        admin_gateway_address = "192.168.205.50"

        with self.assertRaisesRegex(Exception, "Address must be in subnet*"):
            psd_common.validate_admin_network_config(
                admin_subnet,
                admin_start_address,
                admin_end_address,
                admin_gateway_address,
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
            )

    def test_verify_boolean_str(self):
        with self.assertRaisesRegex(Exception, "Invalid boolean string"):
            psd_common.verify_boolean_str("1")
        with self.assertRaisesRegex(Exception, "Invalid boolean string"):
            psd_common.verify_boolean_str("0")
        with self.assertRaisesRegex(Exception, "Invalid boolean string"):
            psd_common.verify_boolean_str("True")
        with self.assertRaisesRegex(Exception, "Invalid boolean string"):
            psd_common.verify_boolean_str("False")
        with self.assertRaisesRegex(Exception, "Invalid boolean string"):
            psd_common.verify_boolean_str("yes")
        with self.assertRaisesRegex(Exception, "Invalid boolean string"):
            psd_common.verify_boolean_str(True)
        psd_common.verify_boolean_str("true")
        psd_common.verify_boolean_str("false")

    def test_validate_migrate_parameter_valid(self):
        psd_common.validate_migrate_parameter({"migrate": "false"})

    def test_validate_migrate_parameter_with_deploy_config(self):
        payload = {"migrate": "true", consts.DEPLOY_CONFIG: "some_config"}
        with self.assertRaisesRegex(
            Exception, "migrate with deploy-config is not allowed"
        ):
            psd_common.validate_migrate_parameter(payload)

    def test_validate_migrate_parameter_enroll_true(self):
        payload = {"migrate": "true", "enroll": "true"}
        with self.assertRaisesRegex(Exception, "migrate with enroll is not allowed"):
            psd_common.validate_migrate_parameter(payload)

    def test_validate_enroll_parameter_enroll_false_with_cloud_init(self):
        payload = {"enroll": "false", "cloud_init_config": "dummy"}
        with self.assertRaisesRegex(
            Exception,
            "cloud_init_config is not allowed with enroll=false",
        ):
            psd_common.validate_enroll_parameter(payload)

    def test_validate_enroll_parameter_missing_install_values(self):
        payload = {"enroll": "true"}
        with self.assertRaisesRegex(
            Exception, "Install values is necessary for subcloud enrollment"
        ):
            psd_common.validate_enroll_parameter(payload)

    def test_validate_enroll_parameter_update_bmc_password(self):
        payload = {"enroll": "true", "install_values": {"bmc_password": "abc"}}
        psd_common.validate_enroll_parameter(payload)
        self.assertEqual(payload["bmc_password"], "abc")

    def test_validate_tarball_not_tar(self):
        bad_data = b"not a tarfile"
        with self.assertRaisesRegex(Exception, "not a valid tar archive."):
            psd_common.validate_tarball(bad_data, "testfile")

    def test_validate_tarball_valid(self):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            with tarfile.open(tmp.name, "w") as tar:
                info = tarfile.TarInfo(name="file.txt")
                content = b"test"
                info.size = len(content)
                content_file = io.BytesIO(content)
                tar.addfile(info, fileobj=content_file)
            tmp.seek(0)
            data = tmp.read()

        psd_common.validate_tarball(data, "testfile")

    def test_upload_binary_file(self):
        mock_open = self._mock_object(builtins, "open")
        mock_file = mock_open.return_value.__enter__.return_value
        test_content = b"binary content"
        test_path = "/test/path/file.bin"
        test_type = "test_file"
        psd_common.upload_binary_file(test_content, test_path, test_type)
        mock_open.assert_called_once_with(test_path, "wb")
        mock_file.write.assert_called_once_with(test_content)

    def test_upload_binary_file_exception(self):
        mock_open = self._mock_object(builtins, "open")
        mock_open.side_effect = Exception("Test exception")
        test_content = b"binary content"
        test_path = "/test/path/file.bin"
        test_name = "test_file"
        with self.assertRaisesRegex(
            Exception,
            f"Failed to upload {test_name} to {test_path}",
        ):
            psd_common.upload_binary_file(test_content, test_path, test_name)


class BaseTestValidateBootstrapValuesErrors(DCManagerTestCase):
    def setUp(self):
        super().setUp()
        self.payload = self.get_payload()

    def get_payload(self):
        raise NotImplementedError("Subclasses must implement get_payload()")

    def check_abort(self, key_to_remove, expected_error):
        if key_to_remove in self.payload:
            del self.payload[key_to_remove]
        with self.assertRaisesRegex(Exception, expected_error):
            psd_common.validate_bootstrap_values(self.payload)


class TestValidateBootstrapValuesIPv4(BaseTestValidateBootstrapValuesErrors):
    def get_payload(self):
        test_subcloud = copy.copy(fake_subcloud.FAKE_SUBCLOUD_DATA)
        additional_fields = {
            "system_mode": "simplex",
            "admin_subnet": "192.168.101.0/24",
            "admin_start_address": "192.168.101.2",
            "admin_end_address": "192.168.101.50",
            "admin_gateway_address": "192.168.101.1",
            "admin_floating_address": "192.168.101.2",
        }
        test_subcloud.update(additional_fields)
        test_subcloud.pop("management_gateway_address", None)
        return test_subcloud

    def test_validate_bootstrap_values(self):
        psd_common.validate_bootstrap_values(self.payload)

    def test_missing_name(self):
        self.check_abort("name", "name required")

    def test_missing_system_mode(self):
        self.check_abort("system_mode", "system_mode required")

    def test_missing_admin_subnet(self):
        self.check_abort("admin_subnet", "admin_subnet required")

    def test_missing_admin_start_address(self):
        self.check_abort(
            "admin_start_address",
            "admin_floating_address does not match admin_start_address",
        )

    def test_missing_admin_end_address(self):
        self.check_abort("admin_end_address", "admin_end_address required")

    def test_missing_admin_gateway_address(self):
        self.check_abort("admin_gateway_address", "admin_gateway_address required")

    def test_missing_management_subnet(self):
        self.check_abort("management_subnet", "management_subnet required")

    def test_missing_management_start_address(self):
        self.check_abort(
            "management_start_address", "management_start_address required"
        )

    def test_missing_management_end_address(self):
        self.check_abort("management_end_address", "management_end_address required")

    def test_both_gateways_defined(self):
        if ":" in self.payload["admin_gateway_address"]:
            self.payload["admin_gateway_address"] = "fd00::1"
            self.payload["management_gateway_address"] = "fd02::1"
        else:
            self.payload["admin_gateway_address"] = "192.168.101.1"
            self.payload["management_gateway_address"] = "192.168.102.1"

        with self.assertRaisesRegex(
            Exception,
            "admin_gateway_address and management_gateway_address "
            "cannot be specified",
        ):
            psd_common.validate_bootstrap_values(self.payload)

    def test_missing_systemcontroller_gateway_address(self):
        self.check_abort(
            "systemcontroller_gateway_address",
            "systemcontroller_gateway_address required",
        )

    def test_missing_external_oam_subnet(self):
        self.check_abort("external_oam_subnet", "external_oam_subnet required")

    def test_missing_external_oam_gateway_address(self):
        self.check_abort(
            "external_oam_gateway_address", "external_oam_gateway_address required"
        )

    def test_missing_external_oam_floating_address(self):
        self.check_abort(
            "external_oam_floating_address", "external_oam_floating_address required"
        )

    def test_floating_differs_from_start(self):
        original_start = self.payload["admin_start_address"]
        if ":" in original_start:
            self.payload["admin_floating_address"] = "fd00::9"
        else:
            self.payload["admin_floating_address"] = "192.168.101.9"
        with self.assertRaisesRegex(
            Exception, "admin_floating_address does not match admin_start_address"
        ):
            psd_common.validate_bootstrap_values(self.payload)


class TestValidateBootstrapValuesIPv6(TestValidateBootstrapValuesIPv4):
    def get_payload(self):
        test_subcloud = copy.copy(fake_subcloud.FAKE_SUBCLOUD_DATA)
        additional_fields = {
            "admin_subnet": "fd00::/64",
            "admin_start_address": "fd00::2",
            "admin_end_address": "fd00::50",
            "admin_gateway_address": "fd00::1",
            "admin_floating_address": "fd00::2",
        }
        test_subcloud.update(additional_fields)
        test_subcloud.pop("management_gateway_address", None)
        return test_subcloud
