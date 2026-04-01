#
# Copyright (c) 2023-2026 Wind River Systems, Inc.
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
            psd_common.verify_boolean_str("yes")
        with self.assertRaisesRegex(Exception, "Invalid boolean string"):
            psd_common.verify_boolean_str(True)

        # Test that function returns normalized lowercase values
        self.assertEqual(psd_common.verify_boolean_str("true"), "true")
        self.assertEqual(psd_common.verify_boolean_str("false"), "false")
        self.assertEqual(psd_common.verify_boolean_str("True"), "true")
        self.assertEqual(psd_common.verify_boolean_str("False"), "false")
        self.assertEqual(psd_common.verify_boolean_str("TRUE"), "true")
        self.assertEqual(psd_common.verify_boolean_str("FALSE"), "false")

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

    def test_validate_migrate_parameter_normalize_boolean_values(self):
        # Test that boolean parameters are normalized to lowercase
        payload = {"migrate": "True"}
        psd_common.validate_migrate_parameter(payload)
        self.assertEqual(payload["migrate"], "true")

        payload = {"migrate": "FALSE"}
        psd_common.validate_migrate_parameter(payload)
        self.assertEqual(payload["migrate"], "false")

        payload = {"migrate": "True", "enroll": "False"}
        psd_common.validate_migrate_parameter(payload)
        self.assertEqual(payload["migrate"], "true")
        self.assertEqual(payload["enroll"], "false")

    def test_validate_enroll_parameter_enroll_false_with_cloud_init(self):
        payload = {"enroll": "false", "cloud_init_config": "dummy"}
        with self.assertRaisesRegex(
            Exception,
            "cloud_init_config is not allowed with enroll=false",
        ):
            psd_common.validate_enroll_parameter(payload)

    def test_validate_enroll_parameter_missing_install_values(self):
        # Should raise an exception when install_values is missing
        payload = {"enroll": "true"}
        with self.assertRaisesRegex(
            Exception,
            "Install values is necessary for subcloud enrollment",
        ):
            psd_common.validate_enroll_parameter(payload)

    def test_validate_enroll_parameter_update_bmc_password(self):
        payload = {"enroll": "true", "install_values": {"bmc_password": "abc"}}
        psd_common.validate_enroll_parameter(payload)
        self.assertEqual(payload["bmc_password"], "abc")

    def test_validate_enroll_parameter_normalize_boolean_values(self):
        # Test that boolean parameters are normalized to lowercase
        payload = {
            "enroll": "True",
            "on_site": "False",
            "install_values": {"bmc_password": "abc"},
        }
        psd_common.validate_enroll_parameter(payload)
        self.assertEqual(payload["enroll"], "true")
        self.assertEqual(payload["on_site"], "false")

        # Test that enroll=FALSE with on_site=TRUE aborts after normalization
        payload = {
            "enroll": "FALSE",
            "on_site": "TRUE",
            "install_values": {"bmc_password": "abc"},
        }
        with self.assertRaisesRegex(
            Exception,
            "on_site is not allowed with enroll=false",
        ):
            psd_common.validate_enroll_parameter(payload)

    def test_validate_enroll_parameter_on_site_logic(self):
        # Test the logic error fix: on_site=true with enroll=false should fail
        payload = {"enroll": "false", "on_site": "true"}
        with self.assertRaisesRegex(
            Exception,
            "on_site is not allowed with enroll=false",
        ):
            psd_common.validate_enroll_parameter(payload)

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
            "admin_gateway_address and management_gateway_address cannot be specified",
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


class TestInstallValuesValidator(DCManagerTestCase):
    """Test cases for InstallValuesValidator class."""

    def setUp(self):
        super().setUp()
        self.payload = {
            "software_version": "22.12",
            "bmc_password": base64.b64encode(b"password").decode("utf-8"),
            "on_site": "false",
        }
        self.install_values = {
            "software_version": "22.12",
            "bootstrap_address": "192.168.1.10",
            "bmc_address": "192.168.1.20",
            "install_type": 0,
        }

    def test_validator_initialization(self):
        """Test validator initialization with valid data."""
        validator = psd_common.InstallValuesValidator(self.payload, self.install_values)
        self.assertEqual(validator.payload, self.payload)
        self.assertEqual(validator.install_values, self.install_values)
        self.assertIsNone(validator.subcloud)
        self.assertFalse(validator.on_site)
        self.assertIsNone(validator.original_install_values)

    def test_validator_initialization_with_subcloud(self):
        """Test validator initialization with subcloud data."""
        subcloud = Subcloud(fake_subcloud.FAKE_SUBCLOUD_DATA, True)
        install_data = {"test": "data"}
        subcloud.data_install = json.dumps(install_data)

        validator = psd_common.InstallValuesValidator(
            self.payload, self.install_values, subcloud
        )
        self.assertEqual(validator.subcloud, subcloud)
        self.assertEqual(validator.original_install_values, install_data)

    def test_validate_bmc_password_missing_no_skip(self):
        """Test BMC password validation when missing and not skipping."""
        payload = {"on_site": "false"}
        install_values = {}
        validator = psd_common.InstallValuesValidator(payload, install_values)

        with self.assertRaisesRegex(Exception, "subcloud bmc_password required"):
            validator._validate_bmc_password()

    def test_validate_bmc_password_invalid_encoding(self):
        """Test BMC password validation with invalid base64 encoding."""
        payload = {
            "bmc_password": "not-base64!@#",
            "on_site": "false",
            "install_values": {},
        }
        install_values = {}
        validator = psd_common.InstallValuesValidator(payload, install_values)

        with self.assertRaisesRegex(
            Exception, "Failed to decode subcloud bmc_password"
        ):
            validator._validate_bmc_password()

    def test_validate_bmc_password_valid(self):
        """Test BMC password validation with valid data."""
        encoded_password = base64.b64encode(b"password").decode("utf-8")
        payload = {
            "bmc_password": encoded_password,
            "on_site": "false",
            "install_values": {},
        }
        install_values = {}
        validator = psd_common.InstallValuesValidator(payload, install_values)
        validator._validate_bmc_password()
        self.assertEqual(payload["install_values"]["bmc_password"], encoded_password)

    def test_validate_software_version_mismatch(self):
        """Test software version validation with mismatch."""
        payload = {"software_version": "22.12"}
        install_values = {"software_version": "21.12"}
        validator = psd_common.InstallValuesValidator(payload, install_values)

        with self.assertRaisesRegex(
            Exception, "software_version value .* does not match"
        ):
            validator._validate_software_version()

    def test_validate_software_version_adds_missing(self):
        """Test software version is added when missing."""
        payload = {"software_version": "22.12", "install_values": {}}
        install_values = {}
        validator = psd_common.InstallValuesValidator(payload, install_values)

        result = validator._validate_software_version()
        self.assertEqual(result, "22.12")
        self.assertEqual(payload["install_values"]["software_version"], "22.12")

    def test_validate_int_field_not_integer(self):
        """Test integer field validation with non-integer value."""
        install_values = {"persistent_size": "not_an_int"}
        validator = psd_common.InstallValuesValidator({}, install_values)

        with self.assertRaisesRegex(
            Exception, "must be a whole number greater than or equal to"
        ):
            validator._validate_int_field("persistent_size", 10000, "MB")

    def test_validate_int_field_below_minimum(self):
        """Test integer field validation with value below minimum."""
        install_values = {"persistent_size": 5000}
        validator = psd_common.InstallValuesValidator({}, install_values)

        with self.assertRaisesRegex(Exception, "is less than"):
            validator._validate_int_field("persistent_size", 10000, "MB")

    def test_validate_int_field_valid(self):
        """Test integer field validation with valid value."""
        install_values = {"persistent_size": 15000}
        validator = psd_common.InstallValuesValidator({}, install_values)
        validator._validate_int_field("persistent_size", 10000, "MB")

    def test_validate_extra_boot_params_empty(self):
        """Test extra boot params validation with empty value."""
        install_values = {"extra_boot_params": ""}
        validator = psd_common.InstallValuesValidator({}, install_values)

        with self.assertRaisesRegex(Exception, "must not be empty"):
            validator._validate_extra_boot_params()

    def test_validate_extra_boot_params_with_spaces(self):
        """Test extra boot params validation with spaces."""
        install_values = {"extra_boot_params": "param1 param2"}
        validator = psd_common.InstallValuesValidator({}, install_values)

        with self.assertRaisesRegex(Exception, "Spaces are not allowed"):
            validator._validate_extra_boot_params()

    def test_validate_extra_boot_params_valid(self):
        """Test extra boot params validation with valid value."""
        install_values = {"extra_boot_params": "param1,param2"}
        validator = psd_common.InstallValuesValidator({}, install_values)
        validator._validate_extra_boot_params()

    def test_validate_ip_address_invalid(self):
        """Test IP address validation with invalid address."""
        install_values = {"bootstrap_address": "invalid_ip"}
        validator = psd_common.InstallValuesValidator({}, install_values)

        with self.assertRaisesRegex(Exception, "bootstrap_address invalid"):
            validator._validate_ip_address("bootstrap_address")

    def test_validate_ip_address_valid(self):
        """Test IP address validation with valid address."""
        install_values = {"bootstrap_address": "192.168.1.10"}
        validator = psd_common.InstallValuesValidator({}, install_values)

        result = validator._validate_ip_address("bootstrap_address")
        self.assertEqual(str(result), "192.168.1.10")

    def test_validate_ip_version_match_mismatch(self):
        """Test IP version match validation with mismatch."""
        import netaddr

        ip1 = netaddr.IPAddress("192.168.1.10")
        ip2 = netaddr.IPAddress("fd00::1")
        validator = psd_common.InstallValuesValidator({}, {})

        with self.assertRaisesRegex(Exception, "must be the same IP version"):
            validator._validate_ip_version_match(ip1, ip2, "field1", "field2")

    def test_validate_ip_version_match_success(self):
        """Test IP version match validation with matching versions."""
        import netaddr

        ip1 = netaddr.IPAddress("192.168.1.10")
        ip2 = netaddr.IPAddress("192.168.1.20")
        validator = psd_common.InstallValuesValidator({}, {})
        validator._validate_ip_version_match(ip1, ip2, "field1", "field2")

    def test_validate_ip_addresses_and_network_missing_nexthop(self):
        """Test network address validation when nexthop is missing."""
        install_values = {
            "bootstrap_address": "192.168.1.10",
            "network_address": "192.168.1.0",
        }
        validator = psd_common.InstallValuesValidator({}, install_values)

        with self.assertRaisesRegex(
            Exception, "nexthop_gateway is required when network_address is present"
        ):
            validator._validate_ip_addresses_and_network()

    def test_validate_ip_addresses_and_network_missing_mask(self):
        """Test network address validation when mask is missing."""
        install_values = {
            "bootstrap_address": "192.168.1.10",
            "network_address": "192.168.1.0",
            "nexthop_gateway": "192.168.1.1",
        }
        validator = psd_common.InstallValuesValidator({}, install_values)

        with self.assertRaisesRegex(
            Exception, "network mask is required when network address is present"
        ):
            validator._validate_ip_addresses_and_network()

    def test_validate_mandatory_values_on_site(self):
        """Test mandatory values when on_site is true."""
        payload = {
            "software_version": "22.12",
            "on_site": "true",
            "install_values": {
                "bootstrap_interface": "eno1",
            },
        }
        install_values = payload["install_values"]
        validator = psd_common.InstallValuesValidator(payload, install_values)
        validator._validate_mandatory_values()

    def test_validate_mandatory_values_on_site_missing(self):
        """Test mandatory values fail when bootstrap_interface missing."""
        payload = {
            "software_version": "22.12",
            "on_site": "true",
            "install_values": {},
        }
        install_values = payload["install_values"]
        validator = psd_common.InstallValuesValidator(payload, install_values)
        with self.assertRaisesRegex(
            Exception,
            "Mandatory install value bootstrap_interface not present",
        ):
            validator._validate_mandatory_values()

    def test_validate_install_values_integration(self):
        """Test full validation flow through validate_install_values function."""
        self._mock_object(psd_common.utils, "get_matching_iso").return_value = (
            "test.iso",
            None,
        )

        payload = {
            "software_version": "22.12",
            "bmc_password": base64.b64encode(b"password").decode("utf-8"),
            "on_site": "false",
            "install_values": {
                "software_version": "22.12",
                "bootstrap_address": "192.168.1.10",
                "bootstrap_address_prefix": 24,
                "bmc_address": "192.168.1.20",
                "install_type": 0,
                "bmc_username": "admin",
                "bootstrap_interface": "eno1",
                "console_type": "tty0",
            },
        }

        psd_common.validate_install_values(payload)
        self.assertEqual(payload["install_values"]["image"], "test.iso")
