#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import copy
import http.client
import json

import mock
from oslo_messaging import RemoteError
from tsconfig.tsconfig import SW_VERSION

from dccommon import consts as dccommon_consts
from dcmanager.api.controllers.v1 import phased_subcloud_deploy as psd_api
from dcmanager.common import consts
from dcmanager.common import phased_subcloud_deploy as psd_common
from dcmanager.common import utils as dutils
from dcmanager.db import api as db_api
from dcmanager.tests.unit.api.test_root_controller import DCManagerApiTest
from dcmanager.tests.unit.api.v1.controllers.test_subclouds import \
    FakeAddressPool
from dcmanager.tests.unit.api.v1.controllers.test_subclouds import SubcloudAPIMixin
from dcmanager.tests.unit.common import fake_subcloud
from dcmanager.tests.unit.manager.test_system_peer_manager import \
    TestSystemPeerManager

FAKE_URL = "/v1.0/phased-subcloud-deploy"
FAKE_SOFTWARE_VERSION = "21.12"


class BaseTestPhasedSubcloudDeployController(DCManagerApiTest):
    """Base class for testing the PhasedSubcloudDeployController"""

    def setUp(self):
        super().setUp()

        self.url = FAKE_URL

        self._mock_rpc_client()
        self._mock_get_ks_client()
        self._mock_query()

    def _mock_populate_payload(self):
        mock_patch_object = mock.patch.object(
            psd_common, "populate_payload_with_pre_existing_data"
        )
        self.mock_populate_payload = mock_patch_object.start()
        self.addCleanup(mock_patch_object.stop)

    def _mock_get_request_data(self):
        mock_patch_object = mock.patch.object(psd_common, "get_request_data")
        self.mock_get_request_data = mock_patch_object.start()
        self.addCleanup(mock_patch_object.stop)

    def _mock_get_subcloud_db_install_values(self):
        mock_patch_object = mock.patch.object(
            psd_common, "get_subcloud_db_install_values"
        )
        self.mock_get_subcloud_db_install_values = mock_patch_object.start()
        self.addCleanup(mock_patch_object.stop)

    def _mock_is_initial_deployment(self):
        mock_patch_object = mock.patch.object(psd_common, "is_initial_deployment")
        self.mock_is_initial_deployment = mock_patch_object.start()
        self.addCleanup(mock_patch_object.stop)


class TestPhasedSubcloudDeployController(BaseTestPhasedSubcloudDeployController):
    """Test class for PhasedSubcloudDeployController"""

    def setUp(self):
        super().setUp()

    def test_unmapped_method(self):
        """Test requesting an unmapped method results in success with null content"""

        self.method = self.app.put

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(response.text, "null")


# Apply the TestSubcloudsPost parameter validation tests to the subcloud deploy
# add endpoint as it uses the same parameter validation functions
class TestPhasedSubcloudDeployPost(BaseTestPhasedSubcloudDeployController):
    """Test class for post requests"""

    def setUp(self):
        super().setUp()

        self.method = self.app.post

        self.params = copy.copy(fake_subcloud.FAKE_BOOTSTRAP_VALUE)
        self.upload_files = SubcloudAPIMixin.get_post_upload_files(SubcloudAPIMixin)

        self._mock_sysinv_client(psd_common)

        self.mock_sysinv_client().get_management_address_pool.return_value = \
            FakeAddressPool("192.168.204.0", 24, "192.168.204.2", "192.168.204.100")
        self.mock_rpc_client().subcloud_deploy_create.side_effect = \
            self.subcloud_deploy_create

    def subcloud_deploy_create(self, context, subcloud_id, _):
        subcloud = db_api.subcloud_get(context, subcloud_id)
        return db_api.subcloud_db_model_to_dict(subcloud)

    def test_post_succeeds(self):
        """Test post succeeds"""

        response = self._send_request()

        self._assert_response(response)
        self.mock_rpc_client().subcloud_deploy_create.assert_called_once()

    def test_post_fails_without_payload(self):
        """Test post fails without payload"""

        self.params = {}
        self.upload_files = None

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST,
            "Missing required parameter(s): bootstrap_values, bootstrap-address"
        )

    def test_post_fails_without_bootstrap_address(self):
        """Test post fails without bootstrap address"""

        del self.params["bootstrap-address"]

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST,
            "Missing required parameter(s): bootstrap-address"
        )
        self.mock_rpc_client().subcloud_deploy_create.assert_not_called()

    def test_post_fails_without_bootstrap_values(self):
        """Test post fails without bootstrap values"""

        self.upload_files = None

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST,
            "Missing required parameter(s): bootstrap_values"
        )
        self.mock_rpc_client().subcloud_deploy_create.assert_not_called()

    def test_post_fails_with_rpc_client_remote_error(self):
        """Test post fails with rpc client remote error"""

        self.mock_rpc_client().subcloud_deploy_create.side_effect = \
            RemoteError("msg", "value")

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.UNPROCESSABLE_ENTITY, "value"
        )
        self.mock_rpc_client().subcloud_deploy_create.assert_called_once()

    def test_post_fails_with_rpc_client_generic_exception(self):
        """Test post fails with rpc client generic exception"""

        self.mock_rpc_client().subcloud_deploy_create.side_effect = Exception()

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.INTERNAL_SERVER_ERROR, "Unable to create subcloud"
        )
        self.mock_rpc_client().subcloud_deploy_create.assert_called_once()


class BaseTestPhasedSubcloudDeployPatch(BaseTestPhasedSubcloudDeployController):
    """Base test class for patch requests"""

    def setUp(self):
        super().setUp()

        self.subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx, name=fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA["name"],
            deploy_status=consts.DEPLOY_STATE_INSTALLED
        )

        self.method = self.app.patch
        self.url = f"{self.url}/{self.subcloud.id}"

        self._mock_get_vault_load_files()
        self._mock_is_initial_deployment()
        self._mock_get_network_address_pool()

        self.mock_get_vault_load_files.return_value = \
            ("iso_file_path", "sig_file_path")
        self.mock_is_initial_deployment.return_value = True
        self.mock_get_network_address_pool.return_value = FakeAddressPool(
            "192.168.204.0", 24, "192.168.204.2", "192.168.204.100"
        )

        self.data_install = copy.copy(fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES)
        self.data_install.pop("software_version")

        bmc_password = self._create_password("bmc_password")
        bmc_password_payload = {"bmc_password": bmc_password}

        self.data_install.update(bmc_password_payload)
        self.install_payload = {
            "install_values": self.data_install,
            "sysadmin_password": self._create_password("testpass"),
            "bmc_password": bmc_password
        }

        self.mock_load_yaml_file_return_value = {
            consts.BOOTSTRAP_ADDRESS:
                fake_subcloud.FAKE_BOOTSTRAP_VALUE[consts.BOOTSTRAP_ADDRESS],
        }

    def _update_subcloud(self, **kwargs):
        self.subcloud = db_api.subcloud_update(
            self.ctx, self.subcloud.id, **kwargs
        )


class TestPhasedSubcloudDeployPatch(BaseTestPhasedSubcloudDeployPatch):
    """Test class for patch requests"""

    def setUp(self):
        super().setUp()

    def test_patch_fails_without_subcloud_ref(self):
        """Test patch fails without subcloud ref"""

        self.url = FAKE_URL

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Subcloud ID required"
        )

    def test_patch_fails_with_invalid_verb(self):
        """Test patch fails with invalid verb"""

        self.url = f"{self.url}/fake"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Invalid request"
        )

    def test_patch_fails_with_subcloud_not_found(self):
        """Test patch fails with inexistent subcloud"""

        self.url = f"{FAKE_URL}/nonexistent_subcloud/"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.NOT_FOUND, "Subcloud not found"
        )


class TestPhasedSubcloudDeployPatchBootstrap(BaseTestPhasedSubcloudDeployPatch):
    """Test class for patch requests with bootstrap verb"""

    def setUp(self):
        super().setUp()

        self.url = f"{self.url}/bootstrap"

        self.params = fake_subcloud.FAKE_BOOTSTRAP_VALUE
        fake_content = \
            json.dumps(fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA).encode("utf-8")
        self.upload_files = \
            [("bootstrap_values", "bootstrap_fake_filename", fake_content)]

        self._mock_load_yaml_file()
        self._setup_mock_load_yaml_file()
        self._mock_os_path_exists()
        self._setup_mock_os_path_exists()

    def _setup_mock_os_path_exists(self):
        config_file = psd_common.get_config_file_path(self.subcloud.name)
        self.mock_os_path_exists.side_effect = \
            lambda file: True if file == config_file else False

    def _setup_mock_load_yaml_file(self):
        self.mock_load_yaml_file_return_value["software_version"] = \
            fake_subcloud.FAKE_SOFTWARE_VERSION
        self.mock_load_yaml_file.return_value = self.mock_load_yaml_file_return_value

    def _assert_payload(self):
        expected_payload = {
            **fake_subcloud.FAKE_BOOTSTRAP_VALUE,
            **fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA
        }
        expected_payload["sysadmin_password"] = "testpass"
        expected_payload["software_version"] = fake_subcloud.FAKE_SOFTWARE_VERSION

        (_, res_subcloud_id, res_payload), _ = \
            self.mock_rpc_client.return_value.subcloud_deploy_bootstrap.call_args

        self.assertDictEqual(res_payload, expected_payload)
        self.assertEqual(res_subcloud_id, self.subcloud.id)

    def test_patch_bootstrap_succeeds(self):
        """Test patch bootstrap succeeds"""

        response = self._send_request()

        self._assert_response(response)
        self._assert_payload()
        self.mock_rpc_client().subcloud_deploy_bootstrap.assert_called_once()

    def test_patch_bootstrap_succeeds_without_bootstrap_values(self):
        """Test patch bootstrap succeeds without bootstrap values"""

        self.upload_files = None

        fake_bootstrap_values = copy.copy(fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA)
        fake_bootstrap_values["software_version"] = \
            fake_subcloud.FAKE_SOFTWARE_VERSION
        self.mock_load_yaml_file.return_value = fake_bootstrap_values

        response = self._send_request()

        self._assert_response(response)
        self._assert_payload()
        self.mock_rpc_client().subcloud_deploy_bootstrap.assert_called_once()

    def test_patch_bootstrap_fails_with_management_subnet_conflict(self):
        """Test patch bootstrap fails with management subnet conflict"""

        conflicting_subnet = {
            "management_subnet": "192.168.102.0/24",
            "management_start_ip": "192.168.102.2",
            "management_end_ip": "192.168.102.50",
            "management_gateway_ip": "192.168.102.1"
        }

        fake_subcloud.create_fake_subcloud(
            self.ctx, name="existing_subcloud",
            deploy_status=consts.DEPLOY_STATE_DONE, **conflicting_subnet
        )

        modified_bootstrap_data = copy.copy(fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA)
        modified_bootstrap_data.update(conflicting_subnet)
        fake_content = json.dumps(modified_bootstrap_data).encode("utf-8")

        self.upload_files = \
            [("bootstrap_values", "bootstrap_fake_filename", fake_content)]

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "management_subnet invalid: Subnet "
            "overlaps with another configured subnet"
        )
        self.mock_rpc_client().subcloud_deploy_bootstrap.assert_not_called()

    def test_patch_bootstrap_fails_with_subcloud_in_invalid_state(self):
        """Test patch bootstrap fails with subcloud in invalid state"""

        self._update_subcloud(deploy_status=consts.DEPLOY_STATE_ABORTING_INSTALL)

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, f"Subcloud deploy status must be "
            f"either: {', '.join(psd_api.VALID_STATES_FOR_DEPLOY_BOOTSTRAP)}"
        )
        self.mock_rpc_client().subcloud_deploy_bootstrap.assert_not_called()

    def test_patch_bootstrap_fails_without_bootstrap_values(self):
        """Test patch bootstrap fails without bootstrap values"""

        self.upload_files = None

        self.mock_os_path_exists.side_effect = lambda file: False

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Required bootstrap-values file was "
            "not provided and it was not previously available at /opt/dc-vault/"
            f"ansible/{fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA['name']}.yml"
        )
        self.mock_rpc_client().subcloud_deploy_bootstrap.assert_not_called()

    def test_patch_bootstrap_fails_with_rpc_client_remote_error(self):
        """Test patch bootstrap fails with rpc client remote error"""

        self.mock_rpc_client().subcloud_deploy_bootstrap.side_effect = \
            RemoteError("msg", "value")

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.UNPROCESSABLE_ENTITY, "value"
        )
        self.mock_rpc_client().subcloud_deploy_bootstrap.assert_called_once()

    def test_patch_bootstrap_fails_with_rpc_client_generic_exception(self):
        """Test patch bootstrap fails with rpc client generic exception"""

        self.mock_rpc_client().subcloud_deploy_bootstrap.side_effect = Exception()

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.INTERNAL_SERVER_ERROR,
            "Unable to bootstrap subcloud"
        )
        self.mock_rpc_client().subcloud_deploy_bootstrap.assert_called_once()


class TestPhasedSubcloudDeployPatchConfigure(BaseTestPhasedSubcloudDeployPatch):
    """Test class for patch requests with configure verb"""

    def setUp(self):
        super().setUp()

        self.url = f"{self.url}/configure"
        self.params = {"sysadmin_password": self._create_password("testpass")}

        self._update_subcloud(
            deploy_status=consts.DEPLOY_STATE_DONE,
            data_install=json.dumps(self.data_install)
        )

        self._mock_populate_payload()
        self._mock_get_request_data()

        self.mock_get_request_data.return_value = self.params

    @mock.patch.object(dutils, "load_yaml_file")
    def test_patch_configure_succeeds(self, mock_load_yaml_file):
        """Test patch configure succeeds"""

        mock_load_yaml_file.return_value = {
            consts.BOOTSTRAP_ADDRESS:
                fake_subcloud.FAKE_BOOTSTRAP_VALUE[consts.BOOTSTRAP_ADDRESS]
        }

        response = self._send_request()

        self._assert_response(response)
        self.mock_rpc_client().subcloud_deploy_config.assert_called_once_with(
            mock.ANY, self.subcloud.id, self.params, initial_deployment=True
        )

    def test_patch_configure_succeeds_with_bootstrap_address_in_data_install(self):
        """Test patch configure succeeds with bootstrap address in data install"""

        response = self._send_request()

        self._assert_response(response)
        self.mock_rpc_client().subcloud_deploy_config.assert_called_once_with(
            mock.ANY, self.subcloud.id, self.params, initial_deployment=True
        )

    def test_patch_configure_fails_without_params(self):
        """Test patch configure fails without params"""

        self.params = {}
        self.mock_get_request_data.return_value = self.params

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Body required"
        )
        self.mock_rpc_client().subcloud_deploy_config.assert_not_called()

    def test_patch_configure_fails_with_invalid_sysadmin_password(self):
        """Test patch configure fails with invalid sysadmin password"""

        self.params = {"sysadmin_password": "fake"}
        self.mock_get_request_data.return_value = self.params

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Failed to decode subcloud "
            "sysadmin_password, verify the password is base64 encoded"
        )
        self.mock_rpc_client().subcloud_deploy_config.assert_not_called()

    def test_patch_configure_fails_with_subcloud_in_invalid_state(self):
        """Test patch configure fails with subcloud in invalid state"""

        self._update_subcloud(deploy_status=consts.DEPLOY_STATE_BOOTSTRAP_FAILED)

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Subcloud deploy status must be "
            f"{', '.join(psd_api.VALID_STATES_FOR_DEPLOY_CONFIG)}"
        )
        self.mock_rpc_client().subcloud_deploy_config.assert_not_called()

    def test_patch_configure_fails_with_ongoing_prestage(self):
        """Test patch configure fails with ongoing prestage"""

        self._update_subcloud(prestage_status=consts.STRATEGY_STATE_PRESTAGE_IMAGES)

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST,
            "Subcloud prestage is ongoing prestaging-images"
        )
        self.mock_rpc_client().subcloud_deploy_config.assert_not_called()

    def test_patch_configure_succeeds_with_peer_group_in_primary_priority(self):
        """Test patch configure succeeds with peer group in primary priority"""

        # Add subcloud to SPG with primary priority
        peer_group = TestSystemPeerManager.create_subcloud_peer_group_static(
            self.ctx, group_priority=consts.PEER_GROUP_PRIMARY_PRIORITY,
            peer_group_name="SubcloudPeerGroup1"
        )

        self._update_subcloud(peer_group_id=peer_group.id)

        response = self._send_request()

        self._assert_response(response)
        self.mock_rpc_client().subcloud_deploy_config.assert_called_once_with(
            mock.ANY, self.subcloud.id, self.params, initial_deployment=True
        )

    def test_patch_configure_fails_with_peer_group_not_in_primary_priority(self):
        """Test patch configure fails with peer group not in primary priority"""

        # Add subcloud to SPG with primary priority
        peer_group = TestSystemPeerManager.create_subcloud_peer_group_static(
            self.ctx, group_priority=1, peer_group_name="SubcloudPeerGroup1"
        )

        self._update_subcloud(peer_group_id=peer_group.id)

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST,
            "Subcloud can only be configured in its primary site."
        )
        self.mock_rpc_client().subcloud_deploy_config.assert_not_called()

    def test_patch_configure_fails_with_rpc_client_remote_error(self):
        """Test patch configure fails with rpc client remote error"""

        self.mock_rpc_client().subcloud_deploy_config.side_effect = \
            RemoteError("msg", "value")

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.UNPROCESSABLE_ENTITY, "value"
        )
        self.mock_rpc_client().subcloud_deploy_config.assert_called_once_with(
            mock.ANY, self.subcloud.id, self.params, initial_deployment=True
        )

    def test_patch_configure_fails_with_rpc_client_generic_exception(self):
        """Test patch configure fails with rpc client generic exception"""

        self.mock_rpc_client().subcloud_deploy_config.side_effect = Exception()

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.INTERNAL_SERVER_ERROR,
            "Unable to configure subcloud"
        )
        self.mock_rpc_client().subcloud_deploy_config.assert_called_once_with(
            mock.ANY, self.subcloud.id, self.params, initial_deployment=True
        )


class TestPhasedSubcloudDeployPatchInstall(BaseTestPhasedSubcloudDeployPatch):
    """Test class for patch requests with install verb"""

    def setUp(self):
        super().setUp()

        self.url = f"{self.url}/install"
        self.params = self.install_payload

        self._update_subcloud(
            deploy_status=consts.DEPLOY_STATE_CREATED, software_version=SW_VERSION
        )

        self._mock_get_subcloud_db_install_values()
        self._mock_validate_k8s_version()
        self._mock_get_request_data()

        self.mock_get_subcloud_db_install_values.return_value = self.data_install
        self.mock_get_request_data.return_value = self.install_payload

    def _assert_response_payload(self, response, software_version=SW_VERSION):
        self.assertEqual(
            consts.DEPLOY_STATE_PRE_INSTALL, response.json["deploy-status"]
        )
        self.assertEqual(software_version, response.json["software-version"])

    def test_patch_install_succeeds(self):
        """Test patch install succeeds"""

        response = self._send_request()

        self._assert_response(response)
        self._assert_response_payload(response)
        self.mock_rpc_client().subcloud_deploy_install.assert_called_once_with(
            mock.ANY, self.subcloud.id, self.params, initial_deployment=True
        )

    def test_patch_install_succeeds_with_release_parameter(self):
        """Test patch install succeeds with release parameter"""

        self._update_subcloud(software_version=None)

        self.install_payload["release"] = FAKE_SOFTWARE_VERSION
        self.params = self.install_payload
        self.mock_get_request_data.return_value = self.install_payload

        with mock.patch(
            "builtins.open",
            mock.mock_open(read_data=fake_subcloud.FAKE_UPGRADES_METADATA)
        ):
            response = self._send_request()

        self._assert_response(response)
        self._assert_response_payload(response, FAKE_SOFTWARE_VERSION)
        self.mock_rpc_client().subcloud_deploy_install.assert_called_once_with(
            mock.ANY, self.subcloud.id, self.params, initial_deployment=True
        )

    def test_patch_install_fails_when_not_in_initial_deployment(self):
        """Test patch install fails when not in initial deployment"""

        self.mock_is_initial_deployment.return_value = False

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "The deploy install command can only "
            "be used during initial deployment."
        )
        self.mock_rpc_client().subcloud_deploy_install.assert_not_called()

    def test_patch_install_fails_without_params(self):
        """Test patch install fails without params"""

        self.params = {}
        self.mock_get_request_data.return_value = self.params

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Body required"
        )
        self.mock_rpc_client().subcloud_deploy_install.assert_not_called()

    def test_patch_install_succeeds_without_install_values_on_request(self):
        """Test patch install succeeds without install values on request"""

        del self.install_payload["install_values"]
        self.params = self.install_payload
        self.mock_get_request_data.return_value = self.install_payload

        response = self._send_request()

        self._assert_response(response)
        self._assert_response_payload(response)
        self.mock_rpc_client().subcloud_deploy_install.assert_called_once_with(
            mock.ANY, self.subcloud.id, self.params, initial_deployment=True
        )

    def test_patch_install_fails_without_install_values_and_load_image(self):
        """Test patch install fails without install values and load image"""

        del self.install_payload["install_values"]
        self.params = self.install_payload
        self.mock_get_request_data.return_value = self.install_payload
        self.mock_get_vault_load_files.return_value = (None, "sig_file_path")

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, f'Failed to get {SW_VERSION} load '
            'image. Provide active/inactive load image via "system --os-region-name '
            'SystemController load-import --active/--inactive"'
        )
        self.mock_rpc_client().subcloud_deploy_install.assert_not_called()

    def test_patch_install_fails_with_subcloud_in_invalid_state(self):
        """Test patch install fails with subcloud in invalid state"""

        self._update_subcloud(deploy_status=consts.DEPLOY_STATE_ABORTING_INSTALL)

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Subcloud deploy status must be "
            f"either: {', '.join(psd_api.VALID_STATES_FOR_DEPLOY_INSTALL)}"
        )
        self.mock_rpc_client().subcloud_deploy_install.assert_not_called()

    def test_patch_install_fails_with_rpc_client_remote_error(self):
        """Test patch install fails with rpc client remote error"""

        self.mock_rpc_client().subcloud_deploy_install.side_effect = \
            RemoteError("msg", "value")

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.UNPROCESSABLE_ENTITY, "value"
        )
        self.mock_rpc_client().subcloud_deploy_install.assert_called_once_with(
            mock.ANY, self.subcloud.id, self.params, initial_deployment=True
        )

    def test_patch_install_fails_with_rpc_client_generic_exception(self):
        """Test patch install fails with rpc client generic exception"""

        self.mock_rpc_client().subcloud_deploy_install.side_effect = Exception()

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.INTERNAL_SERVER_ERROR, "Unable to install subcloud"
        )
        self.mock_rpc_client().subcloud_deploy_install.assert_called_once_with(
            mock.ANY, self.subcloud.id, self.params, initial_deployment=True
        )


class TestPhasedSubcloudDeployPatchComplete(BaseTestPhasedSubcloudDeployPatch):
    """Test class for patch requests with complete verb"""

    def setUp(self):
        super().setUp()

        self.url = f"{self.url}/complete"

        self._update_subcloud(
            deploy_status=consts.DEPLOY_STATE_BOOTSTRAPPED,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE
        )

        self.mock_rpc_client().subcloud_deploy_complete.return_value = \
            ("subcloud_deploy_complete", {"subcloud_id": self.subcloud.id})

    def test_patch_complete_succeeds(self):
        """Test patch complete succeeds"""

        response = self._send_request()

        self._assert_response(response)
        self.mock_rpc_client().subcloud_deploy_complete.assert_called_once_with(
            mock.ANY, self.subcloud.id
        )

    def test_patch_complete_fails_with_subcloud_in_invalid_state(self):
        """Test patch complete fails with subcloud in invalid state"""

        self._update_subcloud(deploy_status=consts.DEPLOY_STATE_INSTALLED)

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Subcloud deploy can only be "
            "completed when its deploy status is: "
            f"{consts.DEPLOY_STATE_BOOTSTRAPPED}"
        )
        self.mock_rpc_client().subcloud_deploy_complete.assert_not_called()

    def test_patch_complete_fails_with_rpc_client_remote_error(self):
        """Test patch complete fails with rpc client remote error"""

        self.mock_rpc_client().subcloud_deploy_complete.side_effect = \
            RemoteError("msg", "value")

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.UNPROCESSABLE_ENTITY, "value"
        )
        self.mock_rpc_client().subcloud_deploy_complete.assert_called_once_with(
            mock.ANY, self.subcloud.id
        )

    def test_patch_complete_fails_with_rpc_client_generic_exception(self):
        """Test patch complete fails with rpc client generic exception"""

        self.mock_rpc_client().subcloud_deploy_complete.side_effect = Exception()

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.INTERNAL_SERVER_ERROR,
            "Unable to complete subcloud deployment"
        )
        self.mock_rpc_client().subcloud_deploy_complete.assert_called_once_with(
            mock.ANY, self.subcloud.id
        )


class TestPhasedSubcloudDeployPatchAbort(BaseTestPhasedSubcloudDeployPatch):
    """Test class for patch requests with abort verb"""

    def setUp(self):
        super().setUp()

        self.url = f"{self.url}/abort"

        self._update_subcloud(deploy_status=consts.DEPLOY_STATE_INSTALLING)

    def test_patch_abort_succeeds(self):
        """Test patch abort succeeds"""

        response = self._send_request()

        self._assert_response(response)
        self.mock_rpc_client().subcloud_deploy_abort.assert_called_once_with(
            mock.ANY, self.subcloud.id, self.subcloud.deploy_status
        )

    def test_patch_abort_fails_when_not_in_initial_deployment(self):
        """Test patch abort fails when not in initial deployment"""

        self.mock_is_initial_deployment.return_value = False

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST,
            "The subcloud can only be aborted during initial deployment."
        )
        self.mock_rpc_client().subcloud_deploy_abort.assert_not_called()

    def test_patch_abort_fails_with_subcloud_in_invalid_state(self):
        """Test patch abort fails with subcloud in invalid state"""

        self._update_subcloud(deploy_status=consts.DEPLOY_STATE_INSTALLED)

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Subcloud deploy status must be in "
            "one of the following states: "
            f"{', '.join(psd_api.VALID_STATES_FOR_DEPLOY_ABORT)}"
        )
        self.mock_rpc_client().subcloud_deploy_abort.assert_not_called()

    def test_patch_abort_fails_with_rpc_client_remote_error(self):
        """Test patch abort fails with rpc client remote error"""

        self.mock_rpc_client().subcloud_deploy_abort.side_effect = \
            RemoteError("msg", "value")

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.UNPROCESSABLE_ENTITY, "value"
        )
        self.mock_rpc_client().subcloud_deploy_abort.assert_called_once_with(
            mock.ANY, self.subcloud.id, self.subcloud.deploy_status
        )

    def test_patch_abort_fails_with_rpc_client_generic_exception(self):
        """Test patch abort fails with rpc client generic exception"""

        self.mock_rpc_client().subcloud_deploy_abort.side_effect = Exception()

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.INTERNAL_SERVER_ERROR,
            "Unable to abort subcloud deployment"
        )
        self.mock_rpc_client().subcloud_deploy_abort.assert_called_once_with(
            mock.ANY, self.subcloud.id, self.subcloud.deploy_status
        )


class TestPhasedSubcloudDeployPatchResume(BaseTestPhasedSubcloudDeployPatch):
    """Test class for patch requests with resume verb"""

    def setUp(self):
        super().setUp()

        self.url = f"{self.url}/resume"

        self._update_subcloud(
            deploy_status=consts.DEPLOY_STATE_CREATED, software_version=SW_VERSION,
            data_install=json.dumps(self.data_install)
        )

        self._mock_get_subcloud_db_install_values()
        self._mock_validate_k8s_version()
        self._mock_get_request_data()
        self._setup_mock_get_request_data()
        self._mock_load_yaml_file()
        self._mock_os_path_isdir()
        self._mock_os_listdir()
        self._mock_os_path_exists()
        self._setup_mock_os_path_exists()

        self.mock_os_path_isdir.return_value = True
        self.mock_load_yaml_file.return_value = self.mock_load_yaml_file_return_value
        self.mock_os_listdir.return_value = [
            "deploy_chart_fake.tgz", "deploy_overrides_fake.yaml",
            "deploy_playbook_fake.yaml"
        ]

    def _setup_mock_get_request_data(self, states_to_execute=psd_api.DEPLOY_PHASES):
        bootstrap_request = {
            "bootstrap_values": fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA
        }
        config_request = {
            "deploy_config": "deploy config values",
        }

        self.resume_request = {"sysadmin_password": self._create_password()}

        for state in states_to_execute:
            if state == psd_api.INSTALL:
                self.resume_request.update(self.install_payload)
            if state == psd_api.BOOTSTRAP:
                self.resume_request.update(bootstrap_request)
            if state == psd_api.CONFIG:
                self.resume_request.update(config_request)

        self.resume_payload = self.resume_request
        self.resume_payload.update(fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA)

        self.params = self.resume_request
        self.mock_get_request_data.return_value = self.resume_payload

    def _setup_mock_os_path_exists(self):
        config_file = psd_common.get_config_file_path(
            self.subcloud.name, consts.DEPLOY_CONFIG
        )
        self.mock_os_path_exists.side_effect = \
            lambda file: True if file == config_file else False

    def _assert_response_payload(self, response):
        next_deploy_phase = psd_api.RESUMABLE_STATES[self.subcloud.deploy_status][0]
        next_deploy_state = psd_api.RESUME_PREP_UPDATE_STATUS[next_deploy_phase]

        self.assertEqual(next_deploy_state, response.json["deploy-status"])
        self.assertEqual(SW_VERSION, response.json["software-version"])

    def test_patch_resume_succeeds(self):
        """Test patch resume succeeds"""

        for index, state in enumerate(psd_api.RESUMABLE_STATES, start=1):
            self._update_subcloud(deploy_status=state)

            self._setup_mock_get_request_data(psd_api.RESUMABLE_STATES[state])

            response = self._send_request()

            self._assert_response(response)
            self._assert_response_payload(response)
            self.assertEqual(
                self.mock_rpc_client().subcloud_deploy_resume.call_count, index
            )

    def test_patch_resume_succeeds_without_install_and_config_values(self):
        """Test patch resume succeeds without install and config values"""

        self.params = {}

        self._update_subcloud(data_install="")

        self.mock_os_path_exists.side_effect = lambda file: False

        response = self._send_request()

        self._assert_response(response)
        self._assert_response_payload(response)
        self.mock_rpc_client().subcloud_deploy_resume.assert_called_once()

    def test_patch_resume_fails_when_not_in_initial_deployment(self):
        """Test patch resume fails when not in initial deployment"""

        self.mock_is_initial_deployment.return_value = False

        for index, state in enumerate(psd_api.RESUMABLE_STATES, start=1):
            self._update_subcloud(deploy_status=state)

            response = self._send_request()

            self._assert_pecan_and_response(
                response, http.client.BAD_REQUEST,
                "The subcloud can only be resumed during initial deployment.",
                call_count=index
            )
            self.mock_rpc_client().subcloud_deploy_resume.assert_not_called()

    def test_patch_resume_fails_with_subcloud_in_invalid_state(self):
        """Test patch resume fails with subcloud in invalid state"""

        invalid_resume_states = [
            consts.DEPLOY_STATE_INSTALLING, consts.DEPLOY_STATE_BOOTSTRAPPING,
            consts.DEPLOY_STATE_CONFIGURING
        ]

        for index, state in enumerate(invalid_resume_states, start=1):
            self._update_subcloud(deploy_status=state)

            response = self._send_request()

            self._assert_pecan_and_response(
                response, http.client.BAD_REQUEST, "Subcloud deploy status must be "
                f"either: {', '.join(psd_api.RESUMABLE_STATES)}", call_count=index
            )
            self.mock_rpc_client().subcloud_deploy_resume.assert_not_called()

    def test_patch_resume_succeeds_with_sysadmin_password_only_in_params(self):
        """Test patch succeeds with sysadmin password only in params"""

        self.mock_load_yaml_file_return_value["software_version"] = \
            fake_subcloud.FAKE_SOFTWARE_VERSION
        self.mock_load_yaml_file.return_value = self.mock_load_yaml_file_return_value

        for index, state in enumerate(psd_api.RESUMABLE_STATES, start=1):
            self._update_subcloud(deploy_status=state)

            resume_request = {"sysadmin_password": self._create_password("testpass")}

            self.params = resume_request
            self.mock_get_request_data.return_value = resume_request

            response = self._send_request()

            self._assert_response(response)
            self._assert_response_payload(response)
            self.assertEqual(
                self.mock_rpc_client().subcloud_deploy_resume.call_count, index
            )

    def test_patch_resume_fails_with_invalid_files_received(self):
        """Test patch resume fails with invalid files received

        When a subcloud is in a bootstrap-failed state, for example, it is expected
        that only the bootstrap values and config values are provided. If the install
        values is received, the execution should abort.
        The same applies to other states and the respective files they should not
        receive.
        """

        skipped_count = 0

        for index, state in enumerate(psd_api.RESUMABLE_STATES, start=1):
            self._update_subcloud(deploy_status=state)

            states_executed = list(
                set(psd_api.DEPLOY_PHASES) - set(psd_api.RESUMABLE_STATES[state])
            )

            # If there isn't any executed state, all files are accepted so there
            # isn't a validation to perform
            if not states_executed:
                skipped_count += 1
                continue

            # Always set up the mock with only one executed state to ensure that
            # pecan raises the correct error message
            self._setup_mock_get_request_data([states_executed[0]])

            response = self._send_request()

            self._assert_pecan_and_response(
                response, http.client.BAD_REQUEST, f"{states_executed[0].title()} "
                "was already executed and "
                f"{psd_api.FILES_MAPPING[states_executed[0]][0].replace('_', '-')} "
                "is not required", call_count=index - skipped_count
            )

    def test_patch_resume_fails_with_deploy_state_to_run_as_config(self):
        """Test patch resume fails with deploy state to run as config"""

        self.params = {}

        self.mock_os_path_exists.side_effect = lambda file: False

        self._update_subcloud(deploy_status=consts.DEPLOY_STATE_CONFIG_ABORTED)

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Only deploy phase left is deploy "
            f"config. Required {consts.DEPLOY_CONFIG} file was not provided and it "
            "was not previously available. If manually configuring the subcloud, "
            "please run 'dcmanager subcloud deploy complete'"
        )
        self.mock_rpc_client().subcloud_deploy_resume.assert_not_called()

    def test_patch_resume_fails_with_rpc_client_remote_error(self):
        """Test patch resume fails with rpc client remote error"""

        self.mock_rpc_client().subcloud_deploy_resume.side_effect = \
            RemoteError("msg", "value")

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.UNPROCESSABLE_ENTITY, "value"
        )
        self.mock_rpc_client().subcloud_deploy_resume.assert_called_once()

    def test_patch_resume_fails_with_rpc_client_generic_exception(self):
        """Test patch resume fails with rpc client generic exception"""

        self.mock_rpc_client().subcloud_deploy_resume.side_effect = Exception()

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.INTERNAL_SERVER_ERROR,
            "Unable to resume subcloud deployment"
        )
        self.mock_rpc_client().subcloud_deploy_resume.assert_called_once()


class TestPhasedSubcloudDeployPatchEnroll(BaseTestPhasedSubcloudDeployPatch):
    """Test class for patch requests with enroll verb"""
    def setUp(self):
        super().setUp()

        self.url = f"{self.url}/enroll"

        self._update_subcloud(
            deploy_status=consts.DEPLOY_STATE_CREATED, software_version=SW_VERSION
        )

        modified_bootstrap_data = copy.copy(fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA)
        fake_content = json.dumps(modified_bootstrap_data).encode("utf-8")

        self.upload_files = \
            [("bootstrap_values", "bootstrap_fake_filename", fake_content)]

    def test_patch_enroll_fails(self):
        """Test patch enroll fails"""

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "subcloud deploy enrollment is not "
                                               "available yet"
        )

    def test_patch_enroll_fails_invalid_deploy_status(self):
        """Test patch enroll fails with invalid deploy status"""

        self._update_subcloud(
            deploy_status=consts.DEPLOY_STATE_BOOTSTRAPPED
        )

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST,
            "Subcloud deploy status must be either: "
            f"{', '.join(psd_api.VALID_STATES_FOR_DEPLOY_ENROLL)}"
        )
