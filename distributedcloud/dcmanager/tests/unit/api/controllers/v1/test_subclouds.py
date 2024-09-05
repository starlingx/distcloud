# Copyright (c) 2017 Ericsson AB
# Copyright (c) 2017-2024 Wind River Systems, Inc.
# All Rights Reserved.
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

import base64
import copy
import http.client
import json
import os


from keystoneauth1.exceptions import EndpointNotFound
import mock
import netaddr
from oslo_messaging import RemoteError
from tsconfig.tsconfig import SW_VERSION
import yaml

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack import vim
from dccommon.exceptions import OAMAddressesNotFound
from dcmanager.api.controllers.v1 import phased_subcloud_deploy as psd
from dcmanager.api.controllers.v1 import subclouds
from dcmanager.common import consts
from dcmanager.common import phased_subcloud_deploy as psd_common
from dcmanager.common import prestage
from dcmanager.common import utils as cutils
from dcmanager.db import api as db_api
from dcmanager.db.sqlalchemy import api as sql_api
from dcmanager.tests.unit.api.controllers.v1.mixins import APIMixin
from dcmanager.tests.unit.api.controllers.v1.mixins import PostMixin
from dcmanager.tests.unit.api.test_root_controller import DCManagerApiTest
from dcmanager.tests.unit.common import fake_strategy
from dcmanager.tests.unit.common import fake_subcloud
from dcmanager.tests.unit.manager import test_system_peer_manager

FAKE_SUBCLOUD_INSTALL_VALUES = fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES

health_report_no_alarm = (
    "System Health:\n"
    "All hosts are provisioned: [Fail]\n"
    "1 Unprovisioned hosts\n"
    "All hosts are unlocked/enabled: [OK]\n"
    "All hosts have current configurations: [OK]\n"
    "All hosts are patch current: [OK]\n"
    "No alarms: [OK]\n"
    "All kubernetes nodes are ready: [OK]\n"
    "All kubernetes control plane pods are ready: [OK]"
)


health_report_no_mgmt_alarm = (
    "System Health:\n"
    "All hosts are provisioned: [OK]\n"
    "All hosts are unlocked/enabled: [OK]\n"
    "All hosts have current configurations: [OK]\n"
    "All hosts are patch current: [OK]\n"
    "Ceph Storage Healthy: [OK]\n"
    "No alarms: [Fail]\n"
    "[1] alarms found, [0] of which are management affecting\n"
    "All kubernetes nodes are ready: [OK]\n"
    "All kubernetes control plane pods are ready: [OK]"
)


health_report_mgmt_alarm = (
    "System Health:\n"
    "All hosts are provisioned: [OK]\n"
    "All hosts are unlocked/enabled: [OK]\n"
    "All hosts have current configurations: [OK]\n"
    "All hosts are patch current: [OK]\n"
    "Ceph Storage Healthy: [OK]\n"
    "No alarms: [Fail]\n"
    "[1] alarms found, [1] of which are management affecting\n"
    "All kubernetes nodes are ready: [OK]\n"
    "All kubernetes control plane pods are ready: [OK]"
)


class FakeAddressPool(object):
    def __init__(self, pool_network, pool_prefix, pool_start, pool_end):
        self.network = pool_network
        self.prefix = pool_prefix
        self.family = netaddr.IPAddress(pool_network).version
        self.ranges = [[pool_start, pool_end]]


class FakeOAMAddressPool(object):
    def __init__(
        self,
        oam_subnet,
        oam_start_ip,
        oam_end_ip,
        oam_c1_ip,
        oam_c0_ip,
        oam_gateway_ip,
        oam_floating_ip,
    ):
        self.oam_start_ip = oam_start_ip
        self.oam_end_ip = oam_end_ip
        self.oam_c1_ip = oam_c1_ip
        self.oam_c0_ip = oam_c0_ip
        self.oam_subnet = oam_subnet
        self.oam_gateway_ip = oam_gateway_ip
        self.oam_floating_ip = oam_floating_ip


class SubcloudAPIMixin(APIMixin):
    API_PREFIX = "/v1.0/subclouds"
    RESULT_KEY = "subclouds"

    EXPECTED_FIELDS = [
        "id",
        "name",
        "description",
        "location",
        "software-version",
        "management-state",
        "availability-status",
        "deploy-status",
        "backup-status",
        "backup-datetime",
        "error-description",
        "region-name",
        "management-subnet",
        "management-start-ip",
        "management-end-ip",
        "management-gateway-ip",
        "openstack-installed",
        "prestage-status",
        "prestage-versions",
        "systemcontroller-gateway-ip",
        "data_install",
        "data_upgrade",
        "created-at",
        "updated-at",
        "group_id",
        "peer_group_id",
        "rehome_data",
    ]

    FAKE_BOOTSTRAP_DATA = {
        "system_mode": "simplex",
        "name": "fake_subcloud1",
        "management_subnet": "192.168.101.0/24",
        "management_start_address": "192.168.101.2",
        "management_end_address": "192.168.101.50",
        "management_gateway_address": "192.168.101.1",
        "external_oam_subnet": "10.10.10.0/24",
        "external_oam_gateway_address": "10.10.10.1",
        "external_oam_floating_address": "10.10.10.12",
        "systemcontroller_gateway_address": "192.168.204.101",
    }

    OPTIONAL_BOOTSTRAP_DATA = {
        "location": "fake location",
        "description": "fake description",
    }

    # based off MANDATORY_INSTALL_VALUES
    # bmc_password must be passed as a param
    FAKE_INSTALL_DATA = {
        "bootstrap_interface": "fake interface",
        "bootstrap_address": "10.10.10.12",
        "bootstrap_address_prefix": "10.10.10.12",
        "bmc_address": "128.224.64.1",
        "bmc_username": "fake bmc user",
        "install_type": 2,
    }

    list_of_post_files = psd.SUBCLOUD_BOOTSTRAP_GET_FILE_CONTENTS
    bootstrap_data = copy.copy(FAKE_BOOTSTRAP_DATA)
    install_data = copy.copy(FAKE_INSTALL_DATA)

    def setUp(self):
        super().setUp()

    def _get_test_subcloud_dict(self, **kw):
        # id should not be part of the structure
        return {
            "name": kw.get("name", "SubcloudX"),
            "description": kw.get("description", "A Subcloud of mystery"),
        }

    def _post_get_test_subcloud(self, **kw):
        return self._get_test_subcloud_dict(**kw)

    # The following methods are required for subclasses of APIMixin
    def get_api_prefix(self):
        return self.API_PREFIX

    def get_result_key(self):
        return self.RESULT_KEY

    def get_expected_api_fields(self):
        return self.EXPECTED_FIELDS

    def get_omitted_api_fields(self):
        return []

    def _create_db_object(self, context, **kw):
        creation_fields = self._get_test_subcloud_dict(**kw)
        return sql_api.subcloud_create(context, **creation_fields)

    def get_post_params(self):
        return copy.copy(fake_subcloud.FAKE_BOOTSTRAP_VALUE)

    def set_list_of_post_files(self, value):
        self.list_of_post_files = value

    def get_post_upload_files(self):
        fields = list()
        for f in self.list_of_post_files:
            fake_name = f + "_fake"
            # The data in the bootstrap file needs to be dictionary syntax
            if f == consts.BOOTSTRAP_VALUES:
                fake_content = json.dumps(self.bootstrap_data).encode("utf-8")
            elif f == consts.INSTALL_VALUES:
                fake_content = json.dumps(self.install_data).encode("utf-8")
            else:
                fake_content = "fake content".encode("utf-8")
            fields.append((f, fake_name, fake_content))
        return fields

    def get_post_object(self):
        return self._post_get_test_subcloud()

    def get_update_object(self):
        return {"description": "Updated description"}


class BaseTestSubcloudsController(DCManagerApiTest, SubcloudAPIMixin):
    """Base class for testing the SubcloudsController"""

    def setUp(self):
        super().setUp()

        self.url = self.API_PREFIX

        self._mock_rpc_client()
        self._mock_rpc_subcloud_state_client()
        self._mock_get_ks_client()
        self._mock_query()
        self._mock_valid_software_deploy_state()

    def _update_subcloud(self, **kwargs):
        self.subcloud = sql_api.subcloud_update(self.ctx, self.subcloud.id, **kwargs)


class TestSubcloudsController(BaseTestSubcloudsController):
    """Test class for SubcloudsController"""

    def setUp(self):
        super().setUp()

    def test_unmapped_method(self):
        """Test requesting an unmapped method results in success with null content"""

        self.method = self.app.put

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(response.text, "null")


class BaseTestSubcloudsGet(BaseTestSubcloudsController):
    """Base test class for get requests"""

    def setUp(self):
        super().setUp()

        self.subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        self.url = f"{self.url}/{self.subcloud.id}"
        self.method = self.app.get


class TestSubcloudsGet(BaseTestSubcloudsGet):
    """Test class for get requests"""

    def setUp(self):
        super().setUp()

        self.url = self.API_PREFIX

    def test_get_succeeds(self):
        """Test get succeeds

        When the request is made without a subcloud_ref, a list of subclouds is
        returned.
        """

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(1, len(response.json["subclouds"]))
        self.assertEqual(self.subcloud.id, response.json["subclouds"][0]["id"])

    def test_get_succeeds_with_subcloud_id(self):
        """Test get succeeds with subcloud id

        When the request is made with a subcloud_ref, a subcloud's details is
        returned.
        """

        self.url = f"{self.API_PREFIX}/{self.subcloud.id}"

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(response.json.get("oam_floating_ip", None), None)
        self.assertEqual(response.json["id"], self.subcloud.id)

    def test_get_succeeds_with_subcloud_name(self):
        """Test get succeeds with subcloud name

        When the request is made with a subcloud_ref, a subcloud's details is
        returned.
        """

        self.url = f"{self.url}/{self.subcloud.name}"

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(response.json["name"], self.subcloud.name)

    def test_get_fails_with_inexistent_subcloud_id(self):
        """Test get fails with inexistent subcloud id"""

        self.url = f"{self.url}/999"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.NOT_FOUND, "Subcloud not found"
        )

    def test_get_fails_with_inexistent_subcloud_name(self):
        """Test get fails with inexistent subcloud name"""

        self.url = f"{self.url}/fake"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.NOT_FOUND, "Subcloud not found"
        )

    @mock.patch.object(db_api, "subcloud_get_all_with_status")
    def test_get_succeeds_returning_correct_sync_status(self, mock_db_api):
        """Test get succeeds, returning the correct sync status

        Previously, there was a bug that, when the patch and load endpoints were
        returned as the first items in the db_api.subcloud_get_all_with_status
        request, the resulting sync status for the subcloud would be out-of-sync,
        even though all endpoints were in-sync.

        In this test, the first subcloud returns the endpoints in the order that
        caused the issue.
        """

        mock_db_api.return_value = [
            (self.subcloud, "patching", "not-available"),
            (self.subcloud, "platform", "in-sync"),
            (self.subcloud, "identity", "in-sync"),
            (self.subcloud, "load", "not-available"),
            (self.subcloud, "dc-cert", "in-sync"),
            (self.subcloud, "firmware", "in-sync"),
            (self.subcloud, "kubernetes", "in-sync"),
            (self.subcloud, "kube-rootca", "in-sync"),
            (self.subcloud, "usm", "in-sync"),
        ]

        response = self._send_request()

        self._assert_response(response)

        subclouds = response.json["subclouds"]
        for subcloud in subclouds:
            self.assertEqual(
                subcloud["sync_status"], dccommon_consts.SYNC_STATUS_IN_SYNC
            )


class TestSubcloudsGetDetail(BaseTestSubcloudsGet):
    """Test class for get requests with detail verb"""

    def setUp(self):
        super().setUp()

        self._update_subcloud(availability_status=dccommon_consts.AVAILABILITY_ONLINE)

        self.url = f"{self.url}/detail"

        self._mock_sysinv_client(cutils)
        self._mock_fm_client(subclouds)

        self.mock_sysinv_client().get_oam_addresses.return_value = FakeOAMAddressPool(
            "10.10.10.254",
            "10.10.10.1",
            "10.10.10.254",
            "10.10.10.4",
            "10.10.10.3",
            "10.10.10.1",
            "10.10.10.2",
        )

    def _assert_response_payload(
        self,
        response,
        oam_ip_address="10.10.10.2",
        sync_status="Deployment: configurations up-to-date",
    ):
        self.assertEqual(oam_ip_address, response.json["oam_floating_ip"])
        self.assertEqual(sync_status, response.json["deploy_config_sync_status"])

    def test_get_detail_succeeds(self):
        """Test get detail succeeds"""

        response = self._send_request()

        self._assert_response(response)
        self._assert_response_payload(response)

    def test_get_detail_succeeds_with_offline_subcloud(self):
        """Test get detail succeeds with offline subcloud"""

        self._update_subcloud(availability_status=dccommon_consts.AVAILABILITY_OFFLINE)

        response = self._send_request()

        self._assert_response(response)
        self._assert_response_payload(response, "unavailable", "unknown")

    def test_get_detail_succeeds_with_fm_client_generic_exception(self):
        """Test get detail succeeds with fm client generic exception"""

        self.mock_fm_client().get_alarms_by_id.side_effect = Exception()

        response = self._send_request()

        self._assert_response(response)
        self._assert_response_payload(response, sync_status="unknown")

    def test_get_detail_succeeds_with_sysinv_client_endpoint_not_found(self):
        """Test get detail succeeds with sysinv client endpoint not found"""

        self.mock_sysinv_client().get_oam_addresses.side_effect = EndpointNotFound()

        response = self._send_request()

        self._assert_response(response)
        self._assert_response_payload(response, oam_ip_address="unavailable")

    def test_get_detail_succeeds_with_sysinv_client_oam_addresses_not_found(self):
        """Test get detail succeeds with sysinv client oam addresses not found"""

        self.mock_sysinv_client().get_oam_addresses.side_effect = OAMAddressesNotFound()

        response = self._send_request()

        self._assert_response(response)
        self._assert_response_payload(response, oam_ip_address="unavailable")


class BaseTestSubcloudsPost(BaseTestSubcloudsController):
    """Base test class for post requests"""

    def setUp(self):
        super().setUp()

        self.method = self.app.post
        self.params = self.get_post_params()
        self.upload_files = self.get_post_upload_files()

        self._mock_get_network_address_pools()
        self.mock_get_network_address_pools.return_value = [
            FakeAddressPool("192.168.204.0", 24, "192.168.204.2", "192.168.204.100")
        ]

    def set_oam_params_ipv4(self):
        self.params["external_oam_subnet"] = "10.10.10.0/24"
        self.params["external_oam_gateway_address"] = "10.10.10.1"
        self.params["external_oam_floating_address"] = "10.10.10.12"

    def set_oam_params_ipv6(self):
        self.params["external_oam_subnet"] = "fd02:4::/64"
        self.params["external_oam_gateway_address"] = "fd02:4::1"
        self.params["external_oam_floating_address"] = "fd02:4::12"


class TestSubcloudsPost(BaseTestSubcloudsPost, PostMixin):
    """Test class for post requests"""

    def setUp(self):
        super().setUp()

    def test_post_succeeds(self):
        """Test post succeeds"""

        response = self._send_request()

        self._assert_response(response)
        self.mock_rpc_client().add_subcloud.assert_called_once()
        self.mock_rpc_client().add_secondary_subcloud.assert_not_called()

    def test_post_fails_with_wrong_url(self):
        """Test post fails with wrong url"""

        self.url = f"{self.url}-fake"

        response = self._send_request()

        self._assert_pecan_and_response(response, http.client.NOT_FOUND, "")

    def test_post_fails_without_payload(self):
        """Test post fails without payload"""

        self.params = {}
        self.upload_files = None

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "subcloud sysadmin_password required"
        )

    def test_post_fails_with_invalid_upload_files(self):
        """Test post fails with invalid upload files"""

        invalid_item = "key:value"
        file_name = consts.BOOTSTRAP_VALUES + "_fake"
        file_content = yaml.dump(self.FAKE_BOOTSTRAP_DATA) + invalid_item

        self.upload_files = [
            (consts.BOOTSTRAP_VALUES, file_name, file_content.encode("utf-8"))
        ]

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Error: Unable to load bootstrap_values file "
            "contents (problem on line: 10).",
        )

    def test_post_fails_with_missing_data_in_bootstrap_values(self):
        """Test post fails with missing data in bootstrap values"""

        for index, key in enumerate(self.FAKE_BOOTSTRAP_DATA, start=1):
            self.bootstrap_data = copy.copy(self.FAKE_BOOTSTRAP_DATA)
            del self.bootstrap_data[key]

            self.upload_files = self.get_post_upload_files()

            response = self._send_request()

            if key == "name":
                self._assert_pecan_and_response(
                    response,
                    http.client.BAD_REQUEST,
                    "Unable to generate subcloud region for subcloud None",
                    index,
                )
            else:
                self._assert_pecan_and_response(
                    response, http.client.BAD_REQUEST, f"{key} required", index
                )

    def test_post_fails_with_invalid_bootstrap_address(self):
        """Test post fails with invalid bootstrap address

        Validates that both invalid IP and IPv6 addresses will result in failure.

        Scenarios:
        - IP: letters, values greater than 255 and incomplete address
        - IPv6: multiple double colons, invalid letter and incomplete value
        """

        invalid_values = [
            "10.10.10.wut",
            "10.10.10.276",
            "2620::10a::a103::1135",
            "2620:10a:a001:a103::wut",
            "2620:10a:a001:a103:1135",
        ]

        for index, invalid_value in enumerate(invalid_values, start=1):
            self.params["bootstrap-address"] = invalid_value

            response = self._send_request()

            self._assert_pecan_and_response(
                response,
                http.client.BAD_REQUEST,
                "bootstrap-address invalid: "
                f"failed to detect a valid IP address from '{invalid_value}'",
                index,
            )

    def test_post_fails_with_invalid_systemcontroller_gateway_address(self):
        """Test post fails with invalid system controller gateway address

        The address must be a valid IP value, within the management address pool,
        i.e. 192.168.204.0/24, and outside the reserved pool from 2 to 100.
        """

        invalid_values = [
            "192.168.205.101",
            "192.168.204.99",
            "192.168.276.276",
            "192.168.206.wut192.168.204",
        ]

        for index, invalid_value in enumerate(invalid_values, start=1):
            self.params["systemcontroller_gateway_address"] = invalid_value

            response = self._send_request()

            error_message = "systemcontroller_gateway_address invalid:"

            # When the address is inside the reserved pool, the error message differs
            if index == 1:
                error_message = (
                    f"{error_message} Address must be in subnet 192.168.204.0/24"
                )
            elif index > 2:
                error_message = (
                    f"{error_message} failed to detect a valid "
                    f"IP address from '{invalid_value}'"
                )
            else:
                error_message = (
                    "systemcontroller_gateway_address invalid, is "
                    "within management pool: 192.168.204.2 - 192.168.204.100"
                )

            self._assert_pecan_and_response(
                response, http.client.BAD_REQUEST, error_message, index
            )

    def test_post_fails_with_invalid_management_subnet(self):
        """Test post fails with invalid management subnet

        The address must be a valid IP with correct mask.

        Scenarios:
            - Mask with only one IP address in it
            - Inexistent mask
            - Invalid value for IP address
            - Address with letters in it
            - Incomplete IP address
        """

        invalid_values = [
            "192.168.101.0/32",
            "192.168.101.0/33",
            "192.168.276.0/24",
            "192.168.206.wut/24",
            "192.168.204/24",
        ]

        for index, invalid_value in enumerate(invalid_values, start=1):
            self.params["management_subnet"] = invalid_value

            response = self._send_request()

            error_msg = "management_subnet invalid:"

            if index == 1:
                error_msg = (
                    f"{error_msg} Subnet too small - must have at least 7 addresses"
                )
            elif index == 5:
                error_msg = (
                    "management_start_address invalid: Address must be in subnet "
                    "192.168.204.0/24"
                )
            else:
                error_msg = f"{error_msg} Invalid subnet - not a valid IP subnet"

            self._assert_pecan_and_response(
                response, http.client.BAD_REQUEST, error_msg, index
            )

    def test_post_fails_with_invalid_management_start_address(self):
        """Test post fails with invalid management start address

        The address must be a valid IP in the 192.168.101.0/24 subnet with the end
        address being 192.168.101.50.

        Scenarios:
            - Address in another the subnet
            - Management start address greater than subnet's end address
            - Management start address too close to subnet's end address
            - Invalid value for IP address
            - Address with letters in it
            - Incomplete IP address
        """

        invalid_values = [
            "192.168.100.2",
            "192.168.101.51",
            "192.168.101.48",
            "192.168.276.0",
            "192.168.206.wut",
            "192.168.204",
        ]

        for index, invalid_value in enumerate(invalid_values, start=1):
            self.params["management_start_address"] = invalid_value

            response = self._send_request()

            error_msg = "management_start_address invalid:"

            if index == 1 or index == 6:
                error_msg = f"{error_msg} Address must be in subnet 192.168.101.0/24"
            elif index == 2:
                error_msg = (
                    "management_start_address greater than management_end_address"
                )
            elif index == 3:
                error_msg = "management address range must contain at least 4 addresses"
            else:
                error_msg = f"{error_msg} Invalid address - not a valid IP address"

            self._assert_pecan_and_response(
                response, http.client.BAD_REQUEST, error_msg, index
            )

    def test_post_fails_with_invalid_management_end_address(self):
        """Test post fails with invalid management end address

        The address must be a valid IP in the 192.168.101.0/24 subnet with the start
        address being 192.168.101.2.

        Scenarios:
            - Address in another the subnet
            - Management end address is less that the start address
            - Management end address too close to subnet's start address
            - Invalid value for IP address
            - Address with letters in it
            - Incomplete IP address
        """

        invalid_values = [
            "192.168.100.50",
            "192.168.101.1",
            "192.168.101.4",
            "192.168.276.50",
            "192.168.206.wut",
            "192.168.204",
        ]

        for index, invalid_value in enumerate(invalid_values, start=1):
            self.params["management_end_address"] = invalid_value

            response = self._send_request()

            error_msg = "management_end_address invalid:"

            if index == 1 or index == 6:
                error_msg = f"{error_msg} Address must be in subnet 192.168.101.0/24"
            elif index == 2:
                error_msg = (
                    "management_start_address greater than management_end_address"
                )
            elif index == 3:
                error_msg = "management address range must contain at least 4 addresses"
            else:
                error_msg = f"{error_msg} Invalid address - not a valid IP address"

            self._assert_pecan_and_response(
                response, http.client.BAD_REQUEST, error_msg, index
            )

    def test_post_fails_with_partial_apply_patch(self):
        """Test post fails with partial-apply patch"""

        self.mock_query.return_value = {"value": {"patchstate": "Partial-Apply"}}

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.UNPROCESSABLE_ENTITY,
            "Subcloud create is not allowed while system controller "
            "patching is still in progress.",
        )

    def test_post_fails_with_migrate_and_not_matching_subcloud_name(self):
        """Test post fails with migrate and not matching subcloud name"""

        self.params["migrate"] = "true"
        self.params["name"] = "subcloud2"

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "subcloud name does not match the name defined in bootstrap file",
        )

    def test_post_succeeds_with_secondary_in_payload(self):
        """Test post succeeds with secondary in payload"""

        self.params["secondary"] = "true"

        response = self._send_request()

        self._assert_response(response)
        self.mock_rpc_client().add_subcloud.assert_not_called()
        self.mock_rpc_client().add_secondary_subcloud.assert_called_once()

    def test_post_fails_with_rpc_client_remote_error(self):
        """Test post fails with rpc client remote error"""

        self.mock_rpc_client().add_subcloud.side_effect = RemoteError("msg", "value")

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.UNPROCESSABLE_ENTITY, "value"
        )

    def test_post_with_rpc_client_generic_exception(self):
        """Test post fails with rpc client generic exception"""

        self.mock_rpc_client().add_subcloud.side_effect = Exception()

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.INTERNAL_SERVER_ERROR, "Unable to add subcloud"
        )


class TestSubcloudsPostDualStack(BaseTestSubcloudsPost, PostMixin):
    """Test class for post requests dual-stack"""

    management_ipv4 = {
        "management_subnet": "192.168.1.0/24",
        "management_start_address": "192.168.1.2",
        "management_end_address": "192.168.1.50",
    }
    management_ipv6 = {
        "management_subnet": "fd10::/64",
        "management_start_address": "fd10::2",
        "management_end_address": "fd10::100",
    }
    management_dual_primary_ipv4 = {
        "management_subnet": "192.168.1.0/24,fd10::/64",
        "management_start_address": "192.168.1.2,fd10::2",
        "management_end_address": "192.168.1.50,fd10::100",
    }
    management_dual_primary_ipv6 = {
        "management_subnet": "fd10::/64,192.168.1.0/24",
        "management_start_address": "fd10::2,192.168.1.2",
        "management_end_address": "fd10::100,192.168.1.50",
    }

    admin_ipv4 = {
        "admin_subnet": "192.168.2.0/24",
        "admin_start_address": "192.168.2.2",
        "admin_end_address": "192.168.2.50",
    }
    admin_ipv6 = {
        "admin_subnet": "fd20::/64",
        "admin_start_address": "fd20::2",
        "admin_end_address": "fd20::50",
    }
    admin_dual_primary_ipv4 = {
        "admin_subnet": "192.168.2.0/24,fd20::/64",
        "admin_start_address": "192.168.2.2,fd20::2",
        "admin_end_address": "192.168.2.50,fd20::50",
    }
    admin_dual_primary_ipv6 = {
        "admin_subnet": "fd20::/64,192.168.2.0/24",
        "admin_start_address": "fd20::2,192.168.2.2",
        "admin_end_address": "fd20::50,192.168.2.50",
    }

    management_gateway_address_ipv4 = "192.168.1.1"
    management_gateway_address_ipv6 = "fd10::1"

    admin_gateway_address_ipv4 = "192.168.2.1"
    admin_gateway_address_ipv6 = "fd20::1"

    systemcontroller_gateway_address_ipv4 = "192.168.204.1"
    systemcontroller_gateway_address_ipv6 = "fd30::1"
    systemcontroller_gateway_address_dual_primary_ipv4 = "192.168.204.1,fd30::1"
    systemcontroller_gateway_address_dual_primary_ipv6 = "fd30::1,192.168.204.1"

    systemcontroller_pools_ipv4 = [
        FakeAddressPool("192.168.204.0", 24, "192.168.204.2", "192.168.204.100")
    ]
    systemcontroller_pools_ipv6 = [
        FakeAddressPool("fd30::", 64, "fd30::2", "fd30::100")
    ]
    systemcontroller_pools_dual_primary_ipv4 = [
        FakeAddressPool("192.168.204.0", 24, "192.168.204.2", "192.168.204.100"),
        FakeAddressPool("fd30::", 64, "fd30::2", "fd30::100"),
    ]
    systemcontroller_pools_dual_primary_ipv6 = [
        FakeAddressPool("fd30::", 64, "fd30::2", "fd30::100"),
        FakeAddressPool("192.168.204.0", 24, "192.168.204.2", "192.168.204.100"),
    ]

    def setUp(self):
        super().setUp()

    def _test_fails_with_invalid_systemcontroller_gateway_address(
        self, invalid_value, index
    ):
        self.params["systemcontroller_gateway_address"] = invalid_value[
            "systemcontroller_gateway_address"
        ]
        if "management" in invalid_value:
            self.bootstrap_data["management_subnet"] = invalid_value["management"][
                "management_subnet"
            ]
            self.bootstrap_data["management_start_address"] = invalid_value[
                "management"
            ]["management_start_address"]
            self.bootstrap_data["management_end_address"] = invalid_value["management"][
                "management_end_address"
            ]
        else:
            if "management_subnet" in self.bootstrap_data:
                del self.bootstrap_data["management_subnet"]
            if "management_start_address" in self.bootstrap_data:
                del self.bootstrap_data["management_start_address"]
            if "management_end_address" in self.bootstrap_data:
                del self.bootstrap_data["management_end_address"]

        if "management_gateway_address" in invalid_value:
            self.bootstrap_data["management_gateway_address"] = invalid_value[
                "management_gateway_address"
            ]
        else:
            if "management_gateway_address" in self.bootstrap_data:
                del self.bootstrap_data["management_gateway_address"]

        if "admin" in invalid_value:
            self.bootstrap_data["admin_subnet"] = invalid_value["admin"]["admin_subnet"]
            self.bootstrap_data["admin_start_address"] = invalid_value["admin"][
                "admin_start_address"
            ]
            self.bootstrap_data["admin_end_address"] = invalid_value["admin"][
                "admin_end_address"
            ]
        else:
            if "admin_subnet" in self.bootstrap_data:
                del self.bootstrap_data["admin_subnet"]
            if "admin_start_address" in self.bootstrap_data:
                del self.bootstrap_data["admin_start_address"]
            if "admin_end_address" in self.bootstrap_data:
                del self.bootstrap_data["admin_end_address"]

        if "admin_gateway_address" in invalid_value:
            self.bootstrap_data["admin_gateway_address"] = invalid_value[
                "admin_gateway_address"
            ]
        else:
            if "admin_gateway_address" in self.bootstrap_data:
                del self.bootstrap_data["admin_gateway_address"]

        self.mock_get_network_address_pools.return_value = invalid_value[
            "systemcontroller_pools"
        ]

        self.upload_files = self.get_post_upload_files()
        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, invalid_value["error_message"], index
        )

    def test_post_with_admin_fails_with_invalid_systemcontroller_gateway_address(self):
        """Test post fails with invalid system controller gateway address

        This tests for single/dual-stack admin/management.
        The gateway address must be of same IP family as primary admin
        (admin subnet has preference over managemnet subnet, if present)
        subnet of subcloud and it must be present on systemcontroller pools too.

        Here we are testing against presence of admin subnet.
        """
        error_message = "systemcontroller_gateway_address invalid:"
        error_message_1 = (
            f"{error_message} failed to detect a valid IP address from '%s'"
        )
        error_message_2 = (
            "systemcontroller_gateway_address IP family is not aligned "
            "with system controller management: {} pool not found in "
            "pools {}"
        )
        tests = [
            (
                self.systemcontroller_gateway_address_dual_primary_ipv4,
                self.admin_dual_primary_ipv4,
                self.admin_gateway_address_ipv4,
                self.management_dual_primary_ipv4,
                self.systemcontroller_pools_dual_primary_ipv4,
                error_message_1
                % format(self.systemcontroller_gateway_address_dual_primary_ipv4),
            ),
            (
                self.systemcontroller_gateway_address_dual_primary_ipv6,
                self.admin_dual_primary_ipv6,
                self.admin_gateway_address_ipv6,
                self.management_dual_primary_ipv6,
                self.systemcontroller_pools_dual_primary_ipv6,
                error_message_1
                % format(self.systemcontroller_gateway_address_dual_primary_ipv6),
            ),
            (
                self.systemcontroller_gateway_address_ipv4,
                self.admin_dual_primary_ipv6,
                self.admin_gateway_address_ipv6,
                self.management_dual_primary_ipv4,
                self.systemcontroller_pools_dual_primary_ipv4,
                f"{error_message} Expected IPv6",
            ),
            (
                self.systemcontroller_gateway_address_ipv6,
                self.admin_dual_primary_ipv4,
                self.admin_gateway_address_ipv4,
                self.management_dual_primary_ipv6,
                self.systemcontroller_pools_dual_primary_ipv6,
                f"{error_message} Expected IPv4",
            ),
            (
                self.systemcontroller_gateway_address_ipv4,
                self.admin_ipv4,
                self.admin_gateway_address_ipv4,
                self.management_dual_primary_ipv4,
                self.systemcontroller_pools_ipv6,
                error_message_2.format("IPv4", self.systemcontroller_pools_ipv6),
            ),
            (
                self.systemcontroller_gateway_address_ipv6,
                self.admin_ipv6,
                self.admin_gateway_address_ipv6,
                self.management_dual_primary_ipv6,
                self.systemcontroller_pools_ipv4,
                error_message_2.format("IPv6", self.systemcontroller_pools_ipv4),
            ),
        ]

        for index, test in enumerate(tests, start=1):
            invalid_value = {
                "systemcontroller_gateway_address": (test[0]),
                "admin": test[1],
                "admin_gateway_address": test[2],
                "management": test[3],
                "systemcontroller_pools": test[4],
                "error_message": test[5],
            }
            self._test_fails_with_invalid_systemcontroller_gateway_address(
                invalid_value, index
            )

    def test_post_without_admin_fails_with_invalid_systemcontroller_gateway_address(
        self,
    ):
        """Test post fails with invalid system controller gateway address

        This tests for single/dual-stack management.
        The gateway address must be of same IP family as primary admin/management
        (admin subnet has preference over managemnet subnet, if present)
        subnet of subcloud and it must be present on systemcontroller pools too.

        Here we are testing against absence of admin subnet.
        """

        error_message = "systemcontroller_gateway_address invalid:"
        error_message_1 = (
            f"{error_message} failed to detect a valid IP address from '%s'"
        )
        error_message_2 = (
            "systemcontroller_gateway_address IP family is not aligned "
            "with system controller management: {} pool not found in "
            "pools {}"
        )

        tests = [
            (
                self.systemcontroller_gateway_address_dual_primary_ipv4,
                self.management_dual_primary_ipv4,
                self.management_gateway_address_ipv4,
                self.systemcontroller_pools_dual_primary_ipv4,
                error_message_1
                % format(self.systemcontroller_gateway_address_dual_primary_ipv4),
            ),
            (
                self.systemcontroller_gateway_address_dual_primary_ipv6,
                self.management_dual_primary_ipv6,
                self.management_gateway_address_ipv6,
                self.systemcontroller_pools_dual_primary_ipv6,
                error_message_1
                % format(self.systemcontroller_gateway_address_dual_primary_ipv6),
            ),
            (
                self.systemcontroller_gateway_address_ipv4,
                self.management_dual_primary_ipv6,
                self.management_gateway_address_ipv6,
                self.systemcontroller_pools_dual_primary_ipv4,
                f"{error_message} Expected IPv6",
            ),
            (
                self.systemcontroller_gateway_address_ipv6,
                self.management_dual_primary_ipv4,
                self.management_gateway_address_ipv4,
                self.systemcontroller_pools_dual_primary_ipv6,
                f"{error_message} Expected IPv4",
            ),
            (
                self.systemcontroller_gateway_address_ipv4,
                self.management_ipv4,
                self.management_gateway_address_ipv4,
                self.systemcontroller_pools_ipv6,
                error_message_2.format("IPv4", self.systemcontroller_pools_ipv6),
            ),
            (
                self.systemcontroller_gateway_address_ipv6,
                self.management_ipv6,
                self.management_gateway_address_ipv6,
                self.systemcontroller_pools_ipv4,
                error_message_2.format("IPv6", self.systemcontroller_pools_ipv4),
            ),
        ]

        for index, test in enumerate(tests, start=1):
            invalid_value = {
                "systemcontroller_gateway_address": (test[0]),
                "management": test[1],
                "management_gateway_address": test[2],
                "systemcontroller_pools": test[3],
                "error_message": test[4],
            }
            self._test_fails_with_invalid_systemcontroller_gateway_address(
                invalid_value, index
            )


class TestSubcloudsPostInstallData(BaseTestSubcloudsPost):
    """Test class for post requests to validate the install data"""

    def setUp(self):
        super().setUp()

        self.set_list_of_post_files(subclouds.SUBCLOUD_ADD_GET_FILE_CONTENTS)
        self.upload_files = self.get_post_upload_files()
        self.params.update({"bmc_password": self._create_password()})

        self._mock_get_vault_load_files()
        self._mock_builtins_open()

        self.mock_get_vault_load_files.return_value = ("fake_iso", "fake_sig")
        self.mock_builtins_open.side_effect = mock.mock_open(
            read_data=fake_subcloud.FAKE_UPGRADES_METADATA
        )

    def _validate_invalid_ip_address(
        self, key, invalid_values=["128.224.64.256", "128.224.64.wut", None], **kwargs
    ):
        """Validates an invalid IP address"""

        self.install_data = copy.copy(self.FAKE_INSTALL_DATA)

        for key in kwargs.keys():
            self.install_data[key] = kwargs.get(key)

        for index, invalid_value in enumerate(invalid_values, start=1):
            self.install_data[key] = invalid_value
            self.upload_files = self.get_post_upload_files()

            response = self._send_request()

            error_msg = f"{key} invalid: failed to detect a valid IP address from"

            if invalid_value is None:
                error_msg = f"{error_msg} {invalid_value}"
            else:
                error_msg = f"{error_msg} '{invalid_value}'"

            self._assert_pecan_and_response(
                response, http.client.BAD_REQUEST, error_msg, index
            )

    def _validate_invalid_property(self, field, invalid_values, error_msg, **kwargs):
        """Validates an invalid property in install values"""

        self.install_data = copy.copy(self.FAKE_INSTALL_DATA)

        for key in kwargs.keys():
            self.install_data[key] = kwargs.get(key)

        for index, invalid_value in enumerate(invalid_values, start=1):
            self.install_data[field] = invalid_value
            self.upload_files = self.get_post_upload_files()

            response = self._send_request()

            self._assert_pecan_and_response(
                response, http.client.BAD_REQUEST, error_msg, index
            )

    def test_post_fails_with_missing_data_in_install_values(self):
        """Test post fails with missing data in install values"""

        for index, key in enumerate(self.FAKE_INSTALL_DATA, start=1):
            self.install_data = copy.copy(self.FAKE_INSTALL_DATA)
            del self.install_data[key]

            self.upload_files = self.get_post_upload_files()

            response = self._send_request()

            self._assert_pecan_and_response(
                response,
                http.client.BAD_REQUEST,
                f"Mandatory install value {key} not present",
                index,
            )

    def test_post_succeeds_with_install_values_and_without_release_parameter(self):
        """Test post succeeds with install values and without release parameter"""

        response = self._send_request()

        self._assert_response(response)
        # Verify that the subcloud was installed with the active release
        # when the release parameter is not provided.
        self.assertEqual(SW_VERSION, response.json["software-version"])

    def test_post_fails_when_release_parameter_is_not_matched(self):
        """Test post fails when release parameter is not matched

        The software version should be the same in install values and parameters
        """

        self.install_data["software_version"] = "22.12"
        self.upload_files = self.get_post_upload_files()

        self.params["release"] = "21.12"

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"The software_version value {self.install_data['software_version']} in "
            "the install values yaml file does not match with the specified/current "
            f"software version of {self.params['release']}. Please correct or remove "
            "this parameter from the yaml file and try again.",
        )

    def test_post_succeeds_with_release_parameter(self):
        """Test post succeeds with release parameter"""

        software_version = "21.12"
        self.install_data["software_version"] = software_version
        self.upload_files = self.get_post_upload_files()
        self.params.update({"release": software_version})

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(software_version, response.json["software-version"])

        # Remove the software_version from install_data
        del self.install_data["software_version"]

    def test_post_succeeds_without_bmc_password(self):
        """Test post succeeds without bmc password"""

        del self.params["bmc_password"]

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "subcloud bmc_password required"
        )

    def test_post_fails_with_missing_vault_file(self):
        """Test post fails with missing vault file"""

        self.mock_get_vault_load_files.return_value = (None, None)

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"Failed to get {SW_VERSION} load image. Provide active/inactive "
            "load image via 'software --os-region-name SystemController upload'",
        )

    @mock.patch.object(os.path, "isfile", return_value=True)
    def test_post_fails_with_invalid_kubernetes_version(self, *_):
        """Test post fails with invalid kubernetes version"""

        software_version = "21.12"
        self.install_data["software_version"] = software_version
        self.bootstrap_data["kubernetes_version"] = "1.21.8"
        self.upload_files = self.get_post_upload_files()
        self.params.update({"release": software_version})

        self.mock_builtins_open.side_effect = mock.mock_open(
            read_data="fresh_install_k8s_version: 1.23.1"
        )

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.INTERNAL_SERVER_ERROR,
            "Error: unable to validate the release version.",
        )

        # Remove kubernetes_version and software_version from bootstrap data
        # and install data
        del self.install_data["software_version"]
        del self.bootstrap_data["kubernetes_version"]

    def test_post_fails_with_invalid_install_type_in_install_values(self):
        """Test post fails with invalid install type in install values

        The install type must be between 0 and 5, inclusive.
        """

        invalid_values = [-1, 6, "3", "w", "", None]

        for index, invalid_value in enumerate(invalid_values, start=1):
            self.install_data = copy.copy(self.FAKE_INSTALL_DATA)
            self.install_data["install_type"] = invalid_value
            self.upload_files = self.get_post_upload_files()

            response = self._send_request()

            self._assert_pecan_and_response(
                response,
                http.client.BAD_REQUEST,
                f"install_type invalid: {invalid_value}",
                index,
            )

    def test_post_fails_with_invalid_bootstrap_address_in_install_values(self):
        """Test post fails with invalid bootstrap address in install values"""

        self._validate_invalid_ip_address(
            "bootstrap_address", ["192.168.1.256", "192.168.206.wut", None]
        )

    def test_post_fails_with_invalid_bmc_address_in_install_values(self):
        """Test post fails with invalid bmc address in install values

        The bootstrap address must match the IP version in bmc address, which
        defaults to IPv4.
        """

        self._validate_invalid_ip_address("bmc_address")

    def test_post_fails_with_invalid_ipv4_bmc_address_in_install_values(self):
        """Test post fails with invalid IPv4 bmc address in install values

        The bootstrap address must match the IP version in bmc address, which
        defaults to IPv4.
        """

        kwargs = {"bootstrap_address": "192.168.1.2"}
        self._validate_invalid_property(
            "bmc_address",
            ["fd01:6::7"],
            "bmc_address and bootstrap_address must be the same IP version",
            **kwargs,
        )
        self.mock_pecan_abort.reset_mock()

        kwargs = {"bootstrap_address": "fd02:3::4"}
        self._validate_invalid_property(
            "bmc_address",
            ["fd01:6::7"],
            "bmc_address and primary OAM network must be the same IP version",
            **kwargs,
        )
        self.mock_pecan_abort.reset_mock()

        self._validate_invalid_ip_address("bmc_address", ["192.168.-1.1", None])

    def test_post_fails_with_invalid_ipv6_bmc_address_in_install_values(self):
        """Test post fails with invalid IPv6 bmc address in install values

        The bootstrap address must match the IP version in bmc address, which
        defaults to IPv4.
        """

        kwargs = {"bootstrap_address": "fd01:6::7"}
        self._validate_invalid_property(
            "bmc_address",
            ["192.168.1.7"],
            "bmc_address and bootstrap_address must be the same IP version",
            **kwargs,
        )
        self.mock_pecan_abort.reset_mock()

        kwargs = {"bootstrap_address": "192.168.1.2"}
        self.set_oam_params_ipv6()
        self._validate_invalid_property(
            "bmc_address",
            ["192.168.1.7"],
            "bmc_address and primary OAM network must be the same IP version",
            **kwargs,
        )
        self.mock_pecan_abort.reset_mock()

        self._validate_invalid_ip_address("bmc_address", ["fd01:6:-1", None])

    def test_post_fails_with_invalid_persistent_size_in_install_values(self):
        """Test post fails with invalid persistent size in install values"""

        invalid_values = ["4000o", "20000", 40000.1, None]

        for index, invalid_value in enumerate(invalid_values, start=1):
            self.install_data = copy.copy(self.FAKE_INSTALL_DATA)
            self.install_data["persistent_size"] = invalid_value
            self.upload_files = self.get_post_upload_files()

            response = self._send_request()

            self._assert_pecan_and_response(
                response,
                http.client.BAD_REQUEST,
                "The install value persistent_size (in MB) must be a whole number "
                "greater than or equal to 30000",
                index,
            )

    def test_post_fails_with_invalid_nexthop_gateway_in_install_values(self):
        """Test post fails with invalid nexthop gateway in install values"""

        self._validate_invalid_ip_address("nexthop_gateway")

    def test_post_fails_with_invalid_ipv4_nexthop_gateway_in_install_values(self):
        """Test post fails with invalid IPv4 nexthop gateway in install values"""

        kwargs = {"bootstrap_address": "192.168.1.5"}

        self._validate_invalid_property(
            "nexthop_gateway",
            ["fd01:6::7"],
            "nexthop_gateway and bootstrap_address must be the same IP version",
            **kwargs,
        )
        self.mock_pecan_abort.reset_mock()

        self._validate_invalid_ip_address("nexthop_gateway", ["192.168.-1.1", None])

    def test_post_fails_with_invalid_ipv6_nexthop_gateway_in_install_values(self):
        """Test post fails with invalid IPv6 nexthop gateway in install values

        All of the required IP addresses must be in the same IP version.
        """

        kwargs = {"bootstrap_address": "fd01:6::6", "bmc_address": "fd01:6::7"}

        self.set_oam_params_ipv6()
        self._validate_invalid_property(
            "nexthop_gateway",
            ["192.168.1.7"],
            "nexthop_gateway and bootstrap_address must be the same IP version",
            **kwargs,
        )
        self.mock_pecan_abort.reset_mock()

        self.set_oam_params_ipv4()
        self._validate_invalid_ip_address("nexthop_gateway", ["fd01:6:-1", None])

    def test_post_fails_with_invalid_network_address_in_install_values(self):
        """Test post fails with invalid network address in install values

        The nexthop gateway and network mask are required when the network address
        is present.
        """
        # TODO(abailey): None will cause the API to fail

        self.install_data = copy.copy(self.FAKE_INSTALL_DATA)
        self.install_data["nexthop_gateway"] = "192.168.1.2"
        self.install_data["network_mask"] = 32
        self.install_data["network_address"] = "fd01:6::0"

        self.upload_files = self.get_post_upload_files()

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "network address invalid: IPv6 minimum prefix length is 64",
        )

    def test_post_fails_with_invalid_network_mask_in_install_values(self):
        """Test post fails with invalid network mask in install values"""

        kwargs = {"nexthop_gateway": "192.168.1.2", "network_address": "192.168.101.10"}

        self._validate_invalid_property(
            "network_mask",
            [64, -1, "junk", None],
            "network address invalid: Invalid subnet - not a valid IP subnet",
            **kwargs,
        )


class BaseTestSubcloudsPatch(BaseTestSubcloudsController):
    """Base test class for patch requests"""

    def setUp(self):
        super().setUp()

        self.subcloud = fake_subcloud.create_fake_subcloud(self.ctx, data_install="")

        self.url = f"{self.url}/{self.subcloud.id}"
        self.method = self.app.patch

        self._mock_get_vault_load_files()
        self._mock_sysinv_client(psd_common)
        self._mock_openstack_driver(subclouds)
        self._mock_vim_client(subclouds.vim)

        self.mock_get_vault_load_files.return_value = (
            FAKE_SUBCLOUD_INSTALL_VALUES["image"],
            "fake_sig",
        )
        self.mock_sysinv_client().get_admin_address_pools.return_value = [
            FakeAddressPool("192.168.205.0", 24, "192.168.205.2", "192.168.205.100")
        ]
        self.mock_sysinv_client().get_management_address_pools.return_value = [
            FakeAddressPool("192.168.204.0", 24, "192.168.204.2", "192.168.204.100")
        ]


class TestSubcloudsPatch(BaseTestSubcloudsPatch):
    """Test class for patch requests"""

    def setUp(self):
        super().setUp()

        self.upload_files = [("fake", "fake_name", "fake content".encode("utf-8"))]

        self.mock_rpc_client().update_subcloud.return_value = (
            db_api.subcloud_db_model_to_dict(self.subcloud)
        )

    def _assert_response_payload(self, response, key, value):
        """Asserts the response's payload"""

        updated_subcloud = sql_api.subcloud_get(self.ctx, self.subcloud.id)
        self.assertEqual(updated_subcloud[key], value)

    def test_patch_fails_without_subcloud_ref(self):
        """Test patch fails without subcloud ref"""

        self.url = self.API_PREFIX

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Subcloud ID required"
        )

    def test_patch_succeeds_with_subcloud_id(self):
        """Test patch succeeds with subcloud id"""

        response = self._send_request()

        self._assert_response(response)

    def test_patch_fails_with_inexistent_subcloud_id(self):
        """Test patch fails with inexistent subcloud id"""

        self.url = f"{self.API_PREFIX}/999"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.NOT_FOUND, "Subcloud not found"
        )

    def test_patch_succeeds_with_subcloud_name(self):
        """Test patch succeeds with subcloud name"""

        self.url = f"{self.API_PREFIX}/{self.subcloud.name}"

        response = self._send_request()

        self._assert_response(response)

    def test_patch_fails_with_inexistent_subcloud_name(self):
        """Test patch fails with inexistent subcloud name"""

        self.url = f"{self.API_PREFIX}/fake"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.NOT_FOUND, "Subcloud not found"
        )

    def test_patch_succeeds_with_invalid_verb(self):
        """Test patch succeeds with invalid verb"""

        self.url = f"{self.url}/fake"

        response = self._send_request()

        self._assert_response(response)

    def test_patch_succeeds_with_management_state(self):
        """Test patch succeeds with management state"""

        self.params = {"management-state": dccommon_consts.MANAGEMENT_UNMANAGED}

        response = self._send_request()

        self._assert_response(response)
        self._assert_response_payload(
            response, "management_state", dccommon_consts.MANAGEMENT_UNMANAGED
        )

    def test_patch_fails_with_invalid_management_state(self):
        """Test patch fails with invalid management state"""

        self.params = {"management-state": "fake"}

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Invalid management-state"
        )

    def test_patch_fails_with_invalid_force(self):
        """Test patch fails with invalid force"""

        self.params = {
            "management-state": dccommon_consts.MANAGEMENT_UNMANAGED,
            "force": "fake",
        }

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Invalid force value"
        )

    def test_patch_fails_with_force_for_unmanaged_subcloud(self):
        """Test patch fails with force for unmanaged subcloud"""

        self.params = {
            "management-state": dccommon_consts.MANAGEMENT_UNMANAGED,
            "force": True,
        }

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Invalid option: force"
        )

    def test_patch_succeeds_with_force_for_managed_subcloud(self):
        """Test patch succeeds with force for managed subcloud"""

        self.params = {
            "management-state": dccommon_consts.MANAGEMENT_MANAGED,
            "force": True,
        }

        response = self._send_request()

        self._assert_response(response)
        self.mock_rpc_client().update_subcloud.assert_called_once_with(
            mock.ANY,
            self.subcloud.id,
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            description=None,
            location=None,
            group_id=None,
            data_install=None,
            force=True,
            peer_group_id=None,
            bootstrap_values=None,
            bootstrap_address=None,
            deploy_status=None,
        )

    def test_patch_succeeds_with_group_id(self):
        """Test patch succeeds with group id"""

        values = [1, "1", "Default"]

        for index, value in enumerate(values, start=1):
            self.params = {"group_id": value}

            response = self._send_request()

            self._assert_response(response)

            if index == 3:
                # When the group_id is not a digit, it's retrieved using the
                # get_by_name method, which returns the Default's group id (1).
                value = 1
            self._assert_response_payload(response, "group_id", int(value))

    def test_patch_fails_with_invalid_group_id(self):
        """Test patch fails with invalid group id"""

        values = [0, -1, 2, 999, "0", "-1", 0.5, "BadName", "False", "True"]

        for index, value in enumerate(values, start=1):
            self.params = {"group_id": value}

            response = self._send_request()

            self._assert_pecan_and_response(
                response, http.client.BAD_REQUEST, "Invalid group", index
            )

    def _test_patch_succeeds_with_install_data(self, install_data):
        """Utility method to perform requests using different install data"""

        self.params = {
            "install_values": json.dumps(copy.copy(install_data)),
            "bmc_password": self._create_password("bmc_password"),
        }

        response = self._send_request()

        self._assert_response(response)

        # Add the bmc_password to install_values as it is done in the code
        data_install = json.loads(self.params["install_values"])
        data_install.update({"bmc_password": self.params["bmc_password"]})
        self.mock_rpc_client().update_subcloud.assert_called_once_with(
            mock.ANY,
            self.subcloud.id,
            management_state=None,
            description=None,
            location=None,
            group_id=None,
            data_install=json.dumps(data_install),
            force=None,
            peer_group_id=None,
            bootstrap_values=None,
            bootstrap_address=None,
            deploy_status=None,
        )

    def test_patch_succeeds_with_persistent_size_in_install_values(self):
        """Test patch succeeds with persistent size in install values"""

        self._test_patch_succeeds_with_install_data(
            fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES_WITH_PERSISTENT_SIZE
        )

    def test_patch_succeeds_with_install_values(self):
        """Test patch succeeds with install values"""

        self._test_patch_succeeds_with_install_data(FAKE_SUBCLOUD_INSTALL_VALUES)

    def test_patch_succeds_with_install_values_and_data_install(self):
        """Test patch succeeds with install values and data install

        During the request, the install_values parameter can be retrieved from the
        install_values in parameters or the data_install property from the subcloud.
        In this test case, both of them are sent.
        """

        self._update_subcloud(
            data_install=json.dumps(copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES))
        )

        self._test_patch_succeeds_with_install_data(FAKE_SUBCLOUD_INSTALL_VALUES)

    def _test_patch_with_vim_strategy(self):
        """Utility method to validate the _check_existing_vim_strategy method"""

        self.params = {
            "sysadmin_password": self._create_password("testpass"),
            "bootstrap_address": "192.168.102.2",
            "management_subnet": "192.168.102.0/24",
            "management_start_ip": "192.168.102.5",
            "management_end_ip": "192.168.102.49",
            "management_gateway_ip": "192.168.102.1",
            "systemcontroller_gateway_address": "192.168.204.101",
        }

        self._update_subcloud(availability_status=dccommon_consts.AVAILABILITY_ONLINE)

        return self._send_request()

    def _test_patch_fails_with_vim_strategy(self):
        """Utility method to validate failure scenarios with vim strategy"""

        response = self._test_patch_with_vim_strategy()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Reconfiguring subcloud network is not allowed while there is an "
            "on-going orchestrated operation in this subcloud. Please try again "
            "after the strategy has completed.",
        )
        self.mock_rpc_client().update_subcloud_with_network_reconfig.assert_not_called()

    def test_patch_fails_with_network_addresses_and_ongoing_vim_strategy(self):
        """Test patch fails with network addresses and ongoing vim strategy"""

        fake_strategy.create_fake_strategy_step(self.ctx, subcloud_id=self.subcloud.id)

        self._test_patch_fails_with_vim_strategy()

    def test_patch_succeeds_with_get_vim_strategy_exception(self):
        """Test patch succeeds with get vim strategy exception"""

        self.mock_vim_client().get_strategy.side_effect = Exception()

        response = self._test_patch_with_vim_strategy()

        self._assert_response(response)
        update_subcloud_with_network_reconfig = (
            self.mock_rpc_client().update_subcloud_with_network_reconfig
        )
        update_subcloud_with_network_reconfig.assert_called_once()
        self.mock_vim_client().get_strategy.assert_called_once()

    def test_patch_fails_with_initial_vim_sys_config_update_strategy(self):
        """Test patch fails with initial vim sys config update strategy"""

        self.mock_vim_client().get_strategy.return_value.state = vim.STATE_INITIAL

        self._test_patch_fails_with_vim_strategy()
        self.mock_vim_client().get_strategy.assert_called_once()

    def test_patch_succeeds_with_applied_vim_sys_config_update_strategy(self):
        """Test patch succeeds with applied vim sys config update strategy"""

        self.mock_vim_client().get_strategy.return_value.state = vim.STATE_APPLIED

        response = self._test_patch_with_vim_strategy()

        self._assert_response(response)
        update_subcloud_with_network_reconfig = (
            self.mock_rpc_client().update_subcloud_with_network_reconfig
        )
        update_subcloud_with_network_reconfig.assert_called_once()
        self.mock_vim_client().get_strategy.assert_called_once()

    @mock.patch.object(sql_api, "strategy_step_get")
    def test_patch_fails_with_db_api_get_vim_strategy_exception(self, mock_sql_api):
        """Test patch fails with db api's get vim strategy exception"""

        mock_sql_api.side_effect = Exception()

        self._test_patch_fails_with_vim_strategy()

    @mock.patch.object(subclouds.SubcloudsController, "_get_patch_data")
    def test_patch_fails_without_body(self, mock_get_patch_data):
        """Test patch fails without body

        It isn't possible to make the decoder.MultipartDecoder return the empty
        dictionary, which is why is necessary to mock either the _get_patch_data or
        the decoder method.
        """

        self.params = {}
        self.upload_files = None

        mock_get_patch_data.return_value = self.upload_files

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Body required"
        )

    def test_patch_restore_fails_with_deprecation(self):
        """Test patch restore fails with deprecation"""

        self.url = f"{self.url}/restore"

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.GONE,
            "This API is deprecated. Please use /v1.0/subcloud-backup/restore",
        )

    def test_patch_reconfigure_fails_with_deprecation(self):
        """Test patch reconfigure fails with deprecation"""

        self.url = f"{self.url}/reconfigure"

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.GONE,
            "This API is deprecated. Please use "
            "/v1.0/phased-subcloud-deploy/{subcloud}/configure",
        )

    def test_patch_reinstall_fails_with_deprecation(self):
        """Test patch reinstall fails with deprecation"""

        self.url = f"{self.url}/reinstall"

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.GONE,
            "This API is deprecated. Please use /v1.0/subclouds/{subcloud}/redeploy",
        )


class TestSubcloudsPatchWithRename(BaseTestSubcloudsPatch):
    """Test class for patch requests without verb and with rename"""

    def setUp(self):
        super().setUp()

        self.params["name"] = "subcloud2"

        self.upload_files = [("fake", "fake_name", "fake content".encode("utf-8"))]

        self.mock_rpc_client().update_subcloud.return_value = (
            db_api.subcloud_db_model_to_dict(self.subcloud)
        )

    def test_patch_with_rename_succeeds(self):
        """Test patch with rename succeeds"""

        response = self._send_request()

        self._assert_response(response)
        self.mock_rpc_client().rename_subcloud.assert_called_once()

    def test_patch_with_rename_fails_with_managed_subcloud(self):
        """Test patch with rename fails with managed subcloud"""

        self._update_subcloud(management_state=dccommon_consts.MANAGEMENT_MANAGED)

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"Subcloud {self.subcloud.name} must be deployed, unmanaged and "
            "no ongoing prestage for the subcloud rename operation.",
        )

    def test_patch_with_rename_fails_with_invalid_name(self):
        """Test patch with rename fails with invalid name"""

        self.params["name"] = "_#"

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "new name must contain alphabetic characters",
        )

    def test_patch_with_rename_fails_with_new_name_as_current_name(self):
        """Test patch with rename fails with new name as current name"""

        self.params["name"] = self.subcloud.name

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"Provided subcloud name {self.params['name']} is the same as the current "
            f"subcloud {self.subcloud.name}. A different name is required to rename "
            "the subcloud",
        )

    def test_patch_with_rename_fails_with_rpc_client_remote_error(self):
        """Test patch with rename fails with rpc client remote error"""

        self.mock_rpc_client().rename_subcloud.side_effect = RemoteError("msg", "value")

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.UNPROCESSABLE_ENTITY, "value"
        )

    def test_patch_with_rename_fails_with_rpc_client_generic_exception(self):
        """Test patch with rename fails with rpc client generic exception"""

        self.mock_rpc_client().rename_subcloud.side_effect = Exception()

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.INTERNAL_SERVER_ERROR, "Unable to rename subcloud"
        )


class TestSubcloudsPatchWithNetworkReconfiguration(BaseTestSubcloudsPatch):
    """Test class for patch requests without verb and with network reconfiguration"""

    def setUp(self):
        super().setUp()

        self.params = {
            "sysadmin_password": self._create_password("testpass"),
            "bootstrap_address": "192.168.102.2",
            "management_subnet": "192.168.102.0/24",
            "management_start_ip": "192.168.102.5",
            "management_end_ip": "192.168.102.49",
            "management_gateway_ip": "192.168.102.1",
            "systemcontroller_gateway_address": "192.168.204.101",
        }
        self.upload_files = [("fake", "fake_name", "fake content".encode("utf-8"))]

        self._update_subcloud(data_install="")

        self.mock_rpc_client().update_subcloud.return_value = (
            db_api.subcloud_db_model_to_dict(self.subcloud)
        )

    def test_patch_with_network_reconfig_succeeds(self):
        """Test patch with network reconfig succeeds"""

        self._update_subcloud(availability_status=dccommon_consts.AVAILABILITY_ONLINE)

        response = self._send_request()

        self._assert_response(response)

        # Validate that the parameters were used in the rpc client call
        # Note: there are more parameter that are added during the request's
        # execution. Because of that, it's necessary to validate only the sent ones.
        call_arg = (
            self.mock_rpc_client().update_subcloud_with_network_reconfig.call_args[0][2]
        )

        for key in self.params:
            # The sysadmin_password is sent encoded, but returns decoded
            if key == "sysadmin_password":
                self.params[key] = base64.b64decode(self.params[key]).decode("utf-8")
            self.assertEqual(self.params[key], call_arg[key])

        update_subcloud_with_network_reconfig = (
            self.mock_rpc_client().update_subcloud_with_network_reconfig
        )
        update_subcloud_with_network_reconfig.assert_called_once_with(
            mock.ANY, self.subcloud.id, mock.ANY
        )

    def test_patch_with_network_reconfig_fails_with_subcloud_secondary_state(self):
        """Test patch with network reconfig fails with subcloud secondary state"""

        invalid_states = [
            consts.DEPLOY_STATE_SECONDARY,
            consts.DEPLOY_STATE_SECONDARY_FAILED,
        ]

        for index, state in enumerate(invalid_states, start=1):
            self._update_subcloud(deploy_status=state)

            response = self._send_request()

            self._assert_pecan_and_response(
                response,
                http.client.INTERNAL_SERVER_ERROR,
                f"Cannot perform on {self.subcloud.deploy_status} state subcloud",
                index,
            )

    def test_patch_with_network_reconfig_fails_with_management_state(self):
        """Test patch with network reconfig fails with management state"""

        self.params["management-state"] = dccommon_consts.MANAGEMENT_MANAGED

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.UNPROCESSABLE_ENTITY,
            "Management state and network reconfiguration must be updated separately",
        )

    def test_patch_with_network_reconfig_fails_with_managed_subcloud(self):
        """Test patch with network reconfig fails with managed subcloud"""

        self._update_subcloud(management_state=dccommon_consts.MANAGEMENT_MANAGED)

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.UNPROCESSABLE_ENTITY,
            "A subcloud must be unmanaged to perform network reconfiguration",
        )

    def test_patch_with_network_reconfig_fails_without_bootstrap_address(self):
        """Test patch with network reconfig fails without bootstrap address"""

        del self.params["bootstrap_address"]

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.UNPROCESSABLE_ENTITY,
            "The bootstrap_address parameter is required for network reconfiguration",
        )

    def test_patch_with_network_reconfig_fails_without_required_parameters(self):
        """Test patch with network reconfig fails without required parameters"""

        required_parameters = ", ".join(
            "--{}".format(param.replace("_", "-"))
            for param in subclouds.SUBCLOUD_MANDATORY_NETWORK_PARAMS
        )
        original_params = copy.copy(self.params)

        for index, parameter in enumerate(
            subclouds.SUBCLOUD_MANDATORY_NETWORK_PARAMS, start=1
        ):

            self.params = copy.copy(original_params)
            del self.params[parameter]

            response = self._send_request()

            if parameter == "management_gateway_ip":
                self._assert_pecan_and_response(
                    response,
                    http.client.BAD_REQUEST,
                    "subcloud management gateway IP's IP family does not exist on "
                    "system controller managements: Invalid address - not a valid "
                    "IP address: failed to detect a valid IP address from None",
                    index,
                )
            else:
                self._assert_pecan_and_response(
                    response,
                    http.client.UNPROCESSABLE_ENTITY,
                    "The following parameters are necessary for subcloud network "
                    f"reconfiguration: {required_parameters}",
                    index,
                )

    def test_patch_with_network_reconfig_fails_with_value_in_use(self):
        """Test patch with network reconfig fails with value in use"""

        self.params["management_end_ip"] = self.subcloud.management_end_ip

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.UNPROCESSABLE_ENTITY,
            "management_end_ip already in use by the subcloud.",
        )

    def test_patch_with_network_reconfig_fails_without_sysadmin_password(self):
        """Test patch with network reconfig fails without sysadmin password"""

        del self.params["sysadmin_password"]

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "subcloud sysadmin_password required"
        )

    def test_patch_with_network_reconfig_fails_with_invalid_sysadmin_password(self):
        """Test patch with network reconfig fails with invalid sysadmin password"""

        self.params["sysadmin_password"] = "fake"

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Failed to decode subcloud sysadmin_password, "
            "verify the password is base64 encoded",
        )


class TestSubcloudsPatchWithPeerGroup(BaseTestSubcloudsPatch):
    """Test class for patch requests with an existing peer group"""

    def setUp(self):
        super().setUp()

        system_peer_manager = test_system_peer_manager.TestSystemPeerManager

        self.peer_group = system_peer_manager.create_subcloud_peer_group_static(
            self.ctx
        )
        self._update_subcloud(
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            deploy_status=consts.DEPLOY_STATE_DONE,
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            prestage_status=consts.PRESTAGE_STATE_COMPLETE,
            rehome_data=(
                '{"saved_payload": {"system_mode": "simplex","'
                '"bootstrap-address": "192.168.100.100"}}'
            ),
        )

        self.params = {"peer_group": self.peer_group.id}
        self.upload_files = [("fake", "fake_name", "fake content".encode("utf-8"))]

        self._mock_openstack_driver(cutils)
        self.mock_openstack_driver_cutils = self.mock_openstack_driver
        self._mock_sysinv_client(cutils)
        self.mock_sysinv_client_cutils = self.mock_sysinv_client

        mock_get_system = mock.MagicMock()
        mock_get_system.uuid = self.peer_group.system_leader_id

        self.mock_sysinv_client_cutils().get_system.return_value = mock_get_system
        self.mock_rpc_client().update_subcloud.return_value = (
            db_api.subcloud_db_model_to_dict(self.subcloud)
        )

    def _setup_system_peer_for_subcloud(self, availability_state):
        system_peer = (
            test_system_peer_manager.TestSystemPeerManager.create_system_peer_static(
                self.ctx, availability_state=availability_state
            )
        )
        self.peer_group = sql_api.subcloud_peer_group_update(
            self.ctx, self.peer_group.id, group_priority=1
        )
        system_peer_manager = test_system_peer_manager.TestSystemPeerManager
        self.peer_group_association = (
            system_peer_manager.create_peer_group_association_static(
                self.ctx,
                system_peer_id=system_peer.id,
                peer_group_id=self.peer_group.id,
            )
        )
        self._update_subcloud(
            deploy_status=consts.DEPLOY_STATE_REHOME_FAILED,
            peer_group_id=self.peer_group_association.id,
        )

    def test_patch_with_peer_group_succeeds(self):
        """Test patch with peer group succeeds"""

        response = self._send_request()

        self._assert_response(response)
        self.mock_rpc_client().update_subcloud.assert_called_once_with(
            mock.ANY,
            self.subcloud.id,
            management_state=mock.ANY,
            description=mock.ANY,
            location=mock.ANY,
            group_id=mock.ANY,
            data_install=mock.ANY,
            force=mock.ANY,
            peer_group_id=self.peer_group.id,
            bootstrap_values=mock.ANY,
            bootstrap_address=mock.ANY,
            deploy_status=mock.ANY,
        )
        self.mock_rpc_client().update_association_sync_status.assert_called_once()

    def test_patch_with_peer_group_fails_without_rehome_data(self):
        """Test patch with peer group fails without rehome data"""

        self._update_subcloud(rehome_data="")

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Cannot update the subcloud peer group: must provide both the "
            "bootstrap-values and bootstrap-address.",
        )
        self.mock_rpc_client().update_subcloud.assert_not_called()
        self.mock_rpc_client().update_association_sync_status.assert_not_called()

    def test_patch_with_peer_group_fails_with_management_state(self):
        """Test patch with peer group fails with management state"""

        self.params["management-state"] = dccommon_consts.MANAGEMENT_MANAGED

        self._update_subcloud(peer_group_id=self.peer_group.id)

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Cannot update the management state of a subcloud that is "
            "associated with a peer group.",
        )

    def test_patch_with_peer_group_succeeds_in_removing_peer_group(self):
        """Test patch with peer group succeeds in removing peer group"""

        self._update_subcloud(rehome_data="", peer_group_id=self.peer_group.id)

        self.params = {"peer_group": None}

        response = self._send_request()

        self._assert_response(response)
        self.mock_rpc_client().update_subcloud.assert_called_once_with(
            mock.ANY,
            self.subcloud.id,
            management_state=mock.ANY,
            description=mock.ANY,
            location=mock.ANY,
            group_id=mock.ANY,
            data_install=mock.ANY,
            force=mock.ANY,
            peer_group_id=str(self.params["peer_group"]).lower(),
            bootstrap_values=mock.ANY,
            bootstrap_address=mock.ANY,
            deploy_status=mock.ANY,
        )
        self.mock_rpc_client().update_association_sync_status.assert_called_once()

    def test_patch_with_peer_group_fails_on_non_primary_site(self):
        """Test patch with peer group fails on non primary site"""

        self.peer_group = sql_api.subcloud_peer_group_update(
            self.ctx, self.peer_group.id, group_priority=1
        )
        self._update_subcloud(rehome_data="", peer_group_id=self.peer_group.id)

        self.params = {"description": "fake"}

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Subcloud update is only allowed when its peer group priority value is 0.",
        )
        self.mock_rpc_client().update_subcloud.assert_not_called()
        self.mock_rpc_client().update_association_sync_status.assert_not_called()

    def test_patch_with_peer_group_succeeds_to_update_bootstrap_address(self):
        """Test patch with peer group succeeds to update bootstrap address"""

        self._update_subcloud(rehome_data="", peer_group_id=self.peer_group.id)

        self.params = {"bootstrap_address": "192.168.10.22"}

        response = self._send_request()

        self._assert_response(response)
        self.mock_rpc_client().update_subcloud.assert_called_once_with(
            mock.ANY,
            self.subcloud.id,
            management_state=None,
            description=None,
            location=None,
            group_id=None,
            data_install=None,
            force=None,
            peer_group_id=None,
            bootstrap_values=None,
            bootstrap_address=self.params["bootstrap_address"],
            deploy_status=None,
        )
        self.mock_rpc_client().update_association_sync_status.assert_called_once()

    def test_patch_with_peer_group_fails_to_update_with_available_system_peer(self):
        """Test patch with peer group fails to update with available system peer

        When the system peer is available but the peer group priority is not 0, it
        isn't possible to update certain parameters.
        """

        self._setup_system_peer_for_subcloud(
            consts.SYSTEM_PEER_AVAILABILITY_STATE_AVAILABLE
        )

        self.params = {"bootstrap_address": "192.168.10.22"}
        self.upload_files = [
            (
                "bootstrap_address",
                "bootstrap_address_name",
                "192.168.10.22".encode("utf-8"),
            )
        ]

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Subcloud bootstrap values or address update in the non-primary site is "
            "only allowed when rehome failed and the primary site is unavailable.",
        )
        self.mock_rpc_client().update_subcloud.assert_not_called()
        self.mock_rpc_client().update_association_sync_status.assert_not_called()
        self.assertEqual(
            consts.ASSOCIATION_SYNC_STATUS_IN_SYNC,
            sql_api.peer_group_association_get(
                self.ctx, self.peer_group_association.id
            ).sync_status,
        )

    def test_patch_with_peer_group_succeeds_to_update_with_unavailable_system_peer(
        self,
    ):
        """Test patch with peer group succeeds to update with unavailable system peer

        When the system peer is unavailable, it's possible to update the data in the
        subcloud even if it isn't in a peer group with priority 0.
        """

        self._setup_system_peer_for_subcloud(
            consts.SYSTEM_PEER_AVAILABILITY_STATE_UNAVAILABLE
        )

        self.params = {"bootstrap_address": "192.168.10.22"}
        self.upload_files = [
            (
                "bootstrap_address",
                "bootstrap_address_name",
                "192.168.10.22".encode("utf-8"),
            )
        ]

        response = self._send_request()

        self._assert_response(response)
        self.mock_rpc_client().update_subcloud.assert_called_once_with(
            mock.ANY,
            self.subcloud.id,
            management_state=None,
            description=None,
            location=None,
            group_id=None,
            data_install=None,
            force=None,
            peer_group_id=None,
            bootstrap_values=None,
            bootstrap_address=self.params["bootstrap_address"],
            deploy_status=None,
        )
        self.assertEqual(
            consts.ASSOCIATION_SYNC_STATUS_OUT_OF_SYNC,
            sql_api.peer_group_association_get(
                self.ctx, self.peer_group_association.id
            ).sync_status,
        )

    def test_patch_with_peer_group_fails_with_rpc_client_remote_error(self):
        """Test patch with peer group fails with rpc client remote error"""

        self.mock_rpc_client().update_association_sync_status.side_effect = RemoteError(
            "msg", "value"
        )

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.UNPROCESSABLE_ENTITY, "value"
        )

    def test_patch_with_peer_group_fails_with_rpc_client_generic_exception(self):
        """Test patch with peer group fails with rpc client generic exception"""

        self.mock_rpc_client().update_association_sync_status.side_effect = Exception()

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.INTERNAL_SERVER_ERROR, "Unable to update subcloud"
        )


class TestSubcloudsPatchUpdateStatus(BaseTestSubcloudsPatch):
    """Test class for patch requests with update status verb"""

    def setUp(self):
        super().setUp()

        self.url = f"{self.url}/update_status"
        self.method = self.app.patch_json
        self.params = {"endpoint": "dc-cert", "status": "in-sync"}

    def test_patch_update_status_succeeds(self):
        """Test patch update status succeeds"""

        response = self._send_request()

        self._assert_response(response)
        self._assert_response(response)
        update_subcloud_endpoint_status = (
            self.mock_rpc_subcloud_state_client().update_subcloud_endpoint_status
        )
        update_subcloud_endpoint_status.assert_called_once_with(
            mock.ANY,
            self.subcloud.name,
            self.subcloud.region_name,
            self.params["endpoint"],
            self.params["status"],
        )

    def test_patch_update_status_fails_without_payload(self):
        """Test patch update status fails without payload"""

        self.params = {}

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Body required"
        )
        update_subcloud_endpoint_status = (
            self.mock_rpc_subcloud_state_client().update_subcloud_endpoint_status
        )
        update_subcloud_endpoint_status.assert_not_called()

    def test_patch_update_status_fails_with_invalid_endpoint(self):
        """Test patch update status fails with invalid endpoint"""

        self.params["endpoint"] = "fake"

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"updating endpoint {self.params['endpoint']} status is not allowed",
        )
        update_subcloud_endpoint_status = (
            self.mock_rpc_subcloud_state_client().update_subcloud_endpoint_status
        )
        update_subcloud_endpoint_status.assert_not_called()

    def test_patch_update_status_fails_without_endpoint(self):
        """Test patch update status fails without endpoint"""

        del self.params["endpoint"]

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "endpoint required"
        )
        update_subcloud_endpoint_status = (
            self.mock_rpc_subcloud_state_client().update_subcloud_endpoint_status
        )
        update_subcloud_endpoint_status.assert_not_called()

    def test_patch_update_status_fails_with_invalid_status(self):
        """Test patch update status fails with invalid status"""

        self.params["status"] = "fake"

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"status {self.params['status']} in invalid.",
        )
        update_subcloud_endpoint_status = (
            self.mock_rpc_subcloud_state_client().update_subcloud_endpoint_status
        )
        update_subcloud_endpoint_status.assert_not_called()

    def test_patch_update_status_fails_without_status(self):
        """Test patch update status fails without status"""

        del self.params["status"]

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "status required"
        )
        update_subcloud_endpoint_status = (
            self.mock_rpc_subcloud_state_client().update_subcloud_endpoint_status
        )
        update_subcloud_endpoint_status.assert_not_called()


class TestSubcloudsPatchRedeploy(BaseTestSubcloudsPatch):
    """Test class for patch requests with redeploy verb"""

    def setUp(self):
        super().setUp()

        self.url = f"{self.url}/redeploy"

        self._create_variables_and_update_subcloud()

        self._mock_load_yaml_file()
        self._mock_builtins_open()
        self._mock_os_listdir()
        self._mock_os_path_isdir()
        self._mock_os_path_exists()

        self.mock_load_yaml_file.return_value = {"software_version": SW_VERSION}
        self.mock_builtins_open.side_effect = mock.mock_open(
            read_data=fake_subcloud.FAKE_UPGRADES_METADATA
        )
        self.mock_os_listdir.return_value = [
            "deploy_chart_fake.tgz",
            "deploy_overrides_fake.yaml",
            "deploy_playbook_fake.yaml",
        ]
        self.mock_os_path_isdir.return_value = True
        config_file = psd_common.get_config_file_path(
            self.subcloud.name, consts.DEPLOY_CONFIG
        )
        self.mock_os_path_exists.side_effect = lambda file: (
            True if file == config_file else False
        )

    def _create_variables_and_update_subcloud(self):
        self.install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)
        self.install_data.pop("software_version")
        self.install_data.update(
            {"bmc_password": self._create_password("bmc_password")}
        )

        self._update_subcloud(data_install=json.dumps(self.install_data))

        self.bootstrap_data = copy.copy(fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA)
        self.bootstrap_data["name"] = self.subcloud.name
        self.config_data = {"deploy_config": "deploy config values"}
        self.params = {
            **self.install_data,
            **self.bootstrap_data,
            **self.config_data,
            "sysadmin_password": self._create_password("sysadmin_password"),
            "bmc_password": self._create_password("bmc_password"),
        }
        self.upload_files = [
            (
                "install_values",
                "install_fake_filename",
                json.dumps(self.install_data).encode(),
            ),
            (
                "bootstrap_values",
                "bootstrap_fake_filename",
                json.dumps(self.bootstrap_data).encode(),
            ),
            (
                "deploy_config",
                "config_fake_filename",
                json.dumps(self.config_data).encode(),
            ),
        ]

    def test_patch_redeploy_succeeds_without_release_version(self):
        """Test patch redeploy succeeds without release version"""

        response = self._send_request()

        self._assert_response(response)
        self.mock_rpc_client().redeploy_subcloud.assert_called_once()
        self.assertEqual(SW_VERSION, response.json["software-version"])

    def test_patch_redeploy_succeeds_with_release_version(self):
        """Test patch redeploy succeeds with release version"""

        self.params["release"] = fake_subcloud.FAKE_SOFTWARE_VERSION

        self._update_subcloud(software_version=SW_VERSION)

        response = self._send_request()

        self._assert_response(response)
        self.mock_rpc_client().redeploy_subcloud.assert_called_once()
        self.assertEqual(self.params["release"], response.json["software-version"])

    def test_patch_redeploy_fails_without_bmc_password(self):
        """Test patch redeploy fails without bmc password"""

        self.params = {}
        self.upload_files = None

        self._update_subcloud(data_install=json.dumps(FAKE_SUBCLOUD_INSTALL_VALUES))

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Failed to get bmc_password from data_install",
        )

    def test_patch_redeploy_succeeds_with_subcloud_data_install(self):
        """Test patch redeploy succeeds with subcloud data install

        Test the patch request succeeds when the required data is filled in the
        subcloud's data install field only.
        """

        self.params = {"sysadmin_password": self._create_password("sysadmin_password")}
        self.upload_files = None

        response = self._send_request()

        self._assert_response(response)

    def test_patch_redeploy_fails_without_payload(self):
        """Test patch redeploy fails without payload"""

        self.params = {}
        self.upload_files = None

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "subcloud sysadmin_password required"
        )

    def test_patch_redeploy_succeeds_without_config_values(self):
        """Test patch redeploy succeeds without config values"""

        self.mock_os_path_exists.side_effect = lambda file: False
        del self.params["deploy_config"]
        del self.upload_files[2]

        response = self._send_request()

        self._assert_response(response)

    def test_patch_redeploy_fails_with_online_subcloud(self):
        """Test patch redeploy fails with online subcloud"""

        self._update_subcloud(availability_status=dccommon_consts.AVAILABILITY_ONLINE)

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Cannot re-deploy an online and/or managed subcloud",
        )

    def test_patch_redeploy_fails_with_managed_subcloud(self):
        """Test patch redeploy fails with managed subcloud"""

        self._update_subcloud(management_state=dccommon_consts.MANAGEMENT_MANAGED)

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Cannot re-deploy an online and/or managed subcloud",
        )

    def test_patch_redeploy_fails_with_missing_property(self):
        """Test patch redeploy fails with missing property"""

        self.params = {
            **self.bootstrap_data,
            "sysadmin_password": self._create_password("sysadmin_password"),
            "bmc_password": self._create_password("bmc_password"),
        }

        for index, key in enumerate(self.bootstrap_data.keys(), start=1):
            del self.params[key]
            self.upload_files = [
                (
                    "bootstrap_values",
                    "bootstrap_fake_filename",
                    json.dumps(self.params).encode(),
                )
            ]

            response = self._send_request()

            if key == "name":
                error_msg = (
                    f"The bootstrap-values '{key}' value (None) must match the "
                    f"current subcloud name ({self.subcloud[key]})"
                )
            elif key == "sysadmin_password":
                error_msg = f"subcloud {key} required"
            else:
                error_msg = f"{key} required"

            self._assert_pecan_and_response(
                response, http.client.BAD_REQUEST, error_msg, index
            )

            self.params[key] = self.bootstrap_data[key]

    def test_patch_redeploy_fails_with_subcloud_in_secondary_state(self):
        """Test patch redeploy fails with subcloud in secondary state"""

        invalid_states = [
            consts.DEPLOY_STATE_SECONDARY,
            consts.DEPLOY_STATE_SECONDARY_FAILED,
        ]

        for index, state in enumerate(invalid_states, start=1):
            self._update_subcloud(deploy_status=state)

            response = self._send_request()

            self._assert_pecan_and_response(
                response,
                http.client.INTERNAL_SERVER_ERROR,
                f"Cannot perform on {self.subcloud.deploy_status} state subcloud",
                index,
            )

    def test_patch_redeploy_fails_with_rpc_client_remote_error(self):
        """Test patch redeploy fails with rpc client remote error"""

        self.mock_rpc_client().redeploy_subcloud.side_effect = RemoteError(
            "msg", "value"
        )

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.UNPROCESSABLE_ENTITY, "value"
        )

    def test_patch_redeploy_fails_with_rpc_client_generic_exception(self):
        """Test patch redeploy fails with rpc client generic exception"""

        self.mock_rpc_client().redeploy_subcloud.side_effect = Exception()

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.INTERNAL_SERVER_ERROR, "Unable to redeploy subcloud"
        )


class TestSubcloudsPatchPrestage(BaseTestSubcloudsPatch):
    """Test class for patch requests with prestage verb"""

    FAKE_SOFTWARE_LIST_ONE_DEPLOYED_RELEASE = [
        {"sw_version": "24.09.0", "state": "deployed"},
    ]

    FAKE_SOFTWARE_LIST_TWO_DEPLOYED_RELEASES = [
        {"sw_version": "24.09.0", "state": "deployed"},
        {"sw_version": "24.09.1", "state": "deployed"},
    ]

    FAKE_SOFTWARE_LIST_ONE_DEPLOYED_ONE_AVAILABLE_RELEASE = [
        {"sw_version": "24.09.0", "state": "deployed"},
        {"sw_version": "24.09.1", "state": "available"},
    ]

    FAKE_SOFTWARE_LIST_ONE_DEPLOYED_ONE_22_12_AVAILABLE_RELEASE = [
        {"sw_version": "24.09.0", "state": "deployed"},
        {"sw_version": "22.12.0", "state": "available"},
    ]

    def setUp(self):
        super().setUp()

        self.url = f"{self.url}/prestage"
        self.method = self.app.patch_json
        self.params = {"sysadmin_password": self._create_password("sysadmin_password")}
        self.versions_supported = ["22.12", "24.09"]
        self.prestage_msg = ""
        self.software_list = []

        self._update_subcloud(
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
        )

        self._mock_openstack_driver(prestage)
        self.mock_openstack_driver_prestage = self.mock_openstack_driver
        self._mock_sysinv_client(prestage)
        self.mock_sysinv_client_prestage = self.mock_sysinv_client
        self._setup_mock_sysinv_client_prestage()

        self._mock_openstack_driver(cutils)
        self.mock_openstack_driver_cutils = self.mock_openstack_driver
        self._mock_sysinv_client(cutils)
        self.mock_sysinv_client_cutils = self.mock_sysinv_client

        self._mock_software_client(cutils.software_v1)
        self.mock_software_client().show_deploy.return_value = None
        self.original_get_validated_sw_version_for_prestage = (
            cutils.get_validated_sw_version_for_prestage
        )
        self._mock_get_validated_sw_version_for_prestage(cutils)
        self._setup_mock_get_validated_sw_version_for_prestage()
        self._mock_get_current_supported_upgrade_versions(cutils)
        self._setup_mock_get_current_supported_upgrade_versions()
        self._mock_get_system_controller_software_list(cutils)
        self._setup_mock_get_system_controller_software_list()

    def _setup_mock_sysinv_client_prestage(self):
        mock_get_system = mock.MagicMock()
        mock_get_system.system_mode = consts.SYSTEM_MODE_SIMPLEX
        self.mock_sysinv_client_prestage().get_system.return_value = mock_get_system
        self.mock_sysinv_client_prestage().get_system_health.return_value = (
            health_report_no_alarm
        )

        mock_get_oam_addresses = mock.MagicMock()
        mock_get_oam_addresses.oam_floating_ip = "10.10.10.12"
        self.mock_sysinv_client_prestage().get_oam_addresses.return_value = (
            mock_get_oam_addresses
        )

    def _mock_get_validated_sw_version_for_prestage(self, target):
        mock_patch_object = mock.patch.object(
            target, "get_validated_sw_version_for_prestage"
        )
        self.mock_get_validated_sw_version_for_prestage = mock_patch_object.start()
        self.addCleanup(mock_patch_object.stop)

    def _mock_get_current_supported_upgrade_versions(self, target):
        mock_patch_object = mock.patch.object(
            target, "get_current_supported_upgrade_versions"
        )
        self.mock_get_current_supported_upgrade_versions = mock_patch_object.start()
        self.addCleanup(mock_patch_object.stop)

    def _mock_get_system_controller_software_list(self, target):
        mock_patch_object = mock.patch.object(
            target, "get_system_controller_software_list"
        )
        self.mock_get_system_controller_software_list = mock_patch_object.start()
        self.addCleanup(mock_patch_object.stop)

    def _setup_mock_get_validated_sw_version_for_prestage(self):
        if "release" not in self.params:
            self.params["release"] = "24.09"

        self.mock_get_validated_sw_version_for_prestage.return_value = (
            self.params["release"],
            self.prestage_msg,
        )

    def _setup_mock_get_current_supported_upgrade_versions(self):
        self.mock_get_current_supported_upgrade_versions.return_value = (
            self.versions_supported
        )

    def _setup_mock_get_system_controller_software_list(self):
        if len(self.software_list) == 0:
            self.software_list = self.FAKE_SOFTWARE_LIST_TWO_DEPLOYED_RELEASES

        self.mock_get_system_controller_software_list.return_value = self.software_list

    def _setup_mock_sysinv_client_prestage_get_host(self, personality):
        mock_get_host = mock.MagicMock()
        mock_get_host.capabilities = {"Personality": personality}
        self.mock_sysinv_client_prestage().get_host.return_value = mock_get_host

    def test_for_sw_deploy_prestage_succeeds(self):
        """Test for sw deploy prestage succeeds"""

        self.params["release"] = "24.09"
        self.params["for_sw_deploy"] = "true"

        response = self._send_request()

        self._assert_response(response)
        self.mock_rpc_client().prestage_subcloud.assert_called_once()

    def test_for_install_prestage_succeeds(self):
        """Test for install prestage succeeds"""

        self.params["release"] = "24.09"
        self.params["for_install"] = "true"

        response = self._send_request()

        self._assert_response(response)
        self.mock_rpc_client().prestage_subcloud.assert_called_once()

    def test_prestage_fails_with_invalid_release_format(self):
        """Test prestage fails with invalid release format"""

        self.params["release"] = "24.09.1"
        self.mock_get_validated_sw_version_for_prestage.side_effect = (
            self.original_get_validated_sw_version_for_prestage
        )

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"Prestage failed '{self.subcloud.name}': Specified release format "
            "is not supported. Version format must be MM.mm.",
        )

    def test_prestage_for_sw_deploy_fails_with_base_release_only_deployed(self):
        """Test prestage for sw deploy fails with base release only deployed"""

        self.params["for_sw_deploy"] = "true"
        self.mock_get_validated_sw_version_for_prestage.side_effect = (
            self.original_get_validated_sw_version_for_prestage
        )

        self.software_list = self.FAKE_SOFTWARE_LIST_ONE_DEPLOYED_RELEASE
        self._setup_mock_get_system_controller_software_list()

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"Prestage failed '{self.subcloud.name}': Only base release is deployed, "
            "cannot prestage for software deploy.",
        )

    def test_prestage_for_sw_deploy_fails_with_invalid_release(self):
        """Test prestage for sw deploy fails with invalid release"""

        self.params["release"] = "25.03"
        self.params["for_sw_deploy"] = "true"

        self.mock_get_validated_sw_version_for_prestage.side_effect = (
            self.original_get_validated_sw_version_for_prestage
        )

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"Prestage failed '{self.subcloud.name}': The requested software "
            "version was not installed in the system controller, cannot "
            "prestage for software deploy.",
        )

    def test_prestage_for_sw_deploy_fails_with_invalid_subcloud_release(self):
        """Test prestage for sw deploy fails with invalid subcloud release"""

        self.params["release"] = "24.09"
        self.params["for_sw_deploy"] = "true"

        mock_subcloud = mock.MagicMock()
        mock_subcloud.get.return_value = "22.12"

        self.mock_get_validated_sw_version_for_prestage.side_effect = (
            self.original_get_validated_sw_version_for_prestage
        )

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"Prestage failed '{self.subcloud.name}': The subcloud release version "
            "is different than that of the system controller, cannot prestage for "
            "software deploy.",
        )

    def test_prestage_for_sw_deploy_fails_with_22_12_release(self):
        """Test prestage for sw deploy fails with 22.12 release"""

        self.params["release"] = "22.12"
        self.params["for_sw_deploy"] = "true"

        self.mock_get_validated_sw_version_for_prestage.side_effect = (
            self.original_get_validated_sw_version_for_prestage
        )

        self.software_list = (
            self.FAKE_SOFTWARE_LIST_ONE_DEPLOYED_ONE_22_12_AVAILABLE_RELEASE
        )
        self._setup_mock_get_system_controller_software_list()

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"Prestage failed '{self.subcloud.name}': The requested software version "
            "is not supported, cannot prestage for software deploy.",
        )

    def test_patch_prestage_fails_with_unmanaged_subcloud(self):
        """Test patch prestage fails with unmanaged subcloud"""

        self._update_subcloud(management_state=dccommon_consts.MANAGEMENT_UNMANAGED)

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"Prestage skipped '{self.subcloud.name}': Subcloud is not managed.",
        )

    def test_patch_prestage_fails_with_offline_subcloud(self):
        """Test patch prestage fails with offline subcloud"""

        self._update_subcloud(availability_status=dccommon_consts.AVAILABILITY_OFFLINE)

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"Prestage skipped '{self.subcloud.name}': Subcloud is offline.",
        )

    def test_patch_prestage_fails_with_ongoing_backup(self):
        """Test patch prestage fails with ongoing backup"""

        self._update_subcloud(backup_status=consts.BACKUP_STATE_IN_PROGRESS)

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"Prestage skipped '{self.subcloud.name}': Prestage operation is not "
            "allowed while backup is in progress.",
        )

    def test_patch_prestage_fails_with_deploy_state_in_progress(self):
        """Test patch prestage fails with deploy state in progress"""

        self._update_subcloud(deploy_status=consts.DEPLOY_STATE_INSTALLING)

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"Prestage skipped '{self.subcloud.name}': Prestage operation is "
            "not allowed when subcloud deploy is in progress.",
        )

    def test_patch_prestage_fails_with_duplex_subcloud(self):
        """Test patch prestage fails with duplex subcloud"""

        mock_get_system = mock.MagicMock()
        mock_get_system.system_mode = consts.SYSTEM_MODE_DUPLEX
        self.mock_sysinv_client_prestage().get_system.return_value = mock_get_system
        self.params["for_install"] = "true"
        self._setup_mock_sysinv_client_prestage_get_host("Controller-Standby")

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"Prestage skipped '{self.subcloud.name}': Prestage for install on "
            "duplex subclouds is only allowed when controller-0 is active.",
        )

    def test_prestage_for_sw_deploy_with_duplex_subcloud(self):
        """Test patch prestage success for-sw-deploy with duplex subcloud"""

        mock_get_system = mock.MagicMock()
        mock_get_system.system_mode = consts.SYSTEM_MODE_DUPLEX
        self.mock_sysinv_client_prestage().get_system.return_value = mock_get_system

        self.params["for_sw_deploy"] = "true"
        self._setup_mock_sysinv_client_prestage_get_host("Controller-Active")

        response = self._send_request()

        self._assert_response(response)
        self.mock_rpc_client().prestage_subcloud.assert_called_once()

    def test_prestage_for_install_with_duplex_subcloud(self):
        """Test patch prestage success for-install with duplex subcloud"""

        mock_get_system = mock.MagicMock()
        mock_get_system.system_mode = consts.SYSTEM_MODE_DUPLEX
        self.mock_sysinv_client_prestage().get_system.return_value = mock_get_system

        self._setup_mock_sysinv_client_prestage_get_host("Controller-Active")
        self.params["for_install"] = "true"

        response = self._send_request()

        self._assert_response(response)
        self.mock_rpc_client().prestage_subcloud.assert_called_once()

    def test_patch_prestage_succeds_without_mgmt_alarm(self):
        """Test patch prestage succeeds without management alarm"""

        self.mock_sysinv_client_prestage().get_system_health.return_value = (
            health_report_no_mgmt_alarm
        )

        response = self._send_request()

        self._assert_response(response)
        self.mock_rpc_client().prestage_subcloud.assert_called_once()

    def test_patch_prestage_fails_with_mgmt_alarm(self):
        """Test patch prestage fails with management alarm"""

        self.mock_sysinv_client_prestage().get_system_health.return_value = (
            health_report_mgmt_alarm
        )

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"Prestage failed '{self.subcloud.name}': Subcloud has management "
            "affecting alarm(s). Please resolve the alarm condition(s) or use "
            "--force option and try again.",
        )

    def test_patch_prestage_succeeds_with_mgmt_alarm_when_forced(self):
        """Test patch prestage succeeds with management alarm when forced"""

        self.params["force"] = "True"

        self.mock_sysinv_client_prestage().get_system_health.return_value = (
            health_report_mgmt_alarm
        )

        response = self._send_request()

        self._assert_response(response)
        self.mock_rpc_client().prestage_subcloud.assert_called_once()

    def test_patch_prestage_fails_with_invalid_force(self):
        """Test patch prestage fails with invalid force"""

        self.params["force"] = "invalid"

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"Invalid value for force option: {self.params['force']}",
        )

    def test_patch_prestage_fails_with_system_controller_software_deploy(self):
        """Test patch prestage fails when system controller has a deploy in-progress"""

        self.mock_software_client().show_deploy.return_value = [
            {"to_release": "24.09.0"}
        ]

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Prestage failed 'SystemController': Prestage operations are not "
            "allowed while system controller has a software deployment in progress.",
        )

    def test_patch_prestage_fails_without_payload(self):
        """Test patch prestage fails without payload"""

        self.params = {}

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "sysadmin_password is required."
        )

    def test_patch_prestage_fails_without_encoded_sysadmin_password(self):
        """Test patch prestage fails without encoded sysadmin password"""

        self.params["sysadmin_password"] = "sysadmin_password"

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Failed to decode subcloud sysadmin_password, "
            "verify the password is base64 encoded",
        )

    @mock.patch.object(json, "loads")
    def test_patch_prestage_fails_with_json_loads_generic_exception(self, mock_json):
        """Test patch prestage fails with json.loads generic exception"""

        mock_json.side_effect = Exception()

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Request body is malformed."
        )

    def test_patch_prestage_succeeds_with_invalid_parameter(self):
        """Test patch prestage succeeds with invalid parameter"""

        self.params["key"] = "value"

        response = self._send_request()

        self._assert_response(response)
        self.mock_rpc_client().prestage_subcloud.assert_called_once()

    def test_patch_prestage_fails_with_subcloud_in_secondary_state(self):
        """Test patch prestage fails with subcloud in secondary state"""

        invalid_states = [
            consts.DEPLOY_STATE_SECONDARY,
            consts.DEPLOY_STATE_SECONDARY_FAILED,
        ]

        for index, state in enumerate(invalid_states, start=1):
            self._update_subcloud(deploy_status=state)

            response = self._send_request()

            self._assert_pecan_and_response(
                response,
                http.client.INTERNAL_SERVER_ERROR,
                f"Cannot perform on {self.subcloud.deploy_status} state subcloud",
                index,
            )

    def test_patch_prestage_fails_with_rpc_client_remote_error(self):
        """Test patch prestage fails with rpc client remote error"""

        self.mock_rpc_client().prestage_subcloud.side_effect = RemoteError(
            "msg", "value"
        )

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.UNPROCESSABLE_ENTITY, "value"
        )

    def test_patch_prestage_fails_with_rpc_client_generic_exception(self):
        """Test patch prestage fails with rpc client generic exception"""

        self.mock_rpc_client().prestage_subcloud.side_effect = Exception()

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.INTERNAL_SERVER_ERROR, "Unable to prestage subcloud"
        )


class TestSubcloudsDelete(BaseTestSubcloudsController):
    """Test class for delete requests"""

    def setUp(self):
        super().setUp()

        self.subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        self.url = f"{self.url}/{self.subcloud.id}"
        self.method = self.app.delete

        self.mock_rpc_client().delete_subcloud.return_value = (
            "delete_subcloud",
            {"subcloud_id": self.subcloud.id},
        )

    def test_delete_succeeds(self):
        """Test delete succeeds"""

        response = self._send_request()

        self._assert_response(response)
        self.mock_rpc_client().delete_subcloud.assert_called_once()

    def test_delete_fails_with_inexistent_subcloud(self):
        """Test delete fails with inexistent subcloud"""

        self.url = f"{self.API_PREFIX}/999"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.NOT_FOUND, "Subcloud not found"
        )

    def test_delete_succeeds_with_subcloud_name(self):
        """Test delete succeeds with subcloud name"""

        self.url = f"{self.API_PREFIX}/{self.subcloud.name}"

        response = self._send_request()

        self._assert_response(response)
        self.mock_rpc_client().delete_subcloud.assert_called_once()

    def test_delete_fails_with_inexistent_subcloud_name(self):
        """Test delete fails with inexistent subcloud name"""

        self.url = f"{self.API_PREFIX}/fake"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.NOT_FOUND, "Subcloud not found"
        )

    def test_delete_fails_with_managed_subcloud(self):
        """Test delete fails with managed subcloud"""

        self._update_subcloud(management_state=dccommon_consts.MANAGEMENT_MANAGED)

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Cannot delete a subcloud that is 'managed' status",
        )

    def test_delete_fails_with_invalid_deploy_states(self):
        """Test delete fails with invalid deploy states"""

        for index, state in enumerate(consts.INVALID_DEPLOY_STATES_FOR_DELETE, start=1):
            self._update_subcloud(deploy_status=state)

            response = self._send_request()

            self._assert_pecan_and_response(
                response,
                http.client.BAD_REQUEST,
                "Cannot delete a subcloud during an active operation.",
                call_count=index,
            )

    def test_delete_fails_with_subcloud_in_peer_group(self):
        """Test delete fails with subcloud in peer group"""

        system_peer_manager = test_system_peer_manager.TestSystemPeerManager
        peer_group = system_peer_manager.create_subcloud_peer_group_static(self.ctx)
        self._update_subcloud(peer_group_id=peer_group.id)

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Cannot delete a subcloud that is part of a peer group on this site",
        )

    def test_delete_fails_with_rpc_client_remote_error(self):
        """Test delete fails with rpc client remote error"""

        self.mock_rpc_client().delete_subcloud.side_effect = RemoteError("msg", "value")

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.UNPROCESSABLE_ENTITY, "value"
        )

    def test_delete_fails_with_rpc_client_generic_exception(self):
        """Test delete fails with rpc client generic exception"""

        self.mock_rpc_client().delete_subcloud.side_effect = Exception()

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.INTERNAL_SERVER_ERROR, "Unable to delete subcloud"
        )
