# Copyright (c) 2023-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import http.client
import json

import mock
from oslo_messaging import RemoteError

from dcmanager.api.controllers.v1 import system_peers
from dcmanager.common import consts
from dcmanager.db import api as db_api
from dcmanager.rpc import client as rpc_client
from dcmanager.tests.unit.api.controllers.v1.mixins import APIMixin
from dcmanager.tests.unit.api.controllers.v1.mixins import DeleteMixin
from dcmanager.tests.unit.api.controllers.v1.mixins import GetMixin
from dcmanager.tests.unit.api.controllers.v1.mixins import PostJSONMixin
from dcmanager.tests.unit.api.controllers.v1.mixins import UpdateMixin
from dcmanager.tests.unit.api.test_root_controller import DCManagerApiTest
from dcmanager.tests.unit.common import fake_subcloud


class SystemPeersAPIMixin(APIMixin):
    API_PREFIX = "/v1.0/system-peers"
    RESULT_KEY = "system_peers"
    EXPECTED_FIELDS = [
        "id",
        "peer-uuid",
        "peer-name",
        "manager-endpoint",
        "manager-username",
        "peer-controller-gateway-address",
        "administrative-state",
        "heartbeat-interval",
        "heartbeat-failure-threshold",
        "heartbeat-failure-policy",
        "heartbeat-maintenance-timeout",
        "created-at",
        "updated-at",
    ]

    def _post_get_test_system_peer(self, **kw):
        return fake_subcloud.get_test_system_peer_dict("dict", **kw)

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
        creation_fields = fake_subcloud.get_test_system_peer_dict("db", **kw)
        return db_api.system_peer_create(context, **creation_fields)

    def get_post_object(self):
        return self._post_get_test_system_peer()

    def get_update_object(self):
        return {"peer_controller_gateway_address": "192.168.205.1"}


class SystemPeersPropertiesValidationMixin(object):
    """Specifies common test cases to validate payload properties in requests"""

    def _remove_empty_string_in_patch_request(self, invalid_values):
        """Removes the empty string in patch requests

        When the request method is patch, the properties can be sent as empty string
        values, which does not happen in post requests. Because of that, it's
        necessary to remove it from the validated values.
        """

        if self.method == self.app.patch_json:
            invalid_values.remove("")

    def test_request_fails_without_payload(self):
        """Test request fails without payload"""

        self.params = {}

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Body required"
        )

    @mock.patch.object(json, "loads")
    def test_request_fails_with_json_loads_exception(self, mock_json_loads):
        """Test request fails with json loads exception"""

        mock_json_loads.side_effect = Exception()

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Request body is malformed."
        )
        mock_json_loads.assert_called_once()

    def test_request_fails_with_invalid_payload(self):
        """Test request fails with invalid payload"""

        self.params = "invalid"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Invalid request body format"
        )

    def test_request_fails_with_invalid_uuid(self):
        """Test request fails with invalid uuid

        A numerical uuid is not permitted. Otherwise, the 'get' operation which
        supports getting a system peer by either name or ID could become confusing
        if the name for a peer was the same as the ID for another.
        """

        invalid_values = ["", "999"]
        self._remove_empty_string_in_patch_request(invalid_values)

        for index, invalid_value in enumerate(invalid_values, start=1):
            self.params["peer_uuid"] = invalid_value

            response = self._send_request()

            self._assert_pecan_and_response(
                response, http.client.BAD_REQUEST, "Invalid peer uuid", index
            )

    def test_request_fails_with_invalid_name(self):
        """Test request fails with invalid name"""

        invalid_values = ["", "999", "a" * 256, ".*+?|()[]{}^$"]
        self._remove_empty_string_in_patch_request(invalid_values)

        for index, invalid_value in enumerate(invalid_values, start=1):
            self.params["peer_name"] = invalid_value

            response = self._send_request()

            self._assert_pecan_and_response(
                response, http.client.BAD_REQUEST, "Invalid peer name", index
            )

    def test_request_fails_with_invalid_manager_endpoint(self):
        """Test request fails with invalid manager endpoint"""

        invalid_values = [
            "",
            "ftp://somepath",
            "a" * system_peers.MAX_SYSTEM_PEER_MANAGER_ENDPOINT_LEN,
        ]
        self._remove_empty_string_in_patch_request(invalid_values)

        for index, invalid_value in enumerate(invalid_values, start=1):
            self.params["manager_endpoint"] = invalid_value

            response = self._send_request()

            self._assert_pecan_and_response(
                response,
                http.client.BAD_REQUEST,
                "Invalid peer manager_endpoint",
                call_count=index,
            )

    def test_request_fails_with_invalid_manager_username(self):
        """Test request fails with invalid manager username"""

        invalid_values = ["", "a" * system_peers.MAX_SYSTEM_PEER_MANAGER_USERNAME_LEN]
        self._remove_empty_string_in_patch_request(invalid_values)

        for index, invalid_value in enumerate(invalid_values, start=1):
            self.params["manager_username"] = invalid_value

            response = self._send_request()

            self._assert_pecan_and_response(
                response,
                http.client.BAD_REQUEST,
                "Invalid peer manager_username",
                call_count=index,
            )

    def test_request_fails_with_invalid_manager_password(self):
        """Test request fails with invalid manager password"""

        invalid_values = ["", "a" * system_peers.MAX_SYSTEM_PEER_MANAGER_PASSWORD_LEN]
        self._remove_empty_string_in_patch_request(invalid_values)

        for index, invalid_value in enumerate(invalid_values, start=1):
            self.params["manager_password"] = invalid_value

            response = self._send_request()

            self._assert_pecan_and_response(
                response,
                http.client.BAD_REQUEST,
                "Invalid peer manager_password",
                call_count=index,
            )

    def test_request_fails_with_invalid_peer_controller_gateway_address(self):
        """Test request fails with invalid peer controller gateway address"""

        invalid_values = [
            "",
            "a" * system_peers.MAX_SYSTEM_PEER_STRING_DEFAULT_LEN,
            "192.168.0.0.1",
        ]
        self._remove_empty_string_in_patch_request(invalid_values)

        for index, invalid_value in enumerate(invalid_values, start=1):
            self.params["peer_controller_gateway_address"] = invalid_value

            response = self._send_request()

            self._assert_pecan_and_response(
                response,
                http.client.BAD_REQUEST,
                "Invalid peer peer_controller_gateway_address",
                call_count=index,
            )

    def test_request_fails_with_invalid_administrative_state(self):
        """Test request fails with invalid administrative state

        The administrative state must be either enabled or disabled.
        """

        self.params["administrative_state"] = "fake"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Invalid peer administrative_state"
        )

    def test_request_fails_with_invalid_heartbeat_interval(self):
        """Test request fails with invalid heartbeat interval

        The heartbeat interval must be between 1 and 600.
        """

        invalid_values = [
            system_peers.MIN_SYSTEM_PEER_HEARTBEAT_INTERVAL - 1,
            system_peers.MAX_SYSTEM_PEER_HEARTBEAT_INTERVAL + 1,
            -1,
            "fake",
        ]

        for index, invalid_value in enumerate(invalid_values, start=1):
            self.params["heartbeat_interval"] = invalid_value

            response = self._send_request()

            self._assert_pecan_and_response(
                response,
                http.client.BAD_REQUEST,
                "Invalid peer heartbeat_interval",
                call_count=index,
            )

    def test_request_fails_with_invalid_heartbeat_failure_threshold(self):
        """Test request fails with invalid heartbeat failure threshold"""

        invalid_values = [
            system_peers.MIN_SYSTEM_PEER_HEARTBEAT_FAILURE_THRESHOLD - 1,
            system_peers.MAX_SYSTEM_PEER_HEARTBEAT_FAILURE_THRESHOLD + 1,
            -1,
            "fake",
        ]

        # When the request method is patch, the invalid_value 0 results in the if
        # condition returning false as if a value was not sent. Because of that,
        # it needs to be removed from the validation.
        if self.method == self.app.patch_json:
            invalid_values.remove(
                system_peers.MIN_SYSTEM_PEER_HEARTBEAT_FAILURE_THRESHOLD - 1
            )

        for index, invalid_value in enumerate(invalid_values, start=1):
            self.params["heartbeat_failure_threshold"] = invalid_value

            response = self._send_request()

            self._assert_pecan_and_response(
                response,
                http.client.BAD_REQUEST,
                "Invalid peer heartbeat_failure_threshold",
                call_count=index,
            )

    def test_request_fails_with_invalid_heartbeat_failure_policy(self):
        """Test request fails with invalid heartbeat failure policy

        The heartbeat failure policy must be either alarm, rehome or delegate.
        """

        self.params["heartbeat_failure_policy"] = "fake"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Invalid peer heartbeat_failure_policy"
        )

    def test_request_fails_with_invalid_heartbeat_maintenance_timeout(self):
        """Test request fails with invalid heartbeat maintenance timeout"""

        invalid_values = [
            system_peers.MIN_SYSTEM_PEER_HEARTBEAT_MAINTENACE_TIMEOUT - 1,
            system_peers.MAX_SYSTEM_PEER_HEARTBEAT_MAINTENACE_TIMEOUT + 1,
            -1,
            "fake",
        ]

        for index, invalid_value in enumerate(invalid_values, start=1):
            self.params["heartbeat_maintenance_timeout"] = invalid_value

            response = self._send_request()

            self._assert_pecan_and_response(
                response,
                http.client.BAD_REQUEST,
                "Invalid peer heartbeat_maintenance_timeout",
                call_count=index,
            )


class BaseTestSystemPeersController(DCManagerApiTest, SystemPeersAPIMixin):
    """Base class for testing the SystemPeersController"""

    def setUp(self):
        super().setUp()

        self.url = "/v1.0/system-peers"
        self._mock_object(rpc_client, "ManagerClient")


class TestSystemPeersController(BaseTestSystemPeersController):
    """Test class for SystemPeersController"""

    def setUp(self):
        super().setUp()

    def test_unmapped_method(self):
        """Test requesting an unmapped method results in success with null content"""

        self.method = self.app.put

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(response.text, "null")


class TestSystemPeersGet(BaseTestSystemPeersController, GetMixin):
    """Test class for get requests"""

    def setUp(self):
        super().setUp()

        self.method = self.app.get

        # TODO(rlima): update the GetMixin to create the object in setUp rather
        # than in the test case and update this class. This should be done in
        # all of the classes

    def _assert_response_content(self, response):
        """Assert the response content from get requests

        The database returned values use _ while the returned dict from the API
        response return values with -.
        """

        for key, value in self.system_peer.items():
            key = key.replace("_", "-")

            if key == "created-at" or key == "updated-at" or "deleted-at":
                continue

            self.assertEqual(response.json[key], value)

    def test_get_succeeds_by_id(self):
        """Test get succeeds by id"""

        self.system_peer = self._create_db_object(self.ctx)

        self.url = f"{self.url}/{self.system_peer.id}"

        response = self._send_request()

        self._assert_response(response)
        self._assert_response_content(response)

    def test_get_succeeds_by_name(self):
        """Test get succeeds by name"""

        self.system_peer = self._create_db_object(self.ctx)

        self.url = f"{self.url}/{self.system_peer.peer_name}"

        response = self._send_request()

        self._assert_response(response)
        self._assert_response_content(response)

    def test_get_succeeds_with_subcloud_peer_groups(self):
        """Test get succeeds with subcloud peer groups"""

        self.system_peer = self._create_db_object(self.ctx)

        self.url = f"{self.url}/{self.system_peer.peer_name}/True"

        response = self._send_request()

        self._assert_response(response)
        self.assertIn("subcloud_peer_groups", response.json)
        self.assertEqual(response.json["subcloud_peer_groups"], [])


class TestSystemPeersPost(
    BaseTestSystemPeersController, SystemPeersPropertiesValidationMixin, PostJSONMixin
):
    """Test class for post requests"""

    def setUp(self):
        super().setUp()

        self.method = self.app.post_json
        self.params = self.get_post_object()

    def test_post_fails_with_db_api_duplicate_entry_exception(self):
        """Test post fails with db api duplicate entry exception"""

        response = self._send_request()

        self._assert_response(response)

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.CONFLICT,
            "A system peer with this UUID already exists",
        )

    @mock.patch.object(db_api, "system_peer_create")
    def test_post_fails_with_db_api_remote_error(self, mock_db_api):
        """Test post fails with db api remote error"""

        mock_db_api.side_effect = RemoteError("msg", "value")

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.UNPROCESSABLE_ENTITY, "value"
        )

    @mock.patch.object(db_api, "system_peer_create")
    def test_post_fails_with_db_api_generic_exception(self, mock_db_api):
        """Test post fails with db api generic exception"""

        mock_db_api.side_effect = Exception()

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.INTERNAL_SERVER_ERROR, "Unable to create system peer"
        )


class BaseTestSystemPeersPatch(BaseTestSystemPeersController):
    """Base test class for patch requests"""

    def setUp(self):
        super().setUp()

        self.method = self.app.patch_json
        self.params = self.get_post_object()


class TestSystemPeersPatchPropertiesValidation(
    BaseTestSystemPeersPatch, SystemPeersPropertiesValidationMixin
):
    """Test class for validating the payload properties in patch requests"""

    def setUp(self):
        super().setUp()

        self.system_peer = self._create_db_object(self.ctx)
        self.url = f"{self.url}/{self.system_peer.peer_uuid}"


class TestSystemPeersPatch(BaseTestSystemPeersPatch, UpdateMixin):
    """Test class for patch requests"""

    def setUp(self):
        super().setUp()

    # Overrides validate_updated_fields from UpdateMixin
    def validate_updated_fields(self, sub_dict, full_obj):
        for key, value in sub_dict.items():
            key = key.replace("_", "-")
            self.assertEqual(value, full_obj.get(key))

    def test_patch_fails_with_inexistent_system_peer(self):
        """Test patch fails with inexistent system peer"""

        self.url = f"{self.url}/9999"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.NOT_FOUND, "System Peer not found"
        )

    def test_patch_fails_without_properties_to_update(self):
        """Test patch fails without properties to update"""

        system_peer = self._create_db_object(self.ctx)

        self.url = f"{self.url}/{system_peer.peer_uuid}"
        self.params = {"key": "value"}

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "nothing to update"
        )

    @mock.patch.object(db_api, "system_peer_update")
    def test_patch_fails_with_db_api_remote_error(self, mock_db_api):
        """Test patch fails with db api remote error"""

        system_peer = self._create_db_object(self.ctx)

        self.url = f"{self.url}/{system_peer.peer_uuid}"

        mock_db_api.side_effect = RemoteError("msg", "value")

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.UNPROCESSABLE_ENTITY, "value"
        )

    @mock.patch.object(db_api, "system_peer_update")
    def test_patch_fails_with_db_api_generic_exception(self, mock_db_api):
        """Test patch fails with db api generic exception"""

        system_peer = self._create_db_object(self.ctx)

        self.url = f"{self.url}/{system_peer.peer_uuid}"

        mock_db_api.side_effect = Exception()

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.INTERNAL_SERVER_ERROR, "Unable to update system peer"
        )


class TestSystemPeersDelete(BaseTestSystemPeersController, DeleteMixin):
    """Test class for delete requests"""

    def setUp(self):
        super().setUp()

        self.method = self.app.delete

    def test_delete_succeeds_by_id(self):
        """Test delete succeeds by id"""

        system_peer = self._create_db_object(self.ctx)

        self.url = f"{self.url}/{system_peer.peer_uuid}"

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(len(db_api.system_peer_get_all(self.ctx)), 0)

    def test_delete_succeeds_by_name(self):
        """Test delete succeeds by name"""

        system_peer = self._create_db_object(self.ctx)

        self.url = f"{self.url}/{system_peer.peer_name}"

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(len(db_api.system_peer_get_all(self.ctx)), 0)

    def test_delete_fails_with_existing_association(self):
        """Test delete fails with existing association"""

        system_peer = self._create_db_object(self.ctx)
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.peer_group_association_create(
            self.ctx,
            subcloud.peer_group_id,
            system_peer.id,
            consts.PEER_GROUP_PRIMARY_PRIORITY,
            consts.ASSOCIATION_TYPE_PRIMARY,
            consts.ASSOCIATION_SYNC_STATUS_IN_SYNC,
            "None",
        )

        self.url = f"{self.url}/{system_peer.peer_uuid}"

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Cannot delete a system peer which is associated with peer group.",
        )

    @mock.patch.object(db_api, "system_peer_destroy")
    def test_delete_fails_with_db_api_remote_error(self, mock_db_api):
        """Test delete fails with db api remote error"""

        system_peer = self._create_db_object(self.ctx)

        self.url = f"{self.url}/{system_peer.peer_uuid}"

        mock_db_api.side_effect = RemoteError("msg", "value")

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.UNPROCESSABLE_ENTITY, "value"
        )

    @mock.patch.object(db_api, "system_peer_destroy")
    def test_delete_fails_with_db_api_generic_exception(self, mock_db_api):
        """Test delete fails with db api generic exception"""

        system_peer = self._create_db_object(self.ctx)

        self.url = f"{self.url}/{system_peer.peer_uuid}"

        mock_db_api.side_effect = Exception()

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.INTERNAL_SERVER_ERROR, "Unable to delete system peer"
        )
