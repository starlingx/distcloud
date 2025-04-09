# Copyright (c) 2023-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import http.client

import mock
from oslo_db import exception as db_exc
from oslo_messaging import RemoteError

from dccommon import consts as dccommon_consts
from dcmanager.api.controllers.v1 import subcloud_peer_group
from dcmanager.common import consts
from dcmanager.db import api as db_api
from dcmanager.rpc import client as rpc_client
from dcmanager.tests.base import FakeException
from dcmanager.tests.unit.api.controllers.v1.mixins import APIMixin
from dcmanager.tests.unit.api.controllers.v1.mixins import PostJSONMixin
from dcmanager.tests.unit.api.test_root_controller import DCManagerApiTest
from dcmanager.tests.unit.common import fake_subcloud

SAMPLE_SUBCLOUD_PEER_GROUP_NAME = "GroupX"
SAMPLE_SUBCLOUD_PEER_GROUP_MAX_SUBCLOUDS_REHOMING = 50
SAMPLE_SUBCLOUD_PEER_GROUP_STATE = "enabled"
SAMPLE_SUBCLOUD_PEER_GROUP_PIRORITY = 0
FAKE_UUID = "62c9592d-f799-4db9-8d40-6786a74d6021"
FAKE_SUBCLOUD_DATA = fake_subcloud.FAKE_SUBCLOUD_DATA

API_PREFIX = "/v1.0/subcloud-peer-groups"
RESULT_KEY = "subcloud_peer_groups"
EXPECTED_FIELDS = [
    "id",
    "peer_group_name",
    "group_priority",
    "group_state",
    "max_subcloud_rehoming",
    "system_leader_id",
    "system_leader_name",
    "created-at",
    "updated-at",
]


class SubcloudPeerGroupAPIMixin(APIMixin):
    def validate_entry(self, result_item):
        self.assert_fields(result_item)

    def setUp(self):
        super().setUp()

    def _get_test_subcloud_peer_group_request(self, **kw):
        # id should not be part of the structure
        group = {
            "peer-group-name": kw.get(
                "peer_group_name", SAMPLE_SUBCLOUD_PEER_GROUP_NAME
            ),
            "system-leader-id": kw.get("system_leader_id", FAKE_UUID),
            "system-leader-name": kw.get("system_leader_name", "dc-test"),
            "group-priority": kw.get("group_priority", "0"),
            "group-state": kw.get("group_state", "enabled"),
            "max-subcloud-rehoming": kw.get(
                "max_subcloud_rehoming",
                SAMPLE_SUBCLOUD_PEER_GROUP_MAX_SUBCLOUDS_REHOMING,
            ),
        }
        return group

    def _get_test_subcloud_peer_group_dict(self, **kw):
        # id should not be part of the structure
        group = {
            "peer_group_name": kw.get(
                "peer_group_name", SAMPLE_SUBCLOUD_PEER_GROUP_NAME
            ),
            "system_leader_id": kw.get("system_leader_id", FAKE_UUID),
            "system_leader_name": kw.get("system_leader_name", "dc-test"),
            "group_priority": kw.get("group_priority", "0"),
            "group_state": kw.get("group_state", SAMPLE_SUBCLOUD_PEER_GROUP_STATE),
            "max_subcloud_rehoming": kw.get(
                "max_subcloud_rehoming",
                SAMPLE_SUBCLOUD_PEER_GROUP_MAX_SUBCLOUDS_REHOMING,
            ),
            "migration_status": None,
        }
        return group

    def _post_get_test_subcloud_peer_group(self, **kw):
        post_body = self._get_test_subcloud_peer_group_request(**kw)
        return post_body

    # The following methods are required for subclasses of APIMixin
    def get_api_prefix(self):
        return API_PREFIX

    def get_result_key(self):
        return RESULT_KEY

    def get_expected_api_fields(self):
        return EXPECTED_FIELDS

    def get_omitted_api_fields(self):
        return []

    def _create_db_object(self, context, **kw):
        creation_fields = self._get_test_subcloud_peer_group_dict(**kw)
        return db_api.subcloud_peer_group_create(context, **creation_fields)

    def get_post_object(self):
        return self._post_get_test_subcloud_peer_group()

    def get_update_object(self):
        update_object = {"system_leader_name": "Updated system_leader_name"}
        return update_object

    def _create_subcloud_db_object(self, context):
        creation_fields = {
            "name": FAKE_SUBCLOUD_DATA.get("name"),
            "description": FAKE_SUBCLOUD_DATA.get("description"),
            "location": FAKE_SUBCLOUD_DATA.get("location"),
            "software_version": FAKE_SUBCLOUD_DATA.get("software_version"),
            "management_subnet": FAKE_SUBCLOUD_DATA.get("management_subnet"),
            "management_gateway_ip": FAKE_SUBCLOUD_DATA.get("management_gateway_ip"),
            "management_start_ip": FAKE_SUBCLOUD_DATA.get("management_start_ip"),
            "management_end_ip": FAKE_SUBCLOUD_DATA.get("management_end_ip"),
            "systemcontroller_gateway_ip": FAKE_SUBCLOUD_DATA.get(
                "systemcontroller_gateway_ip"
            ),
            "external_oam_subnet_ip_family": FAKE_SUBCLOUD_DATA.get(
                "external_oam_subnet_ip_family"
            ),
            "deploy_status": FAKE_SUBCLOUD_DATA.get("deploy_status"),
            "error_description": FAKE_SUBCLOUD_DATA.get("error_description"),
            "openstack_installed": FAKE_SUBCLOUD_DATA.get("openstack_installed"),
            "group_id": FAKE_SUBCLOUD_DATA.get("group_id", 1),
            "region_name": FAKE_SUBCLOUD_DATA.get("region_name", "RegionOne"),
        }
        return db_api.subcloud_create(context, **creation_fields)

    def _update_subcloud_peer_group_id(self, ctx, subcloud, pg_id):
        return db_api.subcloud_update(ctx, subcloud.id, peer_group_id=pg_id)


class BaseTestSubcloudPeerGroupController(DCManagerApiTest, SubcloudPeerGroupAPIMixin):
    """Base class for testing SubcloudPeerGroupController"""

    def setUp(self):
        super().setUp()

        self.url = API_PREFIX

        self.mock_rpc_client = self._mock_object(rpc_client, "ManagerClient")
        self._mock_object(subcloud_peer_group, "OpenStackDriver")
        self.mock_sysinv_client = self._mock_object(subcloud_peer_group, "SysinvClient")

    def _create_subcloud(self):
        if not hasattr(self, "peer_group"):
            self.peer_group = self._create_db_object(self.ctx)

        self.subcloud = self._create_subcloud_db_object(self.ctx)
        self.subcloud = self._update_subcloud_peer_group_id(
            self.ctx, self.subcloud, self.peer_group.id
        )


class TestSubcloudPeerGroupController(BaseTestSubcloudPeerGroupController):
    """Test class for SubcloudPeerGroupController"""

    def setUp(self):
        super().setUp()

    def test_unmapped_method(self):
        """Test requesting an unmapped method results in success with null content"""

        self.method = self.app.put

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(response.text, "null")


class TestSubcloudPeerGroupControllerPost(
    BaseTestSubcloudPeerGroupController, PostJSONMixin
):
    """Test class for post requests"""

    def setUp(self):
        super().setUp()

        self.method = self.app.post_json
        self.params = self.get_post_object()

    def _validate_peer_group_creation(self, key=None, value=None):
        subcloud_peer_groups = db_api.subcloud_peer_group_get_all(self.ctx)
        self.assertEqual(len(subcloud_peer_groups), 1)

        if key is not None:
            self.assertEqual(subcloud_peer_groups[0][key], value)

    def test_post_succeeds_without_system_leader_id(self):
        """Test post succeeds without system leader id"""

        self.mock_sysinv_client().get_system.return_value.uuid = FAKE_UUID

        self.params.pop("system-leader-id")

        response = self._send_request()
        self._assert_response(response)
        self._validate_peer_group_creation("system_leader_id", FAKE_UUID)

    def test_post_succeeds_without_system_leader_name(self):
        """Test post succeeds without system leader name"""

        self.mock_sysinv_client().get_system.return_value.name = "fake name"

        self.params.pop("system-leader-name")

        response = self._send_request()
        self._assert_response(response)
        self._validate_peer_group_creation("system_leader_name", "fake name")

    def test_post_succeeds_without_group_priority_and_group_state(self):
        """Test post succeeds without group priority and group state"""

        self.params.pop("group-priority")
        self.params.pop("group-state")

        response = self._send_request()
        self._assert_response(response)
        self._validate_peer_group_creation()

    def test_post_succeeds_without_max_subcloud_rehoming(self):
        """Test post succeeds without max subcloud rehoming"""

        self.params.pop("max-subcloud-rehoming")

        response = self._send_request()
        self._assert_response(response)
        self._validate_peer_group_creation()

    def test_post_fails_with_empty_body(self):
        """Ensures an empty body returns a bad request"""

        self.params = None

        response = self._send_request()
        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Body required"
        )

    def test_post_fails_with_invalid_peer_group_name(self):
        """Test post fails with invalid peer group name

        A numerical name is not permitted. otherwise the 'get' operations
        which support getting by either name or ID could be confusing
        if the name for a group was the same as an ID for another.
        Additionally, 'none' is not permitted since it is a special word to
        clean a peer-group-id from subcloud.
        """

        invalid_values = [
            "123",
            "none",
            "",
            "a" * (subcloud_peer_group.MAX_SUBCLOUD_PEER_GROUP_NAME_LEN + 1),
        ]

        for index, invalid_value in enumerate(invalid_values, start=1):
            self.params["peer-group-name"] = invalid_value

            response = self._send_request()

            self._assert_pecan_and_response(
                response,
                http.client.BAD_REQUEST,
                "Invalid peer-group-name",
                call_count=index,
            )

    def test_post_fails_with_invalid_system_leader_id(self):
        """Test post fails with invalid system leader id"""

        self.params["system-leader-id"] = "invalid string"

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f'Invalid system-leader-id [{self.params["system-leader-id"]}]',
        )

    def test_post_fails_with_invalid_system_leader_name(self):
        """Test post fails with invalid system leader name"""

        invalid_values = [
            "123",
            "a" * (subcloud_peer_group.MAX_SUBCLOUD_PEER_GROUP_NAME_LEN + 1),
        ]

        for index, invalid_value in enumerate(invalid_values, start=1):
            self.params["system-leader-name"] = invalid_value

            response = self._send_request()

            self._assert_pecan_and_response(
                response,
                http.client.BAD_REQUEST,
                "Invalid system-leader-name",
                call_count=index,
            )

    def test_post_fails_with_invalid_group_priority(self):
        """Test post fails with invalid group priority"""

        invalid_values = [
            "fake string",
            subcloud_peer_group.MIN_SUBCLOUD_PEER_GROUP_PRIORITY - 1,
            subcloud_peer_group.MAX_SUBCLOUD_PEER_GROUP_PRIORITY + 1,
        ]

        for index, invalid_value in enumerate(invalid_values, start=1):
            self.params["group-priority"] = invalid_value

            response = self._send_request()

            self._assert_pecan_and_response(
                response,
                http.client.BAD_REQUEST,
                "Invalid group-priority",
                call_count=index,
            )

    def test_post_fails_with_textual_group_state(self):
        """Test post fails with textual group state"""

        self.params["group-state"] = "fake string"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Invalid group-state"
        )

    def test_post_fails_with_invalid_max_subcloud_rehoming(self):
        """Test post fails with invalid max subcloud rehoming"""

        invalid_values = [
            "fake value",
            subcloud_peer_group.MIN_SUBCLOUD_PEER_GROUP_SUBCLOUD_REHOMING - 1,
            subcloud_peer_group.MAX_SUBCLOUD_PEER_GROUP_SUBCLOUD_REHOMING + 1,
        ]

        for index, invalid_value in enumerate(invalid_values, start=1):
            self.params["max-subcloud-rehoming"] = invalid_value

            response = self._send_request()

            self._assert_pecan_and_response(
                response,
                http.client.BAD_REQUEST,
                "Invalid max-subcloud-rehoming",
                call_count=index,
            )

    def test_post_fails_with_sysinv_client_generic_exception(self):
        """Test post fails with sysinv client generic exception"""

        self.mock_sysinv_client().get_system.side_effect = FakeException()

        self.params.pop("system-leader-id")

        response = self._send_request()

        # TODO(rlima): a generic exception should return an Internal Server Error
        # instead of a Bad Request. Once the code is updated, this test will need
        # to be fixed.
        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Failed to get local system info"
        )

    @mock.patch.object(db_api, "subcloud_peer_group_create")
    def test_post_fails_with_db_api_db_duplicate_entry_exception(self, mock_create):
        """Test post fails with db_api DBDuplicateEntry exception"""

        mock_create.side_effect = db_exc.DBDuplicateEntry()

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.CONFLICT,
            "A subcloud peer group with this name already exists",
        )

    @mock.patch.object(db_api, "subcloud_peer_group_create")
    def test_post_fails_with_db_api_remote_error(self, mock_create):
        """Test post fails with db_api RemoteError exception"""

        mock_create.side_effect = RemoteError("msg", "value")

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.UNPROCESSABLE_ENTITY, "value"
        )

    @mock.patch.object(db_api, "subcloud_peer_group_create")
    def test_post_fails_with_db_api_generic_exception(self, mock_create):
        """Test post fails with db_api generic exception"""

        mock_create.side_effect = FakeException()

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.INTERNAL_SERVER_ERROR,
            "Unable to create subcloud peer group",
        )


class TestSubcloudPeerGroupControllerGet(BaseTestSubcloudPeerGroupController):
    """Test class for get requests"""

    def setUp(self):
        super().setUp()

        self.peer_group = self._create_db_object(self.ctx)

        self.url = f"{self.url}/{self.peer_group.peer_group_name}"
        self.method = self.app.get

        # Override initial_list_size. Default group is setup during db sync
        self.initial_list_size = 1

    def test_get_fails_without_group_ref(self):
        """Test get fails without group ref"""

        self.url = API_PREFIX

        response = self._send_request()
        self._assert_response(response)

    def test_get_fails_with_inexistent_group(self):
        """Test get fails with inexistent group"""

        self.url = f"{API_PREFIX}/123"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.NOT_FOUND, "Subcloud Peer Group not found"
        )

    def test_get_fails_with_inexistent_verb(self):
        """Test get fails with inexistent verb"""

        self.url = f"{API_PREFIX}/1/fake_verb"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Invalid request"
        )

    def test_get_succeeds_without_verb(self):
        """Test get succeeds without verb for a valid id"""

        response = self._send_request()
        self._assert_response(response)
        self.validate_entry(response.json)

    def test_get_succeeds_with_subclouds_verb_without_subclouds_in_peer_group(self):
        """Test get succeeds with subclouds verb without subclouds in peer group"""

        # API GET on: subcloud-peer-groups/<uuid>/subclouds
        self.url = f"{self.url}/subclouds"

        response = self._send_request()
        self._assert_response(response)

        # This API returns 'subclouds' rather than 'subcloud-peer-groups'
        self.assertIn("subclouds", response.json)
        # no subclouds exist yet, so this length should be zero
        self.assertEqual(0, len(response.json.get("subclouds")))

    def test_get_succeeds_with_subclouds_verb_and_subclouds_in_peer_group(self):
        """Test get succeeds with subclouds verb and subclouds in peer group"""

        self._create_subcloud()

        # API GET on: subcloud-peer-groups/<uuid>/subclouds
        self.url = f"{self.url}/subclouds"

        response = self._send_request()
        self._assert_response(response)

        # This API returns 'subclouds' rather than 'subcloud-groups'
        self.assertIn("subclouds", response.json)
        # the subcloud created earlier will have been queried
        self.assertEqual(1, len(response.json.get("subclouds")))

    def test_get_succeeds_with_status_verb(self):
        """Test get succeeds with status verb"""

        self._create_subcloud()

        # API GET on: subcloud-peer-groups/<uuid>/status
        self.url = f"{self.url}/status"

        response = self._send_request()
        self._assert_response(response)

        self.assertIn("total_subclouds", response.json)
        self.assertIn("peer_group_id", response.json)

    def test_get_succeeds_for_subcloud_in_multiple_deploy_states(self):
        """Test get succeeds for subcloud in multiple deploy states"""

        deploy_states = [
            consts.DEPLOY_STATE_REHOMING,
            consts.DEPLOY_STATE_REHOME_FAILED,
            consts.DEPLOY_STATE_REHOME_PREP_FAILED,
            consts.DEPLOY_STATE_SECONDARY,
            consts.DEPLOY_STATE_DONE,
            consts.DEPLOY_STATE_ABORTING_CONFIG,
        ]

        subclouds = []

        for deploy_state in deploy_states:
            subcloud = self._create_subcloud_db_object(self.ctx)

            db_api.subcloud_update(
                self.ctx,
                subcloud.id,
                name=f"subcloud-{deploy_state}",
                management_state="managed",
                peer_group_id=self.peer_group.id,
                deploy_status=deploy_state,
            )
            subclouds.append(subcloud)

        self.url = f"{self.url}/status"

        response = self._send_request()
        self._assert_response(response)

        self.assertEqual(response.json["peer_group_id"], self.peer_group.id)
        self.assertEqual(
            response.json["peer_group_name"], self.peer_group.peer_group_name
        )
        self.assertEqual(response.json["total_subclouds"], len(subclouds))
        self.assertEqual(response.json["managed"], len(subclouds))
        self.assertEqual(response.json["unmanaged"], 0)
        self.assertEqual(response.json["waiting_for_migrate"], 1)
        self.assertEqual(response.json["rehome_failed"], 2)
        self.assertEqual(response.json["complete"], 1)
        self.assertEqual(response.json["rehoming"], 1)


class BaseTestSubcloudPeerGroupControllerPatch(BaseTestSubcloudPeerGroupController):
    """Base test class for patch requests"""

    def setUp(self):
        super().setUp()

        self.peer_group = self._create_db_object(self.ctx)
        self.url = f"{self.url}/{self.peer_group.id}"
        self.method = self.app.patch_json


class TestSubcloudPeerGroupControllerPatch(BaseTestSubcloudPeerGroupControllerPatch):
    """Test class for patch requests"""

    def setUp(self):
        super().setUp()

        self.params = {
            "peer-group-name": "fake value",
            "group-priority": 1,
            "group-state": "enabled",
            "max-subcloud-rehoming": 1,
            "system-leader-id": FAKE_UUID,
            "system-leader-name": "fake value",
            "migration_status": consts.PEER_GROUP_MIGRATING,
        }

        self.mock_rpc_client().update_subcloud_peer_group.return_value = (
            [self.peer_group.id],
            [],
        )

    def _validate_peer_group_update(self):
        subcloud_peer_group = db_api.subcloud_peer_group_get(
            self.ctx, self.peer_group.id
        )

        for key, value in self.params.items():
            self.assertEqual(
                subcloud_peer_group[key.replace("-", "_")], self.params[key]
            )

    def test_patch_succeeds_without_verb(self):
        """Test patch succeeds without verb"""

        response = self._send_request()
        self._assert_response(response)
        self._validate_peer_group_update()

    def test_patch_succeeds_without_migration_status(self):
        """Test patch succeeds without migration status"""

        self.params["migration_status"] = None

        response = self._send_request()
        self._assert_response(response)
        self._validate_peer_group_update()

    def test_patch_succeeds_with_rename(self):
        """Test patch succeeds with rename"""

        self.params["peer-group-name"] = "New name"
        self.params["max-subcloud-rehoming"] = 20

        response = self._send_request()
        self._assert_response(response)
        self.mock_rpc_client().update_subcloud_peer_group.assert_called_once()
        self._validate_peer_group_update()

    @mock.patch.object(
        db_api, "subcloud_peer_group_update", wraps=db_api.subcloud_peer_group_update
    )
    def test_patch_succeeds_without_any_update(self, mock_update):
        """Test patch succeeds without any update

        When a request is made without valid parameters to update, i.e. the sent
        values are not different from the current ones in the database, it results in
        a success without performing the request to update the data.
        """

        self.params = {"peer-group-name": self.peer_group.peer_group_name}

        response = self._send_request()
        self._assert_response(response)
        self._validate_peer_group_update()
        mock_update.assert_not_called()

    def test_patch_fails_with_invalid_verb(self):
        """Test patch fails with invalid verb"""

        self.url = f"{self.url}/fake_verb"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Invalid request"
        )

    def test_patch_fails_with_invalid_group(self):
        """Test patch fails with invalid group"""

        self.url = f"{API_PREFIX}/999"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.NOT_FOUND, "Subcloud Peer Group not found"
        )

    def test_patch_fails_without_body(self):
        """Test patch fails without params"""

        self.params = None

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Body required"
        )

    def test_patch_fails_when_unable_to_sync(self):
        """Test patch fails when unable to sync"""

        self.mock_rpc_client().update_subcloud_peer_group.return_value = (
            [],
            [self.peer_group.id],
        )

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.FORBIDDEN,
            "Unable to sync the update to the peer site(s)",
        )

    def test_patch_fails_with_peer_group_from_non_primary_site(self):
        """Test patch fails with peer group from non primary site"""

        self.peer_group = db_api.subcloud_peer_group_update(
            self.ctx, self.peer_group.id, group_priority=1
        )

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Cannot update a peer group from a non-primary site.",
        )

    def test_patch_fails_with_body_without_known_properties_to_update(self):
        """Test patch fails with body without known properties to update"""

        self.params = {"invalid property": "fake value"}

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "nothing to update"
        )

    def test_patch_fails_with_peer_group_name_length_greater_than_maximum(self):
        """Test patch fails with peer group name length greater than maximum"""

        self.params["peer-group-name"] = "a" * (
            subcloud_peer_group.MAX_SUBCLOUD_PEER_GROUP_NAME_LEN + 1
        )

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Invalid peer-group-name"
        )

    def test_patch_fails_with_invalid_group_priority(self):
        """Test patch fails with invalid group priority"""

        invalid_values = [
            "fake string",
            subcloud_peer_group.MIN_SUBCLOUD_PEER_GROUP_PRIORITY - 1,
            subcloud_peer_group.MAX_SUBCLOUD_PEER_GROUP_PRIORITY + 1,
        ]

        for index, invalid_value in enumerate(invalid_values, start=1):
            self.params["group-priority"] = invalid_value

            response = self._send_request()

            self._assert_pecan_and_response(
                response,
                http.client.BAD_REQUEST,
                "Invalid group-priority",
                call_count=index,
            )

    def test_patch_fails_with_textual_group_state(self):
        """Test patch fails with textual group state"""

        self.params["group-state"] = "fake value"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Invalid group-state"
        )

    def test_patch_fails_with_invalid_max_subcloud_rehoming(self):
        """Test patch fails with invalid max subcloud rehoming"""

        invalid_values = [
            "fake value",
            subcloud_peer_group.MIN_SUBCLOUD_PEER_GROUP_SUBCLOUD_REHOMING - 1,
            subcloud_peer_group.MAX_SUBCLOUD_PEER_GROUP_SUBCLOUD_REHOMING + 1,
        ]

        for index, invalid_value in enumerate(invalid_values, start=1):
            self.params["max-subcloud-rehoming"] = invalid_value

            response = self._send_request()

            self._assert_pecan_and_response(
                response,
                http.client.BAD_REQUEST,
                "Invalid max-subcloud-rehoming",
                call_count=index,
            )

    def test_patch_fails_with_textual_system_leader_id(self):
        """Test patch fails with textual system leader id"""

        self.params["system-leader-id"] = "fake value"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Invalid system-leader-id"
        )

    def test_patch_fails_with_system_leader_name_length_greater_than_maximum(self):
        """Test patch fails with system leader name length greater than maximum"""

        self.params["system-leader-name"] = "a" * (
            subcloud_peer_group.MAX_SUBCLOUD_PEER_GROUP_NAME_LEN + 1
        )

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Invalid system-leader-name"
        )

    def test_patch_fails_with_textual_migration_status(self):
        """Test patch fails with textual migration status"""

        self.params["migration_status"] = "fake value"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Invalid migration_status"
        )

    @mock.patch.object(db_api, "subcloud_peer_group_update")
    def test_patch_fails_with_db_api_remote_error(self, mock_update):
        """Test patch fails with db_api RemoteError"""

        mock_update.side_effect = RemoteError("msg", "value")

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.UNPROCESSABLE_ENTITY, "value"
        )

    @mock.patch.object(db_api, "subcloud_peer_group_update")
    def test_patch_fails_with_db_api_generic_exception(self, mock_update):
        """Test patch fails with db_api FakeException"""

        mock_update.side_effect = FakeException()

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.INTERNAL_SERVER_ERROR,
            "Unable to update subcloud peer group",
        )


class TestSubcloudPeerGroupControllerPatchMigrate(
    BaseTestSubcloudPeerGroupControllerPatch
):
    """Test class for patch requests with migrate verb"""

    def setUp(self):
        super().setUp()

        self.url = f"{self.url}/migrate"
        self.params = {"sysadmin_password": "fake value"}
        self.update_subcloud_values = {
            "rehome_data": '{"saved_payload": {"system_mode": "simplex",'
            '"bootstrap-address": "192.168.100.100"}}',
            "deploy_status": consts.DEPLOY_STATE_SECONDARY,
            "management_state": dccommon_consts.MANAGEMENT_UNMANAGED,
        }

        self._create_subcloud()

    def _update_subcloud(self, **kwargs):
        for key, value in kwargs.items():
            self.update_subcloud_values[key] = value

        db_api.subcloud_update(
            self.ctx, self.subcloud.id, **self.update_subcloud_values
        )

    def test_patch_migrate_succeeds(self):
        """Test patch mgirate succeeds"""

        self._update_subcloud()

        response = self._send_request()

        self._assert_response(response)
        self.mock_rpc_client().batch_migrate_subcloud.assert_called_once()

    def test_patch_migrate_fails_without_params(self):
        """Test patch migrate fails without params"""

        self.params = {}

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Body required"
        )

    def test_patch_migrate_fails_without_sysadmin_password(self):
        """Test patch migrate fails without sysadmin password"""

        self.params = {"fake property": "fake value"}

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"Unable to migrate subcloud peer group: {self.peer_group.id} "
            "need sysadmin_password",
        )

    def test_patch_migrate_fails_with_subcloud_without_rehome_data(self):
        """Test patch migrate fails with subcloud without rehome data"""

        self._update_subcloud(rehome_data=None)

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.INTERNAL_SERVER_ERROR,
            "Batch migrate subclouds error: ['Unable to migrate subcloud: "
            f"{self.subcloud.name} required rehoming data is missing']",
        )

    def test_patch_migrate_fails_with_subcloud_with_empty_rehome_data(self):
        """Test patch migrate fails with subcloud with empty rehome data"""

        self._update_subcloud(rehome_data="{}")

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.INTERNAL_SERVER_ERROR,
            "Batch migrate subclouds error: ['Unable to migrate subcloud: "
            f"{self.subcloud.name} saved_payload is missing in rehoming data']",
        )

    def test_patch_migrate_fails_with_subcloud_with_empty_saved_payload(self):
        """Test patch migrate fails with subcloud with empty saved payload"""

        self._update_subcloud(rehome_data='{"saved_payload": {}}')

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.INTERNAL_SERVER_ERROR,
            "Batch migrate subclouds error: ['Unable to migrate subcloud: "
            f"{self.subcloud.name} saved_payload is empty']",
        )

    def test_patch_migrate_fails_with_subcloud_without_bootstrap_address(self):
        """Test patch migrate fails with subcloud without bootstrap address"""

        self._update_subcloud(
            rehome_data='{"saved_payload": {"system_mode": "simplex"}}'
        )

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.INTERNAL_SERVER_ERROR,
            "Batch migrate subclouds error: ['Unable to migrate subcloud: "
            f"{self.subcloud.name}, bootstrap-address is missing in rehoming data']",
        )

    def test_patch_migrate_fails_with_subcloud_in_rehome_state(self):
        """Test patch migrate fails with subcloud in rehome state"""

        self._update_subcloud(deploy_status=consts.DEPLOY_STATE_PRE_REHOME)

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.INTERNAL_SERVER_ERROR,
            "Batch migrate subclouds error: ['Unable to migrate subcloud peer group "
            f"{self.peer_group.peer_group_name}, subcloud {self.subcloud.name} "
            "already in rehoming process']",
        )

    def test_patch_migrate_fails_with_subcloud_in_deploy_state_done(self):
        """Test patch migrate fails with subcloud in deploy state done"""

        self._update_subcloud(
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            deploy_status=consts.DEPLOY_STATE_DONE,
        )

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Nothing to migrate, no secondary, rehome-failed or rehome-prep-failed "
            f"subcloud in peer group {self.peer_group.peer_group_name}",
        )

    def test_patch_migrate_fails_with_rpc_client_remote_error(self):
        """Test patch migrate fails with rpc_client remote error"""

        self.mock_rpc_client().batch_migrate_subcloud.side_effect = RemoteError(
            "msg", "value"
        )

        self._update_subcloud()

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.UNPROCESSABLE_ENTITY, "value"
        )

    def test_patch_migrate_fails_with_rpc_client_generic_exception(self):
        """Test patch migrate fails with rpc_client generic exception"""

        self.mock_rpc_client().batch_migrate_subcloud.side_effect = FakeException()

        self._update_subcloud()

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.INTERNAL_SERVER_ERROR,
            f"Unable to batch migrate peer group {self.peer_group.peer_group_name}",
        )


class TestSubcloudPeerGroupControllerPatchAudit(
    BaseTestSubcloudPeerGroupControllerPatch
):
    """Test class for patch requests with audit verb"""

    def setUp(self):
        super().setUp()

        self.url = f"{self.url}/audit"
        self.params = {
            "peer_uuid": FAKE_UUID,
            "peer_group_name": "fake name",
            "group_priority": 1,
            "group_state": "deployed",
            "system_leader_id": 1,
            "system_leader_name": "fake name",
            "migration_status": "fake status",
        }

    def test_patch_audit_fails_with_empty_params(self):
        """Test patch audit fails with empty params"""

        self.params = "{}"

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"Unable to audit peer group {self.peer_group.peer_group_name}, "
            "missing peer_uuid",
        )

    def test_patch_audit_fails_without_peer_group_name(self):
        """Test patch audit fails without peer group name"""

        self.params.pop("peer_group_name")

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"Unable to audit peer group {self.peer_group.peer_group_name}, "
            "missing peer_group_name",
        )

    def test_patch_audit_fails_without_group_priority(self):
        """Test patch audit fails without group priority"""

        self.params.pop("group_priority")

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"Unable to audit peer group {self.peer_group.peer_group_name}, "
            "missing group_priority",
        )

    def test_patch_audit_fails_without_group_state(self):
        """Test patch audit fails without group state"""

        self.params.pop("group_state")

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"Unable to audit peer group {self.peer_group.peer_group_name}, "
            "missing group_state",
        )

    def test_patch_audit_fails_without_system_leader_id(self):
        """Test patch audit fails without system leader id"""

        self.params.pop("system_leader_id")

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"Unable to audit peer group {self.peer_group.peer_group_name}, "
            "missing system_leader_id",
        )

    def test_patch_audit_fails_without_system_leader_name(self):
        """Test patch audit fails without system leader name"""

        self.params.pop("system_leader_name")

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"Unable to audit peer group {self.peer_group.peer_group_name}, "
            "missing system_leader_name",
        )

    def test_patch_audit_fails_without_migration_status(self):
        """Test patch audit fails without migration status"""

        self.params.pop("migration_status")

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            f"Unable to audit peer group {self.peer_group.peer_group_name}, "
            "missing migration_status",
        )

    def test_patch_audit_succeeds(self):
        """Test patch audit succeeds"""

        self.mock_rpc_client().peer_group_audit_notify.return_value = None

        response = self._send_request()

        self._assert_response(response)
        self.mock_rpc_client().peer_group_audit_notify.assert_called_once()

    def test_patch_audit_fails_with_rpc_client_generic_exception(self):
        """Test patch audit fails with rpc client generic exception"""

        self.mock_rpc_client().peer_group_audit_notify.side_effect = FakeException()

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.INTERNAL_SERVER_ERROR,
            f"Unable to audit peer group {self.peer_group.peer_group_name}",
        )


class TestSubcloudPeerGroupControllerDelete(BaseTestSubcloudPeerGroupController):
    """Test class for delete requests to SubcloudPeerGroupController"""

    def setUp(self):
        super().setUp()

        self.peer_group = self._create_db_object(self.ctx)

        self.url = f"{self.url}/{self.peer_group.id}"
        self.method = self.app.delete
        self.params = "{}"

    def test_delete_succeeds(self):
        """Test delete succeeds"""

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(len(db_api.subcloud_peer_group_get_all(self.ctx)), 0)

    def test_delete_fails_with_inexistent_group(self):
        """Test delete fails with inexistent group"""

        self.url = f"{API_PREFIX}/123"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.NOT_FOUND, "Subcloud Peer Group not found"
        )

    def test_delete_fails_when_association_exists(self):
        """Test delete fails when association exists"""

        self._create_subcloud()
        system_peer_fields = fake_subcloud.get_test_system_peer_dict("db")
        system_peer = db_api.system_peer_create(self.ctx, **system_peer_fields)
        db_api.peer_group_association_create(
            self.ctx,
            self.subcloud.peer_group_id,
            system_peer.id,
            self.peer_group.group_priority,
            consts.ASSOCIATION_TYPE_PRIMARY,
            consts.ASSOCIATION_SYNC_STATUS_IN_SYNC,
            "None",
        )

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Cannot delete a peer group which is associated with a system peer.",
        )

    @mock.patch.object(db_api, "subcloud_get_for_peer_group")
    @mock.patch.object(db_api, "subcloud_update")
    def test_delete_fails_with_db_api_remote_error(self, mock_update, mock_get):
        """Test delete fails with db_api RemoteError"""

        mock_get.return_value = [self.peer_group]
        mock_update.side_effect = RemoteError("mgs", "value")

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.UNPROCESSABLE_ENTITY, "value"
        )

    @mock.patch.object(db_api, "subcloud_get_for_peer_group")
    @mock.patch.object(db_api, "subcloud_update")
    def test_delete_fails_with_db_api_generic_exception(self, mock_update, mock_get):
        """Test delete fails with db_api generic exception"""

        mock_get.return_value = [self.peer_group]
        mock_update.side_effect = FakeException()

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.INTERNAL_SERVER_ERROR,
            "Unable to delete subcloud peer group",
        )
