# Copyright (c) 2017 Ericsson AB
# Copyright (c) 2020-2022, 2024-2025 Wind River Systems, Inc.
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

import http.client

import mock
from oslo_messaging import RemoteError

from dcmanager.api.controllers.v1 import subcloud_group
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

SAMPLE_SUBCLOUD_GROUP_NAME = "GroupX"
SAMPLE_SUBCLOUD_GROUP_DESCRIPTION = "A Group of mystery"
SAMPLE_SUBCLOUD_GROUP_UPDATE_APPLY_TYPE = consts.SUBCLOUD_APPLY_TYPE_SERIAL
SAMPLE_SUBCLOUD_GROUP_MAX_PARALLEL_SUBCLOUDS = 3


class SubcloudGroupAPIMixin(APIMixin):
    API_PREFIX = "/v1.0/subcloud-groups"
    RESULT_KEY = "subcloud_groups"
    EXPECTED_FIELDS = [
        "id",
        "name",
        "description",
        "max_parallel_subclouds",
        "update_apply_type",
        "created-at",
        "updated-at",
    ]

    def setUp(self):
        super().setUp()

    def _get_test_subcloud_group_dict(self, **kw):
        # id should not be part of the structure
        return {
            "name": kw.get("name", SAMPLE_SUBCLOUD_GROUP_NAME),
            "description": kw.get("description", SAMPLE_SUBCLOUD_GROUP_DESCRIPTION),
            "update_apply_type": kw.get(
                "update_apply_type", SAMPLE_SUBCLOUD_GROUP_UPDATE_APPLY_TYPE
            ),
            "max_parallel_subclouds": kw.get(
                "max_parallel_subclouds", SAMPLE_SUBCLOUD_GROUP_MAX_PARALLEL_SUBCLOUDS
            ),
        }

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
        creation_fields = self._get_test_subcloud_group_dict(**kw)
        return db_api.subcloud_group_create(context, **creation_fields)

    def get_post_object(self):
        return self._get_test_subcloud_group_dict()

    def get_update_object(self):
        return {"description": "Updated description"}


class BaseTestSubcloudGroupController(DCManagerApiTest, SubcloudGroupAPIMixin):
    """Base class for testing the SubcloudGroupController"""

    def setUp(self):
        super().setUp()

        self.url = self.API_PREFIX
        self._mock_object(rpc_client, "ManagerClient")


class TestSubcloudGroupController(BaseTestSubcloudGroupController):
    """Test class for SubcloudGroupController"""

    def setUp(self):
        super().setUp()

    def test_unmapped_method(self):
        """Test requesting an unmapped method results in success with null content"""

        self.method = self.app.put

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(response.text, "null")


class TestSubcloudGroupPost(BaseTestSubcloudGroupController, PostJSONMixin):
    """Test class for post requests"""

    def setUp(self):
        super().setUp()

        self.method = self.app.post_json
        self.params = self.get_post_object()

    def test_post_fails_without_params(self):
        """Test post fails without params"""

        self.params = {}

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Body required"
        )

    def test_post_fails_with_numerical_name(self):
        """Test post fails with numerical name

        A numerical name is not permitted, otherwise the 'get' operations
        which support getting by either name or ID could become confusing
        if a group's name was the same as the id of another.
        """

        self.params["name"] = "999"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Invalid group name"
        )

    def test_post_fails_with_empty_name(self):
        """Test post fails with empty name"""

        self.params["name"] = ""

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Invalid group name"
        )

    def test_post_fails_with_default_name(self):
        """Test post fails with default name

        The name 'Default' is not permitted because it would be a duplicate, but it
        should be unique
        """

        self.params["name"] = consts.DEFAULT_SUBCLOUD_GROUP_NAME

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Invalid group name"
        )

    def test_post_fails_with_invalid_description(self):
        """Test post fails with invalid description"""

        invalid_values = [
            "",
            "a" * (subcloud_group.MAX_SUBCLOUD_GROUP_DESCRIPTION_LEN + 1),
        ]

        for index, invalid_value in enumerate(invalid_values, start=1):
            self.params["description"] = invalid_value

            response = self._send_request()

            self._assert_pecan_and_response(
                response,
                http.client.BAD_REQUEST,
                "Invalid group description",
                call_count=index,
            )

    def test_post_fails_with_invalid_update_apply_type(self):
        """Test post fails with invalid update apply type

        The update apply type should be either serial or parallel
        """

        self.params["update_apply_type"] = "fake"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Invalid group update_apply_type"
        )

    def test_post_fails_without_update_apply_type(self):
        """Test post fails without update apply type"""

        del self.params["update_apply_type"]

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Invalid group update_apply_type"
        )

    def test_post_fails_with_invalid_max_parallel_subclouds(self):
        """Test post fails with invalid max parallel subclouds

        The acceptable range is between 1 and 500
        """

        invalid_values = [0, 5001, -1, "fake"]

        for index, invalid_value in enumerate(invalid_values, start=1):
            self.params["max_parallel_subclouds"] = invalid_value

            response = self._send_request()

            self._assert_pecan_and_response(
                response,
                http.client.BAD_REQUEST,
                "Invalid group max_parallel_subclouds",
                call_count=index,
            )

    def test_post_fails_with_db_api_duplicate_entry(self):
        """Test post fails with db api duplicate entry"""

        self._create_db_object(self.ctx)

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "A subcloud group with this name already exists",
        )

    @mock.patch.object(db_api, "subcloud_group_create")
    def test_post_fails_with_db_api_remote_error(self, mock_db_api):
        """Test post fails with db api remote error"""

        mock_db_api.side_effect = RemoteError("msg", "value")

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.UNPROCESSABLE_ENTITY, "value"
        )

    @mock.patch.object(db_api, "subcloud_group_create")
    def test_post_fails_with_db_api_generic_exception(self, mock_db_api):
        """Test post fails with db api generic exception"""

        mock_db_api.side_effect = Exception()

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.INTERNAL_SERVER_ERROR,
            "Unable to create subcloud group",
        )


class BaseTestSubcloudGroupGet(BaseTestSubcloudGroupController):
    """Base test class for get requests"""

    def setUp(self):
        super().setUp()

        self.subcloud_group = db_api.subcloud_group_get(self.ctx, 1)

        self.url = f"{self.url}/{self.subcloud_group.id}"
        self.method = self.app.get


class TestSubcloudGroupGet(BaseTestSubcloudGroupGet, GetMixin):
    """Test class for get requests"""

    def setUp(self):
        super().setUp()

        # Override initial_list_size. Default group is setup during db sync
        self.initial_list_size = 1

    def test_get_succeeds_with_id(self):
        """Test get succeeds with id"""

        response = self._send_request()

        self._assert_response(response)

    def test_get_succeeds_with_name(self):
        """Test get succeeds with name"""

        self.url = f"{self.API_PREFIX}/{self.subcloud_group.name}"

        response = self._send_request()

        self._assert_response(response)


class TestSubcloudGroupGetSubclouds(BaseTestSubcloudGroupGet):
    """Test class for get requests with subclouds verb"""

    def setUp(self):
        super().setUp()

        self.url = f"{self.url}/subclouds"

    def test_get_subclouds_succeeds(self):
        """Test get subclouds succeeds

        The list size is 0 because there isn't a subcloud associated to the group
        """

        response = self._send_request()

        self._assert_response(response)
        # This API returns 'subclouds' rather than 'subcloud-groups'
        self.assertIn("subclouds", response.json)
        self.assertEqual(0, len(response.json.get("subclouds")))

    def test_get_subclouds_succeeds_with_subcloud_in_group(self):
        """Test get subclouds succeeds with subcloud in group

        When a subcloud is created, it is associated with the Default group
        """

        # subclouds are to Default group by default (unless specified)
        fake_subcloud.create_fake_subcloud(self.ctx)

        response = self._send_request()

        self.assertIn("subclouds", response.json)
        self.assertEqual(1, len(response.json.get("subclouds")))


class TestSubcloudGroupPatch(BaseTestSubcloudGroupController, UpdateMixin):
    """Test class for patch requests"""

    def setUp(self):
        super().setUp()

        self.subcloud_group = db_api.subcloud_group_get(self.ctx, 1)

        self.method = self.app.patch_json
        self.url = f"{self.url}/{self.subcloud_group.id}"

    def test_patch_succeeds_with_name_and_max_parallel_subclouds(self):
        """Test patch succeeds with name and max parallel subclouds"""

        self.subcloud_group = self._create_db_object(self.ctx)

        self.url = f"{self.API_PREFIX}/{self.subcloud_group.id}"

        self.params = {"name": "new name", "max_parallel_subclouds": 2}

        response = self._send_request()

        self._assert_response(response)

    def test_patch_fails_with_group_not_found(self):
        """Test patch fails with group not found"""

        self.url = f"{self.API_PREFIX}/999"
        self.params = {"update_apply_type": "fake"}

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.NOT_FOUND, "Subcloud Group not found"
        )

    def test_patch_fails_with_invalid_property_to_update(self):
        """Test patch fails with invalid property to update"""

        self.params = {"fake": "value"}

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "nothing to update"
        )

    def test_patch_fails_with_invalid_name(self):
        """Test patch fails with invalid name"""

        self.params = {"name": consts.DEFAULT_SUBCLOUD_GROUP_NAME}

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Invalid group name"
        )

    def test_patch_fails_with_new_name_for_default_group(self):
        """Test patch fails with new name for default group"""

        self.params = {"name": "new name"}

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Default group name cannot be changed"
        )

    def test_patch_fails_with_invalid_update_apply_type(self):
        """Test patch fails with invalid update apply type"""

        self.params = {"update_apply_type": "fake"}

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Invalid group update_apply_type"
        )

    def test_patch_fails_with_invalid_max_parallel_subclouds(self):
        """Test patch fails with invalid max parallel subclouds"""

        invalid_values = [0, 5001, -1, "fake"]

        for index, invalid_value in enumerate(invalid_values, start=1):
            self.params = {"max_parallel_subclouds": str(invalid_value)}

            response = self._send_request()

            self._assert_pecan_and_response(
                response,
                http.client.BAD_REQUEST,
                "Invalid group max_parallel_subclouds",
                call_count=index,
            )

    def test_patch_fails_with_invalid_description(self):
        """Test patch fails with invalid description"""

        self.params = {
            "description": "a" * (subcloud_group.MAX_SUBCLOUD_GROUP_DESCRIPTION_LEN + 1)
        }

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Invalid group description",
        )

    @mock.patch.object(db_api, "subcloud_group_update")
    def test_patch_fails_with_db_api_remote_error(self, mock_db_api):
        """Test patch fails with db api remote error"""

        self.params = {"update_apply_type": "serial"}

        mock_db_api.side_effect = RemoteError("msg", "value")

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.UNPROCESSABLE_ENTITY, "value"
        )

    @mock.patch.object(db_api, "subcloud_group_update")
    def test_patch_fails_with_db_api_generic_exception(self, mock_db_api):
        """Test patch fails with db api generic exception"""

        self.params = {"update_apply_type": "serial"}

        mock_db_api.side_effect = Exception()

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.INTERNAL_SERVER_ERROR,
            "Unable to update subcloud group",
        )


class TestSubcloudGroupDelete(BaseTestSubcloudGroupController, DeleteMixin):
    """Test class for delete requests"""

    def setUp(self):
        super().setUp()

        self.subcloud_group = db_api.subcloud_group_get(self.ctx, 1)

        self.method = self.app.delete
        self.url = f"{self.url}/{self.subcloud_group.id}"

    def test_delete_fails_for_default(self):
        """Test delete fails for default

        The default subcloud group can't be deleted
        """

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "Default Subcloud Group may not be deleted",
        )

    def test_delete_fails_with_subcloud_in_group(self):
        """Test delete fails with subcloud in group"""

        subcloud_group = self._create_db_object(self.ctx)
        fake_subcloud.create_fake_subcloud(self.ctx, group_id=subcloud_group.id)

        self.url = f"{self.API_PREFIX}/{subcloud_group.id}"

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.INTERNAL_SERVER_ERROR,
            "Unable to delete subcloud group",
            call_count=2,
        )

    @mock.patch.object(db_api, "subcloud_group_destroy")
    def test_delete_fails_with_db_api_remote_error(self, mock_db_api):
        """Test delete fails with db api remote error"""

        self.subcloud_group = self._create_db_object(self.ctx)

        self.url = f"{self.API_PREFIX}/{self.subcloud_group.id}"

        mock_db_api.side_effect = RemoteError("msg", "value")

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.UNPROCESSABLE_ENTITY, "value"
        )

    @mock.patch.object(db_api, "subcloud_group_destroy")
    def test_delete_fails_with_db_api_generic_exception(self, mock_db_api):
        """Test delete fails with db api generic exception"""

        self.subcloud_group = self._create_db_object(self.ctx)

        self.url = f"{self.API_PREFIX}/{self.subcloud_group.id}"

        mock_db_api.side_effect = Exception()

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.INTERNAL_SERVER_ERROR,
            "Unable to delete subcloud group",
        )
