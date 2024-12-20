# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import copy
import http.client

import mock

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.vim import SW_UPDATE_OPTS_CONST_DEFAULT
from dcmanager.db import api as db_api
from dcmanager.rpc import client as rpc_client
from dcmanager.tests.base import FakeException
from dcmanager.tests.unit.api.test_root_controller import DCManagerApiTest
from dcmanager.tests.unit.common import fake_subcloud


class SwUpdateOptionsMixin(object):
    """Specifies common test cases between the different methods"""

    def test_method_succeeds_with_subcloud_ref_as_default_region_name(self):
        """Test method succeeds with subcloud ref as default region name"""

        self.url = f"{self.url}/{dccommon_consts.DEFAULT_REGION_NAME}"

        response = self._send_request()

        self._assert_response(response)
        self.mock_sw_update_opts_default.assert_called_once()

    def test_method_succeeds_with_subcloud_ref_as_subcloud_id(self):
        """Test method succeeds with subcloud ref as subcloud id"""

        self.url = f"{self.url}/{self.subcloud.id}"

        response = self._send_request()

        self._assert_response(response)
        self.mock_sw_update_opts.assert_called_once()

    def test_method_fails_with_subcloud_id_not_found(self):
        """Test method fails with subcloud id not found"""

        self.url = f"{self.url}/9999"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.NOT_FOUND, "Subcloud not found"
        )
        self.mock_sw_update_opts.assert_not_called()

    def test_method_succeeds_with_subcloud_ref_as_subcloud_name(self):
        """Test method succeeds with subcloud ref as subcloud name"""

        self.url = f"{self.url}/{self.subcloud.name}"

        response = self._send_request()

        self._assert_response(response)
        self.mock_sw_update_opts.assert_called_once()

    def test_method_fails_with_subcloud_name_not_found(self):
        """Test method fails with subcloud name not found"""

        self.url = f"{self.url}/fake"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.NOT_FOUND, "Subcloud not found"
        )
        self.mock_sw_update_opts.assert_not_called()


class BaseTestSwUpdateOptionsController(DCManagerApiTest):
    """Base class for testing the SwUpdateOptionsController"""

    def setUp(self):
        super().setUp()

        self.url = "/v1.0/sw-update-options"
        self.subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        self._mock_object(rpc_client, "ManagerClient")

    def _get_sw_update_opts(self):
        return {
            "storage_apply_type": SW_UPDATE_OPTS_CONST_DEFAULT["storage-apply-type"],
            "worker_apply_type": SW_UPDATE_OPTS_CONST_DEFAULT["worker-apply-type"],
            "max_parallel_workers": SW_UPDATE_OPTS_CONST_DEFAULT[
                "max-parallel-workers"
            ],
            "alarm_restriction_type": SW_UPDATE_OPTS_CONST_DEFAULT[
                "alarm-restriction-type"
            ],
            "default_instance_action": SW_UPDATE_OPTS_CONST_DEFAULT[
                "default-instance-action"
            ],
        }

    def _create_sw_update_opts(self):
        """Creates a sw update options"""

        db_api.sw_update_opts_create(
            self.ctx, self.subcloud.id, **self._get_sw_update_opts()
        )

    def _create_sw_update_opts_default(self):
        """Creates a sw update options for the default region name"""

        db_api.sw_update_opts_default_create(self.ctx, **self._get_sw_update_opts())


class TestSwUpdateOptionsController(BaseTestSwUpdateOptionsController):
    """Test class for SwUpdateOptionsController"""

    def setUp(self):
        super().setUp()

    def test_unmapped_method(self):
        """Test requesting an unmapped method results in success with null content"""

        self.method = self.app.put

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(response.text, "null")


class TestSwUpdateOptionsGet(BaseTestSwUpdateOptionsController, SwUpdateOptionsMixin):
    """Test class for get requests"""

    def setUp(self):
        super().setUp()

        self.method = self.app.get

        self._create_sw_update_opts()

        self.mock_sw_update_opts = self._mock_object(
            db_api,
            "sw_update_opts_get",
            db_api.sw_update_opts_get,
        )
        self.mock_sw_update_opts_default = self._mock_object(
            db_api,
            "sw_update_opts_default_get",
            db_api.sw_update_opts_default_get,
        )

    def test_get_succeeds_without_subcloud_ref(self):
        """Test get succeeds without subcloud ref"""

        response = self._send_request()

        self._assert_response(response)

    def test_get_succeeds_without_subcloud_ref_and_sw_update_opts(self):
        """Test get succeeds without subcloud ref and sw update opts"""

        db_api.sw_update_opts_destroy(self.ctx, self.subcloud.id)

        response = self._send_request()

        self._assert_response(response)

    def test_get_fails_with_generic_exception_without_sw_update_options(self):
        """Test get fails with generic exception without sw update options

        When performing a get request with subcloud ref and without sw update
        options, a SubcloudPatchOptsNotFound exception is raised, resulting in a
        generic exception
        """

        self.url = f"{self.url}/{self.subcloud.name}"

        db_api.sw_update_opts_destroy(self.ctx, self.subcloud.id)

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.NOT_FOUND,
            f"No options found for Subcloud with id {self.subcloud.id}, "
            "defaults will be used.",
        )


class BaseTestSwUpdateOptionsPost(BaseTestSwUpdateOptionsController):
    """Base test class for post requests"""

    def setUp(self):
        super().setUp()

        self.method = self.app.post_json
        self.params = copy.copy(SW_UPDATE_OPTS_CONST_DEFAULT)
        del self.params["created-at"]
        del self.params["updated-at"]


class TestSwUpdateOptionsPost(BaseTestSwUpdateOptionsPost):
    """Test class for post requests"""

    def setUp(self):
        super().setUp()

    def test_post_fails_without_payload(self):
        """Test post fails without payload"""

        self.params = {}

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Body required"
        )


class TestSwUpdateOptionsPostUpdate(BaseTestSwUpdateOptionsPost, SwUpdateOptionsMixin):
    """Test class for post requests to update sw_update_opts

    When a post request is performed for an existing sw_update_opts, it's updated.
    Otherwise, a new one is created.
    """

    def setUp(self):
        super().setUp()

        self._create_sw_update_opts()
        self._create_sw_update_opts_default()

        self.mock_sw_update_opts = self._mock_object(
            db_api,
            "sw_update_opts_update",
            db_api.sw_update_opts_update,
        )
        self.mock_sw_update_opts_default = self._mock_object(
            db_api,
            "sw_update_opts_default_update",
            db_api.sw_update_opts_default_update,
        )

    @mock.patch.object(db_api, "sw_update_opts_default_update")
    def test_post_update_fails_in_default_region_with_db_api_generic_exception(
        self, mock_db_api
    ):
        """Test post update fails in default region with db api generic exception"""

        self.url = f"{self.url}/{dccommon_consts.DEFAULT_REGION_NAME}"

        mock_db_api.side_effect = FakeException()

        self.assertRaises(
            FakeException,
            self.method,
            self.url,
            headers=self.headers,
            params=self.params,
        )


class TestSwUpdateOptionsPostCreate(BaseTestSwUpdateOptionsPost, SwUpdateOptionsMixin):
    """Test class for post requests to create sw_update_opts

    When a post request is performed for an existing sw_update_opts, it's updated.
    Otherwise, a new one is created.
    """

    def setUp(self):
        super().setUp()

        self.mock_sw_update_opts = self._mock_object(
            db_api,
            "sw_update_opts_create",
            db_api.sw_update_opts_create,
        )
        self.mock_sw_update_opts_default = self._mock_object(
            db_api,
            "sw_update_opts_default_create",
            db_api.sw_update_opts_default_create,
        )

    @mock.patch.object(db_api, "sw_update_opts_default_create")
    def test_post_create_fails_in_default_region_with_db_api_generic_exception(
        self, mock_db_api
    ):
        """Test post create fails in default region with db api generic exception"""

        if db_api.sw_update_opts_default_get(self.ctx) is not None:
            db_api.sw_update_opts_default_destroy(self.ctx)

        self.url = f"{self.url}/{dccommon_consts.DEFAULT_REGION_NAME}"

        mock_db_api.side_effect = FakeException()

        self.assertRaises(
            FakeException,
            self.method,
            self.url,
            headers=self.headers,
            params=self.params,
        )


class TestSwUpdateOptionsDelete(
    BaseTestSwUpdateOptionsController, SwUpdateOptionsMixin
):
    """Test class for delete requests"""

    def setUp(self):
        super().setUp()

        self.method = self.app.delete

        self._create_sw_update_opts()
        self._create_sw_update_opts_default()

        self.mock_sw_update_opts = self._mock_object(
            db_api,
            "sw_update_opts_destroy",
            db_api.sw_update_opts_destroy,
        )
        self.mock_sw_update_opts_default = self._mock_object(
            db_api,
            "sw_update_opts_default_destroy",
            db_api.sw_update_opts_default_destroy,
        )

    def test_delete_succeeds_with_generic_exception_for_default_region_name(self):
        """Test delete succeeds with generic exception for default region name

        When a delete request is made for the default region name and there isn't a
        sw_update_opts_default object in the database, a generic exception is catched
        and the execution returnns
        """

        db_api.sw_update_opts_default_destroy(self.ctx)

        self.url = f"{self.url}/{dccommon_consts.DEFAULT_REGION_NAME}"

        response = self._send_request()

        self._assert_response(response)

    def test_delete_fails_without_sw_update_opts_to_delete(self):
        """Test delete fails without sw update opts to delete"""

        db_api.sw_update_opts_destroy(self.ctx, self.subcloud.id)

        self.url = f"{self.url}/{self.subcloud.id}"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.NOT_FOUND, "Subcloud patch options not found"
        )
