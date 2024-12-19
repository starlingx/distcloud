#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import http.client
import uuid

from oslo_config import cfg
from oslo_config import fixture as fixture_config
from oslo_serialization import jsonutils
from oslo_utils import uuidutils
import pecan
from pecan.configuration import set_config
from pecan.testing import load_test_app

from dcagent.api import api_config
from dcagent.common import config
from dcagent.tests.base import DCAgentTestCase
from dcagent.tests.common import consts as test_consts

config.register_options()
OPT_GROUP_NAME = "keystone_authtoken"
cfg.CONF.import_group(OPT_GROUP_NAME, "keystonemiddleware.auth_token")


class DCAgentApiTest(DCAgentTestCase):
    def setUp(self):
        super().setUp()

        self.addCleanup(set_config, {}, overwrite=True)

        api_config.test_init()

        config_fixture = fixture_config.Config()
        self.CONF = self.useFixture(config_fixture).conf
        config_fixture.set_config_dirs([])

        self.CONF.set_override("auth_strategy", "noauth")

        self.app = self._make_app()
        self.mock_pecan_abort = self._mock_object(pecan, "abort", wraps=pecan.abort)

        self.url = "/"
        # The put method is used as a default value, leading to the generic
        # implementation on controllers in case the method is not specified
        self.method = self.app.put
        self.params = {}
        self.upload_files = None
        self.verb = None
        self.headers = {
            "X-Tenant-Id": str(uuid.uuid4()),
            "X_ROLE": "admin,member,reader",
            "X-Identity-Status": "Confirmed",
            "X-Project-Name": "admin",
        }

    def _make_app(self, enable_acl=False):
        self.config_fixture = {
            "app": {
                "root": "dcagent.api.controllers.root.RootController",
                "modules": ["dcagent.api"],
                "enable_acl": enable_acl,
                "errors": {400: "/error", "__force_dict__": True},
            },
        }

        return load_test_app(self.config_fixture)

    def _send_request(self):
        """Send a request to a url"""

        kwargs = {}

        if self.upload_files:
            kwargs = {"upload_files": self.upload_files}

        return self.method(
            self.url,
            headers=self.headers,
            params=self.params,
            expect_errors=True,
            **kwargs,
        )

    def _assert_response(
        self,
        response,
        status_code=http.client.OK,
        content_type=test_consts.APPLICATION_JSON,
        expected_response_text=None,
    ):
        """Assert the response for a request"""

        self.assertEqual(response.status_code, status_code)
        self.assertEqual(response.content_type, content_type)
        if expected_response_text:
            self.assertEqual(response.text, expected_response_text)

    def _assert_pecan(self, http_status, content=None, call_count=1):
        """Assert pecan was called with the correct arguments"""

        self.assertEqual(self.mock_pecan_abort.call_count, call_count)

        if content:
            self.mock_pecan_abort.assert_called_with(http_status, content)
        else:
            self.mock_pecan_abort.assert_called_with(http_status)

    def _assert_pecan_and_response(
        self,
        response,
        http_status,
        content=None,
        call_count=1,
        content_type=test_consts.TEXT_PLAIN,
    ):
        """Assert the response and pecan abort for a failed request"""

        self._assert_pecan(http_status, content, call_count=call_count)
        self._assert_response(response, http_status, content_type)

    def tearDown(self):
        super(DCAgentApiTest, self).tearDown()
        pecan.set_config({}, overwrite=True)


class TestRootController(DCAgentApiTest):
    """Test version listing on root URI."""

    def setUp(self):
        super(TestRootController, self).setUp()

        self.url = "/"
        self.method = self.app.get

    def _test_method_returns_405(self, method, content_type=test_consts.TEXT_PLAIN):
        self.method = method

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.METHOD_NOT_ALLOWED, content_type=content_type
        )

    def test_get(self):
        """Test get request succeeds with correct versions"""

        response = self._send_request()

        self._assert_response(response)
        json_body = jsonutils.loads(response.body)
        versions = json_body.get("versions")
        self.assertEqual(1, len(versions))

    def test_request_id(self):
        """Test request for root returns the correct request id"""

        response = self._send_request()

        self._assert_response(response)
        self.assertIn("x-openstack-request-id", response.headers)
        self.assertTrue(response.headers["x-openstack-request-id"].startswith("req-"))
        id_part = response.headers["x-openstack-request-id"].split("req-")[1]
        self.assertTrue(uuidutils.is_uuid_like(id_part))

    def test_post(self):
        """Test post request is not allowed on root"""

        self._test_method_returns_405(self.app.post)

    def test_put(self):
        """Test put request is not allowed on root"""

        self._test_method_returns_405(self.app.put)

    def test_patch(self):
        """Test patch request is not allowed on root"""

        self._test_method_returns_405(self.app.patch)

    def test_delete(self):
        """Test delete request is not allowed on root"""

        self._test_method_returns_405(self.app.delete)

    def test_head(self):
        """Test head request is not allowed on root"""

        self._test_method_returns_405(self.app.head, content_type=test_consts.TEXT_HTML)


class TestErrors(DCAgentApiTest):
    def setUp(self):
        super(TestErrors, self).setUp()
        cfg.CONF.set_override("admin_tenant", "fake_tenant_id", group="cache")

    def test_404(self):
        self.url = "/assert_called_once"
        self.method = self.app.get

        response = self._send_request()
        self._assert_response(
            response, http.client.NOT_FOUND, content_type=test_consts.TEXT_PLAIN
        )

    def test_version_1_root_controller(self):
        self.url = f"/v1/{uuidutils.generate_uuid()}/bad_method"
        self.method = self.app.patch

        response = self._send_request()

        self._assert_pecan_and_response(response, http.client.NOT_FOUND)


class TestKeystoneAuth(DCAgentApiTest):
    """Test requests using keystone as the authentication strategy"""

    def setUp(self):
        super(TestKeystoneAuth, self).setUp()

        cfg.CONF.set_override("auth_strategy", "keystone")

        self.method = self.app.get

    def test_auth_not_enforced_for_root(self):
        """Test authentication is not enforced for root url"""

        response = self._send_request()
        self._assert_response(response)
