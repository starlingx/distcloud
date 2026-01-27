# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import json
import threading

import mock

from oslotest import base
from webob import Request

from dcorch.api.proxy.apps import authtoken


@mock.patch("dcorch.api.proxy.apps.authtoken.auth_token.AuthProtocol")
class TestAuthWrapper(base.BaseTestCase):
    """Test case for AuthWrapper class."""

    def setUp(self):
        super(TestAuthWrapper, self).setUp()
        self.app = mock.Mock()
        self.conf = {
            "oidc_default_domain": "TestDomain",
            "oidc_default_project": "test_project",
        }

    def test_init(self, mock_auth_protocol):
        wrapper = authtoken.AuthWrapper(self.app, self.conf)

        self.assertEqual(wrapper.app, self.app)
        self.assertEqual(wrapper.conf, self.conf)
        self.assertEqual(wrapper.default_domain, "TestDomain")
        self.assertEqual(wrapper.default_project, "test_project")
        self.assertIsInstance(wrapper._oidc_cache_lock, type(threading.Lock()))
        self.assertEqual(wrapper._oidc_token_cache, {})

    def test_missing_token(self, mock_auth_protocol):
        wrapper = authtoken.AuthWrapper(self.app, self.conf)
        req = Request.blank("/test")

        response = wrapper(req)

        self.assertEqual(response.status_code, 401)
        body = json.loads(response.body.decode("utf-8"))
        self.assertIn("Missing authentication token", body["error_message"])

    @mock.patch("dcorch.api.proxy.apps.authtoken.oidc_utils")
    def test_oidc_auth_success(self, mock_oidc_utils, mock_auth_protocol):
        mock_oidc_utils.get_oidc_token_claims.return_value = {"sub": "user"}
        mock_oidc_utils.parse_oidc_token_claims.return_value = {
            "username": "testuser",
            "roles": ["admin", "member"],
        }

        # Mock app as a WSGI callable
        def mock_app(environ, start_response):
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"OK"]

        wrapper = authtoken.AuthWrapper(mock_app, self.conf)
        req = Request.blank("/test")
        req.headers["OIDC-Token"] = "test_token"

        wrapper(req)

        self.assertEqual(req.environ["HTTP_X_USER_NAME"], "testuser")
        self.assertEqual(req.environ["HTTP_X_ROLE"], "admin,member")
        self.assertEqual(req.environ["HTTP_X_ROLES"], "admin,member")
        self.assertEqual(req.environ["HTTP_X_PROJECT_NAME"], "test_project")

    @mock.patch("dcorch.api.proxy.apps.authtoken.oidc_utils")
    def test_oidc_auth_failure(self, mock_oidc_utils, mock_auth_protocol):
        mock_oidc_utils.get_oidc_token_claims.side_effect = Exception("Invalid token")

        wrapper = authtoken.AuthWrapper(self.app, self.conf)
        req = Request.blank("/test")
        req.headers["OIDC-Token"] = "invalid_token"

        response = wrapper(req)

        self.assertEqual(response.status_code, 401)
        body = json.loads(response.body.decode("utf-8"))
        self.assertIn("OIDC authentication failed", body["error_message"])

    def test_inject_oidc_claims(self, mock_auth_protocol):
        wrapper = authtoken.AuthWrapper(self.app, self.conf)
        environ = {}
        claims = {"username": "testuser", "roles": ["admin", "member"]}

        wrapper._inject_oidc_claims(environ, claims)

        self.assertEqual(environ["HTTP_X_USER_NAME"], "testuser")
        self.assertEqual(environ["HTTP_X_ROLE"], "admin,member")
        self.assertEqual(environ["HTTP_X_ROLES"], "admin,member")
        self.assertEqual(environ["HTTP_X_PROJECT_NAME"], "test_project")

    @mock.patch("dcorch.api.proxy.apps.authtoken.oidc_utils")
    def test_oidc_cache_lock(self, mock_oidc_utils, mock_auth_protocol):
        mock_oidc_utils.get_oidc_token_claims.return_value = {"sub": "user"}
        mock_oidc_utils.parse_oidc_token_claims.return_value = {
            "username": "testuser",
            "roles": ["admin"],
        }

        wrapper = authtoken.AuthWrapper(self.app, self.conf)
        mock_lock = mock.MagicMock()
        wrapper._oidc_cache_lock = mock_lock

        wrapper._oidc_auth("test_token")

        mock_lock.__enter__.assert_called_once()
        mock_lock.__exit__.assert_called_once()
