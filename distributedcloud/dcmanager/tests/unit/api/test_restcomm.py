# Copyright (c) 2026 Wind River Systems, Inc.
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

import mock

from dcmanager.api.controllers import restcomm
from dcmanager.tests.base import DCManagerTestCase


class TestExtractContextFromEnviron(DCManagerTestCase):
    """Test extract_context_from_environ for OIDC and Keystone auth paths."""

    def setUp(self):
        super().setUp()
        self.mock_request = mock.patch(
            "dcmanager.api.controllers.restcomm.request"
        ).start()
        self.addCleanup(mock.patch.stopall)

    def test_oidc_reader_role_context_has_user_and_project(self):
        """Test OIDC reader-role user gets a valid context with user/project set.

        Regression test for CGTS-101750: OIDC users with reader role got
        HTTP 500 because context.user and context.project were None.
        """
        self.mock_request.headers = {"OIDC-Token": "fake-oidc-token"}
        self.mock_request.environ = {}

        with mock.patch.object(restcomm, "parse_oidc_token_claims") as mock_parse:
            mock_parse.return_value = ("testuser", ["reader"])

            ctx = restcomm.extract_context_from_environ()

            self.assertEqual(ctx.user, "testuser")
            self.assertEqual(ctx.project, "admin")
            self.assertEqual(ctx.user_name, "testuser")
            self.assertEqual(ctx.project_name, "admin")
            self.assertEqual(ctx.roles, ["reader"])
            self.assertFalse(ctx.is_admin)
            self.assertEqual(ctx.auth_type, "oidc")

    def test_oidc_admin_role_context_is_admin(self):
        """Test OIDC admin-role user gets is_admin=True."""
        self.mock_request.headers = {"OIDC-Token": "fake-oidc-token"}
        self.mock_request.environ = {}

        with mock.patch.object(restcomm, "parse_oidc_token_claims") as mock_parse:
            mock_parse.return_value = ("adminuser", ["admin", "reader"])

            ctx = restcomm.extract_context_from_environ()

            self.assertEqual(ctx.user, "adminuser")
            self.assertEqual(ctx.project, "admin")
            self.assertTrue(ctx.is_admin)

    def test_oidc_configurator_role_context_is_admin(self):
        """Test OIDC configurator-role user gets is_admin=True."""
        self.mock_request.headers = {"OIDC-Token": "fake-oidc-token"}
        self.mock_request.environ = {}

        with mock.patch.object(restcomm, "parse_oidc_token_claims") as mock_parse:
            mock_parse.return_value = ("cfguser", ["configurator", "reader"])

            ctx = restcomm.extract_context_from_environ()

            self.assertEqual(ctx.user, "cfguser")
            self.assertTrue(ctx.is_admin)

    def test_keystone_context_has_user_and_project(self):
        """Test Keystone auth path sets user and project from headers."""
        self.mock_request.headers = {"OIDC-Token": None}
        self.mock_request.environ = {
            "HTTP_X_AUTH_TOKEN": "fake-keystone-token",
            "HTTP_X_USER_ID": "user-uuid-123",
            "HTTP_X_TENANT_ID": "project-uuid-456",
            "HTTP_X_USER_NAME": "keystoneuser",
            "HTTP_X_PROJECT_NAME": "admin",
            "HTTP_X_DOMAIN_ID": "default-domain-id",
            "HTTP_X_ROLE": "admin,reader",
            "HTTP_X_USER_DOMAIN_ID": "default",
            "HTTP_X_PROJECT_DOMAIN_ID": "default",
            "openstack.request_id": "req-fake-123",
        }

        ctx = restcomm.extract_context_from_environ()

        self.assertEqual(ctx.user, "user-uuid-123")
        self.assertEqual(ctx.project, "project-uuid-456")
        self.assertEqual(ctx.user_name, "keystoneuser")
        self.assertTrue(ctx.is_admin)
        self.assertEqual(ctx.auth_type, "keystone")

    def test_keystone_takes_precedence_over_oidc(self):
        """Test that when both tokens are present, Keystone is used."""
        self.mock_request.headers = {"OIDC-Token": "fake-oidc-token"}
        self.mock_request.environ = {
            "HTTP_X_AUTH_TOKEN": "fake-keystone-token",
            "HTTP_X_USER_ID": "ks-user-id",
            "HTTP_X_TENANT_ID": "ks-project-id",
            "HTTP_X_USER_NAME": "ks-user",
            "HTTP_X_PROJECT_NAME": "admin",
            "HTTP_X_DOMAIN_ID": "default",
            "HTTP_X_ROLE": "reader",
            "HTTP_X_USER_DOMAIN_ID": "default",
            "HTTP_X_PROJECT_DOMAIN_ID": "default",
            "openstack.request_id": "req-fake-456",
        }

        ctx = restcomm.extract_context_from_environ()

        # Keystone should win
        self.assertEqual(ctx.auth_type, "keystone")
        self.assertEqual(ctx.user, "ks-user-id")
