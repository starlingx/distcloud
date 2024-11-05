# Copyright (c) 2021-2024 Wind River Systems, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#

import http.client
import json

from dcmanager.audit import rpcapi
from dcmanager.tests.unit.api.test_root_controller import DCManagerApiTest
from dcmanager.tests.unit.common import consts as test_consts


class BaseTestNotificationsController(DCManagerApiTest):
    """Base class for testing the NotificationsController"""

    def setUp(self):
        super().setUp()

        self.url = "/v1.0/notifications"
        self.mock_audit_rpc_client = self._mock_object(rpcapi, "ManagerAuditClient")


class TestNotificationsController(BaseTestNotificationsController):
    """Test class for NotificationsController"""

    def setUp(self):
        super().setUp()

    def test_unmapped_method(self):
        """Test requesting an unmapped method results in success with null content"""

        self.method = self.app.put

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(response.text, "null")


class TestNotificationsControllerPost(BaseTestNotificationsController):
    """Test class for post requests"""

    def setUp(self):
        super().setUp()

        self.method = self.app.post

    def test_post_succeeds_with_platform_upgrade_completed(self):
        """Test post succeeds with platform upgrade completed event"""

        self.params = json.dumps({"events": ["platform-upgrade-completed"]})

        response = self._send_request()

        self.mock_audit_rpc_client().trigger_load_audit.assert_called_once()

        self._assert_response(response)

    def test_post_succeeds_with_k8s_upgrade_completed(self):
        """Test post succeeds with k8s upgrade completed event"""

        self.params = json.dumps({"events": ["k8s-upgrade-completed"]})

        response = self._send_request()

        self.mock_audit_rpc_client().trigger_kubernetes_audit.assert_called_once()

        self._assert_response(response)

    def test_post_succeeds_with_kube_rootca_update_completed_in_events(self):
        """Tests post succeeds when kube-rootca-update-completed in events"""

        self.params = json.dumps({"events": ["kube-rootca-update-completed"]})

        response = self._send_request()

        trigger_kube_rootca_update_audit = (
            self.mock_audit_rpc_client().trigger_kube_rootca_update_audit
        )
        trigger_kube_rootca_update_audit.assert_called_once()

        self._assert_response(response)

    def test_post_fails_without_events_in_request_body(self):
        """Tests post fails when body doesn't have events"""

        self.params = json.dumps({})

        response = self._send_request()

        self._assert_response(
            response, http.client.BAD_REQUEST, content_type=test_consts.TEXT_PLAIN
        )
        self._assert_pecan(
            http.client.BAD_REQUEST, "Missing required notification events"
        )
