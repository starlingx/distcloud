# Copyright (c) 2020-2021, 2024-2025 Wind River Systems, Inc.
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

from dcmanager.audit import service
from dcmanager.tests.base import DCManagerTestCase


class BaseTestDCManagerAuditService(DCManagerTestCase):
    def setUp(self):
        super().setUp()

        self.mock_thread_group_manager = self._mock_object(service, "scheduler")
        self.mock_rpc_messaging = self._mock_object(service, "rpc_messaging")
        self.mock_log = self._mock_object(service, "LOG")


class TestDCManagerAuditService(BaseTestDCManagerAuditService):
    def setUp(self):
        super().setUp()

        self.service = service.DCManagerAuditService()
        self.mock_rpcapi = self._mock_object(service, "SubcloudAuditManager")

        self.service.start()

    def test_start(self):
        self.assertEqual(self.service.topic, "dcmanager-audit")
        self.mock_rpc_messaging.get_rpc_server.assert_called_once()
        self.mock_rpc_messaging.get_rpc_server().start.assert_called_once()

    def test_stop(self):
        self.mock_rpc_messaging.reset_mock()
        self.mock_thread_group_manager.reset_mock()

        self.service.stop()

        self.mock_rpc_messaging.get_rpc_server().stop.assert_called_once()
        self.mock_rpc_messaging.get_rpc_server().wait.assert_called_once()
        self.mock_thread_group_manager.ThreadGroupManager().stop.assert_called_once()
        calls = [
            mock.call("Engine service stopped successfully"),
            mock.call("All threads were gone, terminating engine"),
        ]
        self.mock_log.info.assert_has_calls(calls)

    def test_stop_without_defined_thread_group_manager(self):
        self.mock_rpc_messaging.reset_mock()
        self.mock_thread_group_manager.reset_mock()

        self.service.TG = None

        self.service.stop()

        self.mock_rpc_messaging.get_rpc_server().stop.assert_called_once()
        self.mock_rpc_messaging.get_rpc_server().wait.assert_called_once()
        self.mock_thread_group_manager.ThreadGroupManager().stop.assert_not_called()

    def test_stop_with_rpc_exception(self):
        self.mock_rpc_messaging.reset_mock()
        self.mock_thread_group_manager.reset_mock()

        self.mock_rpc_messaging.get_rpc_server().stop.side_effect = Exception()

        self.service.stop()

        self.mock_rpc_messaging.get_rpc_server().stop.assert_called_once()
        self.mock_rpc_messaging.get_rpc_server().wait.assert_not_called()
        self.mock_thread_group_manager.ThreadGroupManager().stop.assert_called_once()
        self.mock_log.error.assert_called_once_with(
            "Failed to stop engine service: %s", ""
        )
        self.mock_log.info.assert_called_once_with(
            "All threads were gone, terminating engine"
        )

    def _test_audit_trigger(self, audit_name):
        method_name = f"trigger_{audit_name}_audit"

        method = getattr(self.service, method_name)
        method(self.ctx)

        mock = getattr(self.mock_rpcapi(), method_name)
        mock.assert_called_once()

        # Kube RootCA will have its name with underscore, which is not expected
        audit_name = audit_name.replace("_", " ")
        self.mock_log.info.assert_called_once_with(f"Trigger {audit_name} audit.")

    def test_trigger_firmware_audit(self):
        self._test_audit_trigger("firmware")

    def test_trigger_kube_rootca_update_audit(self):
        self._test_audit_trigger("kube_rootca_update")

    def test_trigger_kubernetes_audit(self):
        self._test_audit_trigger("kubernetes")

    def test_trigger_software_audit(self):
        self._test_audit_trigger("software")

    def test_trigger_subcloud_audits(self):
        self.service.trigger_subcloud_audits(self.ctx, "fake", [])

        self.mock_rpcapi().trigger_subcloud_audits.assert_called_once_with(
            self.ctx, "fake", []
        )
        self.mock_log.info.asser_called_once_with(
            "Trigger all audits for subcloud %s except endpoints %s", "fake", []
        )

    def test_trigger_subcloud_endpoints_update(self):
        self.service.trigger_subcloud_endpoints_update(self.ctx, "fake", [])

        self.mock_rpcapi().trigger_subcloud_endpoints_update.assert_called_once_with(
            self.ctx, "fake", []
        )
        self.mock_log.info.asser_called_once_with(
            "Trigger update endpoints for subcloud %s", "fake"
        )


class DCManagerAuditWorkerService(BaseTestDCManagerAuditService):
    def setUp(self):
        super().setUp()

        self.service = service.DCManagerAuditWorkerService()
        self.mock_rpcacpi = self._mock_object(service, "SubcloudAuditWorkerManager")

        self.service.start()

    def test_start(self):
        self.assertEqual(self.service.topic, "dcmanager-audit-worker")
        self.mock_rpc_messaging.get_rpc_server.assert_called_once()
        self.mock_rpc_messaging.get_rpc_server().start.assert_called_once()

    def test_stop(self):
        self.mock_rpc_messaging.reset_mock()
        self.mock_thread_group_manager.reset_mock()

        self.service.stop()

        self.mock_rpc_messaging.get_rpc_server().stop.assert_called_once()
        self.mock_rpc_messaging.get_rpc_server().wait.assert_called_once()
        self.mock_thread_group_manager.ThreadGroupManager().stop.assert_called_once()
        calls = [
            mock.call("Audit-worker RPC service stopped successfully"),
            mock.call("All threads were gone, terminating audit-worker engine"),
        ]
        self.mock_log.info.assert_has_calls(calls)

    def test_stop_without_defined_thread_group_manager(self):
        self.mock_rpc_messaging.reset_mock()
        self.mock_thread_group_manager.reset_mock()

        self.service.TG = None

        self.service.stop()

        self.mock_rpc_messaging.get_rpc_server().stop.assert_called_once()
        self.mock_rpc_messaging.get_rpc_server().wait.assert_called_once()
        self.mock_thread_group_manager.ThreadGroupManager().stop.assert_not_called()

    def test_stop_with_rpc_exception(self):
        self.mock_rpc_messaging.reset_mock()
        self.mock_thread_group_manager.reset_mock()

        self.mock_rpc_messaging.get_rpc_server().stop.side_effect = Exception()

        self.service.stop()

        self.mock_rpc_messaging.get_rpc_server().stop.assert_called_once()
        self.mock_rpc_messaging.get_rpc_server().wait.assert_not_called()
        self.mock_thread_group_manager.ThreadGroupManager().stop.assert_called_once()
        self.mock_log.error.assert_called_once_with(
            "Failed to stop audit-worker RPC service: %s", ""
        )
        self.mock_log.info.assert_called_once_with(
            "All threads were gone, terminating audit-worker engine"
        )

    def test_audit_subclouds(self):
        self.service.audit_subclouds(self.ctx, 1, [], [], [], [], True)

        self.mock_rpcacpi().audit_subclouds.assert_called_once_with(
            self.ctx, 1, [], [], [], [], True
        )

    def test_update_subcloud_endpoints(self):
        self.service.update_subcloud_endpoints(self.ctx, "fake", [])

        self.mock_rpcacpi().update_subcloud_endpoints.assert_called_once_with(
            self.ctx, "fake", []
        )
