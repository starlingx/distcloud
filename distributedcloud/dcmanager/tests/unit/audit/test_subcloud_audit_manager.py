# Copyright (c) 2017-2025 Wind River Systems, Inc.
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

import os
import sys

import mock

from dccommon import consts as dccommon_consts
from dcmanager.audit import rpcapi
from dcmanager.audit import subcloud_audit_manager
from dcmanager.db import api as db_api
from dcmanager.tests.base import DCManagerTestCase
from dcmanager.tests.unit.common.fake_subcloud import create_fake_subcloud

sys.modules["fm_core"] = mock.Mock()


class FakeServiceGroup(object):
    def __init__(
        self,
        status,
        desired_state,
        service_group_name,
        uuid,
        node_name,
        state,
        condition,
        name,
    ):
        self.status = status
        self.desired_state = desired_state
        self.service_group_name = service_group_name
        self.uuid = uuid
        self.node_name = node_name
        self.state = state
        self.condition = condition
        self.name = name


class FakeApplication(object):
    def __init__(
        self, status, name, manifest_name, active, progress, app_version, manifest_file
    ):
        self.status = status
        self.name = name
        self.manifest_name = manifest_name
        self.active = active
        self.progress = progress
        self.app_version = app_version
        self.manifest_file = manifest_file


FAKE_SERVICE_GROUPS = [
    FakeServiceGroup(
        "",
        "active",
        "distributed-cloud-services",
        "b00fd252-5bd7-44b5-bbde-7d525e7125c7",
        "controller-0",
        "active",
        "",
        "controller",
    ),
    FakeServiceGroup(
        "",
        "active",
        "storage-monitoring-services",
        "5a14a1d1-dac1-48b0-9598-3702e0b0338a",
        "controller-0",
        "active",
        "",
        "controller",
    ),
    FakeServiceGroup(
        "",
        "active",
        "storage-services",
        "5cbfa903-379f-4329-81b4-2e88acdfa215",
        "controller-0",
        "active",
        "",
        "controller",
    ),
    FakeServiceGroup(
        "",
        "active",
        "web-services",
        "42829858-008f-4931-94e1-4b86fe31ce3c",
        "controller-0",
        "active",
        "",
        "controller",
    ),
    FakeServiceGroup(
        "",
        "active",
        "directory-services",
        "74225295-2601-4376-a52c-7cbd149146f6",
        "controller-0",
        "active",
        "",
        "controller",
    ),
    FakeServiceGroup(
        "",
        "active",
        "patching-services",
        "6870c079-e1c3-4402-b88b-63a5ef06a77a",
        "controller-0",
        "active",
        "",
        "controller",
    ),
    FakeServiceGroup(
        "",
        "active",
        "vim-services",
        "d8367a52-316e-418b-9211-a13331e073ef",
        "controller-0",
        "active",
        "",
        "controller",
    ),
    FakeServiceGroup(
        "",
        "active",
        "cloud-services",
        "12682dc0-cef5-427a-b1a6-145cf950b49c",
        "controller-0",
        "active",
        "",
        "controller",
    ),
    FakeServiceGroup(
        "",
        "active",
        "controller-services",
        "daac63fb-24b3-4cd1-b895-260a32e356ae",
        "controller-0",
        "active",
        "",
        "controller",
    ),
    FakeServiceGroup(
        "",
        "active",
        "oam-services",
        "4b66913d-98ba-4a4a-86c3-168625f629eb",
        "controller-0",
        "active",
        "",
        "controller",
    ),
]

FAKE_APPLICATIONS = [
    FakeApplication(
        "applied",
        "platform-integ-apps",
        "platform-integration-manifest",
        True,
        "completed",
        "1.0-8",
        "manifest.yaml",
    ),
    FakeApplication(
        "applied",
        "stx-openstack",
        "stx-openstack-manifest",
        True,
        "completed",
        "1.0-8",
        "manifest.yaml",
    ),
]


class FakeSysinvClient(object):

    def __init__(self, region, session):
        self.get_service_groups_result = FAKE_SERVICE_GROUPS
        self.get_applications_result = FAKE_APPLICATIONS

    def get_service_groups(self):
        return self.get_service_groups_result

    def get_applications(self):
        return self.get_applications_result


class FakeFmClient(object):

    def get_alarm_summary(self):
        pass


class FakeOpenStackDriver(object):

    def __init__(self, region_name):
        self.sysinv_client = FakeSysinvClient("fake_region", "fake_session")
        self.fm_client = FakeFmClient()


class TestSubcloudAuditManager(DCManagerTestCase):
    def setUp(self):
        super().setUp()

        # Mock the Audit Worker API
        self.mock_audit_worker_api = self._mock_object(
            rpcapi, "ManagerAuditWorkerClient"
        )

        # Mock the context
        self.mock_context = self._mock_object(subcloud_audit_manager, "context")
        self.mock_context.get_admin_context.return_value = self.ctx

        self.mock_firmware_audit = self._mock_object(
            subcloud_audit_manager, "firmware_audit"
        )
        self.mock_kubernetes_audit = self._mock_object(
            subcloud_audit_manager, "kubernetes_audit"
        )
        self.mock_kube_rootca_update_audit = self._mock_object(
            subcloud_audit_manager, "kube_rootca_update_audit"
        )
        self.mock_software_audit = self._mock_object(
            subcloud_audit_manager, "software_audit"
        )

        self.mock_os_path = self._mock_object(os, "path")
        self.mock_eventlet = self._mock_object(subcloud_audit_manager, "eventlet")
        self.mock_db = self._mock_object(
            subcloud_audit_manager, "db_api", subcloud_audit_manager.db_api
        )

        self.subcloud_audit_manager = subcloud_audit_manager.SubcloudAuditManager()

        self.subcloud = create_fake_subcloud(self.ctx)

    def _test_trigger_and_reset_audit(self, audit_name, mock):
        """Test triggering and resetting a force audit flag

        The method is dynamically retrieved and called, checking the resulting value
        in the flag.
        """

        suffix = f"{audit_name}_audit"

        for action in ["trigger", "reset_force"]:
            method = getattr(self.subcloud_audit_manager, f"{action}_{suffix}")

            if action == "trigger":
                method(self.ctx)
                expected = True
            else:
                method()
                expected = False

            flag = getattr(self.subcloud_audit_manager, f"force_{suffix}")
            self.assertEqual(expected, flag)

    def test_force_firmware_audit(self):
        self._test_trigger_and_reset_audit("firmware", self.mock_firmware_audit)

    def test_force_kubernets_audit(self):
        self._test_trigger_and_reset_audit("kubernetes", self.mock_kubernetes_audit)

    def test_force_kube_rootca_update_audit(self):
        self._test_trigger_and_reset_audit(
            "kube_rootca_update", self.mock_kube_rootca_update_audit
        )

    def test_force_software_audit(self):
        self._test_trigger_and_reset_audit("software", self.mock_software_audit)

    def test_skip_subcloud_audit(self):
        self.subcloud = db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            management_state="unmanaged",
            availability_status=dccommon_consts.AVAILABILITY_OFFLINE,
        )
        self.subcloud_audit_manager.trigger_firmware_audit(self.ctx)

        self.subcloud_audit_manager._periodic_subcloud_audit_loop()

        # Verify that the audit is called
        self.mock_db.subcloud_audits_bulk_update_audit_finished_at.assert_called_once()

    def test_trigger_subcloud_audits_without_exclusion(self):
        self.subcloud_audit_manager.trigger_subcloud_audits(
            self.ctx, self.subcloud.id, None
        )

        # Subaudits should be requested.
        result = db_api.subcloud_audits_get(self.ctx, self.subcloud.id)

        for audit_requested in dccommon_consts.ENDPOINT_AUDIT_REQUESTS.values():
            self.assertTrue(result[audit_requested])

    def test_trigger_subcloud_audits_with_exclusion(self):
        self.subcloud_audit_manager.trigger_subcloud_audits(
            self.ctx,
            self.subcloud.id,
            [
                dccommon_consts.ENDPOINT_TYPE_IDENTITY,
                dccommon_consts.ENDPOINT_TYPE_FIRMWARE,
            ],
        )

        # Subaudits should be requested.
        result = db_api.subcloud_audits_get(self.ctx, self.subcloud.id)

        for endpoint, audit in dccommon_consts.ENDPOINT_AUDIT_REQUESTS.items():
            if endpoint == dccommon_consts.ENDPOINT_TYPE_FIRMWARE:
                self.assertFalse(result[audit])
                continue

            self.assertTrue(result[audit])
