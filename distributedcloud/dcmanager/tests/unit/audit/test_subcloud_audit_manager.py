# Copyright (c) 2017-2024 Wind River Systems, Inc.
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

import sys

import mock

from dccommon import consts as dccommon_consts
from dcmanager.audit import subcloud_audit_manager
from dcmanager.common import consts
from dcmanager.db.sqlalchemy import api as db_api
from dcmanager.tests import base

sys.modules["fm_core"] = mock.Mock()


class FakeAuditWorkerAPI(object):

    def __init__(self):
        self.audit_subclouds = mock.MagicMock()
        self.update_subcloud_endpoints = mock.MagicMock()


class FakePatchAudit(object):

    def __init__(self):
        self.get_regionone_audit_data = mock.MagicMock()
        self.get_software_regionone_audit_data = mock.MagicMock()


class FakeFirmwareAudit(object):

    def __init__(self):
        self.get_regionone_audit_data = mock.MagicMock()


class FakeKubernetesAudit(object):

    def __init__(self):
        self.get_regionone_audit_data = mock.MagicMock()


class FakeKubeRootcaUpdateAudit(object):

    def __init__(self):
        self.get_regionone_audit_data = mock.MagicMock()


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


class TestAuditManager(base.DCManagerTestCase):
    def setUp(self):
        super(TestAuditManager, self).setUp()

        # Mock the Audit Worker API
        self.fake_audit_worker_api = FakeAuditWorkerAPI()
        p = mock.patch("dcmanager.audit.rpcapi.ManagerAuditWorkerClient")
        self.mock_audit_worker_api = p.start()
        self.mock_audit_worker_api.return_value = self.fake_audit_worker_api
        self.addCleanup(p.stop)

        # Mock the context
        p = mock.patch.object(subcloud_audit_manager, "context")
        self.mock_context = p.start()
        self.mock_context.get_admin_context.return_value = self.ctx
        self.addCleanup(p.stop)

        # Mock patch audit
        self.fake_patch_audit = FakePatchAudit()
        p = mock.patch.object(subcloud_audit_manager, "patch_audit")
        self.mock_patch_audit = p.start()
        self.mock_patch_audit.PatchAudit.return_value = self.fake_patch_audit
        self.addCleanup(p.stop)

        # Mock firmware audit
        self.fake_firmware_audit = FakeFirmwareAudit()
        p = mock.patch.object(subcloud_audit_manager, "firmware_audit")
        self.mock_firmware_audit = p.start()
        self.mock_firmware_audit.FirmwareAudit.return_value = self.fake_firmware_audit
        self.addCleanup(p.stop)

        # Mock kubernetes audit
        self.fake_kubernetes_audit = FakeKubernetesAudit()
        p = mock.patch.object(subcloud_audit_manager, "kubernetes_audit")
        self.mock_kubernetes_audit = p.start()
        self.mock_kubernetes_audit.KubernetesAudit.return_value = (
            self.fake_kubernetes_audit
        )
        self.addCleanup(p.stop)

        # Mock kube rootca update audit
        self.fake_kube_rootca_update_audit = FakeKubeRootcaUpdateAudit()
        p = mock.patch.object(subcloud_audit_manager, "kube_rootca_update_audit")
        self.mock_kube_rootca_update_audit = p.start()
        self.mock_kubernetes_audit.KubeRootcaUpdateAudit.return_value = (
            self.fake_kube_rootca_update_audit
        )
        self.addCleanup(p.stop)

    @staticmethod
    def create_subcloud_static(ctxt, **kwargs):
        values = {
            "name": "subcloud1",
            "description": "This is a subcloud",
            "location": "This is the location of the subcloud",
            "software_version": "10.04",
            "management_subnet": "192.168.101.0/24",
            "management_gateway_ip": "192.168.101.1",
            "management_start_ip": "192.168.101.2",
            "management_end_ip": "192.168.101.50",
            "systemcontroller_gateway_ip": "192.168.204.101",
            "external_oam_subnet_ip_family": "4",
            "deploy_status": "not-deployed",
            "error_description": "No errors present",
            "region_name": base.SUBCLOUD_1["region_name"],
            "openstack_installed": False,
            "group_id": 1,
        }
        values.update(kwargs)
        return db_api.subcloud_create(ctxt, **values)

    def test_init(self):
        am = subcloud_audit_manager.SubcloudAuditManager()
        self.assertIsNotNone(am)
        self.assertEqual("subcloud_audit_manager", am.service_name)
        self.assertEqual("localhost", am.host)
        self.assertEqual(self.ctx, am.context)

    def test_periodic_subcloud_audit(self):
        am = subcloud_audit_manager.SubcloudAuditManager()
        am._periodic_subcloud_audit_loop()

    @mock.patch.object(subcloud_audit_manager.db_api, "subcloud_audits_bulk_end_audit")
    def test_skip_subcloud_audit(self, mock_subcloud_audits_bulk_end_audit):
        subcloud = self.create_subcloud_static(self.ctx)
        am = subcloud_audit_manager.SubcloudAuditManager()
        subcloud = db_api.subcloud_update(
            self.ctx,
            subcloud.id,
            management_state="unmanaged",
            availability_status=dccommon_consts.AVAILABILITY_OFFLINE,
            deploy_status=consts.DEPLOY_STATE_CREATED,
        )
        am._periodic_subcloud_audit_loop()
        # Verify that the audit is skipped
        mock_subcloud_audits_bulk_end_audit.assert_called_once()

    def test_audit_one_subcloud(self):
        subcloud = self.create_subcloud_static(self.ctx)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.trigger_subcloud_audits(self.ctx, subcloud.id, None)
        # Subaudits should be requested.
        result = db_api.subcloud_audits_get(self.ctx, subcloud.id)
        self.assertEqual(result["patch_audit_requested"], True)
        self.assertEqual(result["firmware_audit_requested"], True)
        self.assertEqual(result["load_audit_requested"], True)
        self.assertEqual(result["kubernetes_audit_requested"], True)
        self.assertEqual(result["kube_rootca_update_audit_requested"], True)

    def test_audit_one_subcloud_exclude_endpoints(self):
        subcloud = self.create_subcloud_static(self.ctx)
        am = subcloud_audit_manager.SubcloudAuditManager()
        exclude_endpoints = [
            dccommon_consts.ENDPOINT_TYPE_PATCHING,
            dccommon_consts.ENDPOINT_TYPE_LOAD,
        ]
        am.trigger_subcloud_audits(self.ctx, subcloud.id, exclude_endpoints)
        # Verify subaudits be requested.
        result = db_api.subcloud_audits_get(self.ctx, subcloud.id)
        self.assertEqual(result["patch_audit_requested"], False)
        self.assertEqual(result["firmware_audit_requested"], True)
        self.assertEqual(result["load_audit_requested"], False)
        self.assertEqual(result["kubernetes_audit_requested"], True)
        self.assertEqual(result["kube_rootca_update_audit_requested"], True)

    def test_trigger_load_audit(self):
        subcloud = self.create_subcloud_static(self.ctx)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.trigger_load_audit(self.ctx)
        # Load audit should be requested.
        result = db_api.subcloud_audits_get(self.ctx, subcloud.id)
        self.assertEqual(result["patch_audit_requested"], False)
        self.assertEqual(result["load_audit_requested"], True)

    def test_trigger_one_subcloud_patch_load_audits(self):
        subcloud = self.create_subcloud_static(self.ctx)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.trigger_subcloud_patch_load_audits(self.ctx, subcloud.id)
        # Subcloud patch and load audits should be requested.
        result = db_api.subcloud_audits_get(self.ctx, subcloud.id)
        self.assertEqual(result["patch_audit_requested"], True)
        self.assertEqual(result["load_audit_requested"], True)
        # Other audits should not be requested
        self.assertEqual(result["firmware_audit_requested"], False)
        self.assertEqual(result["kubernetes_audit_requested"], False)
        self.assertEqual(result["kube_rootca_update_audit_requested"], False)
