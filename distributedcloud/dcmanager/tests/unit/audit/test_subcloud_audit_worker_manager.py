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

import copy
import random
import sys

import mock

from dccommon import consts as dccommon_consts
from dccommon.endpoint_cache import EndpointCache
from dcmanager.audit import rpcapi
from dcmanager.audit import subcloud_audit_manager
from dcmanager.audit import subcloud_audit_worker_manager
from dcmanager.common import consts
from dcmanager.common import scheduler
from dcmanager.db import api as db_api
from dcmanager.rpc import client as rpc_client
from dcmanager.tests import base
from dcorch.rpc import client as dcorch_rpc_client

sys.modules["fm_core"] = mock.Mock()


class FakeDCManagerAPI(object):

    def __init__(self):
        self.update_subcloud_sync_endpoint_type = mock.MagicMock()


class FakeAuditWorkerAPI(object):

    def __init__(self):
        self.audit_subclouds = mock.MagicMock()


class FakeDCOrchWorkerAPI(object):

    def __init__(self):
        self.update_subcloud_version = mock.MagicMock()


class FakeAlarmAggregation(object):

    def __init__(self):
        self.update_alarm_summary = mock.MagicMock()


class FakeFirmwareAudit(object):

    def __init__(self):
        self.get_regionone_audit_data = mock.MagicMock()


class FakeKubernetesAudit(object):

    def __init__(self):
        self.get_regionone_audit_data = mock.MagicMock()


class FakeKubeRootcaUpdateAudit(object):

    def __init__(self):
        self.get_regionone_audit_data = mock.MagicMock()


class FakeSoftwareAudit(object):

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


class TestAuditWorkerManager(base.DCManagerTestCase):
    def setUp(self):
        super().setUp()

        # Mock the DCManager API
        self.mock_dcmanager_api = self._mock_object(rpc_client, "ManagerClient")
        self.mock_dcmanager_api().return_value = FakeDCManagerAPI()

        # Mock the admin session
        self._mock_object(EndpointCache, "get_admin_session")

        # Mock the DCManager subcloud state API
        self.mock_dcmanager_state_api = self._mock_object(
            rpc_client, "SubcloudStateClient"
        )

        # Mock the Audit Worker API
        self.mock_audit_worker_api = self._mock_object(
            rpcapi, "ManagerAuditWorkerClient"
        )
        self.mock_audit_worker_api.return_value = FakeAuditWorkerAPI()

        # Mock the DCOrch Worker API
        self.mock_dcorch_worker_api = self._mock_object(
            dcorch_rpc_client, "EngineWorkerClient"
        )
        self.mock_dcorch_worker_api.return_value = FakeDCOrchWorkerAPI()

        # Mock the context
        self.mock_audit_worker_manager_context = self._mock_object(
            subcloud_audit_worker_manager, "context"
        )
        self.mock_audit_worker_manager_context.get_admin_context.return_value = self.ctx

        # Mock the context
        self.mock_subcloud_audit_manager_context = self._mock_object(
            subcloud_audit_manager, "context"
        )
        self.mock_subcloud_audit_manager_context.get_admin_context.return_value = (
            self.ctx
        )

        # Mock alarm aggregation
        self.mock_alarm_aggr = self._mock_object(
            subcloud_audit_worker_manager.alarm_aggregation, "AlarmAggregation"
        )
        self.mock_alarm_aggr().return_value = FakeAlarmAggregation()

        # Mock all audits
        self.fake_firmware_audit = FakeFirmwareAudit()
        self.fake_kubernetes_audit = FakeKubernetesAudit()
        self.fake_kube_rootca_update_audit = FakeKubeRootcaUpdateAudit()
        self.fake_software_audit = FakeSoftwareAudit()

        audits = {
            "firmware_audit": {
                "value": self.fake_firmware_audit,
                "class": "FirmwareAudit",
            },
            "kubernetes_audit": {
                "value": self.fake_kubernetes_audit,
                "class": "KubernetesAudit",
            },
            "kube_rootca_update_audit": {
                "value": self.fake_kube_rootca_update_audit,
                "class": "KubeRootcaUpdateAudit",
            },
            "software_audit": {
                "value": self.fake_software_audit,
                "class": "SoftwareAudit",
            },
        }

        for key, value in audits.items():
            self.temporary_mock = self._mock_object(subcloud_audit_worker_manager, key)
            getattr(self.temporary_mock, value["class"]).return_value = value["value"]

            self.temporary_mock = self._mock_object(subcloud_audit_manager, key)
            getattr(self.temporary_mock, value["class"]).return_value = value["value"]

        self.mock_dcagent_client = self._mock_object(
            subcloud_audit_worker_manager, "DcagentClient"
        )

        state_api = self.mock_dcmanager_state_api()
        self.update_subcloud_availability_and_endpoint_status = (
            state_api.bulk_update_subcloud_availability_and_endpoint_status
        )

        self.availability_data = dict()
        self.endpoint_data = dict()

    def _update_availability(
        self, availability_status, update_status_only, audit_fail_count
    ):
        self.availability_data.update(
            {
                "availability_status": availability_status,
                "update_state_only": update_status_only,
                "audit_fail_count": audit_fail_count,
            }
        )

    def _set_all_audits_in_sync(self):
        # Reassign constants to avoid line too long
        FIRMWARE = dccommon_consts.ENDPOINT_TYPE_FIRMWARE
        KUBERNETES = dccommon_consts.ENDPOINT_TYPE_KUBERNETES
        KUBE_ROOTCA = dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA
        SOFTWARE = dccommon_consts.AUDIT_TYPE_SOFTWARE

        self.endpoint_data.update(
            {
                FIRMWARE: dccommon_consts.SYNC_STATUS_IN_SYNC,
                KUBERNETES: dccommon_consts.SYNC_STATUS_IN_SYNC,
                KUBE_ROOTCA: dccommon_consts.SYNC_STATUS_IN_SYNC,
                SOFTWARE: dccommon_consts.SYNC_STATUS_IN_SYNC,
            }
        )

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
        am = subcloud_audit_worker_manager.SubcloudAuditWorkerManager()
        self.assertIsNotNone(am)
        self.assertEqual("subcloud_audit_worker_manager", am.service_name)
        self.assertEqual("localhost", am.host)
        self.assertEqual(self.ctx, am.context)

    def test_audit_subcloud_online_managed(self):
        self.mock_dcagent_client().audit.return_value = {
            dccommon_consts.BASE_AUDIT: {
                "availability": dccommon_consts.AVAILABILITY_ONLINE
            },
            dccommon_consts.FIRMWARE_AUDIT: dccommon_consts.SYNC_STATUS_IN_SYNC,
            dccommon_consts.KUBERNETES_AUDIT: dccommon_consts.SYNC_STATUS_IN_SYNC,
            dccommon_consts.KUBE_ROOTCA_AUDIT: dccommon_consts.SYNC_STATUS_IN_SYNC,
            dccommon_consts.SOFTWARE_AUDIT: dccommon_consts.SYNC_STATUS_IN_SYNC,
        }

        subcloud = self.create_subcloud_static(self.ctx, name="subcloud1")
        self.assertIsNotNone(subcloud)

        # Set the subcloud to managed
        subcloud = db_api.subcloud_update(
            self.ctx,
            subcloud.id,
            management_state="managed",
            first_identity_sync_complete=True,
        )

        am = subcloud_audit_manager.SubcloudAuditManager()
        wm = subcloud_audit_worker_manager.SubcloudAuditWorkerManager()

        # Audit the subcloud
        update_subcloud_state = False
        do_firmware_audit = True
        do_kubernetes_audit = True
        do_kube_rootca_update_audit = True
        do_software_audit = True
        use_cache = True
        (
            firmware_audit_data,
            kubernetes_audit_data,
            kube_rootca_update_audit_data,
            software_audit_data,
        ) = am._get_audit_data(
            do_firmware_audit,
            do_kubernetes_audit,
            do_kube_rootca_update_audit,
            do_software_audit,
        )
        # Convert to dict like what would happen calling via RPC
        # Note: the other data should also be converted...
        wm._audit_subcloud(
            subcloud,
            update_subcloud_state,
            firmware_audit_data,
            kubernetes_audit_data,
            kube_rootca_update_audit_data,
            software_audit_data,
            do_firmware_audit,
            do_kubernetes_audit,
            do_kube_rootca_update_audit,
            do_software_audit,
            use_cache,
        )

        # Verify the subcloud was set to online
        self._update_availability(dccommon_consts.AVAILABILITY_ONLINE, False, 0)
        self._set_all_audits_in_sync()
        self.update_subcloud_availability_and_endpoint_status.assert_called_once_with(
            mock.ANY,
            subcloud.id,
            subcloud.name,
            self.availability_data,
            self.endpoint_data,
        )

        # Verify the _update_subcloud_audit_fail_count is not called
        with mock.patch.object(
            wm, "_update_subcloud_audit_fail_count"
        ) as mock_update_subcloud_audit_fail_count:
            mock_update_subcloud_audit_fail_count.assert_not_called()

        # Verify alarm update is called
        self.mock_alarm_aggr().update_alarm_summary.assert_not_called()

    def test_audit_subcloud_online_first_identity_sync_not_complete(self):
        self.mock_dcagent_client().audit.return_value = {
            dccommon_consts.BASE_AUDIT: {
                "availability": dccommon_consts.AVAILABILITY_ONLINE
            },
        }

        subcloud = self.create_subcloud_static(self.ctx, name="subcloud1")
        self.assertIsNotNone(subcloud)

        # Set the subcloud to managed
        subcloud = db_api.subcloud_update(
            self.ctx, subcloud.id, management_state="managed"
        )

        am = subcloud_audit_manager.SubcloudAuditManager()
        wm = subcloud_audit_worker_manager.SubcloudAuditWorkerManager()

        # Audit the subcloud
        update_subcloud_state = False
        do_firmware_audit = True
        do_kubernetes_audit = True
        do_kube_rootca_update_audit = True
        do_software_audit = True
        use_cache = True
        (
            firmware_audit_data,
            kubernetes_audit_data,
            kube_rootca_update_audit_data,
            software_audit_data,
        ) = am._get_audit_data(
            do_firmware_audit,
            do_kubernetes_audit,
            do_kube_rootca_update_audit,
            do_software_audit,
        )
        # Convert to dict like what would happen calling via RPC
        # Note: the other data should also be converted...
        wm._audit_subcloud(
            subcloud,
            update_subcloud_state,
            firmware_audit_data,
            kubernetes_audit_data,
            kube_rootca_update_audit_data,
            software_audit_data,
            do_firmware_audit,
            do_kubernetes_audit,
            do_kube_rootca_update_audit,
            do_software_audit,
            use_cache,
        )

        # Verify the subcloud was set to online
        self._update_availability(dccommon_consts.AVAILABILITY_ONLINE, False, 0)
        self.update_subcloud_availability_and_endpoint_status.assert_called_with(
            mock.ANY,
            subcloud.id,
            subcloud.name,
            self.availability_data,
            self.endpoint_data,
        )

        # Verify the _update_subcloud_audit_fail_count is not called
        with mock.patch.object(
            wm, "_update_subcloud_audit_fail_count"
        ) as mock_update_subcloud_audit_fail_count:
            mock_update_subcloud_audit_fail_count.assert_not_called()

        # Verify alarm update is not called
        self.mock_alarm_aggr().update_alarm_summary.assert_not_called()

    def test_audit_subcloud_online_unmanaged(self):
        self.mock_dcagent_client().audit.return_value = {
            dccommon_consts.BASE_AUDIT: {
                "availability": dccommon_consts.AVAILABILITY_ONLINE
            }
        }

        subcloud = self.create_subcloud_static(self.ctx, name="subcloud1")
        self.assertIsNotNone(subcloud)

        am = subcloud_audit_manager.SubcloudAuditManager()
        wm = subcloud_audit_worker_manager.SubcloudAuditWorkerManager()

        # Audit the subcloud
        update_subcloud_state = False
        do_firmware_audit = True
        do_kubernetes_audit = True
        do_kube_rootca_update_audit = True
        do_software_audit = True
        use_cache = True
        (
            firmware_audit_data,
            kubernetes_audit_data,
            kube_rootca_update_audit_data,
            software_audit_data,
        ) = am._get_audit_data(
            do_firmware_audit,
            do_kubernetes_audit,
            do_kube_rootca_update_audit,
            do_software_audit,
        )
        # Convert to dict like what would happen calling via RPC
        # Note: the other data should also be converted...
        wm._audit_subcloud(
            subcloud,
            update_subcloud_state,
            firmware_audit_data,
            kubernetes_audit_data,
            kube_rootca_update_audit_data,
            software_audit_data,
            do_firmware_audit,
            do_kubernetes_audit,
            do_kube_rootca_update_audit,
            do_software_audit,
            use_cache,
        )

        # Verify the subcloud was set to online
        self._update_availability(dccommon_consts.AVAILABILITY_ONLINE, False, 0)
        self.update_subcloud_availability_and_endpoint_status.assert_called_with(
            mock.ANY,
            subcloud.id,
            subcloud.name,
            self.availability_data,
            self.endpoint_data,
        )

        # Verify the _update_subcloud_audit_fail_count is not called
        with mock.patch.object(
            wm, "_update_subcloud_audit_fail_count"
        ) as mock_update_subcloud_audit_fail_count:
            mock_update_subcloud_audit_fail_count.assert_not_called()

        # Verify alarm update is not called
        self.mock_alarm_aggr().update_alarm_summary.assert_not_called()

    def test_audit_subcloud_online_no_change(self):

        subcloud = self.create_subcloud_static(self.ctx, name="subcloud1")
        self.assertIsNotNone(subcloud)

        wm = subcloud_audit_worker_manager.SubcloudAuditWorkerManager()

        # Set the subcloud to online
        subcloud = db_api.subcloud_update(
            self.ctx,
            subcloud.id,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
        )

        # Audit the subcloud
        wm._audit_subcloud(
            subcloud,
            update_subcloud_state=False,
            firmware_audit_data=None,
            kubernetes_audit_data=None,
            kube_rootca_update_audit_data=None,
            software_audit_data=None,
            do_firmware_audit=False,
            do_kubernetes_audit=False,
            do_kube_rootca_update_audit=False,
            do_software_audit=False,
            use_cache=True,
        )

        # Verify the subcloud state was not updated
        self.update_subcloud_availability_and_endpoint_status.assert_not_called()

        # Verify the _update_subcloud_audit_fail_count is not called
        with mock.patch.object(
            wm, "_update_subcloud_audit_fail_count"
        ) as mock_update_subcloud_audit_fail_count:
            mock_update_subcloud_audit_fail_count.assert_not_called()

        # Verify alarm update is not called
        self.mock_alarm_aggr().update_alarm_summary.assert_not_called()

    def test_audit_subcloud_online_no_change_force_update(self):
        self.mock_dcagent_client().audit.return_value = {
            dccommon_consts.BASE_AUDIT: {
                "availability": dccommon_consts.AVAILABILITY_ONLINE
            }
        }

        subcloud = self.create_subcloud_static(self.ctx, name="subcloud1")
        self.assertIsNotNone(subcloud)

        wm = subcloud_audit_worker_manager.SubcloudAuditWorkerManager()

        # Set the subcloud to online
        subcloud = db_api.subcloud_update(
            self.ctx,
            subcloud.id,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
        )

        # Audit the subcloud and force a state update
        wm._audit_subcloud(
            subcloud,
            update_subcloud_state=True,
            firmware_audit_data=None,
            kubernetes_audit_data=None,
            kube_rootca_update_audit_data=None,
            software_audit_data=None,
            do_firmware_audit=False,
            do_kubernetes_audit=False,
            do_kube_rootca_update_audit=False,
            do_software_audit=False,
            use_cache=True,
        )

        # Verify the subcloud state was updated
        self._update_availability(dccommon_consts.AVAILABILITY_ONLINE, True, None)
        self.update_subcloud_availability_and_endpoint_status.assert_called_with(
            mock.ANY,
            subcloud.id,
            subcloud.name,
            self.availability_data,
            self.endpoint_data,
        )

        # Verify the _update_subcloud_audit_fail_count is not called
        with mock.patch.object(
            wm, "_update_subcloud_audit_fail_count"
        ) as mock_update_subcloud_audit_fail_count:
            mock_update_subcloud_audit_fail_count.assert_not_called()

        # Verify alarm update is not called
        self.mock_alarm_aggr().update_alarm_summary.assert_not_called()

    def test_audit_subcloud_go_offline(self):
        self.mock_dcagent_client().audit.return_value = {
            dccommon_consts.BASE_AUDIT: {
                "availability": dccommon_consts.AVAILABILITY_OFFLINE,
                "alarms": "Fake",
            },
            dccommon_consts.FIRMWARE_AUDIT: dccommon_consts.SYNC_STATUS_IN_SYNC,
            dccommon_consts.KUBERNETES_AUDIT: dccommon_consts.SYNC_STATUS_IN_SYNC,
            dccommon_consts.KUBE_ROOTCA_AUDIT: dccommon_consts.SYNC_STATUS_IN_SYNC,
            dccommon_consts.SOFTWARE_AUDIT: dccommon_consts.SYNC_STATUS_IN_SYNC,
        }

        subcloud = self.create_subcloud_static(self.ctx, name="subcloud1")
        self.assertIsNotNone(subcloud)

        am = subcloud_audit_manager.SubcloudAuditManager()
        wm = subcloud_audit_worker_manager.SubcloudAuditWorkerManager()

        # Set the subcloud to managed/online
        subcloud = db_api.subcloud_update(
            self.ctx,
            subcloud.id,
            management_state="managed",
            first_identity_sync_complete=True,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
        )

        # Mark a service group as inactive
        service_groups = copy.deepcopy(FAKE_SERVICE_GROUPS)
        service_groups[3].state = "inactive"

        # Audit the subcloud
        do_firmware_audit = True
        do_kubernetes_audit = True
        do_kube_rootca_update_audit = True
        do_software_audit = True
        (
            firmware_audit_data,
            kubernetes_audit_data,
            kube_rootca_update_audit_data,
            software_audit_data,
        ) = am._get_audit_data(
            do_firmware_audit,
            do_kubernetes_audit,
            do_kube_rootca_update_audit,
            do_software_audit,
        )
        # Convert to dict like what would happen calling via RPC
        wm._audit_subcloud(
            subcloud,
            update_subcloud_state=False,
            firmware_audit_data=firmware_audit_data,
            kubernetes_audit_data=kubernetes_audit_data,
            kube_rootca_update_audit_data=kube_rootca_update_audit_data,
            software_audit_data=software_audit_data,
            do_firmware_audit=do_firmware_audit,
            do_kubernetes_audit=do_kubernetes_audit,
            do_kube_rootca_update_audit=do_kube_rootca_update_audit,
            do_software_audit=do_software_audit,
            use_cache=True,
        )

        # Verify alarm update is called once
        self.mock_alarm_aggr().update_alarm_summary.assert_called_once()

        # Verify the audit fail count was updated in db
        audit_fail_count = 1
        subcloud = db_api.subcloud_get(self.ctx, subcloud.id)
        self.assertEqual(subcloud.audit_fail_count, audit_fail_count)

        # Verify the state was called only for the audits
        self._set_all_audits_in_sync()
        self.update_subcloud_availability_and_endpoint_status.assert_called_once_with(
            mock.ANY,
            subcloud.id,
            subcloud.name,
            self.availability_data,
            self.endpoint_data,
        )

        # Update the DB like dcmanager would do.
        subcloud = db_api.subcloud_update(
            self.ctx,
            subcloud.id,
            availability_status=dccommon_consts.AVAILABILITY_OFFLINE,
            audit_fail_count=audit_fail_count,
        )

        # Audit the subcloud again
        wm._audit_subcloud(
            subcloud,
            update_subcloud_state=False,
            firmware_audit_data=firmware_audit_data,
            kubernetes_audit_data=kubernetes_audit_data,
            kube_rootca_update_audit_data=kube_rootca_update_audit_data,
            software_audit_data=software_audit_data,
            do_firmware_audit=do_firmware_audit,
            do_kubernetes_audit=do_kubernetes_audit,
            do_kube_rootca_update_audit=do_kube_rootca_update_audit,
            do_software_audit=do_software_audit,
            use_cache=True,
        )

        audit_fail_count = audit_fail_count + 1

        # Verify the audit fail count was updated in db
        subcloud = db_api.subcloud_get(self.ctx, subcloud.id)
        self.assertEqual(subcloud.audit_fail_count, audit_fail_count)

        # Verify the subcloud state was not called again
        self.assertEqual(
            self.update_subcloud_availability_and_endpoint_status.call_count, 2
        )

        # Verify alarm update is called
        self.assertEqual(self.mock_alarm_aggr().update_alarm_summary.call_count, 2)

    def test_audit_subcloud_offline_no_change(self):
        subcloud = self.create_subcloud_static(self.ctx, name="subcloud1")
        self.assertIsNotNone(subcloud)

        am = subcloud_audit_manager.SubcloudAuditManager()
        wm = subcloud_audit_worker_manager.SubcloudAuditWorkerManager()

        subcloud = db_api.subcloud_update(
            self.ctx, subcloud.id, audit_fail_count=consts.AVAIL_FAIL_COUNT_MAX
        )

        # Mark a service group as inactive
        service_groups = copy.deepcopy(FAKE_SERVICE_GROUPS)
        service_groups[3].state = "inactive"

        # Audit the subcloud
        do_firmware_audit = True
        do_kubernetes_audit = True
        do_kube_rootca_update_audit = True
        do_software_audit = True
        (
            firmware_audit_data,
            kubernetes_audit_data,
            kube_rootca_update_audit_data,
            software_audit_data,
        ) = am._get_audit_data(
            do_firmware_audit,
            do_kubernetes_audit,
            do_kube_rootca_update_audit,
            do_software_audit,
        )
        # Convert to dict like what would happen calling via RPC
        wm._audit_subcloud(
            subcloud,
            update_subcloud_state=False,
            firmware_audit_data=firmware_audit_data,
            kubernetes_audit_data=kubernetes_audit_data,
            kube_rootca_update_audit_data=kube_rootca_update_audit_data,
            software_audit_data=software_audit_data,
            do_firmware_audit=do_firmware_audit,
            do_kubernetes_audit=do_kubernetes_audit,
            do_kube_rootca_update_audit=do_kube_rootca_update_audit,
            do_software_audit=do_software_audit,
            use_cache=True,
        )

        # Verify the subcloud state was not updated
        self.update_subcloud_availability_and_endpoint_status.assert_not_called()

        # Verify the _update_subcloud_audit_fail_count is not called
        with mock.patch.object(
            wm, "_update_subcloud_audit_fail_count"
        ) as mock_update_subcloud_audit_fail_count:
            mock_update_subcloud_audit_fail_count.assert_not_called()

        # Verify alarm update is not called
        self.mock_alarm_aggr().update_alarm_summary.assert_not_called()

    @mock.patch.object(scheduler.ThreadGroupManager, "start")
    @mock.patch.object(
        subcloud_audit_worker_manager.db_api, "subcloud_audits_bulk_end_audit"
    )
    def test_online_subcloud_audit_not_skipping_while_installing(
        self, mock_subcloud_audits_bulk_end_audit, mock_thread_start
    ):

        subcloud = self.create_subcloud_static(self.ctx, name="subcloud1")
        self.assertIsNotNone(subcloud)

        wm = subcloud_audit_worker_manager.SubcloudAuditWorkerManager()

        # Set the subcloud to unmanaged/online/installing
        subcloud = db_api.subcloud_update(
            self.ctx,
            subcloud.id,
            management_state="unmanaged",
            first_identity_sync_complete=True,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            deploy_status=consts.DEPLOY_STATE_INSTALLING,
        )

        wm.audit_subclouds(
            context=self.ctx,
            subcloud_ids=[subcloud.id],
            firmware_audit_data=True,
            kubernetes_audit_data=True,
            kube_rootca_update_audit_data=True,
            software_audit_data=False,
            use_cache=True,
        )

        # Verify if audit was not skipped
        mock_subcloud_audits_bulk_end_audit.assert_not_called()
        # The thread start should be called two times: one for the
        # _update_subclouds_end_audit and another for _do_audit_subcloud
        self.assertEqual(mock_thread_start.call_count, 2)

    def test_audit_subcloud_going_offline_while_installing(self):
        subcloud = self.create_subcloud_static(self.ctx, name="subcloud1")
        self.assertIsNotNone(subcloud)

        am = subcloud_audit_manager.SubcloudAuditManager()
        wm = subcloud_audit_worker_manager.SubcloudAuditWorkerManager()

        # Set the subcloud to managed/online
        subcloud = db_api.subcloud_update(
            self.ctx,
            subcloud.id,
            management_state="unmanaged",
            first_identity_sync_complete=True,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            deploy_status=consts.DEPLOY_STATE_INSTALLING,
            audit_fail_count=1,
        )

        # Audit the subcloud
        do_firmware_audit = True
        do_kubernetes_audit = True
        do_kube_rootca_update_audit = True
        do_software_audit = True
        (
            firmware_audit_data,
            kubernetes_audit_data,
            kube_rootca_update_audit_data,
            software_audit_data,
        ) = am._get_audit_data(
            do_firmware_audit,
            do_kubernetes_audit,
            do_kube_rootca_update_audit,
            do_software_audit,
        )
        # Convert to dict like what would happen calling via RPC
        wm._audit_subcloud(
            subcloud,
            update_subcloud_state=False,
            firmware_audit_data=firmware_audit_data,
            kubernetes_audit_data=kubernetes_audit_data,
            kube_rootca_update_audit_data=kube_rootca_update_audit_data,
            software_audit_data=software_audit_data,
            do_firmware_audit=do_firmware_audit,
            do_kubernetes_audit=do_kubernetes_audit,
            do_kube_rootca_update_audit=do_kube_rootca_update_audit,
            do_software_audit=do_software_audit,
            use_cache=True,
        )

        # Verify that the subcloud was updated to offline
        self._update_availability(dccommon_consts.AVAILABILITY_OFFLINE, False, 2)
        self.update_subcloud_availability_and_endpoint_status.assert_called_with(
            mock.ANY,
            subcloud.id,
            subcloud.name,
            self.availability_data,
            self.endpoint_data,
        )

    def test_audit_subcloud_offline_update_audit_fail_count_only(self):
        subcloud = self.create_subcloud_static(self.ctx, name="subcloud1")
        self.assertIsNotNone(subcloud)

        am = subcloud_audit_manager.SubcloudAuditManager()
        wm = subcloud_audit_worker_manager.SubcloudAuditWorkerManager()

        audit_fail_count = random.randint(
            consts.AVAIL_FAIL_COUNT_TO_ALARM, consts.AVAIL_FAIL_COUNT_MAX - 1
        )
        subcloud = db_api.subcloud_update(
            self.ctx, subcloud.id, audit_fail_count=audit_fail_count
        )

        # Mark a service group as inactive
        service_groups = copy.deepcopy(FAKE_SERVICE_GROUPS)
        service_groups[3].state = "inactive"

        # Audit the subcloud
        do_firmware_audit = True
        do_kubernetes_audit = True
        do_kube_rootca_update_audit = True
        do_software_audit = True
        (
            firmware_audit_data,
            kubernetes_audit_data,
            kube_rootca_update_audit_data,
            software_audit_data,
        ) = am._get_audit_data(
            do_firmware_audit,
            do_kubernetes_audit,
            do_kube_rootca_update_audit,
            do_software_audit,
        )
        # Convert to dict like what would happen calling via RPC
        wm._audit_subcloud(
            subcloud,
            update_subcloud_state=False,
            firmware_audit_data=firmware_audit_data,
            kubernetes_audit_data=kubernetes_audit_data,
            kube_rootca_update_audit_data=kube_rootca_update_audit_data,
            software_audit_data=software_audit_data,
            do_firmware_audit=do_firmware_audit,
            do_kubernetes_audit=do_kubernetes_audit,
            do_kube_rootca_update_audit=do_kube_rootca_update_audit,
            do_software_audit=do_software_audit,
            use_cache=True,
        )

        # Verify the audit fail count was updated in the DB.
        subcloud = db_api.subcloud_get(self.ctx, subcloud.id)
        self.assertEqual(subcloud.audit_fail_count, audit_fail_count + 1)

        # Verify the subcloud state was not updated
        self.update_subcloud_availability_and_endpoint_status.assert_not_called()

        # Verify alarm update is not called
        self.mock_alarm_aggr().update_alarm_summary.assert_not_called()

    @mock.patch.object(subcloud_audit_worker_manager, "LOG")
    def test_update_subcloud_audit_fail_count_subcloud_deleted(self, mock_logging):
        subcloud = self.create_subcloud_static(self.ctx, name="subcloud1")
        self.assertIsNotNone(subcloud)

        wm = subcloud_audit_worker_manager.SubcloudAuditWorkerManager()

        audit_fail_count = random.randint(
            consts.AVAIL_FAIL_COUNT_TO_ALARM, consts.AVAIL_FAIL_COUNT_MAX - 1
        )
        subcloud = db_api.subcloud_update(
            self.ctx, subcloud.id, audit_fail_count=audit_fail_count
        )
        db_api.subcloud_destroy(self.ctx, subcloud.id)
        wm._update_subcloud_audit_fail_count(subcloud, audit_fail_count)
        mock_logging.info.assert_called_with(
            "Ignoring SubcloudNotFound when attempting update "
            "audit_fail_count for subcloud: %s" % subcloud.name
        )

    def test_audit_subcloud_online_with_openstack_installed(self):

        subcloud = self.create_subcloud_static(self.ctx, name="subcloud1")
        self.assertIsNotNone(subcloud)

        wm = subcloud_audit_worker_manager.SubcloudAuditWorkerManager()

        # Set the subcloud to online
        subcloud = db_api.subcloud_update(
            self.ctx,
            subcloud.id,
            management_state="managed",
            first_identity_sync_complete=True,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
        )

        # Audit the subcloud
        wm._audit_subcloud(
            subcloud,
            False,  # update_subcloud_state
            None,  # firmware_audit_data
            None,  # kubernetes_audit_data
            None,  # kube_rootca_update_audit_data
            None,  # software_audit_data
            False,  # do_firmware_audit
            False,  # do_kubernetes_audit
            False,  # do_kube_rootca_audit
            False,  # do_software_audit
            True,  # use_cache
        )

        # Verify the subcloud state was not updated
        self.update_subcloud_availability_and_endpoint_status.assert_not_called()

        # Verify the _update_subcloud_audit_fail_count is not called
        with mock.patch.object(
            wm, "_update_subcloud_audit_fail_count"
        ) as mock_update_subcloud_audit_fail_count:
            mock_update_subcloud_audit_fail_count.assert_not_called()

    def test_audit_subcloud_online_with_openstack_removed(self):

        subcloud = self.create_subcloud_static(self.ctx, name="subcloud1")
        self.assertIsNotNone(subcloud)

        wm = subcloud_audit_worker_manager.SubcloudAuditWorkerManager()

        # Set the subcloud to online and openstack installed
        subcloud = db_api.subcloud_update(
            self.ctx,
            subcloud.id,
            management_state="managed",
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            first_identity_sync_complete=True,
            openstack_installed=True,
        )

        # Remove stx-openstack application
        FAKE_APPLICATIONS.pop(1)

        # Audit the subcloud
        wm._audit_subcloud(
            subcloud,
            False,  # update_subcloud_state
            None,  # firmware_audit_data
            None,  # kubernetes_audit_data
            None,  # kube_roota_update_audit_data
            None,  # software_audit_data
            False,  # do_firmware_audit
            False,  # do_kubernetes_audit
            False,  # do_kube_rootca_update_audit
            False,  # do_software_audit
            True,  # use_cache
        )

        # Verify the subcloud state was not updated
        self.update_subcloud_availability_and_endpoint_status.assert_not_called()

        # Verify the _update_subcloud_audit_fail_count is not called
        with mock.patch.object(
            wm, "_update_subcloud_audit_fail_count"
        ) as mock_update_subcloud_audit_fail_count:
            mock_update_subcloud_audit_fail_count.assert_not_called()

    def test_audit_subcloud_online_with_openstack_inactive(self):

        subcloud = self.create_subcloud_static(self.ctx, name="subcloud1")
        self.assertIsNotNone(subcloud)

        wm = subcloud_audit_worker_manager.SubcloudAuditWorkerManager()

        # Set the subcloud to online and openstack installed
        subcloud = db_api.subcloud_update(
            self.ctx,
            subcloud.id,
            management_state="managed",
            first_identity_sync_complete=True,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            openstack_installed=True,
        )

        # stx-openstack application is not active
        FAKE_APPLICATIONS[1].active = False

        # Audit the subcloud
        wm._audit_subcloud(
            subcloud,
            False,  # update_subcloud_state
            None,  # firmware_audit_data
            None,  # kubernetes_audit_data
            None,  # kube_rootca_update_audit_data
            None,  # software_audit_data
            False,  # do_firmware_audit
            False,  # do_kubernetes_audit
            False,  # do_kube_rootca_update_audit
            False,  # do_software_audit
            True,  # use_cache
        )

        # Verify the subcloud state was not updated
        self.update_subcloud_availability_and_endpoint_status.assert_not_called()

        # Verify the _update_subcloud_audit_fail_count is not called
        with mock.patch.object(
            wm, "_update_subcloud_audit_fail_count"
        ) as mock_update_subcloud_audit_fail_count:
            mock_update_subcloud_audit_fail_count.assert_not_called()

    def test_audit_subcloud_partial_subaudits(self):
        subcloud = self.create_subcloud_static(self.ctx, name="subcloud1")
        self.assertIsNotNone(subcloud)

        # Set the subcloud to managed
        subcloud = db_api.subcloud_update(
            self.ctx,
            subcloud.id,
            first_identity_sync_complete=True,
            management_state="managed",
        )

        am = subcloud_audit_manager.SubcloudAuditManager()
        wm = subcloud_audit_worker_manager.SubcloudAuditWorkerManager()

        # Pretend like we're going to audit the subcloud
        do_firmware_audit = False
        do_kubernetes_audit = False
        do_kube_rootca_audit = False
        do_kube_rootca_update_audit = False
        do_software_audit = False
        (
            firmware_audit_data,
            kubernetes_audit_data,
            kube_rootca_update_audit_data,
            software_audit_data,
        ) = am._get_audit_data(
            do_firmware_audit,
            do_kubernetes_audit,
            do_kube_rootca_update_audit,
            do_software_audit,
        )
        # Convert to dict like what would happen calling via RPC

        # Now pretend someone triggered all the subaudits in the DB
        # after the subcloud audit was triggered but before it ran.
        am.trigger_subcloud_audits(self.ctx, subcloud.id, None)

        # Make sure all subaudits are requested in DB
        audits = db_api.subcloud_audits_get(self.ctx, subcloud.id)
        self.assertEqual(audits.firmware_audit_requested, True)

        # Do the actual audit
        wm._do_audit_subcloud(
            subcloud,
            False,  # update_subcloud_state
            firmware_audit_data,
            kubernetes_audit_data,
            kube_rootca_update_audit_data,
            software_audit_data,
            do_firmware_audit,
            do_kubernetes_audit,
            do_kube_rootca_audit,
            do_software_audit,
            use_cache=True,
        )

        # Verify the _update_subcloud_audit_fail_count is not called
        with mock.patch.object(
            wm, "_update_subcloud_audit_fail_count"
        ) as mock_update_subcloud_audit_fail_count:
            mock_update_subcloud_audit_fail_count.assert_not_called()

        # Request the end audit to be performed
        # Because the thread runs infinitely, the time.sleep is mocked to raise an
        # exception, quitting the process after the first call
        try:
            wm._update_subclouds_end_audit()
        except Exception:
            # Do something
            wm.audits_finished = dict()

        # Ensure the subaudits that didn't run are still requested
        audits = db_api.subcloud_audits_get(self.ctx, subcloud.id)
        self.assertEqual(audits.firmware_audit_requested, True)
        self.assertEqual(audits.kubernetes_audit_requested, True)
        self.assertEqual(audits.kube_rootca_update_audit_requested, True)
