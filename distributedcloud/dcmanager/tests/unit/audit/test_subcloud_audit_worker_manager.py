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

import copy
import random
import sys

from keystoneauth1 import exceptions as keystone_exceptions
import mock

from dccommon import consts as dccommon_consts
from dcmanager.audit import subcloud_audit_manager
from dcmanager.audit import subcloud_audit_worker_manager
from dcmanager.common import consts
from dcmanager.common import scheduler
from dcmanager.db.sqlalchemy import api as db_api
from dcmanager.tests import base

sys.modules['fm_core'] = mock.Mock()


class FakeDCManagerAPI(object):

    def __init__(self):
        self.update_subcloud_sync_endpoint_type = mock.MagicMock()


class FakeAuditWorkerAPI(object):

    def __init__(self):
        self.audit_subclouds = mock.MagicMock()


class FakeAlarmAggregation(object):

    def __init__(self):
        self.update_alarm_summary = mock.MagicMock()


class FakePatchAudit(object):

    def __init__(self):
        self.subcloud_audit = mock.MagicMock()
        self.subcloud_patch_audit = mock.MagicMock(
            return_value=dccommon_consts.SYNC_STATUS_IN_SYNC
        )
        self.subcloud_load_audit = mock.MagicMock(
            return_value=dccommon_consts.SYNC_STATUS_IN_SYNC
        )
        self.get_regionone_audit_data = mock.MagicMock()
        self.get_software_regionone_audit_data = mock.MagicMock()


class FakeFirmwareAudit(object):

    def __init__(self):
        self.subcloud_firmware_audit = mock.MagicMock(
            return_value=dccommon_consts.SYNC_STATUS_IN_SYNC
        )
        self.get_regionone_audit_data = mock.MagicMock()


class FakeKubernetesAudit(object):

    def __init__(self):
        self.subcloud_kubernetes_audit = mock.MagicMock(
            return_value=dccommon_consts.SYNC_STATUS_IN_SYNC
        )
        self.get_regionone_audit_data = mock.MagicMock()


class FakeKubeRootcaUpdateAudit(object):

    def __init__(self):
        self.subcloud_kube_rootca_audit = mock.MagicMock(
            return_value=dccommon_consts.SYNC_STATUS_IN_SYNC
        )
        self.get_regionone_audit_data = mock.MagicMock()


class FakeSoftwareAudit(object):

    def __init__(self):
        self.subcloud_software_audit = mock.MagicMock(
            return_value=dccommon_consts.SYNC_STATUS_IN_SYNC
        )
        self.get_regionone_audit_data = mock.MagicMock()


class FakeServiceGroup(object):
    def __init__(self, status, desired_state, service_group_name, uuid,
                 node_name, state, condition, name):
        self.status = status
        self.desired_state = desired_state
        self.service_group_name = service_group_name
        self.uuid = uuid
        self.node_name = node_name
        self.state = state
        self.condition = condition
        self.name = name


class FakeApplication(object):
    def __init__(self, status, name, manifest_name, active, progress,
                 app_version, manifest_file):
        self.status = status
        self.name = name
        self.manifest_name = manifest_name
        self.active = active
        self.progress = progress
        self.app_version = app_version
        self.manifest_file = manifest_file


FAKE_SERVICE_GROUPS = [
    FakeServiceGroup("",
                     "active",
                     "distributed-cloud-services",
                     "b00fd252-5bd7-44b5-bbde-7d525e7125c7",
                     "controller-0",
                     "active",
                     "",
                     "controller"),
    FakeServiceGroup("",
                     "active",
                     "storage-monitoring-services",
                     "5a14a1d1-dac1-48b0-9598-3702e0b0338a",
                     "controller-0",
                     "active",
                     "",
                     "controller"),
    FakeServiceGroup("",
                     "active",
                     "storage-services",
                     "5cbfa903-379f-4329-81b4-2e88acdfa215",
                     "controller-0",
                     "active",
                     "",
                     "controller"),
    FakeServiceGroup("",
                     "active",
                     "web-services",
                     "42829858-008f-4931-94e1-4b86fe31ce3c",
                     "controller-0",
                     "active",
                     "",
                     "controller"),
    FakeServiceGroup("",
                     "active",
                     "directory-services",
                     "74225295-2601-4376-a52c-7cbd149146f6",
                     "controller-0",
                     "active",
                     "",
                     "controller"),
    FakeServiceGroup("",
                     "active",
                     "patching-services",
                     "6870c079-e1c3-4402-b88b-63a5ef06a77a",
                     "controller-0",
                     "active",
                     "",
                     "controller"),
    FakeServiceGroup("",
                     "active",
                     "vim-services",
                     "d8367a52-316e-418b-9211-a13331e073ef",
                     "controller-0",
                     "active",
                     "",
                     "controller"),
    FakeServiceGroup("",
                     "active",
                     "cloud-services",
                     "12682dc0-cef5-427a-b1a6-145cf950b49c",
                     "controller-0",
                     "active",
                     "",
                     "controller"),
    FakeServiceGroup("",
                     "active",
                     "controller-services",
                     "daac63fb-24b3-4cd1-b895-260a32e356ae",
                     "controller-0",
                     "active",
                     "",
                     "controller"),
    FakeServiceGroup("",
                     "active",
                     "oam-services",
                     "4b66913d-98ba-4a4a-86c3-168625f629eb",
                     "controller-0",
                     "active",
                     "",
                     "controller"),
]

FAKE_APPLICATIONS = [
    FakeApplication("applied",
                    "platform-integ-apps",
                    "platform-integration-manifest",
                    True,
                    "completed",
                    "1.0-8",
                    "manifest.yaml"),
    FakeApplication("applied",
                    "stx-openstack",
                    "stx-openstack-manifest",
                    True,
                    "completed",
                    "1.0-8",
                    "manifest.yaml"),
]


class TestAuditWorkerManager(base.DCManagerTestCase):
    def setUp(self):
        super(TestAuditWorkerManager, self).setUp()

        # Mock the DCManager API
        self.fake_dcmanager_api = FakeDCManagerAPI()
        p = mock.patch('dcmanager.rpc.client.ManagerClient')
        self.mock_dcmanager_api = p.start()
        self.mock_dcmanager_api.return_value = self.fake_dcmanager_api
        self.addCleanup(p.stop)

        # Mock the DCManager subcloud state API
        p = mock.patch('dcmanager.rpc.client.SubcloudStateClient')
        self.mock_dcmanager_state_api = p.start()
        self.addCleanup(p.stop)

        # Mock the Audit Worker API
        self.fake_audit_worker_api = FakeAuditWorkerAPI()
        p = mock.patch('dcmanager.audit.rpcapi.ManagerAuditWorkerClient')
        self.mock_audit_worker_api = p.start()
        self.mock_audit_worker_api.return_value = self.fake_audit_worker_api
        self.addCleanup(p.stop)

        # Mock the context
        p = mock.patch.object(subcloud_audit_worker_manager, 'context')
        self.mock_context = p.start()
        self.mock_context.get_admin_context.return_value = self.ctx
        self.addCleanup(p.stop)

        # Mock the context
        p = mock.patch.object(subcloud_audit_manager, 'context')
        self.mock_context2 = p.start()
        self.mock_context2.get_admin_context.return_value = self.ctx
        self.addCleanup(p.stop)

        # Mock alarm aggregation
        self.fake_alarm_aggr = FakeAlarmAggregation()
        p = mock.patch.object(subcloud_audit_worker_manager,
                              'alarm_aggregation')
        self.mock_alarm_aggr = p.start()
        self.mock_alarm_aggr.AlarmAggregation.return_value = \
            self.fake_alarm_aggr
        self.addCleanup(p.stop)

        # Mock patch audit
        self.fake_patch_audit = FakePatchAudit()
        p = mock.patch.object(subcloud_audit_worker_manager,
                              'patch_audit')
        self.mock_patch_audit = p.start()
        self.mock_patch_audit.PatchAudit.return_value = \
            self.fake_patch_audit
        self.addCleanup(p.stop)

        # Mock patch audit
        self.fake_patch_audit2 = FakePatchAudit()
        p = mock.patch.object(subcloud_audit_manager,
                              'patch_audit')
        self.mock_patch_audit2 = p.start()
        self.mock_patch_audit2.PatchAudit.return_value = \
            self.fake_patch_audit2
        self.addCleanup(p.stop)

        # Mock firmware audit
        self.fake_firmware_audit = FakeFirmwareAudit()
        p = mock.patch.object(subcloud_audit_worker_manager,
                              'firmware_audit')
        self.mock_firmware_audit = p.start()
        self.mock_firmware_audit.FirmwareAudit.return_value = \
            self.fake_firmware_audit
        self.addCleanup(p.stop)

        self.fake_firmware_audit2 = FakeFirmwareAudit()
        p = mock.patch.object(subcloud_audit_manager,
                              'firmware_audit')
        self.mock_firmware_audit2 = p.start()
        self.mock_firmware_audit2.FirmwareAudit.return_value = \
            self.fake_firmware_audit2
        self.addCleanup(p.stop)

        # Mock kubernetes audit in Audit Worker and Audit Manager
        self.fake_kubernetes_audit = FakeKubernetesAudit()
        p = mock.patch.object(subcloud_audit_worker_manager,
                              'kubernetes_audit')
        self.mock_kubernetes_audit = p.start()
        self.mock_kubernetes_audit.KubernetesAudit.return_value = \
            self.fake_kubernetes_audit
        self.addCleanup(p.stop)

        self.fake_kubernetes_audit2 = FakeKubernetesAudit()
        p = mock.patch.object(subcloud_audit_manager,
                              'kubernetes_audit')
        self.mock_kubernetes_audit2 = p.start()
        self.mock_kubernetes_audit2.KubernetesAudit.return_value = \
            self.fake_kubernetes_audit2
        self.addCleanup(p.stop)

        # Mock kube rootca update audit in Audit Worker and Audit Manager
        self.fake_kube_rootca_update_audit = FakeKubeRootcaUpdateAudit()
        p = mock.patch.object(subcloud_audit_worker_manager,
                              'kube_rootca_update_audit')
        self.mock_kube_rootca_update_audit = p.start()
        self.mock_kube_rootca_update_audit.KubeRootcaUpdateAudit.return_value = \
            self.fake_kube_rootca_update_audit
        self.addCleanup(p.stop)

        self.fake_kube_rootca_update_audit2 = FakeKubeRootcaUpdateAudit()
        p = mock.patch.object(subcloud_audit_manager,
                              'kube_rootca_update_audit')
        self.mock_kube_rootca_update_audit2 = p.start()
        self.mock_kube_rootca_update_audit2.KubeRootcaUpdateAudit.return_value = \
            self.fake_kube_rootca_update_audit2
        self.addCleanup(p.stop)

        # Mock software audit in Audit Worker and Audit Manager
        self.fake_software_audit = FakeSoftwareAudit()
        p = mock.patch.object(subcloud_audit_worker_manager, 'software_audit')
        self.mock_software_audit = p.start()
        self.mock_software_audit.SoftwareAudit.return_value = \
            self.fake_software_audit
        self.addCleanup(p.stop)

        self.fake_software_audit2 = FakeSoftwareAudit()
        p = mock.patch.object(subcloud_audit_manager, 'software_audit')
        self.mock_software_audit2 = p.start()
        self.mock_software_audit2.SoftwareAudit.return_value = \
            self.fake_software_audit2
        self.addCleanup(p.stop)

        self._mock_openstack_driver(subcloud_audit_worker_manager)
        self._mock_sysinv_client(subcloud_audit_worker_manager)
        self._mock_fm_client(subcloud_audit_worker_manager)

        self.mock_fm_client().get_alarm_summary.return_value = None
        self.mock_sysinv_client().get_service_groups.return_value = \
            FAKE_SERVICE_GROUPS
        self.mock_sysinv_client().get_applications.return_value = \
            FAKE_APPLICATIONS

        self.batch_state_request_data = {
            "availability": None,
            dccommon_consts.ENDPOINT_TYPE_PATCHING: None,
            dccommon_consts.ENDPOINT_TYPE_LOAD: None,
            dccommon_consts.ENDPOINT_TYPE_FIRMWARE: None,
            dccommon_consts.ENDPOINT_TYPE_KUBERNETES: None,
            dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA: None,
            dccommon_consts.ENDPOINT_TYPE_SOFTWARE: None
        }

    def _update_availability(
        self, availability_status, update_status_only, audit_fail_count
    ):
        self.batch_state_request_data.update({
            "availability": {
                "availability_status": availability_status,
                "update_state_only": update_status_only,
                "audit_fail_count": audit_fail_count
            }
        })

    def _set_all_audits_in_sync(self):
        for key in self.batch_state_request_data:
            if key != "availability":
                self.batch_state_request_data[key] = \
                    dccommon_consts.SYNC_STATUS_IN_SYNC

    @staticmethod
    def create_subcloud_static(ctxt, **kwargs):
        values = {
            'name': "subcloud1",
            'description': "This is a subcloud",
            'location': "This is the location of the subcloud",
            'software_version': "10.04",
            'management_subnet': "192.168.101.0/24",
            'management_gateway_ip': "192.168.101.1",
            'management_start_ip': "192.168.101.2",
            'management_end_ip': "192.168.101.50",
            'systemcontroller_gateway_ip': "192.168.204.101",
            'deploy_status': "not-deployed",
            'error_description': 'No errors present',
            'region_name': base.SUBCLOUD_1['region_name'],
            'openstack_installed': False,
            'group_id': 1,
        }
        values.update(kwargs)
        return db_api.subcloud_create(ctxt, **values)

    def test_init(self):
        am = subcloud_audit_worker_manager.SubcloudAuditWorkerManager()
        self.assertIsNotNone(am)
        self.assertEqual('subcloud_audit_worker_manager', am.service_name)
        self.assertEqual('localhost', am.host)
        self.assertEqual(self.ctx, am.context)

    def test_audit_subcloud_online_managed(self):

        subcloud = self.create_subcloud_static(self.ctx, name='subcloud1')
        self.assertIsNotNone(subcloud)

        # Set the subcloud to managed
        subcloud = db_api.subcloud_update(
            self.ctx, subcloud.id,
            management_state='managed',
            first_identity_sync_complete=True)

        am = subcloud_audit_manager.SubcloudAuditManager()
        wm = subcloud_audit_worker_manager.SubcloudAuditWorkerManager()

        # Audit the subcloud
        update_subcloud_state = False
        do_audit_openstack = False
        do_patch_audit = True
        do_load_audit = True
        do_firmware_audit = True
        do_kubernetes_audit = True
        do_kube_rootca_update_audit = True
        do_software_audit = True
        (
            patch_audit_data,
            firmware_audit_data,
            kubernetes_audit_data,
            kube_rootca_update_audit_data,
            software_audit_data,
        ) = am._get_audit_data(
            do_patch_audit,
            do_firmware_audit,
            do_kubernetes_audit,
            do_kube_rootca_update_audit,
            do_software_audit,
        )
        # Convert to dict like what would happen calling via RPC
        # Note: the other data should also be converted...
        patch_audit_data = patch_audit_data.to_dict()
        wm._audit_subcloud(subcloud,
                           update_subcloud_state,
                           do_audit_openstack,
                           patch_audit_data,
                           firmware_audit_data,
                           kubernetes_audit_data,
                           kube_rootca_update_audit_data,
                           software_audit_data,
                           do_patch_audit,
                           do_load_audit,
                           do_firmware_audit,
                           do_kubernetes_audit,
                           do_kube_rootca_update_audit,
                           do_software_audit)

        # Verify the subcloud was set to online
        self._update_availability(dccommon_consts.AVAILABILITY_ONLINE, False, 0)
        self._set_all_audits_in_sync()
        self.mock_dcmanager_state_api().\
            batch_update_subcloud_availability_and_endpoint_status.\
            assert_called_once_with(
                mock.ANY, subcloud.name, subcloud.region_name,
                self.batch_state_request_data
        )

        # Verify the _update_subcloud_audit_fail_count is not called
        with mock.patch.object(wm, '_update_subcloud_audit_fail_count') as \
                mock_update_subcloud_audit_fail_count:
            mock_update_subcloud_audit_fail_count.assert_not_called()

        # Verify the openstack endpoints were not updated
        self.fake_dcmanager_api.update_subcloud_sync_endpoint_type.\
            assert_not_called()

        # Verify alarm update is called
        self.fake_alarm_aggr.update_alarm_summary.assert_called_with(
            subcloud.name, self.mock_fm_client())

        # Verify patch audit is called
        self.fake_patch_audit.subcloud_patch_audit.assert_called_with(
            mock.ANY, mock.ANY, subcloud.management_start_ip, subcloud.name,
            subcloud.region_name, patch_audit_data)

        self.fake_patch_audit.subcloud_load_audit.assert_called_with(
            mock.ANY, subcloud.name, patch_audit_data
        )

        # Verify firmware audit is called
        self.fake_firmware_audit.subcloud_firmware_audit.assert_called_with(
            mock.ANY, subcloud.name, firmware_audit_data)

        # Verify kubernetes audit is called
        self.fake_kubernetes_audit.subcloud_kubernetes_audit.assert_called_with(
            mock.ANY, subcloud.name, kubernetes_audit_data)

        # Verify kube rootca update audit is called
        self.fake_kube_rootca_update_audit.subcloud_kube_rootca_audit.\
            assert_called_with(
                mock.ANY, self.mock_fm_client(), subcloud,
                kube_rootca_update_audit_data
            )

    def test_audit_subcloud_online_first_identity_sync_not_complete(self):

        subcloud = self.create_subcloud_static(self.ctx, name='subcloud1')
        self.assertIsNotNone(subcloud)

        # Set the subcloud to managed
        subcloud = db_api.subcloud_update(
            self.ctx, subcloud.id,
            management_state='managed')

        am = subcloud_audit_manager.SubcloudAuditManager()
        wm = subcloud_audit_worker_manager.SubcloudAuditWorkerManager()

        # Audit the subcloud
        update_subcloud_state = False
        do_audit_openstack = False
        do_patch_audit = True
        do_load_audit = True
        do_firmware_audit = True
        do_kubernetes_audit = True
        do_kube_rootca_update_audit = True
        do_software_audit = True
        (
            patch_audit_data,
            firmware_audit_data,
            kubernetes_audit_data,
            kube_rootca_update_audit_data,
            software_audit_data,
        ) = am._get_audit_data(
            do_patch_audit,
            do_firmware_audit,
            do_kubernetes_audit,
            do_kube_rootca_update_audit,
            do_software_audit,
        )
        # Convert to dict like what would happen calling via RPC
        # Note: the other data should also be converted...
        patch_audit_data = patch_audit_data.to_dict()
        wm._audit_subcloud(subcloud,
                           update_subcloud_state,
                           do_audit_openstack,
                           patch_audit_data,
                           firmware_audit_data,
                           kubernetes_audit_data,
                           kube_rootca_update_audit_data,
                           software_audit_data,
                           do_patch_audit,
                           do_load_audit,
                           do_firmware_audit,
                           do_kubernetes_audit,
                           do_kube_rootca_update_audit,
                           do_software_audit)

        # Verify the subcloud was set to online
        self._update_availability(dccommon_consts.AVAILABILITY_ONLINE, False, 0)
        self.mock_dcmanager_state_api().\
            batch_update_subcloud_availability_and_endpoint_status.\
            assert_called_with(
                mock.ANY, subcloud.name, subcloud.region_name,
                self.batch_state_request_data
        )

        # Verify the _update_subcloud_audit_fail_count is not called
        with mock.patch.object(wm, '_update_subcloud_audit_fail_count') as \
                mock_update_subcloud_audit_fail_count:
            mock_update_subcloud_audit_fail_count.assert_not_called()

        # Verify the openstack endpoints were not added
        self.fake_dcmanager_api.update_subcloud_sync_endpoint_type.\
            assert_not_called()

        # Verify alarm update is not called
        self.fake_alarm_aggr.update_alarm_summary.assert_not_called()

        # Verify patch audit is not called
        self.fake_patch_audit.subcloud_patch_audit.assert_not_called()
        self.fake_patch_audit.subcloud_load_audit.assert_not_called()

        # Verify firmware audit is not called
        self.fake_firmware_audit.subcloud_firmware_audit.assert_not_called()

        # Verify kubernetes audit is not called
        self.fake_kubernetes_audit.subcloud_kubernetes_audit.assert_not_called()

        # Verify kube rootca update audit is not called
        self.fake_kube_rootca_update_audit.subcloud_kube_rootca_audit.\
            assert_not_called()

    def test_audit_subcloud_online_unmanaged(self):

        subcloud = self.create_subcloud_static(self.ctx, name='subcloud1')
        self.assertIsNotNone(subcloud)

        am = subcloud_audit_manager.SubcloudAuditManager()
        wm = subcloud_audit_worker_manager.SubcloudAuditWorkerManager()

        # Audit the subcloud
        update_subcloud_state = False
        do_audit_openstack = False
        do_patch_audit = True
        do_load_audit = True
        do_firmware_audit = True
        do_kubernetes_audit = True
        do_kube_rootca_update_audit = True
        do_software_audit = True
        (
            patch_audit_data,
            firmware_audit_data,
            kubernetes_audit_data,
            kube_rootca_update_audit_data,
            software_audit_data,
        ) = am._get_audit_data(
            do_patch_audit,
            do_firmware_audit,
            do_kubernetes_audit,
            do_kube_rootca_update_audit,
            do_software_audit,
        )
        # Convert to dict like what would happen calling via RPC
        # Note: the other data should also be converted...
        patch_audit_data = patch_audit_data.to_dict()
        wm._audit_subcloud(
            subcloud, update_subcloud_state, do_audit_openstack, patch_audit_data,
            firmware_audit_data, kubernetes_audit_data,
            kube_rootca_update_audit_data, software_audit_data, do_patch_audit,
            do_load_audit, do_firmware_audit, do_kubernetes_audit,
            do_kube_rootca_update_audit, do_software_audit
        )

        # Verify the subcloud was set to online
        self._update_availability(dccommon_consts.AVAILABILITY_ONLINE, False, 0)
        self.mock_dcmanager_state_api().\
            batch_update_subcloud_availability_and_endpoint_status.\
            assert_called_with(
                mock.ANY, subcloud.name, subcloud.region_name,
                self.batch_state_request_data
        )

        # Verify the _update_subcloud_audit_fail_count is not called
        with mock.patch.object(wm, '_update_subcloud_audit_fail_count') as \
                mock_update_subcloud_audit_fail_count:
            mock_update_subcloud_audit_fail_count.assert_not_called()

        # Verify the openstack endpoints were not added
        self.fake_dcmanager_api.update_subcloud_sync_endpoint_type.\
            assert_not_called()

        # Verify alarm update is not called
        self.fake_alarm_aggr.update_alarm_summary.assert_not_called()

        # Verify patch audit is not called
        self.fake_patch_audit.subcloud_patch_audit.assert_not_called()
        self.fake_patch_audit.subcloud_load_audit.assert_not_called()

        # Verify firmware audit is not called
        self.fake_firmware_audit.subcloud_firmware_audit.assert_not_called()

        # Verify kubernetes audit is not called
        self.fake_kubernetes_audit.subcloud_kubernetes_audit.assert_not_called()

        # Verify kube rootca update audit is not called
        self.fake_kube_rootca_update_audit.subcloud_kube_rootca_audit.\
            assert_not_called()

    def test_audit_subcloud_online_no_change(self):

        subcloud = self.create_subcloud_static(self.ctx, name='subcloud1')
        self.assertIsNotNone(subcloud)

        wm = subcloud_audit_worker_manager.SubcloudAuditWorkerManager()

        # Set the subcloud to online
        subcloud = db_api.subcloud_update(
            self.ctx, subcloud.id,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE)

        # Audit the subcloud
        wm._audit_subcloud(subcloud, update_subcloud_state=False,
                           do_audit_openstack=False, patch_audit_data=None,
                           firmware_audit_data=None,
                           kubernetes_audit_data=None,
                           kube_rootca_update_audit_data=None,
                           software_audit_data=None,
                           do_patch_audit=False,
                           do_load_audit=False,
                           do_firmware_audit=False,
                           do_kubernetes_audit=False,
                           do_kube_rootca_update_audit=False,
                           do_software_audit=False)

        # Verify the subcloud state was not updated
        self.mock_dcmanager_state_api().\
            batch_update_subcloud_availability_and_endpoint_status.\
            assert_not_called()

        # Verify the _update_subcloud_audit_fail_count is not called
        with mock.patch.object(wm, '_update_subcloud_audit_fail_count') as \
                mock_update_subcloud_audit_fail_count:
            mock_update_subcloud_audit_fail_count.assert_not_called()

        # Verify the openstack endpoints were not added
        self.fake_dcmanager_api.update_subcloud_sync_endpoint_type.\
            assert_not_called()

        # Verify alarm update is not called
        self.fake_alarm_aggr.update_alarm_summary.assert_not_called()

        # Verify patch audit is not called
        self.fake_patch_audit.subcloud_patch_audit.assert_not_called()
        self.fake_patch_audit.subcloud_load_audit.assert_not_called()

    def test_audit_subcloud_online_no_change_force_update(self):

        subcloud = self.create_subcloud_static(self.ctx, name='subcloud1')
        self.assertIsNotNone(subcloud)

        wm = subcloud_audit_worker_manager.SubcloudAuditWorkerManager()

        # Set the subcloud to online
        subcloud = db_api.subcloud_update(
            self.ctx, subcloud.id,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE)

        # Audit the subcloud and force a state update
        wm._audit_subcloud(subcloud, update_subcloud_state=True,
                           do_audit_openstack=False, patch_audit_data=None,
                           firmware_audit_data=None,
                           kubernetes_audit_data=None,
                           kube_rootca_update_audit_data=None,
                           software_audit_data=None,
                           do_patch_audit=False,
                           do_load_audit=False,
                           do_firmware_audit=False,
                           do_kubernetes_audit=False,
                           do_kube_rootca_update_audit=False,
                           do_software_audit=False)

        # Verify the subcloud state was updated
        self._update_availability(
            dccommon_consts.AVAILABILITY_ONLINE, True, None
        )
        self.mock_dcmanager_state_api().\
            batch_update_subcloud_availability_and_endpoint_status.\
            assert_called_with(
                mock.ANY, subcloud.name, subcloud.region_name,
                self.batch_state_request_data
        )

        # Verify the _update_subcloud_audit_fail_count is not called
        with mock.patch.object(wm, '_update_subcloud_audit_fail_count') as \
                mock_update_subcloud_audit_fail_count:
            mock_update_subcloud_audit_fail_count.assert_not_called()

        # Verify the openstack endpoints were not updated
        self.fake_dcmanager_api.update_subcloud_sync_endpoint_type.\
            assert_not_called()

        # Verify alarm update is not called
        self.fake_alarm_aggr.update_alarm_summary.assert_not_called()

        # Verify patch audit is not called
        self.fake_patch_audit.subcloud_patch_audit.assert_not_called()
        self.fake_patch_audit.subcloud_load_audit.assert_not_called()

        # Verify firmware audit is not called
        self.fake_firmware_audit.subcloud_firmware_audit.assert_not_called()

        # Verify kubernetes audit is not called
        self.fake_kubernetes_audit.subcloud_kubernetes_audit.assert_not_called()

        # Verify kube rootca update audit is not called
        self.fake_kube_rootca_update_audit.subcloud_kube_rootca_audit.\
            assert_not_called()

    def test_audit_subcloud_go_offline(self):

        subcloud = self.create_subcloud_static(self.ctx, name='subcloud1')
        self.assertIsNotNone(subcloud)

        am = subcloud_audit_manager.SubcloudAuditManager()
        wm = subcloud_audit_worker_manager.SubcloudAuditWorkerManager()

        # Set the subcloud to managed/online
        subcloud = db_api.subcloud_update(
            self.ctx, subcloud.id,
            management_state='managed',
            first_identity_sync_complete=True,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE)

        # Mark a service group as inactive
        service_groups = copy.deepcopy(FAKE_SERVICE_GROUPS)
        service_groups[3].state = 'inactive'
        self.mock_sysinv_client().get_service_groups.return_value = service_groups

        # Audit the subcloud
        do_patch_audit = True
        do_load_audit = True
        do_firmware_audit = True
        do_kubernetes_audit = True
        do_kube_rootca_update_audit = True
        do_software_audit = True
        (
            patch_audit_data,
            firmware_audit_data,
            kubernetes_audit_data,
            kube_rootca_update_audit_data,
            software_audit_data,
        ) = am._get_audit_data(
            do_patch_audit,
            do_firmware_audit,
            do_kubernetes_audit,
            do_kube_rootca_update_audit,
            do_software_audit,
        )
        # Convert to dict like what would happen calling via RPC
        patch_audit_data = patch_audit_data.to_dict()
        wm._audit_subcloud(
            subcloud, update_subcloud_state=False, do_audit_openstack=False,
            patch_audit_data=patch_audit_data,
            firmware_audit_data=firmware_audit_data,
            kubernetes_audit_data=kubernetes_audit_data,
            kube_rootca_update_audit_data=kube_rootca_update_audit_data,
            software_audit_data=software_audit_data,
            do_patch_audit=do_patch_audit, do_load_audit=do_load_audit,
            do_firmware_audit=do_firmware_audit,
            do_kubernetes_audit=do_kubernetes_audit,
            do_kube_rootca_update_audit=do_kube_rootca_update_audit,
            do_software_audit=do_software_audit)

        # Verify alarm update is called once
        self.fake_alarm_aggr.update_alarm_summary.assert_called_once_with(
            subcloud.name, self.mock_fm_client())

        # Verify patch audit is called once
        self.fake_patch_audit.subcloud_patch_audit.assert_called_once_with(
            mock.ANY, mock.ANY, subcloud.management_start_ip,
            subcloud.name, subcloud.region_name, patch_audit_data)
        self.fake_patch_audit.subcloud_load_audit.assert_called_once_with(
            mock.ANY, subcloud.name, patch_audit_data)

        # Verify firmware audit is called once
        self.fake_firmware_audit.subcloud_firmware_audit.assert_called_once_with(
            mock.ANY, subcloud.name, mock.ANY)

        # Verify kubernetes audit is called once
        self.fake_kubernetes_audit.subcloud_kubernetes_audit.assert_called_once_with(
            mock.ANY, subcloud.name, mock.ANY)

        # Verify kube rootca update audit is called once
        self.fake_kube_rootca_update_audit.subcloud_kube_rootca_audit.\
            assert_called_once_with(mock.ANY, mock.ANY, subcloud, mock.ANY)

        # Verify the audit fail count was updated in db
        audit_fail_count = 1
        subcloud = db_api.subcloud_get(self.ctx, subcloud.id)
        self.assertEqual(subcloud.audit_fail_count, audit_fail_count)

        # Verify the state was called only for the audits
        self._set_all_audits_in_sync()
        self.mock_dcmanager_state_api().\
            batch_update_subcloud_availability_and_endpoint_status.\
            assert_called_once_with(
                mock.ANY, subcloud.name, subcloud.region_name,
                self.batch_state_request_data
        )

        # Update the DB like dcmanager would do.
        subcloud = db_api.subcloud_update(
            self.ctx, subcloud.id,
            availability_status=dccommon_consts.AVAILABILITY_OFFLINE,
            audit_fail_count=audit_fail_count)

        # Audit the subcloud again
        wm._audit_subcloud(
            subcloud, update_subcloud_state=False, do_audit_openstack=False,
            patch_audit_data=patch_audit_data,
            firmware_audit_data=firmware_audit_data,
            kubernetes_audit_data=kubernetes_audit_data,
            kube_rootca_update_audit_data=kube_rootca_update_audit_data,
            software_audit_data=software_audit_data,
            do_patch_audit=do_patch_audit, do_load_audit=do_load_audit,
            do_firmware_audit=do_firmware_audit,
            do_kubernetes_audit=do_kubernetes_audit,
            do_kube_rootca_update_audit=do_kube_rootca_update_audit,
            do_software_audit=do_software_audit)

        audit_fail_count = audit_fail_count + 1

        # Verify the audit fail count was updated in db
        subcloud = db_api.subcloud_get(self.ctx, subcloud.id)
        self.assertEqual(subcloud.audit_fail_count, audit_fail_count)

        # Verify the subcloud state was not called
        self.mock_dcmanager_state_api().\
            batch_update_subcloud_availability_and_endpoint_status.\
            assert_called_once_with(
                mock.ANY, subcloud.name, subcloud.region_name,
                self.batch_state_request_data
        )

        # Verify alarm update is called only once
        self.fake_alarm_aggr.update_alarm_summary.assert_called_once()

        # Verify patch audit is called only once
        self.fake_patch_audit.subcloud_patch_audit.assert_called_once()
        self.fake_patch_audit.subcloud_load_audit.assert_called_once()

        # Verify firmware audit is only called once
        self.fake_firmware_audit.subcloud_firmware_audit.assert_called_once()

        # Verify kubernetes audit is only called once
        self.fake_kubernetes_audit.subcloud_kubernetes_audit.assert_called_once()

        # Verify kube rootca update audit is only called once
        self.fake_kube_rootca_update_audit.subcloud_kube_rootca_audit.\
            assert_called_once()

    def test_audit_subcloud_offline_no_change(self):
        subcloud = self.create_subcloud_static(self.ctx, name='subcloud1')
        self.assertIsNotNone(subcloud)

        am = subcloud_audit_manager.SubcloudAuditManager()
        wm = subcloud_audit_worker_manager.SubcloudAuditWorkerManager()

        subcloud = db_api.subcloud_update(
            self.ctx, subcloud.id, audit_fail_count=consts.AVAIL_FAIL_COUNT_MAX)

        # Mark a service group as inactive
        service_groups = copy.deepcopy(FAKE_SERVICE_GROUPS)
        service_groups[3].state = 'inactive'
        self.mock_sysinv_client().get_service_groups.return_value = service_groups

        # Audit the subcloud
        do_patch_audit = True
        do_load_audit = True
        do_firmware_audit = True
        do_kubernetes_audit = True
        do_kube_rootca_update_audit = True
        do_software_audit = True
        (
            patch_audit_data,
            firmware_audit_data,
            kubernetes_audit_data,
            kube_rootca_update_audit_data,
            software_audit_data,
        ) = am._get_audit_data(
            do_patch_audit,
            do_firmware_audit,
            do_kubernetes_audit,
            do_kube_rootca_update_audit,
            do_software_audit,
        )
        # Convert to dict like what would happen calling via RPC
        patch_audit_data = patch_audit_data.to_dict()
        wm._audit_subcloud(
            subcloud, update_subcloud_state=False, do_audit_openstack=True,
            patch_audit_data=patch_audit_data,
            firmware_audit_data=firmware_audit_data,
            kubernetes_audit_data=kubernetes_audit_data,
            kube_rootca_update_audit_data=kube_rootca_update_audit_data,
            software_audit_data=software_audit_data,
            do_patch_audit=do_patch_audit, do_load_audit=do_load_audit,
            do_firmware_audit=do_firmware_audit,
            do_kubernetes_audit=do_kubernetes_audit,
            do_kube_rootca_update_audit=do_kube_rootca_update_audit,
            do_software_audit=do_software_audit)

        # Verify the subcloud state was not updated
        self.mock_dcmanager_state_api().\
            batch_update_subcloud_availability_and_endpoint_status.\
            assert_not_called()

        # Verify the _update_subcloud_audit_fail_count is not called
        with mock.patch.object(wm, '_update_subcloud_audit_fail_count') as \
                mock_update_subcloud_audit_fail_count:
            mock_update_subcloud_audit_fail_count.assert_not_called()

        # Verify the openstack endpoints were not updated
        self.fake_dcmanager_api.update_subcloud_sync_endpoint_type.\
            assert_not_called()

        # Verify alarm update is not called
        self.fake_alarm_aggr.update_alarm_summary.assert_not_called()

        # Verify patch audit is not called
        self.fake_patch_audit.subcloud_patch_audit.assert_not_called()
        self.fake_patch_audit.subcloud_load_audit.assert_not_called()

        # Verify firmware audit is not called
        self.fake_firmware_audit.subcloud_firmware_audit.assert_not_called()

        # Verify kubernetes audit is not called
        self.fake_kubernetes_audit.subcloud_kubernetes_audit.assert_not_called()

        # Verify kube rootca update audit is not called
        self.fake_kube_rootca_update_audit.subcloud_kube_rootca_audit.\
            assert_not_called()

    @mock.patch.object(scheduler.ThreadGroupManager, 'start')
    @mock.patch.object(subcloud_audit_worker_manager.db_api,
                       'subcloud_audits_end_audit')
    def test_online_subcloud_audit_not_skipping_while_installing(
        self, mock_subcloud_audits_end_audit, mock_thread_start
    ):

        subcloud = self.create_subcloud_static(self.ctx, name='subcloud1')
        self.assertIsNotNone(subcloud)

        wm = subcloud_audit_worker_manager.SubcloudAuditWorkerManager()

        # Set the subcloud to unmanaged/online/installing
        subcloud = db_api.subcloud_update(
            self.ctx, subcloud.id,
            management_state='unmanaged',
            first_identity_sync_complete=True,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            deploy_status=consts.DEPLOY_STATE_INSTALLING)

        wm.audit_subclouds(context=self.ctx,
                           subcloud_ids=[subcloud.id],
                           patch_audit_data=True,
                           firmware_audit_data=True,
                           kubernetes_audit_data=True,
                           do_openstack_audit=False,
                           kube_rootca_update_audit_data=True,
                           software_audit_data=False)

        # Verify if audit was not skipped
        mock_subcloud_audits_end_audit.assert_not_called()
        mock_thread_start.assert_called_once()

    def test_audit_subcloud_going_offline_while_installing(self):
        subcloud = self.create_subcloud_static(self.ctx, name='subcloud1')
        self.assertIsNotNone(subcloud)

        am = subcloud_audit_manager.SubcloudAuditManager()
        wm = subcloud_audit_worker_manager.SubcloudAuditWorkerManager()

        # Set the subcloud to managed/online
        subcloud = db_api.subcloud_update(
            self.ctx, subcloud.id,
            management_state='unmanaged',
            first_identity_sync_complete=True,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            deploy_status=consts.DEPLOY_STATE_INSTALLING,
            audit_fail_count=1)

        # Simulate a connection timeout
        self.mock_openstack_driver.side_effect = keystone_exceptions.ConnectTimeout()

        # Audit the subcloud
        do_patch_audit = True
        do_load_audit = True
        do_firmware_audit = True
        do_kubernetes_audit = True
        do_kube_rootca_update_audit = True
        do_software_audit = True
        (
            patch_audit_data,
            firmware_audit_data,
            kubernetes_audit_data,
            kube_rootca_update_audit_data,
            software_audit_data,
        ) = am._get_audit_data(
            do_patch_audit,
            do_firmware_audit,
            do_kubernetes_audit,
            do_kube_rootca_update_audit,
            do_software_audit,
        )
        # Convert to dict like what would happen calling via RPC
        patch_audit_data = patch_audit_data.to_dict()
        wm._audit_subcloud(
            subcloud, update_subcloud_state=False, do_audit_openstack=False,
            patch_audit_data=patch_audit_data,
            firmware_audit_data=firmware_audit_data,
            kubernetes_audit_data=kubernetes_audit_data,
            kube_rootca_update_audit_data=kube_rootca_update_audit_data,
            software_audit_data=software_audit_data,
            do_patch_audit=do_patch_audit, do_load_audit=do_load_audit,
            do_firmware_audit=do_firmware_audit,
            do_kubernetes_audit=do_kubernetes_audit,
            do_kube_rootca_update_audit=do_kube_rootca_update_audit,
            do_software_audit=do_software_audit)

        # Verify that the subcloud was updated to offline
        self._update_availability(dccommon_consts.AVAILABILITY_OFFLINE, False, 2)
        self.mock_dcmanager_state_api().\
            batch_update_subcloud_availability_and_endpoint_status.\
            assert_called_with(
                mock.ANY, subcloud.name, subcloud.region_name,
                self.batch_state_request_data
        )

    def test_audit_subcloud_offline_update_audit_fail_count_only(self):
        subcloud = self.create_subcloud_static(self.ctx, name='subcloud1')
        self.assertIsNotNone(subcloud)

        am = subcloud_audit_manager.SubcloudAuditManager()
        wm = subcloud_audit_worker_manager.SubcloudAuditWorkerManager()

        audit_fail_count = random.randint(
            consts.AVAIL_FAIL_COUNT_TO_ALARM, consts.AVAIL_FAIL_COUNT_MAX - 1)
        subcloud = db_api.subcloud_update(
            self.ctx, subcloud.id, audit_fail_count=audit_fail_count)

        # Mark a service group as inactive
        service_groups = copy.deepcopy(FAKE_SERVICE_GROUPS)
        service_groups[3].state = 'inactive'
        self.mock_sysinv_client().get_service_groups.return_value = service_groups

        # Audit the subcloud
        do_patch_audit = True
        do_load_audit = True
        do_firmware_audit = True
        do_kubernetes_audit = True
        do_kube_rootca_update_audit = True
        do_software_audit = True
        (
            patch_audit_data,
            firmware_audit_data,
            kubernetes_audit_data,
            kube_rootca_update_audit_data,
            software_audit_data,
        ) = am._get_audit_data(
            do_patch_audit,
            do_firmware_audit,
            do_kubernetes_audit,
            do_kube_rootca_update_audit,
            do_software_audit,
        )
        # Convert to dict like what would happen calling via RPC
        patch_audit_data = patch_audit_data.to_dict()
        wm._audit_subcloud(
            subcloud, update_subcloud_state=False, do_audit_openstack=True,
            patch_audit_data=patch_audit_data,
            firmware_audit_data=firmware_audit_data,
            kubernetes_audit_data=kubernetes_audit_data,
            kube_rootca_update_audit_data=kube_rootca_update_audit_data,
            software_audit_data=software_audit_data,
            do_patch_audit=do_patch_audit, do_load_audit=do_load_audit,
            do_firmware_audit=do_firmware_audit,
            do_kubernetes_audit=do_kubernetes_audit,
            do_kube_rootca_update_audit=do_kube_rootca_update_audit,
            do_software_audit=do_software_audit)

        # Verify the audit fail count was updated in the DB.
        subcloud = db_api.subcloud_get(self.ctx, subcloud.id)
        self.assertEqual(
            subcloud.audit_fail_count, audit_fail_count + 1)

        # Verify the subcloud state was not updated
        self.mock_dcmanager_state_api().\
            batch_update_subcloud_availability_and_endpoint_status.\
            assert_not_called()

        # Verify the openstack endpoints were not updated
        self.fake_dcmanager_api.update_subcloud_sync_endpoint_type.\
            assert_not_called()

        # Verify alarm update is not called
        self.fake_alarm_aggr.update_alarm_summary.assert_not_called()

        # Verify patch audit is not called
        self.fake_patch_audit.subcloud_patch_audit.assert_not_called()
        self.fake_patch_audit.subcloud_load_audit.assert_not_called()

        # Verify firmware audit is not called
        self.fake_firmware_audit.subcloud_firmware_audit.assert_not_called()

        # Verify kubernetes audit is not called
        self.fake_kubernetes_audit.subcloud_kubernetes_audit.assert_not_called()

        # Verify kube rootca update audit is not called
        self.fake_kube_rootca_update_audit.subcloud_kube_rootca_audit.\
            assert_not_called()

    @mock.patch.object(subcloud_audit_worker_manager, 'LOG')
    def test_update_subcloud_audit_fail_count_subcloud_deleted(self, mock_logging):
        subcloud = self.create_subcloud_static(self.ctx, name='subcloud1')
        self.assertIsNotNone(subcloud)

        wm = subcloud_audit_worker_manager.SubcloudAuditWorkerManager()

        audit_fail_count = random.randint(
            consts.AVAIL_FAIL_COUNT_TO_ALARM, consts.AVAIL_FAIL_COUNT_MAX - 1)
        subcloud = db_api.subcloud_update(
            self.ctx, subcloud.id, audit_fail_count=audit_fail_count)
        db_api.subcloud_destroy(self.ctx, subcloud.id)
        wm._update_subcloud_audit_fail_count(subcloud, audit_fail_count)
        mock_logging.info.assert_called_with(
            'Ignoring SubcloudNotFound when attempting update'
            'audit_fail_count for subcloud: %s' % subcloud.name)

    def test_audit_subcloud_online_with_openstack_installed(self):

        subcloud = self.create_subcloud_static(self.ctx, name='subcloud1')
        self.assertIsNotNone(subcloud)

        wm = subcloud_audit_worker_manager.SubcloudAuditWorkerManager()

        # Set the subcloud to online
        subcloud = db_api.subcloud_update(
            self.ctx, subcloud.id,
            management_state='managed',
            first_identity_sync_complete=True,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE)

        # Audit the subcloud
        wm._audit_subcloud(subcloud,
                           False,   # update_subcloud_state
                           True,    # do_audit_openstack
                           None,    # patch_audit_data
                           None,    # firmware_audit_data
                           None,    # kubernetes_audit_data
                           None,    # kube_rootca_update_audit_data
                           None,    # software_audit_data
                           False,   # do_patch_audit
                           False,   # do_load_audit
                           False,   # do_firmware_audit
                           False,   # do_kubernetes_audit
                           False,   # do_kube_rootca_audit
                           False,)  # do_software_audit

        # Verify the subcloud state was not updated
        self.mock_dcmanager_state_api().\
            batch_update_subcloud_availability_and_endpoint_status.\
            assert_not_called()

        # Verify the _update_subcloud_audit_fail_count is not called
        with mock.patch.object(wm, '_update_subcloud_audit_fail_count') as \
                mock_update_subcloud_audit_fail_count:
            mock_update_subcloud_audit_fail_count.assert_not_called()

        # Verify the openstack endpoints were added
        # self.fake_dcmanager_api.update_subcloud_sync_endpoint_type.\
        #    assert_called_with(mock.ANY, 'subcloud1',
        #                       dccommon_consts.ENDPOINT_TYPES_LIST_OS,
        #                       True)

        # Verify alarm update is called
        self.fake_alarm_aggr.update_alarm_summary.assert_called_once_with(
            'subcloud1', self.mock_fm_client())

        # Verify patch audit is not called
        self.fake_patch_audit.subcloud_patch_audit.assert_not_called()
        self.fake_patch_audit.subcloud_load_audit.assert_not_called()

        # Verify firmware audit is not called
        self.fake_firmware_audit.subcloud_firmware_audit.assert_not_called()

        # Verify kubernetes audit is not called
        self.fake_kubernetes_audit.subcloud_kubernetes_audit.assert_not_called()

        # Verify kube rootca update audit is not called
        self.fake_kube_rootca_update_audit.subcloud_kube_rootca_audit.\
            assert_not_called()

    def test_audit_subcloud_online_with_openstack_removed(self):

        subcloud = self.create_subcloud_static(self.ctx, name='subcloud1')
        self.assertIsNotNone(subcloud)

        wm = subcloud_audit_worker_manager.SubcloudAuditWorkerManager()

        # Set the subcloud to online and openstack installed
        subcloud = db_api.subcloud_update(
            self.ctx, subcloud.id,
            management_state='managed',
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            first_identity_sync_complete=True,
            openstack_installed=True)

        # Remove stx-openstack application
        FAKE_APPLICATIONS.pop(1)

        # Audit the subcloud
        wm._audit_subcloud(subcloud,
                           False,  # update_subcloud_state
                           True,  # do_audit_openstack
                           None,  # patch_audit_data
                           None,  # firmware_audit_data
                           None,  # kubernetes_audit_data
                           None,  # kube_roota_update_audit_data
                           None,  # software_audit_data
                           False,  # do_patch_audit
                           False,  # do_load_audit,
                           False,  # do_firmware_audit
                           False,  # do_kubernetes_audit
                           False,  # do_kube_rootca_update_audit
                           False)  # do_software_audit

        # Verify the subcloud state was not updated
        self.mock_dcmanager_state_api().\
            batch_update_subcloud_availability_and_endpoint_status.\
            assert_not_called()

        # Verify the _update_subcloud_audit_fail_count is not called
        with mock.patch.object(wm, '_update_subcloud_audit_fail_count') as \
                mock_update_subcloud_audit_fail_count:
            mock_update_subcloud_audit_fail_count.assert_not_called()

        # Verify the openstack endpoints were removed
        self.fake_dcmanager_api.update_subcloud_sync_endpoint_type.\
            assert_called_with(mock.ANY, subcloud.region_name,
                               dccommon_consts.ENDPOINT_TYPES_LIST_OS, False)

        # Verify alarm update is called
        self.fake_alarm_aggr.update_alarm_summary.assert_called_once_with(
            subcloud.name, self.mock_fm_client())

        # Verify patch audit is not called
        self.fake_patch_audit.subcloud_patch_audit.assert_not_called()
        self.fake_patch_audit.subcloud_load_audit.assert_not_called()

        # Verify firmware audit is not called
        self.fake_firmware_audit.subcloud_firmware_audit.assert_not_called()

        # Verify kubernetes audit is not called
        self.fake_kubernetes_audit.subcloud_kubernetes_audit.assert_not_called()

        # Verify kube rootca update audit is not called
        self.fake_kube_rootca_update_audit.subcloud_kube_rootca_audit.\
            assert_not_called()

    def test_audit_subcloud_online_with_openstack_inactive(self):

        subcloud = self.create_subcloud_static(self.ctx, name='subcloud1')
        self.assertIsNotNone(subcloud)

        wm = subcloud_audit_worker_manager.SubcloudAuditWorkerManager()

        # Set the subcloud to online and openstack installed
        subcloud = db_api.subcloud_update(
            self.ctx, subcloud.id,
            management_state='managed',
            first_identity_sync_complete=True,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            openstack_installed=True)

        # stx-openstack application is not active
        FAKE_APPLICATIONS[1].active = False

        # Audit the subcloud
        wm._audit_subcloud(subcloud,
                           False,  # update_subcloud_state
                           True,  # do_audit_openstack
                           None,  # patch_audit_data
                           None,  # firmware_audit_data
                           None,  # kubernetes_audit_data
                           None,  # kube_rootca_update_audit_data
                           None,  # software_audit_data
                           False,  # do_patch_audit
                           False,  # do_load_audit
                           False,  # do_firmware_audit
                           False,  # do_kubernetes_audit
                           False,  # do_kube_rootca_update_audit
                           False)  # do_software_audit

        # Verify the subcloud state was not updated
        self.mock_dcmanager_state_api().\
            batch_update_subcloud_availability_and_endpoint_status.\
            assert_not_called()

        # Verify the _update_subcloud_audit_fail_count is not called
        with mock.patch.object(wm, '_update_subcloud_audit_fail_count') as \
                mock_update_subcloud_audit_fail_count:
            mock_update_subcloud_audit_fail_count.assert_not_called()

        # Verify the openstack endpoints were removed
        self.fake_dcmanager_api.update_subcloud_sync_endpoint_type.\
            assert_called_with(mock.ANY, subcloud.region_name,
                               dccommon_consts.ENDPOINT_TYPES_LIST_OS, False)

        # Verify alarm update is called
        self.fake_alarm_aggr.update_alarm_summary.assert_called_once_with(
            'subcloud1', self.mock_fm_client())

        # Verify patch audit is not called
        self.fake_patch_audit.subcloud_patch_audit.assert_not_called()
        self.fake_patch_audit.subcloud_load_audit.assert_not_called()

        # Verify firmware audit is not called
        self.fake_firmware_audit.subcloud_firmware_audit.assert_not_called()

        # Verify kubernetes audit is not called
        self.fake_kubernetes_audit.subcloud_kubernetes_audit.assert_not_called()

        # Verify kube rootca update audit is not called
        self.fake_kube_rootca_update_audit.subcloud_kube_rootca_audit.\
            assert_not_called()

    def test_audit_subcloud_partial_subaudits(self):
        subcloud = self.create_subcloud_static(self.ctx, name='subcloud1')
        self.assertIsNotNone(subcloud)

        # Set the subcloud to managed
        subcloud = db_api.subcloud_update(
            self.ctx, subcloud.id,
            first_identity_sync_complete=True,
            management_state='managed')

        am = subcloud_audit_manager.SubcloudAuditManager()
        wm = subcloud_audit_worker_manager.SubcloudAuditWorkerManager()

        # Pretend like we're going to audit the subcloud
        do_patch_audit = True
        do_load_audit = False
        do_firmware_audit = False
        do_kubernetes_audit = False
        do_kube_rootca_audit = False
        do_kube_rootca_update_audit = False
        do_software_audit = False
        (
            patch_audit_data,
            firmware_audit_data,
            kubernetes_audit_data,
            kube_rootca_update_audit_data,
            software_audit_data,
        ) = am._get_audit_data(
            do_patch_audit,
            do_firmware_audit,
            do_kubernetes_audit,
            do_kube_rootca_update_audit,
            do_software_audit,
        )
        # Convert to dict like what would happen calling via RPC
        patch_audit_data = patch_audit_data.to_dict()

        # Now pretend someone triggered all the subaudits in the DB
        # after the subcloud audit was triggered but before it ran.
        am.trigger_subcloud_audits(self.ctx, subcloud.id, None)

        # Make sure all subaudits are requested in DB
        audits = db_api.subcloud_audits_get(self.ctx, subcloud.id)
        self.assertEqual(audits.patch_audit_requested, True)
        self.assertEqual(audits.load_audit_requested, True)
        self.assertEqual(audits.firmware_audit_requested, True)

        # Do the actual audit
        wm._do_audit_subcloud(subcloud,
                              False,  # update_subcloud_state
                              False,  # do_audit_openstack
                              patch_audit_data,
                              firmware_audit_data,
                              kubernetes_audit_data,
                              kube_rootca_update_audit_data,
                              software_audit_data,
                              do_patch_audit,
                              do_load_audit,
                              do_firmware_audit,
                              do_kubernetes_audit,
                              do_kube_rootca_audit,
                              do_software_audit)

        # Verify patch audit is called
        self.fake_patch_audit.subcloud_patch_audit.assert_called_once_with(
            mock.ANY, mock.ANY, subcloud.management_start_ip,
            subcloud.name, subcloud.region_name, patch_audit_data)
        self.fake_patch_audit.subcloud_load_audit.assert_not_called()

        # Verify the _update_subcloud_audit_fail_count is not called
        with mock.patch.object(wm, '_update_subcloud_audit_fail_count') as \
                mock_update_subcloud_audit_fail_count:
            mock_update_subcloud_audit_fail_count.assert_not_called()

        # Verify firmware audit is not called
        self.fake_firmware_audit.subcloud_firmware_audit.assert_not_called()

        # Verify kubernetes audit is not called
        self.fake_kubernetes_audit.subcloud_kubernetes_audit.assert_not_called()

        # Verify kube rootca update audit is not called
        self.fake_kube_rootca_update_audit.subcloud_kube_rootca_audit.\
            assert_not_called()

        # Ensure the subaudits that didn't run are still requested
        audits = db_api.subcloud_audits_get(self.ctx, subcloud.id)
        self.assertEqual(audits.patch_audit_requested, False)
        self.assertEqual(audits.load_audit_requested, True)
        self.assertEqual(audits.firmware_audit_requested, True)
        self.assertEqual(audits.kubernetes_audit_requested, True)
        self.assertEqual(audits.kube_rootca_update_audit_requested, True)
