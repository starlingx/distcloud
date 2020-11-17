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
# Copyright (c) 2017-2021 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

import mock
import uuid

from dcmanager.audit import firmware_audit
from dcmanager.audit import kubernetes_audit
from dcmanager.audit import patch_audit
from dcmanager.audit import subcloud_audit_manager
from dcmanager.common import consts
from dcorch.common import consts as dcorch_consts

from dcmanager.tests import base
from dcmanager.tests import utils


PREVIOUS_KUBE_VERSION = 'v1.2.3'
UPGRADED_KUBE_VERSION = 'v1.2.3-a'


class FakeDCManagerAPI(object):

    def __init__(self):
        self.update_subcloud_availability = mock.MagicMock()
        self.update_subcloud_endpoint_status = mock.MagicMock()


class FakeKubeVersion(object):
    def __init__(self,
                 obj_id=1,
                 version=UPGRADED_KUBE_VERSION,
                 target=True,
                 state='active'):
        self.id = obj_id
        self.uuid = str(uuid.uuid4())
        self.version = version
        self.target = target
        self.state = state
        self.upgrade_from = []
        self.applied_patches = []
        self.available_patches = []

    def to_dict(self):
        return dict(self.__dict__)


class FakeAuditWorkerAPI(object):

    def __init__(self):
        self.audit_subclouds = mock.MagicMock()


class FakeSysinvClient(object):
    def __init__(self):
        self.region = None
        self.session = None
        self.get_kube_versions = mock.MagicMock()


class TestKubernetesAudit(base.DCManagerTestCase):
    def setUp(self):
        super(TestKubernetesAudit, self).setUp()
        self.ctxt = utils.dummy_context()

        # Mock the DCManager API
        self.fake_dcmanager_api = FakeDCManagerAPI()
        p = mock.patch('dcmanager.rpc.client.ManagerClient')
        self.mock_dcmanager_api = p.start()
        self.mock_dcmanager_api.return_value = self.fake_dcmanager_api
        self.addCleanup(p.stop)

        # Mock the Audit Worker API
        self.fake_audit_worker_api = FakeAuditWorkerAPI()
        p = mock.patch('dcmanager.audit.rpcapi.ManagerAuditWorkerClient')
        self.mock_audit_worker_api = p.start()
        self.mock_audit_worker_api.return_value = self.fake_audit_worker_api
        self.addCleanup(p.stop)

        # Note: mock where an item is used, not where it comes from
        p = mock.patch.object(patch_audit, 'OpenStackDriver')
        self.mock_patch_audit_driver = p.start()
        self.mock_patch_audit_driver.return_value = mock.MagicMock()
        self.addCleanup(p.stop)

        p = mock.patch.object(patch_audit, 'SysinvClient')
        self.mock_patch_audit_sys = p.start()
        self.mock_patch_audit_sys.return_value = mock.MagicMock()
        self.addCleanup(p.stop)

        p = mock.patch.object(patch_audit, 'PatchingClient')
        self.mock_patch_audit_pc = p.start()
        self.mock_patch_audit_pc.return_value = mock.MagicMock()
        self.addCleanup(p.stop)

        p = mock.patch.object(firmware_audit, 'OpenStackDriver')
        self.mock_firmware_audit_driver = p.start()
        self.mock_firmware_audit_driver.return_value = mock.MagicMock()
        self.addCleanup(p.stop)

        p = mock.patch.object(firmware_audit, 'SysinvClient')
        self.mock_firmware_audit_sys = p.start()
        self.mock_firmware_audit_sys .return_value = mock.MagicMock()
        self.addCleanup(p.stop)

        p = mock.patch.object(kubernetes_audit, 'OpenStackDriver')
        self.kube_openstack_driver = mock.MagicMock()
        self.mock_kube_audit_driver = p.start()
        self.mock_kube_audit_driver.return_value = self.kube_openstack_driver
        self.addCleanup(p.stop)

        p = mock.patch.object(kubernetes_audit, 'SysinvClient')
        self.kube_sysinv_client = FakeSysinvClient()
        self.mock_kube_audit_sys = p.start()
        self.mock_kube_audit_sys.return_value = self.kube_sysinv_client
        self.addCleanup(p.stop)

    def _rpc_convert(self, object_list):
        # Convert to dict like what would happen calling via RPC
        dict_results = []
        for result in object_list:
            dict_results.append(result.to_dict())
        return dict_results

    def test_init(self):
        audit = kubernetes_audit.KubernetesAudit(self.ctxt,
                                                 self.fake_dcmanager_api)
        self.assertIsNotNone(audit)
        self.assertEqual(self.ctxt, audit.context)
        self.assertEqual(self.fake_dcmanager_api, audit.dcmanager_rpc_client)

    @mock.patch.object(subcloud_audit_manager, 'context')
    def test_no_kubernetes_audit_data_to_sync(self, mock_context):
        mock_context.get_admin_context.return_value = self.ctxt

        audit = kubernetes_audit.KubernetesAudit(self.ctxt,
                                                 self.fake_dcmanager_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.kubernetes_audit = audit

        patch_audit_data, firmware_audit_data, kubernetes_audit_data = \
            am._get_audit_data(True, True, True)
        # Convert to dict like what would happen calling via RPC
        kubernetes_audit_data = self._rpc_convert(kubernetes_audit_data)

        for name in ['subcloud1', 'subcloud2']:
            audit.subcloud_kubernetes_audit(name, kubernetes_audit_data)
            expected_calls = [
                mock.call(mock.ANY,
                          subcloud_name=name,
                          endpoint_type=dcorch_consts.ENDPOINT_TYPE_KUBERNETES,
                          sync_status=consts.SYNC_STATUS_IN_SYNC)]
            self.fake_dcmanager_api.update_subcloud_endpoint_status. \
                assert_has_calls(expected_calls)

    @mock.patch.object(subcloud_audit_manager, 'context')
    def test_kubernetes_audit_data_out_of_sync_older(self, mock_context):
        mock_context.get_admin_context.return_value = self.ctxt
        audit = kubernetes_audit.KubernetesAudit(self.ctxt,
                                                 self.fake_dcmanager_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.kubernetes_audit = audit

        # Set the region one data as being the upgraded version
        self.kube_sysinv_client.get_kube_versions.return_value = [
            FakeKubeVersion(version=UPGRADED_KUBE_VERSION),
        ]
        patch_audit_data, firmware_audit_data, kubernetes_audit_data = \
            am._get_audit_data(True, True, True)
        # Convert to dict like what would happen calling via RPC
        kubernetes_audit_data = self._rpc_convert(kubernetes_audit_data)

        for name in ['subcloud1', 'subcloud2']:
            # return different kube versions in the subclouds
            self.kube_sysinv_client.get_kube_versions.return_value = [
                FakeKubeVersion(version=PREVIOUS_KUBE_VERSION),
            ]
            audit.subcloud_kubernetes_audit(name, kubernetes_audit_data)
            expected_calls = [
                mock.call(mock.ANY,
                          subcloud_name=name,
                          endpoint_type=dcorch_consts.ENDPOINT_TYPE_KUBERNETES,
                          sync_status=consts.SYNC_STATUS_OUT_OF_SYNC)]
            self.fake_dcmanager_api.update_subcloud_endpoint_status. \
                assert_has_calls(expected_calls)

    @mock.patch.object(subcloud_audit_manager, 'context')
    def test_kubernetes_audit_data_out_of_sync_newer(self, mock_context):
        mock_context.get_admin_context.return_value = self.ctxt
        audit = kubernetes_audit.KubernetesAudit(self.ctxt,
                                                 self.fake_dcmanager_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.kubernetes_audit = audit

        # Set the region one data as being the upgraded version
        self.kube_sysinv_client.get_kube_versions.return_value = [
            FakeKubeVersion(version=PREVIOUS_KUBE_VERSION),
        ]
        patch_audit_data, firmware_audit_data, kubernetes_audit_data = \
            am._get_audit_data(True, True, True)
        # Convert to dict like what would happen calling via RPC
        kubernetes_audit_data = self._rpc_convert(kubernetes_audit_data)

        for name in ['subcloud1', 'subcloud2']:
            # return different kube versions in the subclouds
            self.kube_sysinv_client.get_kube_versions.return_value = [
                FakeKubeVersion(version=UPGRADED_KUBE_VERSION),
            ]
            audit.subcloud_kubernetes_audit(name, kubernetes_audit_data)
            expected_calls = [
                mock.call(mock.ANY,
                          subcloud_name=name,
                          endpoint_type=dcorch_consts.ENDPOINT_TYPE_KUBERNETES,
                          sync_status=consts.SYNC_STATUS_OUT_OF_SYNC)]
            self.fake_dcmanager_api.update_subcloud_endpoint_status. \
                assert_has_calls(expected_calls)
