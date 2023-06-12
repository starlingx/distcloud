# Copyright (c) 2017-2022 Wind River Systems, Inc.
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

import mock
import uuid

from dccommon import consts as dccommon_consts
from dcmanager.audit import firmware_audit
from dcmanager.audit import kubernetes_audit
from dcmanager.audit import patch_audit
from dcmanager.audit import subcloud_audit_manager

from dcmanager.tests import base
from dcmanager.tests import utils

PREVIOUS_KUBE_VERSION = 'v1.2.3'
UPGRADED_KUBE_VERSION = 'v1.2.3-a'


class FakeDCManagerStateAPI(object):
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


class FakeKubeUpgrade(object):
    def __init__(self):
        pass


class FakeAuditWorkerAPI(object):

    def __init__(self):
        self.audit_subclouds = mock.MagicMock()


class FakeSysinvClient(object):
    def __init__(self):
        self.region = None
        self.session = None
        self.get_kube_versions = mock.MagicMock()
        self.get_kube_upgrades = mock.MagicMock()


class TestKubernetesAudit(base.DCManagerTestCase):
    def setUp(self):
        super(TestKubernetesAudit, self).setUp()
        self.ctxt = utils.dummy_context()

        # Mock the DCManager subcloud state API
        self.fake_dcmanager_state_api = FakeDCManagerStateAPI()
        p = mock.patch('dcmanager.rpc.client.SubcloudStateClient')
        self.mock_dcmanager_state_api = p.start()
        self.mock_dcmanager_state_api.return_value = \
            self.fake_dcmanager_state_api
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

        # Set the kube upgrade objects as being empty for all regions
        self.kube_sysinv_client.get_kube_upgrades.return_value = []

    def _rpc_convert(self, object_list):
        # Convert to dict like what would happen calling via RPC
        dict_results = []
        for result in object_list:
            dict_results.append(result.to_dict())
        return dict_results

    def get_kube_audit_data(self, am):
        patch_audit_data, firmware_audit_data, kubernetes_audit_data, kube_rootca = \
            am._get_audit_data(True, True, True, True)
        # Convert to dict like what would happen calling via RPC
        kubernetes_audit_data = self._rpc_convert(kubernetes_audit_data)
        return kubernetes_audit_data

    def test_init(self):
        audit = kubernetes_audit.KubernetesAudit(self.ctxt,
                                                 self.fake_dcmanager_state_api)
        self.assertIsNotNone(audit)
        self.assertEqual(self.ctxt, audit.context)
        self.assertEqual(self.fake_dcmanager_state_api,
                         audit.state_rpc_client)

    @mock.patch.object(subcloud_audit_manager, 'context')
    def test_no_kubernetes_audit_data_to_sync(self, mock_context):
        mock_context.get_admin_context.return_value = self.ctxt

        audit = kubernetes_audit.KubernetesAudit(self.ctxt,
                                                 self.fake_dcmanager_state_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.kubernetes_audit = audit
        kubernetes_audit_data = self.get_kube_audit_data(am)

        subclouds = {base.SUBCLOUD_1['name']: base.SUBCLOUD_1['region_name'],
                     base.SUBCLOUD_2['name']: base.SUBCLOUD_2['region_name']}
        for name, region in subclouds.items():
            audit.subcloud_kubernetes_audit(name, region, kubernetes_audit_data)
            expected_calls = [
                mock.call(mock.ANY,
                          subcloud_name=name,
                          subcloud_region=region,
                          endpoint_type=dccommon_consts.ENDPOINT_TYPE_KUBERNETES,
                          sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC)]
            self.fake_dcmanager_state_api.update_subcloud_endpoint_status. \
                assert_has_calls(expected_calls)

    @mock.patch.object(subcloud_audit_manager, 'context')
    def test_kubernetes_audit_data_out_of_sync_older(self, mock_context):
        mock_context.get_admin_context.return_value = self.ctxt
        audit = kubernetes_audit.KubernetesAudit(self.ctxt,
                                                 self.fake_dcmanager_state_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.kubernetes_audit = audit

        # Set the region one data as being the upgraded version
        self.kube_sysinv_client.get_kube_versions.return_value = [
            FakeKubeVersion(version=UPGRADED_KUBE_VERSION),
        ]
        kubernetes_audit_data = self.get_kube_audit_data(am)

        subclouds = {base.SUBCLOUD_1['name']: base.SUBCLOUD_1['region_name'],
                     base.SUBCLOUD_2['name']: base.SUBCLOUD_2['region_name']}
        for name, region in subclouds.items():
            # return different kube versions in the subclouds
            self.kube_sysinv_client.get_kube_versions.return_value = [
                FakeKubeVersion(version=PREVIOUS_KUBE_VERSION),
            ]
            audit.subcloud_kubernetes_audit(name, region, kubernetes_audit_data)
            expected_calls = [
                mock.call(mock.ANY,
                          subcloud_name=name,
                          subcloud_region=region,
                          endpoint_type=dccommon_consts.ENDPOINT_TYPE_KUBERNETES,
                          sync_status=dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)]
            self.fake_dcmanager_state_api.update_subcloud_endpoint_status. \
                assert_has_calls(expected_calls)

    @mock.patch.object(subcloud_audit_manager, 'context')
    def test_kubernetes_audit_data_out_of_sync_newer(self, mock_context):
        mock_context.get_admin_context.return_value = self.ctxt
        audit = kubernetes_audit.KubernetesAudit(self.ctxt,
                                                 self.fake_dcmanager_state_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.kubernetes_audit = audit

        # Set the region one data as being the previous version
        self.kube_sysinv_client.get_kube_versions.return_value = [
            FakeKubeVersion(version=PREVIOUS_KUBE_VERSION),
        ]
        kubernetes_audit_data = self.get_kube_audit_data(am)

        subclouds = {base.SUBCLOUD_1['name']: base.SUBCLOUD_1['region_name'],
                     base.SUBCLOUD_2['name']: base.SUBCLOUD_2['region_name']}
        for name, region in subclouds.items():
            # return different kube versions in the subclouds
            self.kube_sysinv_client.get_kube_versions.return_value = [
                FakeKubeVersion(version=UPGRADED_KUBE_VERSION),
            ]
            audit.subcloud_kubernetes_audit(name, region, kubernetes_audit_data)
            expected_calls = [
                mock.call(mock.ANY,
                          subcloud_name=name,
                          subcloud_region=region,
                          endpoint_type=dccommon_consts.ENDPOINT_TYPE_KUBERNETES,
                          sync_status=dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)]
            self.fake_dcmanager_state_api.update_subcloud_endpoint_status. \
                assert_has_calls(expected_calls)

    @mock.patch.object(subcloud_audit_manager, 'context')
    def test_kubernetes_audit_data_in_sync(self,
                                           mock_context):
        mock_context.get_admin_context.return_value = self.ctxt
        audit = kubernetes_audit.KubernetesAudit(self.ctxt,
                                                 self.fake_dcmanager_state_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.kubernetes_audit = audit

        # Set the region one data as being the upgraded version
        self.kube_sysinv_client.get_kube_versions.return_value = [
            FakeKubeVersion(version=UPGRADED_KUBE_VERSION),
        ]
        kubernetes_audit_data = self.get_kube_audit_data(am)

        subclouds = {base.SUBCLOUD_1['name']: base.SUBCLOUD_1['region_name'],
                     base.SUBCLOUD_2['name']: base.SUBCLOUD_2['region_name']}
        for name, region in subclouds.items():
            # return same kube versions in the subclouds
            self.kube_sysinv_client.get_kube_versions.return_value = [
                FakeKubeVersion(version=UPGRADED_KUBE_VERSION),
            ]
            audit.subcloud_kubernetes_audit(name, region, kubernetes_audit_data)
            expected_calls = [
                mock.call(mock.ANY,
                          subcloud_name=name,
                          subcloud_region=region,
                          endpoint_type=dccommon_consts.ENDPOINT_TYPE_KUBERNETES,
                          sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC)]
            self.fake_dcmanager_state_api.update_subcloud_endpoint_status. \
                assert_has_calls(expected_calls)

    @mock.patch.object(subcloud_audit_manager, 'context')
    def test_kubernetes_audit_data_in_sync_but_existing_upgrade(self,
                                                                mock_context):
        # If a subcloud has an existing upgrade, it is out of sync
        # even if the kube versions match
        mock_context.get_admin_context.return_value = self.ctxt
        audit = kubernetes_audit.KubernetesAudit(self.ctxt,
                                                 self.fake_dcmanager_state_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.kubernetes_audit = audit

        # mock that there is a kube upgrade (only queried in subclouds)
        self.kube_sysinv_client.get_kube_upgrades.return_value = [
            FakeKubeUpgrade()
        ]
        # Set the region one data as being the upgraded version
        self.kube_sysinv_client.get_kube_versions.return_value = [
            FakeKubeVersion(version=UPGRADED_KUBE_VERSION),
        ]
        kubernetes_audit_data = self.get_kube_audit_data(am)

        subclouds = {base.SUBCLOUD_1['name']: base.SUBCLOUD_1['region_name'],
                     base.SUBCLOUD_2['name']: base.SUBCLOUD_2['region_name']}
        for name, region in subclouds.items():
            # return same kube versions in the subclouds
            self.kube_sysinv_client.get_kube_versions.return_value = [
                FakeKubeVersion(version=UPGRADED_KUBE_VERSION),
            ]
            audit.subcloud_kubernetes_audit(name, region, kubernetes_audit_data)
            expected_calls = [
                mock.call(mock.ANY,
                          subcloud_name=name,
                          subcloud_region=region,
                          endpoint_type=dccommon_consts.ENDPOINT_TYPE_KUBERNETES,
                          sync_status=dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)]
            self.fake_dcmanager_state_api.update_subcloud_endpoint_status. \
                assert_has_calls(expected_calls)
