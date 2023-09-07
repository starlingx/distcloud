# Copyright (c) 2017-2023 Wind River Systems, Inc.
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

from oslo_config import cfg

import sys

from dccommon import consts as dccommon_consts

sys.modules['fm_core'] = mock.Mock()

from dcmanager.audit import patch_audit
from dcmanager.audit import subcloud_audit_manager
from dcmanager.tests import base
from dcmanager.tests import utils

CONF = cfg.CONF


class FakeDCManagerStateAPI(object):
    def __init__(self):
        self.update_subcloud_availability = mock.MagicMock()
        self.update_subcloud_endpoint_status = mock.MagicMock()


class FakeAuditWorkerAPI(object):

    def __init__(self):
        self.audit_subclouds = mock.MagicMock()


class Load(object):
    def __init__(self, software_version, state):
        self.software_version = software_version
        self.state = state


class Upgrade(object):
    def __init__(self, state):
        self.state = state


class System(object):
    def __init__(self, software_version):
        self.software_version = software_version


class FakePatchingClientInSync(object):
    def __init__(self, region, session, endpoint):
        self.region = region
        self.session = session
        self.endpoint = endpoint

    def query(self):
        if self.region == 'RegionOne':
            return {'DC.1': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    'DC.2': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    'DC.3': {'sw_version': '17.07',
                             'repostate': 'Committed',
                             'patchstate': 'Committed'},
                    'DC.4': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    # This patch won't make us out of sync because it is for
                    # a different release.
                    'OTHER_REL_DC.1': {'sw_version': '17.08',
                                       'repostate': 'Applied',
                                       'patchstate': 'Applied'},
                    }
        elif self.region in [base.SUBCLOUD_1['region_name'],
                             base.SUBCLOUD_2['region_name']]:
            return {'DC.1': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    'DC.2': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    'DC.3': {'sw_version': '17.07',
                             'repostate': 'Committed',
                             'patchstate': 'Committed'},
                    'DC.4': {'sw_version': '17.07',
                             'repostate': 'Committed',
                             'patchstate': 'Committed'},
                    }
        else:
            return {}


class FakePatchingClientOutOfSync(object):
    def __init__(self, region, session, endpoint):
        self.region = region
        self.session = session
        self.endpoint = endpoint

    def query(self):
        if self.region == 'RegionOne':
            return {'DC.1': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Partial-Apply'},
                    'DC.2': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'}}
        elif self.region == base.SUBCLOUD_1['region_name']:
            return {'DC.1': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    'DC.2': {'sw_version': '17.07',
                             'repostate': 'Available',
                             'patchstate': 'Available'}}
        elif self.region == base.SUBCLOUD_2['region_name']:
            return {'DC.1': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'}}
        elif self.region == base.SUBCLOUD_3['region_name']:
            return {'DC.1': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    'DC.2': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'}}
        elif self.region == base.SUBCLOUD_4['region_name']:
            return {'DC.1': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    'DC.2': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Partial-Apply'}}
        else:
            return {}


class FakePatchingClientExtraPatches(object):
    def __init__(self, region, session, endpoint):
        self.region = region
        self.session = session
        self.endpoint = endpoint

    def query(self):
        if self.region == 'RegionOne':
            return {'DC.1': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    'DC.2': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'}}
        elif self.region == 'subcloud1':
            return {'DC.1': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    'DC.2': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    'DC.3': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'}}
        elif self.region == 'subcloud2':
            return {'DC.1': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    'DC.2': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    'OTHER_REL_DC.1': {'sw_version': '17.08',
                                       'repostate': 'Applied',
                                       'patchstate': 'Applied'}}
        else:
            return {}


class FakeSysinvClientOneLoad(object):
    def __init__(self, region, session, endpoint):
        self.region = region
        self.session = session
        self.endpoint = endpoint
        self.loads = [Load('17.07', 'active')]
        self.upgrades = []
        self.system = System('17.07')

    def get_loads(self):
        return self.loads

    def get_upgrades(self):
        return self.upgrades

    def get_system(self):
        return self.system


class FakeSysinvClientOneLoadUnmatchedSoftwareVersion(object):
    def __init__(self, region, session, endpoint):
        self.region = region
        self.session = session
        self.endpoint = endpoint
        self.loads = [Load('17.07', 'active')]
        self.upgrades = []
        self.system = System('17.07')

    def get_loads(self):
        return self.loads

    def get_upgrades(self):
        return self.upgrades

    def get_system(self):
        if self.region == base.SUBCLOUD_2['region_name']:
            return System('17.06')
        else:
            return self.system


class FakeSysinvClientOneLoadUpgradeInProgress(object):
    def __init__(self, region, session, endpoint):
        self.region = region
        self.session = session
        self.endpoint = endpoint
        self.loads = [Load('17.07', 'active')]
        self.upgrades = []
        self.system = System('17.07')

    def get_loads(self):
        return self.loads

    def get_upgrades(self):
        if self.region == base.SUBCLOUD_2['region_name']:
            return [Upgrade('started')]
        else:
            return self.upgrades

    def get_system(self):
        return self.system


class TestPatchAudit(base.DCManagerTestCase):
    def setUp(self):
        super(TestPatchAudit, self).setUp()
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

    def get_patch_audit_data(self, am):
        (patch_audit_data, firmware_audit_data,
         kubernetes_audit_data, kube_rootca_data) = \
            am._get_audit_data(True, True, True, True)
        # Convert to dict like what would happen calling via RPC
        patch_audit_data = patch_audit_data.to_dict()
        return patch_audit_data

    def test_init(self):
        pm = patch_audit.PatchAudit(self.ctxt,
                                    self.fake_dcmanager_state_api)
        self.assertIsNotNone(pm)
        self.assertEqual(self.ctxt, pm.context)
        self.assertEqual(self.fake_dcmanager_state_api, pm.state_rpc_client)

    @mock.patch.object(patch_audit, 'SysinvClient')
    @mock.patch.object(patch_audit, 'PatchingClient')
    @mock.patch.object(patch_audit, 'OpenStackDriver')
    @mock.patch.object(subcloud_audit_manager, 'context')
    def test_periodic_patch_audit_in_sync(self, mock_context,
                                          mock_openstack_driver,
                                          mock_patching_client,
                                          mock_sysinv_client):
        mock_context.get_admin_context.return_value = self.ctxt
        mock_patching_client.side_effect = FakePatchingClientInSync
        mock_sysinv_client.side_effect = FakeSysinvClientOneLoad

        pm = patch_audit.PatchAudit(self.ctxt,
                                    self.fake_dcmanager_state_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.patch_audit = pm

        do_load_audit = True
        patch_audit_data = self.get_patch_audit_data(am)

        subclouds = {base.SUBCLOUD_1['name']: base.SUBCLOUD_1['region_name'],
                     base.SUBCLOUD_2['name']: base.SUBCLOUD_2['region_name']}
        for name, region in subclouds.items():
            pm.subcloud_patch_audit(name, region, patch_audit_data, do_load_audit)
            expected_calls = [
                mock.call(mock.ANY,
                          subcloud_name=name,
                          subcloud_region=region,
                          endpoint_type=dccommon_consts.ENDPOINT_TYPE_PATCHING,
                          sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC),
                mock.call(mock.ANY,
                          subcloud_name=name,
                          subcloud_region=region,
                          endpoint_type=dccommon_consts.ENDPOINT_TYPE_LOAD,
                          sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC)]
            self.fake_dcmanager_state_api.update_subcloud_endpoint_status. \
                assert_has_calls(expected_calls)

    @mock.patch.object(patch_audit, 'SysinvClient')
    @mock.patch.object(patch_audit, 'PatchingClient')
    @mock.patch.object(patch_audit, 'OpenStackDriver')
    @mock.patch.object(subcloud_audit_manager, 'context')
    def test_periodic_patch_audit_out_of_sync(self, mock_context,
                                              mock_openstack_driver,
                                              mock_patching_client,
                                              mock_sysinv_client):
        mock_context.get_admin_context.return_value = self.ctxt
        pm = patch_audit.PatchAudit(self.ctxt,
                                    self.fake_dcmanager_state_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.patch_audit = pm

        mock_patching_client.side_effect = FakePatchingClientOutOfSync
        mock_sysinv_client.side_effect = FakeSysinvClientOneLoad

        do_load_audit = True
        patch_audit_data = self.get_patch_audit_data(am)

        subclouds = {base.SUBCLOUD_1['name']: base.SUBCLOUD_1['region_name'],
                     base.SUBCLOUD_2['name']: base.SUBCLOUD_2['region_name'],
                     base.SUBCLOUD_3['name']: base.SUBCLOUD_3['region_name'],
                     base.SUBCLOUD_4['name']: base.SUBCLOUD_4['region_name']}
        for name, region in subclouds.items():
            pm.subcloud_patch_audit(name, region, patch_audit_data, do_load_audit)

        expected_calls = [
            mock.call(mock.ANY,
                      subcloud_name=base.SUBCLOUD_1['name'],
                      subcloud_region=base.SUBCLOUD_1['region_name'],
                      endpoint_type=dccommon_consts.ENDPOINT_TYPE_PATCHING,
                      sync_status=dccommon_consts.SYNC_STATUS_OUT_OF_SYNC),
            mock.call(mock.ANY,
                      subcloud_name=base.SUBCLOUD_1['name'],
                      subcloud_region=base.SUBCLOUD_1['region_name'],
                      endpoint_type=dccommon_consts.ENDPOINT_TYPE_LOAD,
                      sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC),
            mock.call(mock.ANY,
                      subcloud_name=base.SUBCLOUD_2['name'],
                      subcloud_region=base.SUBCLOUD_2['region_name'],
                      endpoint_type=dccommon_consts.ENDPOINT_TYPE_PATCHING,
                      sync_status=dccommon_consts.SYNC_STATUS_OUT_OF_SYNC),
            mock.call(mock.ANY,
                      subcloud_name=base.SUBCLOUD_2['name'],
                      subcloud_region=base.SUBCLOUD_2['region_name'],
                      endpoint_type=dccommon_consts.ENDPOINT_TYPE_LOAD,
                      sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC),
            mock.call(mock.ANY,
                      subcloud_name=base.SUBCLOUD_3['name'],
                      subcloud_region=base.SUBCLOUD_3['region_name'],
                      endpoint_type=dccommon_consts.ENDPOINT_TYPE_PATCHING,
                      sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC),
            mock.call(mock.ANY,
                      subcloud_name=base.SUBCLOUD_3['name'],
                      subcloud_region=base.SUBCLOUD_3['region_name'],
                      endpoint_type=dccommon_consts.ENDPOINT_TYPE_LOAD,
                      sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC),
            mock.call(mock.ANY,
                      subcloud_name=base.SUBCLOUD_4['name'],
                      subcloud_region=base.SUBCLOUD_4['region_name'],
                      endpoint_type=dccommon_consts.ENDPOINT_TYPE_PATCHING,
                      sync_status=dccommon_consts.SYNC_STATUS_OUT_OF_SYNC),
            mock.call(mock.ANY,
                      subcloud_name=base.SUBCLOUD_4['name'],
                      subcloud_region=base.SUBCLOUD_4['region_name'],
                      endpoint_type=dccommon_consts.ENDPOINT_TYPE_LOAD,
                      sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC),
            ]

        self.fake_dcmanager_state_api.update_subcloud_endpoint_status.\
            assert_has_calls(expected_calls)

    @mock.patch.object(patch_audit, 'SysinvClient')
    @mock.patch.object(patch_audit, 'PatchingClient')
    @mock.patch.object(patch_audit, 'OpenStackDriver')
    @mock.patch.object(subcloud_audit_manager, 'context')
    def test_periodic_patch_audit_extra_patches(self, mock_context,
                                                mock_openstack_driver,
                                                mock_patching_client,
                                                mock_sysinv_client):
        mock_context.get_admin_context.return_value = self.ctxt
        pm = patch_audit.PatchAudit(self.ctxt,
                                    self.fake_dcmanager_state_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.patch_audit = pm

        mock_patching_client.side_effect = FakePatchingClientExtraPatches
        mock_sysinv_client.side_effect = FakeSysinvClientOneLoad

        do_load_audit = True
        patch_audit_data = self.get_patch_audit_data(am)

        subclouds = {base.SUBCLOUD_1['name']: base.SUBCLOUD_1['region_name'],
                     base.SUBCLOUD_2['name']: base.SUBCLOUD_2['region_name']}
        for name, region in subclouds.items():
            pm.subcloud_patch_audit(name, region, patch_audit_data, do_load_audit)
            expected_calls = [
                mock.call(mock.ANY,
                          subcloud_name=name,
                          subcloud_region=region,
                          endpoint_type=dccommon_consts.ENDPOINT_TYPE_PATCHING,
                          sync_status=dccommon_consts.SYNC_STATUS_OUT_OF_SYNC),
                mock.call(mock.ANY,
                          subcloud_name=name,
                          subcloud_region=region,
                          endpoint_type=dccommon_consts.ENDPOINT_TYPE_LOAD,
                          sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC)]
            self.fake_dcmanager_state_api.update_subcloud_endpoint_status.\
                assert_has_calls(expected_calls)

    @mock.patch.object(patch_audit, 'SysinvClient')
    @mock.patch.object(patch_audit, 'PatchingClient')
    @mock.patch.object(patch_audit, 'OpenStackDriver')
    @mock.patch.object(subcloud_audit_manager, 'context')
    def test_periodic_patch_audit_unmatched_software_version(
            self, mock_context,
            mock_openstack_driver,
            mock_patching_client,
            mock_sysinv_client):
        mock_context.get_admin_context.return_value = self.ctxt
        pm = patch_audit.PatchAudit(self.ctxt,
                                    self.fake_dcmanager_state_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.patch_audit = pm
        mock_patching_client.side_effect = FakePatchingClientInSync
        mock_sysinv_client.side_effect = FakeSysinvClientOneLoadUnmatchedSoftwareVersion

        do_load_audit = True
        patch_audit_data = self.get_patch_audit_data(am)

        subclouds = {base.SUBCLOUD_1['name']: base.SUBCLOUD_1['region_name'],
                     base.SUBCLOUD_2['name']: base.SUBCLOUD_2['region_name']}
        for name, region in subclouds.items():
            pm.subcloud_patch_audit(name, region, patch_audit_data, do_load_audit)

        expected_calls = [
            mock.call(mock.ANY,
                      subcloud_name=base.SUBCLOUD_1['name'],
                      subcloud_region=base.SUBCLOUD_1['region_name'],
                      endpoint_type=dccommon_consts.ENDPOINT_TYPE_PATCHING,
                      sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC),
            mock.call(mock.ANY,
                      subcloud_name=base.SUBCLOUD_1['name'],
                      subcloud_region=base.SUBCLOUD_1['region_name'],
                      endpoint_type=dccommon_consts.ENDPOINT_TYPE_LOAD,
                      sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC),
            mock.call(mock.ANY,
                      subcloud_name=base.SUBCLOUD_2['name'],
                      subcloud_region=base.SUBCLOUD_2['region_name'],
                      endpoint_type=dccommon_consts.ENDPOINT_TYPE_PATCHING,
                      sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC),
            mock.call(mock.ANY,
                      subcloud_name=base.SUBCLOUD_2['name'],
                      subcloud_region=base.SUBCLOUD_2['region_name'],
                      endpoint_type=dccommon_consts.ENDPOINT_TYPE_LOAD,
                      sync_status=dccommon_consts.SYNC_STATUS_OUT_OF_SYNC),
        ]
        self.fake_dcmanager_state_api.update_subcloud_endpoint_status.\
            assert_has_calls(expected_calls)

    @mock.patch.object(patch_audit, 'SysinvClient')
    @mock.patch.object(patch_audit, 'PatchingClient')
    @mock.patch.object(patch_audit, 'OpenStackDriver')
    @mock.patch.object(subcloud_audit_manager, 'context')
    def test_periodic_patch_audit_upgrade_in_progress(
            self, mock_context,
            mock_openstack_driver,
            mock_patching_client,
            mock_sysinv_client):
        mock_context.get_admin_context.return_value = self.ctxt
        pm = patch_audit.PatchAudit(self.ctxt,
                                    self.fake_dcmanager_state_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.patch_audit = pm
        mock_patching_client.side_effect = FakePatchingClientInSync
        mock_sysinv_client.side_effect = FakeSysinvClientOneLoadUpgradeInProgress

        do_load_audit = True
        patch_audit_data = self.get_patch_audit_data(am)

        subclouds = {base.SUBCLOUD_1['name']: base.SUBCLOUD_1['region_name'],
                     base.SUBCLOUD_2['name']: base.SUBCLOUD_2['region_name']}
        for name, region in subclouds.items():
            pm.subcloud_patch_audit(name, region, patch_audit_data, do_load_audit)

        expected_calls = [
            mock.call(mock.ANY,
                      subcloud_name=base.SUBCLOUD_1['name'],
                      subcloud_region=base.SUBCLOUD_1['region_name'],
                      endpoint_type=dccommon_consts.ENDPOINT_TYPE_PATCHING,
                      sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC),
            mock.call(mock.ANY,
                      subcloud_name=base.SUBCLOUD_1['name'],
                      subcloud_region=base.SUBCLOUD_1['region_name'],
                      endpoint_type=dccommon_consts.ENDPOINT_TYPE_LOAD,
                      sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC),
            mock.call(mock.ANY,
                      subcloud_name=base.SUBCLOUD_2['name'],
                      subcloud_region=base.SUBCLOUD_2['region_name'],
                      endpoint_type=dccommon_consts.ENDPOINT_TYPE_PATCHING,
                      sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC),
            mock.call(mock.ANY,
                      subcloud_name=base.SUBCLOUD_2['name'],
                      subcloud_region=base.SUBCLOUD_2['region_name'],
                      endpoint_type=dccommon_consts.ENDPOINT_TYPE_LOAD,
                      sync_status=dccommon_consts.SYNC_STATUS_OUT_OF_SYNC),
        ]
        self.fake_dcmanager_state_api.update_subcloud_endpoint_status.\
            assert_has_calls(expected_calls)
