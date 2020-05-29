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
# Copyright (c) 2017-2020 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

import mock

from oslo_config import cfg

import sys
sys.modules['fm_core'] = mock.Mock()

from dcmanager.audit import patch_audit
from dcmanager.audit import subcloud_audit_manager
from dcmanager.common import consts
from dcmanager.tests import base
from dcmanager.tests import utils

from dcorch.common import consts as dcorch_consts


CONF = cfg.CONF


class FakeDCManagerAPI(object):

    def __init__(self):
        self.update_subcloud_availability = mock.MagicMock()
        self.update_subcloud_endpoint_status = mock.MagicMock()


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
    def __init__(self, region, session):
        self.region = region
        self.session = session

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
                    # This patch won't make us out of sync because it is for
                    # a different release.
                    'OTHER_REL_DC.1': {'sw_version': '17.08',
                                       'repostate': 'Applied',
                                       'patchstate': 'Applied'},
                    }
        elif self.region in ['subcloud1', 'subcloud2']:
            return {'DC.1': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    'DC.2': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    'DC.3': {'sw_version': '17.07',
                             'repostate': 'Committed',
                             'patchstate': 'Committed'},
                    }
        else:
            return {}


class FakePatchingClientOutOfSync(object):
    def __init__(self, region, session):
        self.region = region
        self.session = session

    def query(self):
        if self.region == 'RegionOne':
            return {'DC.1': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Partial-Apply'},
                    'DC.2': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'}}
        elif self.region == 'subcloud1':
            return {'DC.1': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    'DC.2': {'sw_version': '17.07',
                             'repostate': 'Available',
                             'patchstate': 'Available'}}
        elif self.region == 'subcloud2':
            return {'DC.1': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'}}
        elif self.region == 'subcloud3':
            return {'DC.1': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    'DC.2': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'}}
        elif self.region == 'subcloud4':
            return {'DC.1': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    'DC.2': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Partial-Apply'}}
        else:
            return {}


class FakePatchingClientExtraPatches(object):
    def __init__(self, region, session):
        self.region = region
        self.session = session

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
    def __init__(self, region, session):
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
    def __init__(self, region, session):
        self.region = region
        self.loads = [Load('17.07', 'active')]
        self.upgrades = []
        self.system = System('17.07')

    def get_loads(self):
        return self.loads

    def get_upgrades(self):
        return self.upgrades

    def get_system(self):
        if self.region == 'subcloud2':
            return System('17.06')
        else:
            return self.system


class FakeSysinvClientOneLoadUpgradeInProgress(object):
    def __init__(self, region, session):
        self.region = region
        self.loads = [Load('17.07', 'active')]
        self.upgrades = []
        self.system = System('17.07')

    def get_loads(self):
        return self.loads

    def get_upgrades(self):
        if self.region == 'subcloud2':
            return [Upgrade('started')]
        else:
            return self.upgrades

    def get_system(self):
        return self.system


class TestPatchAudit(base.DCManagerTestCase):
    def setUp(self):
        super(TestPatchAudit, self).setUp()
        self.ctxt = utils.dummy_context()

        # Mock the DCManager API
        self.fake_dcmanager_api = FakeDCManagerAPI()
        p = mock.patch('dcmanager.rpc.client.ManagerClient')
        self.mock_dcmanager_api = p.start()
        self.mock_dcmanager_api.return_value = self.fake_dcmanager_api
        self.addCleanup(p.stop)

    def test_init(self):
        pm = patch_audit.PatchAudit(self.ctxt,
                                    self.fake_dcmanager_api)
        self.assertIsNotNone(pm)
        self.assertEqual(self.ctxt, pm.context)
        self.assertEqual(self.fake_dcmanager_api, pm.dcmanager_rpc_client)

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
                                    self.fake_dcmanager_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.patch_audit = pm

        patch_audit_data, do_load_audit = am._get_patch_audit()
        for name in ['subcloud1', 'subcloud2']:
            pm.subcloud_patch_audit(name, patch_audit_data, do_load_audit)
            expected_calls = [
                mock.call(mock.ANY,
                          subcloud_name=name,
                          endpoint_type=dcorch_consts.ENDPOINT_TYPE_PATCHING,
                          sync_status=consts.SYNC_STATUS_IN_SYNC),
                mock.call(mock.ANY,
                          subcloud_name=name,
                          endpoint_type=dcorch_consts.ENDPOINT_TYPE_LOAD,
                          sync_status=consts.SYNC_STATUS_IN_SYNC)]
            self.fake_dcmanager_api.update_subcloud_endpoint_status. \
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
                                    self.fake_dcmanager_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.patch_audit = pm

        mock_patching_client.side_effect = FakePatchingClientOutOfSync
        mock_sysinv_client.side_effect = FakeSysinvClientOneLoad

        patch_audit_data, do_load_audit = am._get_patch_audit()
        for name in ['subcloud1', 'subcloud2', 'subcloud3', 'subcloud4']:
            pm.subcloud_patch_audit(name, patch_audit_data, do_load_audit)

        expected_calls = [
            mock.call(mock.ANY,
                      subcloud_name='subcloud1',
                      endpoint_type=dcorch_consts.ENDPOINT_TYPE_PATCHING,
                      sync_status=consts.SYNC_STATUS_OUT_OF_SYNC),
            mock.call(mock.ANY,
                      subcloud_name='subcloud1',
                      endpoint_type=dcorch_consts.ENDPOINT_TYPE_LOAD,
                      sync_status=consts.SYNC_STATUS_IN_SYNC),
            mock.call(mock.ANY,
                      subcloud_name='subcloud2',
                      endpoint_type=dcorch_consts.ENDPOINT_TYPE_PATCHING,
                      sync_status=consts.SYNC_STATUS_OUT_OF_SYNC),
            mock.call(mock.ANY,
                      subcloud_name='subcloud2',
                      endpoint_type=dcorch_consts.ENDPOINT_TYPE_LOAD,
                      sync_status=consts.SYNC_STATUS_IN_SYNC),
            mock.call(mock.ANY,
                      subcloud_name='subcloud3',
                      endpoint_type=dcorch_consts.ENDPOINT_TYPE_PATCHING,
                      sync_status=consts.SYNC_STATUS_IN_SYNC),
            mock.call(mock.ANY,
                      subcloud_name='subcloud3',
                      endpoint_type=dcorch_consts.ENDPOINT_TYPE_LOAD,
                      sync_status=consts.SYNC_STATUS_IN_SYNC),
            mock.call(mock.ANY,
                      subcloud_name='subcloud4',
                      endpoint_type=dcorch_consts.ENDPOINT_TYPE_PATCHING,
                      sync_status=consts.SYNC_STATUS_OUT_OF_SYNC),
            mock.call(mock.ANY,
                      subcloud_name='subcloud4',
                      endpoint_type=dcorch_consts.ENDPOINT_TYPE_LOAD,
                      sync_status=consts.SYNC_STATUS_IN_SYNC),
            ]

        self.fake_dcmanager_api.update_subcloud_endpoint_status.\
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
                                    self.fake_dcmanager_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.patch_audit = pm

        mock_patching_client.side_effect = FakePatchingClientExtraPatches
        mock_sysinv_client.side_effect = FakeSysinvClientOneLoad

        patch_audit_data, do_load_audit = am._get_patch_audit()
        for name in ['subcloud1', 'subcloud2']:
            pm.subcloud_patch_audit(name, patch_audit_data, do_load_audit)
            expected_calls = [
                mock.call(mock.ANY,
                          subcloud_name=name,
                          endpoint_type=dcorch_consts.ENDPOINT_TYPE_PATCHING,
                          sync_status=consts.SYNC_STATUS_OUT_OF_SYNC),
                mock.call(mock.ANY,
                          subcloud_name=name,
                          endpoint_type=dcorch_consts.ENDPOINT_TYPE_LOAD,
                          sync_status=consts.SYNC_STATUS_IN_SYNC)]
            self.fake_dcmanager_api.update_subcloud_endpoint_status.\
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
                                    self.fake_dcmanager_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.patch_audit = pm
        mock_patching_client.side_effect = FakePatchingClientInSync
        mock_sysinv_client.side_effect = FakeSysinvClientOneLoadUnmatchedSoftwareVersion

        patch_audit_data, do_load_audit = am._get_patch_audit()
        for name in ['subcloud1', 'subcloud2']:
            pm.subcloud_patch_audit(name, patch_audit_data, do_load_audit)

        expected_calls = [
            mock.call(mock.ANY,
                      subcloud_name='subcloud1',
                      endpoint_type=dcorch_consts.ENDPOINT_TYPE_PATCHING,
                      sync_status=consts.SYNC_STATUS_IN_SYNC),
            mock.call(mock.ANY,
                      subcloud_name='subcloud1',
                      endpoint_type=dcorch_consts.ENDPOINT_TYPE_LOAD,
                      sync_status=consts.SYNC_STATUS_IN_SYNC),
            mock.call(mock.ANY,
                      subcloud_name='subcloud2',
                      endpoint_type=dcorch_consts.ENDPOINT_TYPE_PATCHING,
                      sync_status=consts.SYNC_STATUS_IN_SYNC),
            mock.call(mock.ANY,
                      subcloud_name='subcloud2',
                      endpoint_type=dcorch_consts.ENDPOINT_TYPE_LOAD,
                      sync_status=consts.SYNC_STATUS_OUT_OF_SYNC),
        ]
        self.fake_dcmanager_api.update_subcloud_endpoint_status.\
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
                                    self.fake_dcmanager_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.patch_audit = pm
        mock_patching_client.side_effect = FakePatchingClientInSync
        mock_sysinv_client.side_effect = FakeSysinvClientOneLoadUpgradeInProgress

        patch_audit_data, do_load_audit = am._get_patch_audit()
        for name in ['subcloud1', 'subcloud2']:
            pm.subcloud_patch_audit(name, patch_audit_data, do_load_audit)

        expected_calls = [
            mock.call(mock.ANY,
                      subcloud_name='subcloud1',
                      endpoint_type=dcorch_consts.ENDPOINT_TYPE_PATCHING,
                      sync_status=consts.SYNC_STATUS_IN_SYNC),
            mock.call(mock.ANY,
                      subcloud_name='subcloud1',
                      endpoint_type=dcorch_consts.ENDPOINT_TYPE_LOAD,
                      sync_status=consts.SYNC_STATUS_IN_SYNC),
            mock.call(mock.ANY,
                      subcloud_name='subcloud2',
                      endpoint_type=dcorch_consts.ENDPOINT_TYPE_PATCHING,
                      sync_status=consts.SYNC_STATUS_IN_SYNC),
            mock.call(mock.ANY,
                      subcloud_name='subcloud2',
                      endpoint_type=dcorch_consts.ENDPOINT_TYPE_LOAD,
                      sync_status=consts.SYNC_STATUS_OUT_OF_SYNC),
        ]
        self.fake_dcmanager_api.update_subcloud_endpoint_status.\
            assert_has_calls(expected_calls)
