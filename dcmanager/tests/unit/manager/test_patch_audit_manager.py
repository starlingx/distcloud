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
# Copyright (c) 2017 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

import mock

from oslo_config import cfg

from dcmanager.common import consts
from dcmanager.manager import patch_audit_manager
from dcmanager.manager import subcloud_manager
from dcmanager.tests import base
from dcmanager.tests import utils

from dcorch.common import consts as dcorch_consts
from dcorch.common import messaging as dcorch_messaging


CONF = cfg.CONF


class Subcloud(object):
    def __init__(self, id, name, is_managed, is_online):
        self.id = id
        self.name = name
        self.software_version = '17.07'
        if is_managed:
            self.management_state = consts.MANAGEMENT_MANAGED
        else:
            self.management_state = consts.MANAGEMENT_UNMANAGED
        if is_online:
            self.availability_status = consts.AVAILABILITY_ONLINE
        else:
            self.availability_status = consts.AVAILABILITY_OFFLINE


class Load(object):
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
        self.loads = [Load('17.07')]

    def get_loads(self):
        return self.loads


class TestAuditManager(base.DCManagerTestCase):
    def setUp(self):
        super(TestAuditManager, self).setUp()
        self.ctxt = utils.dummy_context()
        dcorch_messaging.setup("fake://", optional=True)

    @mock.patch.object(patch_audit_manager, 'PatchingClient')
    @mock.patch.object(patch_audit_manager, 'KeystoneClient')
    @mock.patch.object(patch_audit_manager, 'context')
    def test_init(self, mock_context,
                  mock_keystone_client,
                  mock_patching_client):
        mock_context.get_admin_context.return_value = self.ctxt

        sm = subcloud_manager.SubcloudManager()
        am = patch_audit_manager.PatchAuditManager(subcloud_manager=sm)
        self.assertIsNotNone(am)
        self.assertEqual('patch_audit_manager', am.service_name)
        self.assertEqual('localhost', am.host)
        self.assertEqual(self.ctxt, am.context)

    @mock.patch.object(patch_audit_manager, 'SysinvClient')
    @mock.patch.object(patch_audit_manager, 'db_api')
    @mock.patch.object(patch_audit_manager, 'PatchingClient')
    @mock.patch.object(patch_audit_manager, 'KeystoneClient')
    @mock.patch.object(patch_audit_manager, 'context')
    def test_periodic_patch_audit_in_sync(
            self, mock_context,
            mock_keystone_client,
            mock_patching_client,
            mock_db_api,
            mock_sysinv_client):
        mock_context.get_admin_context.return_value = self.ctxt
        mock_sm = mock.Mock()
        am = patch_audit_manager.PatchAuditManager(subcloud_manager=mock_sm)

        mock_patching_client.side_effect = FakePatchingClientInSync
        mock_sysinv_client.side_effect = FakeSysinvClientOneLoad
        fake_subcloud1 = Subcloud(1, 'subcloud1',
                                  is_managed=True, is_online=True)
        fake_subcloud2 = Subcloud(2, 'subcloud2',
                                  is_managed=True, is_online=True)
        mock_db_api.subcloud_get_all.return_value = [fake_subcloud1,
                                                     fake_subcloud2]

        am._periodic_patch_audit_loop()
        expected_calls = [
            mock.call(mock.ANY,
                      subcloud_name='subcloud1',
                      endpoint_type=dcorch_consts.ENDPOINT_TYPE_PATCHING,
                      sync_status=consts.SYNC_STATUS_IN_SYNC),
            mock.call(mock.ANY,
                      subcloud_name='subcloud2',
                      endpoint_type=dcorch_consts.ENDPOINT_TYPE_PATCHING,
                      sync_status=consts.SYNC_STATUS_IN_SYNC),
        ]
        mock_sm.update_subcloud_endpoint_status.assert_has_calls(
            expected_calls)

    @mock.patch.object(patch_audit_manager, 'SysinvClient')
    @mock.patch.object(patch_audit_manager, 'db_api')
    @mock.patch.object(patch_audit_manager, 'PatchingClient')
    @mock.patch.object(patch_audit_manager, 'KeystoneClient')
    @mock.patch.object(patch_audit_manager, 'context')
    def test_periodic_patch_audit_out_of_sync(
            self, mock_context,
            mock_keystone_client,
            mock_patching_client,
            mock_db_api,
            mock_sysinv_client):
        mock_context.get_admin_context.return_value = self.ctxt
        mock_sm = mock.Mock()
        am = patch_audit_manager.PatchAuditManager(
            subcloud_manager=mock_sm)

        mock_patching_client.side_effect = FakePatchingClientOutOfSync
        mock_sysinv_client.side_effect = FakeSysinvClientOneLoad
        fake_subcloud1 = Subcloud(1, 'subcloud1',
                                  is_managed=True, is_online=True)
        fake_subcloud2 = Subcloud(2, 'subcloud2',
                                  is_managed=True, is_online=True)
        fake_subcloud3 = Subcloud(3, 'subcloud3',
                                  is_managed=True, is_online=True)
        fake_subcloud4 = Subcloud(4, 'subcloud4',
                                  is_managed=True, is_online=True)
        mock_db_api.subcloud_get_all.return_value = [fake_subcloud1,
                                                     fake_subcloud2,
                                                     fake_subcloud3,
                                                     fake_subcloud4]

        am._periodic_patch_audit_loop()
        expected_calls = [
            mock.call(mock.ANY,
                      subcloud_name='subcloud1',
                      endpoint_type=dcorch_consts.ENDPOINT_TYPE_PATCHING,
                      sync_status=consts.SYNC_STATUS_OUT_OF_SYNC),
            mock.call(mock.ANY,
                      subcloud_name='subcloud2',
                      endpoint_type=dcorch_consts.ENDPOINT_TYPE_PATCHING,
                      sync_status=consts.SYNC_STATUS_OUT_OF_SYNC),
            mock.call(mock.ANY,
                      subcloud_name='subcloud3',
                      endpoint_type=dcorch_consts.ENDPOINT_TYPE_PATCHING,
                      sync_status=consts.SYNC_STATUS_IN_SYNC),
            mock.call(mock.ANY,
                      subcloud_name='subcloud4',
                      endpoint_type=dcorch_consts.ENDPOINT_TYPE_PATCHING,
                      sync_status=consts.SYNC_STATUS_OUT_OF_SYNC),
        ]
        mock_sm.update_subcloud_endpoint_status.assert_has_calls(
            expected_calls)

    @mock.patch.object(patch_audit_manager, 'db_api')
    @mock.patch.object(patch_audit_manager, 'PatchingClient')
    @mock.patch.object(patch_audit_manager, 'KeystoneClient')
    @mock.patch.object(patch_audit_manager, 'context')
    def test_periodic_patch_audit_ignore_unmanaged_or_offline(
            self, mock_context,
            mock_keystone_client,
            mock_patching_client,
            mock_db_api):
        mock_context.get_admin_context.return_value = self.ctxt
        mock_sm = mock.Mock()
        am = patch_audit_manager.PatchAuditManager(
            subcloud_manager=mock_sm)

        mock_patching_client.side_effect = FakePatchingClientOutOfSync
        fake_subcloud1 = Subcloud(1, 'subcloud1',
                                  is_managed=False, is_online=True)
        fake_subcloud2 = Subcloud(2, 'subcloud2',
                                  is_managed=True, is_online=False)
        mock_db_api.subcloud_get_all.return_value = [fake_subcloud1,
                                                     fake_subcloud2]

        am._periodic_patch_audit_loop()
        mock_sm.update_subcloud_endpoint_status.assert_not_called()

    @mock.patch.object(patch_audit_manager, 'SysinvClient')
    @mock.patch.object(patch_audit_manager, 'db_api')
    @mock.patch.object(patch_audit_manager, 'PatchingClient')
    @mock.patch.object(patch_audit_manager, 'KeystoneClient')
    @mock.patch.object(patch_audit_manager, 'context')
    def test_periodic_patch_audit_extra_patches(
            self, mock_context,
            mock_keystone_client,
            mock_patching_client,
            mock_db_api,
            mock_sysinv_client):
        mock_context.get_admin_context.return_value = self.ctxt
        mock_sm = mock.Mock()
        am = patch_audit_manager.PatchAuditManager(
            subcloud_manager=mock_sm)

        mock_patching_client.side_effect = FakePatchingClientExtraPatches
        mock_sysinv_client.side_effect = FakeSysinvClientOneLoad
        fake_subcloud1 = Subcloud(1, 'subcloud1',
                                  is_managed=True, is_online=True)
        fake_subcloud2 = Subcloud(2, 'subcloud2',
                                  is_managed=True, is_online=True)
        mock_db_api.subcloud_get_all.return_value = [fake_subcloud1,
                                                     fake_subcloud2]

        am._periodic_patch_audit_loop()
        expected_calls = [
            mock.call(mock.ANY,
                      subcloud_name='subcloud1',
                      endpoint_type=dcorch_consts.ENDPOINT_TYPE_PATCHING,
                      sync_status=consts.SYNC_STATUS_OUT_OF_SYNC),
            mock.call(mock.ANY,
                      subcloud_name='subcloud2',
                      endpoint_type=dcorch_consts.ENDPOINT_TYPE_PATCHING,
                      sync_status=consts.SYNC_STATUS_OUT_OF_SYNC),
        ]
        mock_sm.update_subcloud_endpoint_status.assert_has_calls(
            expected_calls)
