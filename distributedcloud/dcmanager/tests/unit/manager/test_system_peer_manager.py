#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import json
import uuid

import mock

from dccommon import exceptions as dccommon_exceptions
from dcmanager.db.sqlalchemy import api as db_api
from dcmanager.manager import system_peer_manager
from dcmanager.tests import base
from dcmanager.tests.unit.common import fake_subcloud

# FAKE SYSINV DATA
FAKE_SITE0_SYSTEM_UUID = str(uuid.uuid4())
FAKE_SITE1_SYSTEM_UUID = str(uuid.uuid4())

# FAKE SYSTEM PEER DATA
FAKE_SYSTEM_PEER_ID = 1
FAKE_SYSTEM_PEER_UUID = FAKE_SITE1_SYSTEM_UUID
FAKE_SYSTEM_PEER_NAME = 'PeerSite1'
FAKE_MANAGER_ENDPOINT = 'http://128.128.128.128:5000/v3'
FAKE_MANAGER_USERNAME = 'admin'
FAKE_MANAGER_PASSWORD = 'cGFzc3dvcmQ='
FAKE_PEER_CONTROLLER_GATEWAY_IP = '128.128.1.1'

# FAKE SUBCLOUD PEER GROUP DATA (SITE0)
FAKE_SITE0_PEER_GROUP_ID = 1
FAKE_SITE0_PEER_GROUP_NAME = 'PeerGroup1'
FAKE_SITE0_PEER_GROUP_SYSTEM_LEADER_ID = FAKE_SITE0_SYSTEM_UUID
FAKE_SITE0_PEER_GROUP_SYSTEM_LEADER_NAME = 'site0'
FAKE_SITE0_PEER_GROUP_MAX_SUBCLOUDS_REHOMING = 50
FAKE_SITE0_PEER_GROUP_PRIORITY = 0
FAKE_SITE0_PEER_GROUP_STATE = 'enabled'

# FAKE SUBCLOUD PEER GROUP DATA (SITE1)
FAKE_SITE1_PEER_GROUP_ID = 9

# FAKE SUBCLOUD DATA (SITE1)
FAKE_SITE1_SUBCLOUD1_ID = 11
FAKE_SITE1_SUBCLOUD1_REGION_NAME = str(uuid.uuid4())
FAKE_SITE1_SUBCLOUD1_DEPLOY_STATUS = 'secondary'
FAKE_SITE1_SUBCLOUD1_DATA = {"id": FAKE_SITE1_SUBCLOUD1_ID,
                             "name": "subcloud1",
                             "region-name": FAKE_SITE1_SUBCLOUD1_REGION_NAME,
                             "deploy-status":
                             FAKE_SITE1_SUBCLOUD1_DEPLOY_STATUS}
FAKE_SITE1_SUBCLOUD2_ID = 12
FAKE_SITE1_SUBCLOUD2_REGION_NAME = str(uuid.uuid4())
FAKE_SITE1_SUBCLOUD2_DEPLOY_STATUS = 'secondary-failed'
FAKE_SITE1_SUBCLOUD2_DATA = {"id": FAKE_SITE1_SUBCLOUD2_ID,
                             "name": "subcloud2",
                             "region-name": FAKE_SITE1_SUBCLOUD2_REGION_NAME,
                             "deploy-status":
                             FAKE_SITE1_SUBCLOUD2_DEPLOY_STATUS}
FAKE_SITE1_SUBCLOUD3_ID = 13
FAKE_SITE1_SUBCLOUD3_DEPLOY_STATUS = 'secondary'
FAKE_SITE1_SUBCLOUD3_DATA = {"id": FAKE_SITE1_SUBCLOUD3_ID,
                             "name": "subcloud3",
                             "region-name": "subcloud3",
                             "deploy-status":
                             FAKE_SITE1_SUBCLOUD3_DEPLOY_STATUS}

# FAKE PEER GROUP ASSOCIATION DATA (SITE0)
FAKE_ASSOCIATION_PEER_GROUP_ID = \
    FAKE_SITE0_PEER_GROUP_ID
FAKE_ASSOCIATION_SYSTEM_PEER_ID = \
    FAKE_SYSTEM_PEER_ID
FAKE_ASSOCIATION_PEER_GROUP_PRIORITY = 1
FAKE_ASSOCIATION_SYNC_STATUS = 'synced'
FAKE_ASSOCIATION_SYNC_MESSAGE = 'None'
FAKE_ASSOCIATION_TYPE = 'primary'

# FAKE PEER GROUP ASSOCIATION DATA (SITE1)
FAKE_SITE1_ASSOCIATION_ID = 10


class FakeDCManagerAuditAPI(object):
    def __init__(self):
        pass


class FakeSystem(object):
    def __init__(self, uuid):
        self.uuid = uuid


class FakePeerGroup(object):
    def __init__(self):
        self.id = FAKE_SITE1_PEER_GROUP_ID


class FakeKeystoneClient(object):
    def __init__(self):
        self.keystone_client = mock.MagicMock()
        self.session = mock.MagicMock()
        self.endpoint_cache = mock.MagicMock()


class FakeSysinvClient(object):
    def __init__(self):
        self.system = FakeSystem(FAKE_SITE1_SYSTEM_UUID)

    def get_system(self):
        return self.system


class FakeDcmanagerClient(object):
    def __init__(self):
        self.peer_groups = [FakePeerGroup()]

    def add_subcloud_peer_group(self, **kwargs):
        return self.peer_groups

    def get_subcloud_peer_group(self, peer_group_name):
        return self.peer_groups


class FakeException(Exception):
    pass


class TestSystemPeerManager(base.DCManagerTestCase):
    def setUp(self):
        super(TestSystemPeerManager, self).setUp()

        # Mock the DCManager Audit API
        self.fake_dcmanager_audit_api = FakeDCManagerAuditAPI()
        p = mock.patch('dcmanager.audit.rpcapi.ManagerAuditClient')
        self.mock_dcmanager_audit_api = p.start()
        self.mock_dcmanager_audit_api.return_value = \
            self.fake_dcmanager_audit_api
        self.addCleanup(p.stop)

    @staticmethod
    def create_subcloud_with_pg_static(ctxt, peer_group_id,
                                       rehome_data=None, **kwargs):
        subcloud = fake_subcloud.create_fake_subcloud(ctxt, **kwargs)
        return db_api.subcloud_update(ctxt, subcloud.id,
                                      peer_group_id=peer_group_id,
                                      rehome_data=rehome_data)

    @staticmethod
    def create_system_peer_static(ctxt, **kwargs):
        values = {
            'peer_uuid': FAKE_SYSTEM_PEER_UUID,
            'peer_name': FAKE_SYSTEM_PEER_NAME,
            'endpoint': FAKE_MANAGER_ENDPOINT,
            'username': FAKE_MANAGER_USERNAME,
            'password': FAKE_MANAGER_PASSWORD,
            'gateway_ip': FAKE_PEER_CONTROLLER_GATEWAY_IP
        }
        values.update(kwargs)
        return db_api.system_peer_create(ctxt, **values)

    @staticmethod
    def create_subcloud_peer_group_static(ctxt, **kwargs):
        values = {
            "peer_group_name": FAKE_SITE0_PEER_GROUP_NAME,
            "system_leader_id": FAKE_SITE0_PEER_GROUP_SYSTEM_LEADER_ID,
            "system_leader_name": FAKE_SITE0_PEER_GROUP_SYSTEM_LEADER_NAME,
            "group_priority": FAKE_SITE0_PEER_GROUP_PRIORITY,
            "group_state": FAKE_SITE0_PEER_GROUP_STATE,
            "max_subcloud_rehoming":
            FAKE_SITE0_PEER_GROUP_MAX_SUBCLOUDS_REHOMING,
            "migration_status": None
        }
        values.update(kwargs)
        return db_api.subcloud_peer_group_create(ctxt, **values)

    @staticmethod
    def create_peer_group_association_static(ctxt, **kwargs):
        values = {
            "system_peer_id": FAKE_ASSOCIATION_SYSTEM_PEER_ID,
            "peer_group_id": FAKE_ASSOCIATION_PEER_GROUP_ID,
            "peer_group_priority": FAKE_ASSOCIATION_PEER_GROUP_PRIORITY,
            "sync_status": FAKE_ASSOCIATION_SYNC_STATUS,
            "sync_message": FAKE_ASSOCIATION_SYNC_MESSAGE,
            "association_type": FAKE_ASSOCIATION_TYPE
        }
        values.update(kwargs)
        return db_api.peer_group_association_create(ctxt, **values)

    def test_init(self):
        spm = system_peer_manager.SystemPeerManager(mock.MagicMock())
        self.assertIsNotNone(spm)
        self.assertEqual('system_peer_manager', spm.service_name)
        self.assertEqual('localhost', spm.host)

    @mock.patch.object(system_peer_manager, 'PeerSiteDriver')
    @mock.patch.object(system_peer_manager, 'SysinvClient')
    @mock.patch.object(system_peer_manager, 'DcmanagerClient')
    def test_sync_subclouds(self, mock_dc_client,
                            mock_sysinv_client,
                            mock_keystone_client):
        mock_keystone_client().keystone_client = FakeKeystoneClient()
        mock_sysinv_client.return_value = FakeSysinvClient()
        mock_dc_client.return_value = FakeDcmanagerClient()
        mock_dc_client().add_subcloud_with_secondary_status = mock.MagicMock()
        mock_dc_client().add_subcloud_with_secondary_status.return_value = {
            "region-name": FAKE_SITE1_SUBCLOUD2_REGION_NAME}
        mock_dc_client().delete_subcloud = mock.MagicMock()

        peer = self.create_system_peer_static(
            self.ctx,
            peer_name='SystemPeer1')
        peer_group = self.create_subcloud_peer_group_static(
            self.ctx,
            peer_group_name='SubcloudPeerGroup1')
        rehome_data = {
            "saved_payload": {
                "bootstrap-address": "192.168.10.10",
                "systemcontroller_gateway_address": "192.168.204.101"
            }
        }
        # Create local dc subcloud1 mock data in database
        self.create_subcloud_with_pg_static(
            self.ctx,
            peer_group_id=peer_group.id,
            rehome_data=json.dumps(rehome_data),
            name='subcloud1',
            region_name='subcloud1')
        # Create local dc subcloud2 mock data in database
        self.create_subcloud_with_pg_static(
            self.ctx,
            peer_group_id=peer_group.id,
            rehome_data=json.dumps(rehome_data),
            name='subcloud2',
            region_name='subcloud2')
        peer_subcloud1 = FAKE_SITE1_SUBCLOUD1_DATA
        peer_subcloud2 = FAKE_SITE1_SUBCLOUD2_DATA
        peer_subcloud3 = FAKE_SITE1_SUBCLOUD3_DATA
        mock_dc_client().get_subcloud = mock.MagicMock()
        mock_dc_client().get_subcloud.side_effect = [
            peer_subcloud1, dccommon_exceptions.SubcloudNotFound,
            peer_subcloud1, dccommon_exceptions.SubcloudNotFound,
            peer_subcloud3]
        mock_dc_client().get_subcloud_list_by_peer_group = mock.MagicMock()
        mock_dc_client().get_subcloud_list_by_peer_group.return_value = [
            peer_subcloud1, peer_subcloud2, peer_subcloud3]
        mock_dc_client().update_subcloud = mock.MagicMock()
        mock_dc_client().update_subcloud.side_effect = [
            peer_subcloud1, peer_subcloud1, peer_subcloud2]

        spm = system_peer_manager.SystemPeerManager(mock.MagicMock())
        spm._sync_subclouds(self.ctx, peer, peer_group.id,
                            FAKE_SITE1_PEER_GROUP_ID)

        mock_dc_client().get_subcloud.assert_has_calls([
            mock.call(peer_subcloud1.get('name')),
            mock.call(peer_subcloud2.get('name')),
            mock.call(peer_subcloud3.get('name'))
        ])
        mock_dc_client().update_subcloud.assert_has_calls([
            mock.call('subcloud1', mock.ANY, mock.ANY),
            mock.call(FAKE_SITE1_SUBCLOUD1_REGION_NAME, files=None,
                      data={'peer_group': str(FAKE_SITE1_PEER_GROUP_ID)},
                      is_region_name=True),
            mock.call(FAKE_SITE1_SUBCLOUD2_REGION_NAME, files=None,
                      data={'peer_group': str(FAKE_SITE1_PEER_GROUP_ID)},
                      is_region_name=True)
        ])
        mock_dc_client().add_subcloud_with_secondary_status. \
            assert_called_once()
        mock_dc_client().delete_subcloud.assert_called_once_with('subcloud3')

    @mock.patch.object(
        system_peer_manager.SystemPeerManager, '_sync_subclouds')
    @mock.patch.object(system_peer_manager, 'utils')
    @mock.patch.object(system_peer_manager, 'PeerSiteDriver')
    @mock.patch.object(system_peer_manager, 'SysinvClient')
    @mock.patch.object(system_peer_manager, 'DcmanagerClient')
    def test_sync_subcloud_peer_group(self,
                                      mock_dc_client,
                                      mock_sysinv_client,
                                      mock_keystone_client,
                                      mock_utils,
                                      mock_sync_subclouds):
        mock_sync_subclouds.return_value = True
        mock_keystone_client().keystone_client = FakeKeystoneClient()
        mock_sysinv_client.return_value = FakeSysinvClient()
        mock_dc_client.return_value = FakeDcmanagerClient()
        mock_dc_client().get_subcloud_peer_group = mock.MagicMock()
        mock_dc_client().update_subcloud_peer_group = mock.MagicMock()
        mock_dc_client().get_system_peer = mock.MagicMock()
        mock_dc_client().get_peer_group_association_with_peer_id_and_pg_id = \
            mock.MagicMock()
        mock_dc_client().update_peer_group_association_sync_status = \
            mock.MagicMock()
        mock_utils().get_local_system = mock.MagicMock()

        peer = self.create_system_peer_static(
            self.ctx,
            peer_name='SystemPeer1')
        peer_group = self.create_subcloud_peer_group_static(
            self.ctx,
            peer_group_name='SubcloudPeerGroup1')
        association = self.create_peer_group_association_static(
            self.ctx,
            system_peer_id=peer.id,
            peer_group_id=peer_group.id)

        spm = system_peer_manager.SystemPeerManager(mock.MagicMock())
        spm.sync_subcloud_peer_group(self.ctx, association.id, False)

        mock_dc_client().get_subcloud_peer_group.assert_called_once_with(
            peer_group.peer_group_name)
        mock_dc_client().update_subcloud_peer_group.assert_called_once()

    @mock.patch.object(
        system_peer_manager.SystemPeerManager, '_sync_subclouds')
    @mock.patch.object(system_peer_manager, 'utils')
    @mock.patch.object(system_peer_manager, 'PeerSiteDriver')
    @mock.patch.object(system_peer_manager, 'SysinvClient')
    @mock.patch.object(system_peer_manager, 'DcmanagerClient')
    def test_sync_subcloud_peer_group_not_exist(self, mock_dc_client,
                                                mock_sysinv_client,
                                                mock_keystone_client,
                                                mock_utils,
                                                mock_sync_subclouds):
        mock_sync_subclouds.return_value = True
        mock_keystone_client().keystone_client = FakeKeystoneClient()
        mock_sysinv_client.return_value = FakeSysinvClient()
        mock_dc_client.return_value = FakeDcmanagerClient()
        mock_dc_client().get_subcloud_peer_group = mock.MagicMock()
        mock_dc_client().add_subcloud_peer_group = mock.MagicMock()
        mock_dc_client().update_subcloud_peer_group = mock.MagicMock()
        mock_dc_client().get_system_peer = mock.MagicMock()
        mock_dc_client().get_peer_group_association_with_peer_id_and_pg_id = \
            mock.MagicMock()
        mock_dc_client().update_peer_group_association_sync_status = \
            mock.MagicMock()
        mock_utils().get_local_system = mock.MagicMock()

        peer = self.create_system_peer_static(
            self.ctx,
            peer_name='SystemPeer1')
        peer_group = self.create_subcloud_peer_group_static(
            self.ctx,
            peer_group_name='SubcloudPeerGroup1')
        association = self.create_peer_group_association_static(
            self.ctx,
            system_peer_id=peer.id,
            peer_group_id=peer_group.id)

        mock_dc_client().get_subcloud_peer_group.side_effect = \
            dccommon_exceptions.SubcloudPeerGroupNotFound

        spm = system_peer_manager.SystemPeerManager(mock.MagicMock())
        spm.sync_subcloud_peer_group(self.ctx, association.id, False)

        mock_dc_client().get_subcloud_peer_group.assert_called_once_with(
            peer_group.peer_group_name)
        mock_dc_client().add_subcloud_peer_group.assert_called_once_with(**{
            'peer-group-name': peer_group.peer_group_name,
            'group-priority': association.peer_group_priority,
            'group-state': peer_group.group_state,
            'system-leader-id': peer_group.system_leader_id,
            'system-leader-name': peer_group.system_leader_name,
            'max-subcloud-rehoming': peer_group.max_subcloud_rehoming
        })

    @mock.patch.object(system_peer_manager, 'utils')
    @mock.patch.object(system_peer_manager, 'PeerSiteDriver')
    @mock.patch.object(system_peer_manager, 'SysinvClient')
    @mock.patch.object(system_peer_manager, 'DcmanagerClient')
    def test_delete_peer_group_association(self,
                                           mock_dc_client,
                                           mock_sysinv_client,
                                           mock_keystone_client,
                                           mock_utils):
        mock_keystone_client().keystone_client = FakeKeystoneClient()
        mock_sysinv_client.return_value = FakeSysinvClient()
        mock_dc_client.return_value = FakeDcmanagerClient()
        mock_dc_client().delete_subcloud_peer_group = mock.MagicMock()
        mock_dc_client().delete_subcloud = mock.MagicMock()
        mock_dc_client().get_subcloud_peer_group = mock.MagicMock()
        mock_dc_client().get_system_peer = mock.MagicMock()
        mock_dc_client().get_peer_group_association_with_peer_id_and_pg_id = \
            mock.MagicMock()
        mock_dc_client().delete_peer_group_association = mock.MagicMock()
        mock_utils().get_local_system = mock.MagicMock()

        peer = self.create_system_peer_static(
            self.ctx,
            peer_name='SystemPeer1')
        peer_group = self.create_subcloud_peer_group_static(
            self.ctx,
            peer_group_name='SubcloudPeerGroup1')
        # Create local dc subcloud1 mock data in database
        subcloud1 = self.create_subcloud_with_pg_static(
            self.ctx,
            peer_group_id=peer_group.id,
            name='subcloud1')
        # Create local dc subcloud2 mock data in database
        subcloud2 = self.create_subcloud_with_pg_static(
            self.ctx,
            peer_group_id=peer_group.id,
            name='subcloud2')
        association = self.create_peer_group_association_static(
            self.ctx,
            system_peer_id=peer.id,
            peer_group_id=peer_group.id)
        peer_subcloud1 = FAKE_SITE1_SUBCLOUD1_DATA
        peer_subcloud2 = FAKE_SITE1_SUBCLOUD2_DATA
        mock_dc_client().get_subcloud = mock.MagicMock()
        mock_dc_client().get_subcloud.side_effect = [
            peer_subcloud1, peer_subcloud2]
        mock_dc_client().get_peer_group_association_with_peer_id_and_pg_id.\
            return_value = {'id': FAKE_SITE1_ASSOCIATION_ID}

        spm = system_peer_manager.SystemPeerManager(mock.MagicMock())
        spm.delete_peer_group_association(self.ctx, association.id)

        mock_dc_client().delete_subcloud.assert_has_calls([
            mock.call(subcloud1.name),
            mock.call(subcloud2.name)
        ])
        mock_dc_client().delete_subcloud_peer_group.assert_called_once_with(
            peer_group.peer_group_name)
        mock_dc_client().delete_peer_group_association.assert_called_once_with(
            FAKE_SITE1_ASSOCIATION_ID)

        associations = db_api.peer_group_association_get_all(self.ctx)
        self.assertEqual(0, len(associations))

    @mock.patch.object(system_peer_manager, 'utils')
    @mock.patch.object(system_peer_manager, 'PeerSiteDriver')
    @mock.patch.object(system_peer_manager, 'SysinvClient')
    @mock.patch.object(system_peer_manager, 'DcmanagerClient')
    def test_delete_peer_group_association_peer_site_association_not_exsit(
        self, mock_dc_client, mock_sysinv_client, mock_keystone_client, mock_utils
    ):
        mock_keystone_client().keystone_client = FakeKeystoneClient()
        mock_sysinv_client.return_value = FakeSysinvClient()
        mock_dc_client.return_value = FakeDcmanagerClient()
        mock_dc_client().delete_subcloud_peer_group = mock.MagicMock()
        mock_dc_client().delete_subcloud = mock.MagicMock()
        mock_dc_client().get_subcloud_peer_group = mock.MagicMock()
        mock_dc_client().get_system_peer = mock.MagicMock()
        mock_dc_client().get_peer_group_association_with_peer_id_and_pg_id = \
            mock.MagicMock()
        mock_dc_client().delete_peer_group_association = mock.MagicMock()
        mock_utils().get_local_system = mock.MagicMock()

        peer = self.create_system_peer_static(
            self.ctx,
            peer_name='SystemPeer1')
        peer_group = self.create_subcloud_peer_group_static(
            self.ctx,
            peer_group_name='SubcloudPeerGroup1')
        # Create local dc subcloud1 mock data in database
        subcloud1 = self.create_subcloud_with_pg_static(
            self.ctx,
            peer_group_id=peer_group.id,
            name='subcloud1')
        association = self.create_peer_group_association_static(
            self.ctx,
            system_peer_id=peer.id,
            peer_group_id=peer_group.id)
        peer_subcloud1 = FAKE_SITE1_SUBCLOUD1_DATA
        mock_dc_client().get_subcloud = mock.MagicMock()
        mock_dc_client().get_subcloud.side_effect = [
            peer_subcloud1, dccommon_exceptions.SubcloudNotFound]
        mock_dc_client().get_peer_group_association_with_peer_id_and_pg_id.\
            side_effect = [dccommon_exceptions.PeerGroupAssociationNotFound]

        spm = system_peer_manager.SystemPeerManager(mock.MagicMock())
        spm.delete_peer_group_association(self.ctx, association.id)

        mock_dc_client().delete_subcloud.assert_has_calls([
            mock.call(subcloud1.name)])
        mock_dc_client().delete_subcloud_peer_group.assert_called_once_with(
            peer_group.peer_group_name)
        mock_dc_client().delete_peer_group_association.assert_not_called()

        associations = db_api.peer_group_association_get_all(self.ctx)
        self.assertEqual(0, len(associations))
