#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import json
import uuid

import mock

from dccommon import exceptions as dccommon_exceptions
from dcmanager.common import consts
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
FAKE_SITE1_PEER_GROUP_NAME = 'PeerGroup2'
FAKE_SITE1_PEER_GROUP_MAX_SUBCLOUDS_REHOMING = 20
FAKE_SITE1_PEER_GROUP_STATE = 'enabled'

# FAKE SYSTEM PEER DATA (SITE1)
FAKE_SITE1_SYSTEM_PEER_ID = 10

FAKE_SITE1_SUBCLOUD1_REGION_NAME = str(uuid.uuid4())
FAKE_SITE1_SUBCLOUD2_REGION_NAME = str(uuid.uuid4())

# FAKE PEER GROUP ASSOCIATION DATA (SITE0)
FAKE_ASSOCIATION_PEER_GROUP_ID = \
    FAKE_SITE0_PEER_GROUP_ID
FAKE_ASSOCIATION_SYSTEM_PEER_ID = \
    FAKE_SYSTEM_PEER_ID
FAKE_ASSOCIATION_PEER_GROUP_PRIORITY = 1
FAKE_ASSOCIATION_SYNC_STATUS = 'in-sync'
FAKE_ASSOCIATION_SYNC_MESSAGE = 'None'
FAKE_ASSOCIATION_TYPE = 'primary'

# FAKE PEER GROUP ASSOCIATION DATA (SITE1)
FAKE_SITE1_ASSOCIATION_ID = 10


class FakeSystem(object):
    def __init__(self, uuid):
        self.uuid = uuid


class FakeSysinvClient(object):
    def __init__(self):
        self.system = FakeSystem(FAKE_SITE1_SYSTEM_UUID)

    def get_system(self):
        return self.system


class TestSystemPeerManager(base.DCManagerTestCase):
    """Test class for testing system peer manager"""

    def setUp(self):
        super().setUp()

        self._mock_sysinv_client(system_peer_manager)
        self._mock_audit_rpc_client()
        self._mock_get_local_system()
        self._mock_system_peer_manager_dcmanagerclient()
        self._mock_system_peer_manager_peersitedriver()

        self.spm = system_peer_manager.SystemPeerManager(mock.MagicMock())
        self.mock_sysinv_client.return_value = FakeSysinvClient()

        self.peer_subcloud1 = self._fake_site_data(1)
        self.peer_subcloud2 = self._fake_site_data(2)
        self.peer_subcloud3 = self._fake_site_data(3)

        self.peer = self.create_system_peer_static(
            self.ctx, peer_name='SystemPeer1'
        )
        self.peer_group = self.create_subcloud_peer_group_static(
            self.ctx, peer_group_name='SubcloudPeerGroup1'
        )
        self.association = self.create_peer_group_association_static(
            self.ctx,
            system_peer_id=self.peer.id,
            peer_group_id=self.peer_group.id)

    def _fake_site_data(self, subcloud_id):
        # FAKE SITE SUBCLOUD DATA
        return {
            'id': subcloud_id,
            'name': f'subcloud{subcloud_id}',
            'region-name': FAKE_SITE1_SUBCLOUD1_REGION_NAME if subcloud_id == 1
            else FAKE_SITE1_SUBCLOUD2_REGION_NAME if subcloud_id == 2
            else 'subcloud3',
            'deploy-status': 'secondary' if subcloud_id in [1, 3]
            else 'secondary-failed'
        }

    def _mock_system_peer_manager_dcmanagerclient(self):
        """Mock system_peer_manager's DcmanagerClient"""

        mock_patch = mock.patch.object(system_peer_manager, 'DcmanagerClient')
        self.mock_dc_client = mock_patch.start()
        self.addCleanup(mock_patch.stop)

    def _mock_system_peer_manager_peersitedriver(self):
        """Mock system_peer_manager's PeerSiteDriver"""

        mock_patch = mock.patch.object(system_peer_manager, 'PeerSiteDriver')
        self.mock_keystone_client = mock_patch.start()
        self.addCleanup(mock_patch.stop)

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
            'gateway_ip': FAKE_PEER_CONTROLLER_GATEWAY_IP,
            'availability_state':
                consts.SYSTEM_PEER_AVAILABILITY_STATE_AVAILABLE
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
        self.assertIsNotNone(self.spm)
        self.assertEqual('system_peer_manager', self.spm.service_name)
        self.assertEqual('localhost', self.spm.host)

    def test_sync_subclouds(self):
        self.mock_dc_client().add_subcloud_with_secondary_status.return_value = {
            "region-name": FAKE_SITE1_SUBCLOUD2_REGION_NAME}
        rehome_data = {
            "saved_payload": {
                "bootstrap-address": "192.168.10.10",
                "systemcontroller_gateway_address": "192.168.204.101"
            }
        }
        # Create local dc subcloud1 mock data in database
        data_install = json.dumps(fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES)
        self.create_subcloud_with_pg_static(
            self.ctx,
            peer_group_id=self.peer_group.id,
            rehome_data=json.dumps(rehome_data),
            name='subcloud1',
            region_name='subcloud1',
            data_install=data_install)
        # Create local dc subcloud2 mock data in database
        self.create_subcloud_with_pg_static(
            self.ctx,
            peer_group_id=self.peer_group.id,
            rehome_data=json.dumps(rehome_data),
            name='subcloud2',
            region_name='subcloud2',
            data_install=None)
        self.mock_dc_client().get_subcloud.side_effect = [
            self.peer_subcloud1, dccommon_exceptions.SubcloudNotFound,
            self.peer_subcloud1, dccommon_exceptions.SubcloudNotFound,
            self.peer_subcloud3]
        self.mock_dc_client().get_subcloud_list_by_peer_group.return_value = [
            self.peer_subcloud1, self.peer_subcloud2, self.peer_subcloud3]
        self.mock_dc_client().update_subcloud.side_effect = [
            self.peer_subcloud1, self.peer_subcloud1, self.peer_subcloud2]

        self.spm._sync_subclouds(self.ctx, self.peer, self.peer_group.id,
                                 FAKE_SITE1_PEER_GROUP_ID)

        self.mock_dc_client().get_subcloud.assert_has_calls([
            mock.call(self.peer_subcloud1.get('name')),
            mock.call(self.peer_subcloud2.get('name')),
            mock.call(self.peer_subcloud3.get('name'))
        ])
        self.mock_dc_client().update_subcloud.assert_has_calls([
            mock.call('subcloud1', mock.ANY, mock.ANY, is_region_name=True),
            mock.call(FAKE_SITE1_SUBCLOUD1_REGION_NAME, files=None,
                      data={'peer_group': str(FAKE_SITE1_PEER_GROUP_ID)},
                      is_region_name=True),
            mock.call(FAKE_SITE1_SUBCLOUD2_REGION_NAME, files=None,
                      data={'peer_group': str(FAKE_SITE1_PEER_GROUP_ID)},
                      is_region_name=True)
        ])
        self.mock_dc_client().add_subcloud_with_secondary_status. \
            assert_called_once()
        self.mock_dc_client().delete_subcloud.assert_called_once_with('subcloud3')

    @mock.patch.object(
        system_peer_manager.SystemPeerManager, '_sync_subclouds')
    def test_sync_subcloud_peer_group(self,
                                      mock_sync_subclouds):
        mock_sync_subclouds.return_value = True

        self.spm.sync_subcloud_peer_group(self.ctx, self.association.id, False)

        self.mock_dc_client().get_subcloud_peer_group.assert_called_once_with(
            self.peer_group.peer_group_name)
        self.mock_dc_client().update_subcloud_peer_group.assert_called_once()

    @mock.patch.object(
        system_peer_manager.SystemPeerManager, '_sync_subclouds')
    def test_sync_subcloud_peer_group_not_exist(self,
                                                mock_sync_subclouds):
        mock_sync_subclouds.return_value = True
        self.mock_dc_client().get_subcloud_peer_group.side_effect = \
            dccommon_exceptions.SubcloudPeerGroupNotFound

        self.spm.sync_subcloud_peer_group(self.ctx, self.association.id, False)

        self.mock_dc_client().get_subcloud_peer_group.assert_called_once_with(
            self.peer_group.peer_group_name)
        self.mock_dc_client().add_subcloud_peer_group.assert_called_once_with(**{
            'peer-group-name': self.peer_group.peer_group_name,
            'group-priority': self.association.peer_group_priority,
            'group-state': self.peer_group.group_state,
            'system-leader-id': self.peer_group.system_leader_id,
            'system-leader-name': self.peer_group.system_leader_name,
            'max-subcloud-rehoming': self.peer_group.max_subcloud_rehoming
        })

    def test_delete_peer_group_association(self):
        # Create local dc subcloud1 mock data in database
        subcloud1 = self.create_subcloud_with_pg_static(
            self.ctx,
            peer_group_id=self.peer_group.id,
            name='subcloud1')
        # Create local dc subcloud2 mock data in database
        subcloud2 = self.create_subcloud_with_pg_static(
            self.ctx,
            peer_group_id=self.peer_group.id,
            name='subcloud2')
        self.mock_dc_client().get_subcloud.side_effect = [
            self.peer_subcloud1, self.peer_subcloud2]
        self.mock_dc_client().get_peer_group_association_with_peer_id_and_pg_id.\
            return_value = {'id': FAKE_SITE1_ASSOCIATION_ID}

        self.spm.delete_peer_group_association(self.ctx, self.association.id)

        self.mock_dc_client().delete_subcloud.assert_has_calls([
            mock.call(subcloud1.name),
            mock.call(subcloud2.name)
        ])
        self.mock_dc_client().delete_subcloud_peer_group.assert_called_once_with(
            self.peer_group.peer_group_name)
        self.mock_dc_client().delete_peer_group_association.assert_called_once_with(
            FAKE_SITE1_ASSOCIATION_ID)

        associations = db_api.peer_group_association_get_all(self.ctx)
        self.assertEqual(0, len(associations))

    def test_delete_peer_group_association_peer_site_association_not_exsit(self):
        # Create local dc subcloud1 mock data in database
        subcloud1 = self.create_subcloud_with_pg_static(
            self.ctx,
            peer_group_id=self.peer_group.id,
            name='subcloud1')
        self.mock_dc_client().get_subcloud.side_effect = [
            self.peer_subcloud1, dccommon_exceptions.SubcloudNotFound]
        self.mock_dc_client().get_peer_group_association_with_peer_id_and_pg_id.\
            side_effect = [dccommon_exceptions.PeerGroupAssociationNotFound]

        self.spm.delete_peer_group_association(self.ctx, self.association.id)

        self.mock_dc_client().delete_subcloud.assert_has_calls([
            mock.call(subcloud1.name)])
        self.mock_dc_client().delete_subcloud_peer_group.assert_called_once_with(
            self.peer_group.peer_group_name)
        self.mock_dc_client().delete_peer_group_association.assert_not_called()

        associations = db_api.peer_group_association_get_all(self.ctx)
        self.assertEqual(0, len(associations))

    @mock.patch('dcmanager.manager.system_peer_manager.'
                'SystemPeerManager.get_peer_dc_client')
    def test_update_sync_status(self, mock_client):
        mock_client.return_value = self.mock_dc_client()
        self.mock_get_local_system.return_value = FakeSystem(FAKE_SITE0_SYSTEM_UUID)

        db_api.peer_group_association_update(
            self.ctx, associate_id=self.association.id,
            sync_status=consts.ASSOCIATION_SYNC_STATUS_UNKNOWN)

        self.mock_dc_client().get_subcloud_peer_group.return_value = \
            {'id': FAKE_SITE1_PEER_GROUP_ID}
        self.mock_dc_client().get_system_peer.return_value = \
            {'id': FAKE_SITE1_SYSTEM_PEER_ID}
        self.mock_dc_client().get_peer_group_association_with_peer_id_and_pg_id.\
            return_value = {'id': FAKE_SITE1_ASSOCIATION_ID}

        self.spm.update_sync_status(
            self.ctx, self.peer, consts.ASSOCIATION_SYNC_STATUS_IN_SYNC)

        self.mock_dc_client().get_subcloud_peer_group.assert_called_once_with(
            self.peer_group.peer_group_name)
        self.mock_dc_client().get_system_peer.assert_called_once_with(
            FAKE_SITE0_SYSTEM_UUID)
        self.mock_dc_client().get_peer_group_association_with_peer_id_and_pg_id.\
            assert_called_once_with(FAKE_SITE1_SYSTEM_PEER_ID,
                                    FAKE_SITE1_PEER_GROUP_ID)
        self.mock_dc_client().update_peer_group_association_sync_status.\
            assert_called_once_with(FAKE_SITE1_ASSOCIATION_ID,
                                    consts.ASSOCIATION_SYNC_STATUS_IN_SYNC)

        association_new = db_api.peer_group_association_get(
            self.ctx, self.association.id)
        self.assertEqual(consts.ASSOCIATION_SYNC_STATUS_IN_SYNC,
                         association_new.sync_status)

    @mock.patch.object(system_peer_manager.SystemPeerManager,
                       'update_sync_status')
    def test_update_association_sync_status(self, mock_update_sync_status):

        db_api.peer_group_association_update(
            self.ctx, associate_id=self.association.id,
            sync_status=consts.ASSOCIATION_SYNC_STATUS_IN_SYNC)

        self.spm.update_association_sync_status(
            self.ctx, self.peer_group.id,
            consts.ASSOCIATION_SYNC_STATUS_OUT_OF_SYNC)

        mock_update_sync_status.assert_called_once_with(
            self.ctx, mock.ANY, consts.ASSOCIATION_SYNC_STATUS_OUT_OF_SYNC,
            mock.ANY, None, 'None', mock.ANY)

    @mock.patch.object(system_peer_manager.SystemPeerManager,
                       'update_sync_status')
    def test_update_association_sync_status_when_peer_site_down(
            self, mock_update_sync_status):

        db_api.peer_group_association_update(
            self.ctx, associate_id=self.association.id,
            sync_status=consts.ASSOCIATION_SYNC_STATUS_UNKNOWN)

        self.spm.update_association_sync_status(
            self.ctx, self.peer_group.id,
            consts.ASSOCIATION_SYNC_STATUS_OUT_OF_SYNC)

        association = db_api. \
            peer_group_association_get_by_peer_group_and_system_peer_id(
                self.ctx, self.peer_group.id, self.peer.id)
        self.assertEqual(consts.ASSOCIATION_SYNC_STATUS_FAILED,
                         association.sync_status)
        self.assertEqual("Failed to update sync_status, "
                         "because the peer site is unreachable.",
                         association.sync_message)

        mock_update_sync_status.assert_not_called()

    def test_update_subcloud_peer_group(self):
        self.spm.update_subcloud_peer_group(
            self.ctx, self.peer_group.id,
            FAKE_SITE1_PEER_GROUP_STATE,
            FAKE_SITE1_PEER_GROUP_MAX_SUBCLOUDS_REHOMING,
            FAKE_SITE0_PEER_GROUP_NAME,
            FAKE_SITE1_PEER_GROUP_NAME)

        peer_group_kwargs = {
            'peer-group-name': FAKE_SITE1_PEER_GROUP_NAME,
            'group-state': FAKE_SITE1_PEER_GROUP_STATE,
            'max-subcloud-rehoming':
                FAKE_SITE1_PEER_GROUP_MAX_SUBCLOUDS_REHOMING
        }
        self.mock_dc_client().update_subcloud_peer_group.assert_called_once_with(
            FAKE_SITE0_PEER_GROUP_NAME, **peer_group_kwargs)
