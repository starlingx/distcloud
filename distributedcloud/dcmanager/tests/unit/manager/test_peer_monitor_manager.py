#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import uuid

import mock

from dcmanager.common import consts
from dcmanager.db.sqlalchemy import api as db_api
from dcmanager.manager import peer_monitor_manager
from dcmanager.tests import base

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

# FAKE SYSTEM PEER DATA (SITE1)
FAKE_SITE1_SYSTEM_PEER_ID = 10

# FAKE SUBCLOUD PEER GROUP DATA (SITE1)
FAKE_SITE1_PEER_GROUP_ID = 9

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


class FakeLocalSystem(object):
    def __init__(self):
        self.uuid = FAKE_SITE0_SYSTEM_UUID


class TestPeerMonitor(base.DCManagerTestCase):
    def setUp(self):
        super(TestPeerMonitor, self).setUp()

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

    def test_initialize_peer_monitor_manager(self):
        peer = self.create_system_peer_static(self.ctx)
        pm = peer_monitor_manager.PeerMonitor(peer, self.ctx, mock.MagicMock())
        self.assertIsNotNone(pm)
        self.assertEqual(FAKE_SYSTEM_PEER_NAME, pm.peer.peer_name)

    def test_update_sync_status_when_secondary_site_becomes_unreachable(self):
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

        pm = peer_monitor_manager.PeerMonitor(peer, self.ctx, mock.MagicMock())
        pm._update_sync_status_when_secondary_site_becomes_unreachable()

        association_new = db_api.peer_group_association_get(
            self.ctx, association.id)
        self.assertEqual(consts.ASSOCIATION_SYNC_STATUS_UNKNOWN,
                         association_new.sync_status)

    @mock.patch('dcmanager.manager.peer_monitor_manager.'
                'SystemPeerManager.get_peer_dc_client')
    def test_update_sync_status_and_association_is_non_primary(self, mock_client):
        mock_dc_client = mock.MagicMock()
        mock_dc_client().get_subcloud_peer_group = mock.MagicMock()
        mock_client.return_value = mock_dc_client()

        peer = self.create_system_peer_static(
            self.ctx, peer_name='SystemPeer1')
        peer_group = self.create_subcloud_peer_group_static(
            self.ctx, peer_group_name='SubcloudPeerGroup1')
        association = self.create_peer_group_association_static(
            self.ctx, system_peer_id=peer.id,
            peer_group_id=peer_group.id,
            association_type=consts.ASSOCIATION_TYPE_NON_PRIMARY)

        mock_dc_client().get_subcloud_peer_group.return_value = \
            {'id': FAKE_SITE1_PEER_GROUP_ID}

        # Test the case where the association is non-primary
        pm = peer_monitor_manager.PeerMonitor(peer, self.ctx, mock.MagicMock())
        pm._update_sync_status_when_secondary_site_becomes_reachable()
        mock_dc_client().get_subcloud_peer_group.assert_not_called()

        association_new = db_api.peer_group_association_get(
            self.ctx, association.id)
        self.assertEqual(consts.ASSOCIATION_SYNC_STATUS_IN_SYNC,
                         association_new.sync_status)

    @mock.patch('dcmanager.manager.system_peer_manager.'
                'utils.get_local_system')
    @mock.patch('dcmanager.manager.peer_monitor_manager.'
                'SystemPeerManager.get_peer_dc_client')
    def test_update_sync_status_when_secondary_site_becomes_reachable(
            self, mock_client, mock_utils):
        mock_dc_client = mock.MagicMock()
        mock_dc_client().get_subcloud_peer_group = mock.MagicMock()
        mock_dc_client().get_system_peer = mock.MagicMock()
        mock_dc_client().get_peer_group_association_with_peer_id_and_pg_id = \
            mock.MagicMock()
        mock_dc_client().update_peer_group_association_sync_status = \
            mock.MagicMock()
        mock_client.return_value = mock_dc_client()
        mock_utils.return_value = FakeLocalSystem()

        peer = self.create_system_peer_static(
            self.ctx, peer_name='SystemPeer1')
        peer_group = self.create_subcloud_peer_group_static(
            self.ctx, peer_group_name='SubcloudPeerGroup1')
        association = self.create_peer_group_association_static(
            self.ctx, system_peer_id=peer.id,
            peer_group_id=peer_group.id,
            sync_status=consts.ASSOCIATION_SYNC_STATUS_UNKNOWN)

        mock_dc_client().get_subcloud_peer_group.return_value = \
            {'id': FAKE_SITE1_PEER_GROUP_ID}
        mock_dc_client().get_system_peer.return_value = \
            {'id': FAKE_SITE1_SYSTEM_PEER_ID}
        mock_dc_client().get_peer_group_association_with_peer_id_and_pg_id.\
            return_value = {'id': FAKE_SITE1_ASSOCIATION_ID}

        # Test the case where the association sync_status is unknown
        pm = peer_monitor_manager.PeerMonitor(peer, self.ctx, mock.MagicMock())
        pm._update_sync_status_when_secondary_site_becomes_reachable()
        mock_dc_client().get_subcloud_peer_group.assert_called_once()
        mock_dc_client().get_system_peer.assert_called_once_with(
            FAKE_SITE0_SYSTEM_UUID)
        mock_dc_client().get_peer_group_association_with_peer_id_and_pg_id.\
            assert_called_once_with(FAKE_SITE1_SYSTEM_PEER_ID,
                                    FAKE_SITE1_PEER_GROUP_ID)
        mock_dc_client().update_peer_group_association_sync_status.\
            assert_called_once_with(FAKE_SITE1_ASSOCIATION_ID,
                                    consts.ASSOCIATION_SYNC_STATUS_IN_SYNC)

        association_new = db_api.peer_group_association_get(
            self.ctx, association.id)
        self.assertEqual(consts.ASSOCIATION_SYNC_STATUS_IN_SYNC,
                         association_new.sync_status)
