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
from dcmanager.tests.unit.manager import test_system_peer_manager

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

# FAKE SYSTEM PEER DATA (SITE1)
FAKE_SITE1_SYSTEM_PEER_ID = 10

# FAKE SUBCLOUD PEER GROUP DATA (SITE1)
FAKE_SITE1_PEER_GROUP_ID = 9

# FAKE PEER GROUP ASSOCIATION DATA (SITE1)
FAKE_SITE1_ASSOCIATION_ID = 10


class TestPeerMonitor(base.DCManagerTestCase):
    def setUp(self):
        super().setUp()

        self._mock_get_local_system()
        self._mock_peer_monitor_manager_get_peer_dc_client()

        self.peer = self.create_system_peer_static(self.ctx)
        self.peer_group1 = test_system_peer_manager.TestSystemPeerManager.\
            create_subcloud_peer_group_static(
                self.ctx, peer_group_name='SubcloudPeerGroup1')
        self.peer_group2 = test_system_peer_manager.TestSystemPeerManager.\
            create_subcloud_peer_group_static(
                self.ctx, peer_group_name='SubcloudPeerGroup2')
        self.association = test_system_peer_manager.TestSystemPeerManager.\
            create_peer_group_association_static(
                self.ctx, system_peer_id=self.peer.id,
                peer_group_id=self.peer_group1.id)

        self.pm = peer_monitor_manager.PeerMonitor(
            self.peer, self.ctx, mock.MagicMock())

    def _mock_peer_monitor_manager_get_peer_dc_client(self):
        """Mock peer_monitor_manager's get_peer_dc_client"""

        mock_patch = mock.patch.object(
            peer_monitor_manager.SystemPeerManager, 'get_peer_dc_client')
        self.mock_get_peer_dc_client = mock_patch.start()
        self.addCleanup(mock_patch.stop)

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

    def test_initialize_peer_monitor_manager(self):
        self.assertIsNotNone(self.pm)
        self.assertEqual(FAKE_SYSTEM_PEER_NAME, self.pm.peer.peer_name)

    def test_update_sync_status_when_secondary_site_becomes_unreachable(self):
        self.pm._update_sync_status_when_secondary_site_becomes_unreachable()
        association_new = db_api.peer_group_association_get(
            self.ctx, self.association.id)
        self.assertEqual(consts.ASSOCIATION_SYNC_STATUS_UNKNOWN,
                         association_new.sync_status)

    def test_update_sync_status_and_association_is_non_primary(self):
        association = test_system_peer_manager.TestSystemPeerManager.\
            create_peer_group_association_static(
                self.ctx, system_peer_id=self.peer.id,
                peer_group_id=self.peer_group2.id,
                association_type=consts.ASSOCIATION_TYPE_NON_PRIMARY)
        self.mock_get_peer_dc_client().get_subcloud_peer_group.return_value = \
            {'id': FAKE_SITE1_PEER_GROUP_ID}

        # Test the case where the association is non-primary
        self.pm._update_sync_status_when_secondary_site_becomes_reachable()
        self.mock_get_peer_dc_client().get_subcloud_peer_group.\
            assert_called_once_with(self.peer_group1.peer_group_name)
        association_new = db_api.peer_group_association_get(
            self.ctx, association.id)
        self.assertEqual(consts.ASSOCIATION_SYNC_STATUS_IN_SYNC,
                         association_new.sync_status)

    def test_update_sync_status_when_secondary_site_becomes_reachable(self):
        self.mock_get_local_system.return_value = \
            test_system_peer_manager.FakeSystem(FAKE_SITE0_SYSTEM_UUID)
        db_api.peer_group_association_update(
            self.ctx, self.association.id,
            sync_status=consts.ASSOCIATION_SYNC_STATUS_UNKNOWN)
        self.mock_get_peer_dc_client().get_subcloud_peer_group.return_value = \
            {'id': FAKE_SITE1_PEER_GROUP_ID}
        self.mock_get_peer_dc_client().get_system_peer.return_value = \
            {'id': FAKE_SITE1_SYSTEM_PEER_ID}
        self.mock_get_peer_dc_client().\
            get_peer_group_association_with_peer_id_and_pg_id.\
            return_value = {'id': FAKE_SITE1_ASSOCIATION_ID}

        # Test the case where the association sync_status is unknown
        self.pm._update_sync_status_when_secondary_site_becomes_reachable()
        self.mock_get_peer_dc_client().get_subcloud_peer_group.assert_called_once()
        self.mock_get_peer_dc_client().get_system_peer.assert_called_once_with(
            FAKE_SITE0_SYSTEM_UUID)
        self.mock_get_peer_dc_client().\
            get_peer_group_association_with_peer_id_and_pg_id.\
            assert_called_once_with(FAKE_SITE1_SYSTEM_PEER_ID,
                                    FAKE_SITE1_PEER_GROUP_ID)
        self.mock_get_peer_dc_client().update_peer_group_association_sync_status.\
            assert_called_once_with(FAKE_SITE1_ASSOCIATION_ID,
                                    consts.ASSOCIATION_SYNC_STATUS_IN_SYNC)

        association_new = db_api.peer_group_association_get(
            self.ctx, self.association.id)
        self.assertEqual(consts.ASSOCIATION_SYNC_STATUS_IN_SYNC,
                         association_new.sync_status)
