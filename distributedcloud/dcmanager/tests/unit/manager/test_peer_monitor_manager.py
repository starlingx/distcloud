#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import threading
import uuid

from fm_api import constants as fm_const
import mock

from dcmanager.common import consts
from dcmanager.common import utils as dutils
from dcmanager.db.sqlalchemy import api as db_api
from dcmanager.manager import peer_group_audit_manager
from dcmanager.manager import peer_monitor_manager
from dcmanager.manager import subcloud_manager
from dcmanager.tests import base
from dcmanager.tests.unit.manager import test_system_peer_manager

# FAKE SYSINV DATA
FAKE_SITE0_SYSTEM_UUID = str(uuid.uuid4())
FAKE_SITE1_SYSTEM_UUID = str(uuid.uuid4())

# FAKE SYSTEM PEER DATA
FAKE_SYSTEM_PEER_ID = 1
FAKE_SYSTEM_PEER_UUID = FAKE_SITE1_SYSTEM_UUID
FAKE_SYSTEM_PEER_NAME = "PeerSite1"
FAKE_MANAGER_ENDPOINT = "http://128.128.128.128:5000/v3"
FAKE_MANAGER_USERNAME = "admin"
FAKE_MANAGER_PASSWORD = "cGFzc3dvcmQ="
FAKE_PEER_CONTROLLER_GATEWAY_IP = "128.128.1.1"

# FAKE SYSTEM PEER DATA (SITE1)
FAKE_SITE1_SYSTEM_PEER_ID = 10

# FAKE SUBCLOUD PEER GROUP DATA (SITE1)
FAKE_SITE1_PEER_GROUP_ID = 9

# FAKE PEER GROUP ASSOCIATION DATA (SITE1)
FAKE_SITE1_ASSOCIATION_ID = 10


class TestPeerMonitor(base.DCManagerTestCase):
    def setUp(self):
        super().setUp()

        self.mock_get_local_system = self._mock_object(dutils, "get_local_system")
        self.mock_subcloud_manager = self._mock_object(
            subcloud_manager, "SubcloudManager"
        )
        self.mock_log = self._mock_object(peer_monitor_manager, "LOG")
        self._mock_peer_monitor_manager_get_peer_dc_client()

        self.peer = self.create_system_peer_static(self.ctx)
        self.system_peer_manager = test_system_peer_manager.TestSystemPeerManager
        self.peer_group1 = self.system_peer_manager.create_subcloud_peer_group_static(
            self.ctx, peer_group_name="SubcloudPeerGroup1"
        )
        self.peer_group2 = self.system_peer_manager.create_subcloud_peer_group_static(
            self.ctx, peer_group_name="SubcloudPeerGroup2"
        )
        self.association = (
            self.system_peer_manager.create_peer_group_association_static(
                self.ctx, system_peer_id=self.peer.id, peer_group_id=self.peer_group1.id
            )
        )

        self.peer_monitor = peer_monitor_manager.PeerMonitor(
            self.peer, self.ctx, self.mock_subcloud_manager
        )
        self.peer_monitor_manager = peer_monitor_manager.PeerMonitorManager(
            self.mock_subcloud_manager
        )

    def _mock_peer_monitor_manager_get_peer_dc_client(self):
        """Mock peer_monitor_manager's get_peer_dc_client"""

        mock_patch = mock.patch.object(
            peer_monitor_manager.SystemPeerManager, "get_peer_dc_client"
        )
        self.mock_get_peer_dc_client = mock_patch.start()
        self.addCleanup(mock_patch.stop)

    @staticmethod
    def create_system_peer_static(ctxt, **kwargs):
        values = {
            "peer_uuid": FAKE_SYSTEM_PEER_UUID,
            "peer_name": FAKE_SYSTEM_PEER_NAME,
            "endpoint": FAKE_MANAGER_ENDPOINT,
            "username": FAKE_MANAGER_USERNAME,
            "password": FAKE_MANAGER_PASSWORD,
            "gateway_ip": FAKE_PEER_CONTROLLER_GATEWAY_IP,
        }
        values.update(kwargs)
        return db_api.system_peer_create(ctxt, **values)

    def test_initialize_peer_monitor_manager(self):
        self.assertIsNotNone(self.peer_monitor)
        self.assertEqual(FAKE_SYSTEM_PEER_NAME, self.peer_monitor.peer.peer_name)

    def test_update_sync_status_secondary_site_becomes_unreachable(self):
        self.peer_monitor._update_sync_status_secondary_site_becomes_unreachable()
        association_new = db_api.peer_group_association_get(
            self.ctx, self.association.id
        )
        self.assertEqual(
            consts.ASSOCIATION_SYNC_STATUS_UNKNOWN, association_new.sync_status
        )

    def test_update_sync_status_and_association_is_non_primary(self):
        # Delete the primary association created during setUp
        db_api.peer_group_association_destroy(self.ctx, self.association.id)

        # Create a non-primary association
        association = self.system_peer_manager.create_peer_group_association_static(
            self.ctx,
            system_peer_id=self.peer.id,
            peer_group_id=self.peer_group2.id,
            association_type=consts.ASSOCIATION_TYPE_NON_PRIMARY,
            sync_status=consts.ASSOCIATION_SYNC_STATUS_UNKNOWN,
        )

        # Mock update_sync_status
        mock_patch = mock.patch.object(
            peer_monitor_manager.SystemPeerManager, "update_sync_status"
        )
        mock_update_sync_status = mock_patch.start()
        self.addCleanup(mock_patch.stop)

        self.peer_monitor._update_sync_status_secondary_site_becomes_reachable()

        # Assert that the association sync status was not updated
        mock_update_sync_status.assert_not_called()
        association_new = db_api.peer_group_association_get(self.ctx, association.id)
        self.assertEqual(
            consts.ASSOCIATION_SYNC_STATUS_UNKNOWN, association_new.sync_status
        )

    def test_update_sync_status_and_association_is_in_sync(self):
        # Mock update_sync_status
        mock_patch = mock.patch.object(
            peer_monitor_manager.SystemPeerManager, "update_sync_status"
        )
        mock_update_sync_status = mock_patch.start()
        self.addCleanup(mock_patch.stop)

        self.peer_monitor._update_sync_status_secondary_site_becomes_reachable()

        # Assert that the association sync status was not updated as it's
        # already in-sync
        association_new = db_api.peer_group_association_get(
            self.ctx, self.association.id
        )
        self.assertEqual(
            consts.ASSOCIATION_SYNC_STATUS_IN_SYNC, association_new.sync_status
        )

        # But the update_sync_status still has to be triggered so it handles any
        # sync message update
        mock_update_sync_status.assert_called_once()

    def test_update_sync_status_secondary_site_becomes_reachable(self):
        self.mock_get_local_system.return_value = test_system_peer_manager.FakeSystem(
            FAKE_SITE0_SYSTEM_UUID
        )
        db_api.peer_group_association_update(
            self.ctx,
            self.association.id,
            sync_status=consts.ASSOCIATION_SYNC_STATUS_UNKNOWN,
        )
        self.mock_get_peer_dc_client().get_subcloud_peer_group.return_value = {
            "id": FAKE_SITE1_PEER_GROUP_ID
        }
        self.mock_get_peer_dc_client().get_system_peer.return_value = {
            "id": FAKE_SITE1_SYSTEM_PEER_ID
        }
        peer_dc_client = self.mock_get_peer_dc_client()
        peer_group_assoc = (
            peer_dc_client.get_peer_group_association_with_peer_id_and_pg_id
        )
        peer_group_assoc.return_value = {"id": FAKE_SITE1_ASSOCIATION_ID}

        # Test the case where the association sync_status is unknown
        self.peer_monitor._update_sync_status_secondary_site_becomes_reachable()
        self.mock_get_peer_dc_client().get_subcloud_peer_group.assert_called_once()
        self.mock_get_peer_dc_client().get_system_peer.assert_called_once_with(
            FAKE_SITE0_SYSTEM_UUID
        )
        peer_group_assoc.assert_called_once_with(
            FAKE_SITE1_SYSTEM_PEER_ID, FAKE_SITE1_PEER_GROUP_ID
        )
        update_peer_group_association_sync_status = (
            self.mock_get_peer_dc_client().update_peer_group_association_sync_status
        )
        update_peer_group_association_sync_status.assert_called_once_with(
            FAKE_SITE1_ASSOCIATION_ID, consts.ASSOCIATION_SYNC_STATUS_IN_SYNC
        )

        association_new = db_api.peer_group_association_get(
            self.ctx, self.association.id
        )
        self.assertEqual(
            consts.ASSOCIATION_SYNC_STATUS_IN_SYNC, association_new.sync_status
        )

    def test_update_sync_status_unreachable_non_primary(self):
        association = self.system_peer_manager.create_peer_group_association_static(
            self.ctx,
            system_peer_id=self.peer.id,
            peer_group_id=self.peer_group2.id,
            association_type=consts.ASSOCIATION_TYPE_NON_PRIMARY,
        )

        # Test the case where the association is non-primary
        self.peer_monitor._update_sync_status_secondary_site_becomes_unreachable()
        association_new = db_api.peer_group_association_get(self.ctx, association.id)
        self.assertEqual(
            consts.ASSOCIATION_SYNC_STATUS_IN_SYNC, association_new.sync_status
        )

    def test_update_sync_status_unreachable_sync_status(self):
        test_cases = [
            (
                consts.ASSOCIATION_SYNC_STATUS_OUT_OF_SYNC,
                consts.ASSOCIATION_SYNC_STATUS_FAILED,
            ),
            (
                consts.ASSOCIATION_SYNC_STATUS_IN_SYNC,
                consts.ASSOCIATION_SYNC_STATUS_UNKNOWN,
            ),
            (
                consts.ASSOCIATION_SYNC_STATUS_UNKNOWN,
                consts.ASSOCIATION_SYNC_STATUS_UNKNOWN,
            ),
            (
                consts.ASSOCIATION_SYNC_STATUS_SYNCING,
                consts.ASSOCIATION_SYNC_STATUS_FAILED,
            ),
            (
                consts.ASSOCIATION_SYNC_STATUS_FAILED,
                consts.ASSOCIATION_SYNC_STATUS_FAILED,
            ),
        ]
        for initial_status, expected_status in test_cases:
            db_api.peer_group_association_update(
                self.ctx, self.association.id, sync_status=initial_status
            )

            self.peer_monitor._update_sync_status_secondary_site_becomes_unreachable()
            association_new = db_api.peer_group_association_get(
                self.ctx, self.association.id
            )
            self.assertEqual(expected_status, association_new.sync_status)

    def test_peer_group_audit_notify_error(self):
        payload = {"peer_uuid": 100}
        self.peer_monitor_manager.peer_group_audit_notify(
            self.ctx, self.peer_group1.peer_group_name, payload
        )
        self.mock_log.exception.assert_called_once_with(
            "Handling peer group audit notify error: "
            f"System Peer with peer_uuid {payload.get('peer_uuid')} doesn't exist."
        )

    def test_peer_group_audit_notify_skip_audit(self):
        payload = {"peer_uuid": self.peer.peer_uuid}
        self.peer_monitor_manager.peer_group_audit_notify(
            self.ctx, self.peer_group1.peer_group_name, payload
        )
        msg = (
            f"System peer with UUID={self.peer.peer_uuid} is not under monitoring. "
            f"Skipping audit for peer group {self.peer_group1.peer_group_name}"
        )
        self.mock_log.warning.assert_called_once_with(msg)

    @mock.patch.object(threading, "Thread")
    def test_peer_monitor_notify(self, mock_thread_start):
        # Test to create peer monitor task
        self.peer_monitor_manager.peer_monitor_notify(self.ctx)
        Calls = [
            mock.call.debug("PeerMonitorManager initialization..."),
            mock.call.info("Caught peer monitor notify..."),
            mock.call.info(f"Create monitoring thread for peer: {self.peer.peer_name}"),
            mock.call.info(
                f"New peer group [{self.peer.id}] "
                f"found for peer [{self.peer.peer_name}]"
            ),
        ]
        self.mock_log.assert_has_calls(Calls)

    @mock.patch.object(threading, "Thread")
    def test_peer_monitor_notify_delete(self, mock_thread_start):
        obj = peer_group_audit_manager.PeerGroupAuditManager(
            mock.MagicMock(), self.peer_group1.id
        )
        self.peer_monitor.peer_group_audit_obj_map = {self.peer_group1.id: obj}
        self.peer_monitor.thread = mock.MagicMock()
        self.peer_monitor_manager.peer_monitor_thread_map = {"2": self.peer_monitor}

        # Test to delete peer monitor task
        self.peer_monitor_manager.peer_monitor_notify(self.ctx)
        self.assertNotIn(2, self.peer_monitor_manager.peer_monitor_thread_map)

    @mock.patch.object(threading.Event, "wait")
    def test_do_monitor_peer_clear_alarm(self, mock_event):
        self.peer_monitor.fm_api = mock.MagicMock()
        obj = peer_group_audit_manager.PeerGroupAuditManager(self, self.peer_group1.id)
        self.peer_monitor.peer_group_audit_obj_map = {self.peer_group1.id: obj}
        mock_event.side_effect = [False, False, True]
        self.peer_monitor._do_monitor_peer()
        self.peer_monitor.fm_api.clear_fault.assert_called_once()

    @mock.patch.object(threading.Event, "wait")
    def test_do_monitor_peer_problem_clearing_fault(self, mock_event):
        self.peer_monitor.fm_api.get_fault = mock.MagicMock(
            side_effect=Exception("boom")
        )
        mock_event.side_effect = [False, False, True]
        self.peer_monitor._do_monitor_peer()
        self.mock_log.exception.assert_called_with(
            f"Problem clearing fault for peer {self.peer.peer_name}, alarm_id="
            f"{fm_const.FM_ALARM_ID_DC_SYSTEM_PEER_HEARTBEAT_FAILED} error: boom"
        )

    @mock.patch.object(threading.Event, "wait")
    def test_do_monitor_peer_raising_alarm(self, mock_event):
        self.peer_monitor.fm_api = mock.MagicMock()
        self.mock_get_peer_dc_client().get_subcloud_peer_group_list.side_effect = (
            Exception("Mocked exception")
        )
        mock_event.side_effect = [False, False, False, True]
        self.peer_monitor_manager.peer_monitor_thread_map = {"1": self.peer_monitor}

        # heartbeat_failure_threshold reached.
        self.peer_monitor._do_monitor_peer()
        ret_system_peer = db_api.system_peer_get_by_uuid(self.ctx, self.peer.peer_uuid)
        self.assertEqual(
            consts.SYSTEM_PEER_AVAILABILITY_STATE_UNAVAILABLE,
            ret_system_peer.availability_state,
        )
        self.peer_monitor.fm_api.set_fault.assert_called_once()

    @mock.patch.object(
        peer_monitor_manager.PeerMonitor, "_heartbeat_check_via_get_peer_group_list"
    )
    @mock.patch.object(threading.Event, "wait")
    def test_do_monitor_peer_exception(
        self, mock_event, mock_heartbeat_check_via_get_peer_group_list
    ):
        mock_heartbeat_check_via_get_peer_group_list.side_effect = Exception("boom")
        mock_event.side_effect = [False, False, True]
        self.peer_monitor._do_monitor_peer()
        self.mock_log.exception.assert_called_with(
            "Unexpected error monitoring peer 'PeerSite1': boom"
        )

    def test_heartbeat_check_via_get_peer_group_list_pg_not_found(self):
        self.mock_get_peer_dc_client().get_subcloud_peer_group_list.return_value = []
        ret = self.peer_monitor._heartbeat_check_via_get_peer_group_list()
        self.mock_get_peer_dc_client.assert_called()
        self.mock_log.warning.assert_called_once_with(
            "No subcloud peer groups found for DC peer: PeerSite1 "
            "(endpoint: http://128.128.128.128:5000/v3)"
        )
        self.assertEqual((False, []), ret)

    def test_audit_specific_local_peer_group(self):
        obj = peer_group_audit_manager.PeerGroupAuditManager(
            self.mock_subcloud_manager, self.peer_group1.id
        )
        self.peer_monitor.peer_group_audit_obj_map = {self.peer_group1.id: obj}
        with mock.patch.object(
            peer_group_audit_manager.PeerGroupAuditManager,
            "audit",
            wraps=obj.audit,
        ):
            ret_msg = self.peer_monitor.audit_specific_local_peer_group(
                self.peer_group1, self.peer_group1
            )
            obj.audit.assert_called_once()  # pylint: disable=no-member
        self.assertEqual(None, ret_msg)
