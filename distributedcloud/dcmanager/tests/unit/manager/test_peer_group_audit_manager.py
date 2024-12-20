#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import copy
import json
import uuid

import mock

from dccommon import consts as dccommon_consts
from dcmanager.common import consts
from dcmanager.common import utils
from dcmanager.db.sqlalchemy import api as db_api
from dcmanager.manager import peer_group_audit_manager
from dcmanager.manager import subcloud_manager
from dcmanager.manager.system_peer_manager import SystemPeerManager
from dcmanager.tests.base import DCManagerTestCase
from dcmanager.tests.unit.manager import test_peer_monitor_manager as tpm
from dcmanager.tests.unit.manager import test_system_peer_manager as tsm

# FAKE SUBCLOUD PEER GROUP DATA (SITE1)
FAKE_SITE1_PEER_GROUP_ID = 9
FAKE_SITE1_PEER_GROUP_NAME = "PeerGroup2"
FAKE_SITE1_PEER_GROUP_SYSTEM_LEADER_ID = tpm.FAKE_SYSTEM_PEER_UUID  # SITE1 UUID
FAKE_SITE1_PEER_GROUP_SYSTEM_LEADER_NAME = tpm.FAKE_SYSTEM_PEER_NAME  # SITE1 NAME
FAKE_SITE1_PEER_GROUP_MAX_SUBCLOUDS_REHOMING = 20
FAKE_SITE1_PEER_GROUP_PRIORITY = 1
FAKE_SITE1_PEER_GROUP_STATE = "enabled"
FAKE_SITE1_PEER_GROUP_MIGRATION_STATUS = consts.PEER_GROUP_MIGRATION_COMPLETE
FAKE_SITE1_PEER_GROUP_DATA = {
    "peer_group_name": FAKE_SITE1_PEER_GROUP_NAME,
    "system_leader_id": FAKE_SITE1_PEER_GROUP_SYSTEM_LEADER_ID,
    "system_leader_name": FAKE_SITE1_PEER_GROUP_SYSTEM_LEADER_NAME,
    "group_priority": FAKE_SITE1_PEER_GROUP_PRIORITY,
    "group_state": FAKE_SITE1_PEER_GROUP_STATE,
    "max_subcloud_rehoming": FAKE_SITE1_PEER_GROUP_MAX_SUBCLOUDS_REHOMING,
    "migration_status": FAKE_SITE1_PEER_GROUP_MIGRATION_STATUS,
}

# FAKE SUBCLOUD PEER GROUP DATA (SITE2)
FAKE_SITE2_PEER_GROUP_PRIORITY = 0
FAKE_SITE2_PEER_GROUP_DATA = {
    "peer_group_name": "PeerGroup3",
    "system_leader_id": FAKE_SITE1_PEER_GROUP_SYSTEM_LEADER_ID,
    "system_leader_name": FAKE_SITE1_PEER_GROUP_SYSTEM_LEADER_NAME,
    "group_priority": FAKE_SITE2_PEER_GROUP_PRIORITY,
    "group_state": FAKE_SITE1_PEER_GROUP_STATE,
    "max_subcloud_rehoming": FAKE_SITE1_PEER_GROUP_MAX_SUBCLOUDS_REHOMING,
    "migration_status": consts.PEER_GROUP_MIGRATING,
}

# FAKE SUBCLOUD
FAKE_SUBCLOUD1_REGION_NAME = str(uuid.uuid4())
FAKE_SUBCLOUD1_NAME = "subcloud1"
FAKE_SUBCLOUD2_REGION_NAME = str(uuid.uuid4())
FAKE_SUBCLOUD2_NAME = "subcloud2"
FAKE_SUBCLOUD3_REGION_NAME = str(uuid.uuid4())
FAKE_SUBCLOUD3_NAME = "subcloud3"

# FAKE SUBCLOUD REHOME DATA
FAKE_REHOME_DATA1 = {
    "saved_payload": {
        "bootstrap-address": "192.168.10.11",
        "systemcontroller_gateway_address": "192.168.204.101",
    }
}
FAKE_REHOME_DATA2 = {
    "saved_payload": {
        "bootstrap-address": "192.168.10.12",
        "systemcontroller_gateway_address": "192.168.204.101",
    }
}
FAKE_REHOME_DATA3 = {
    "saved_payload": {
        "bootstrap-address": "192.168.10.13",
        "systemcontroller_gateway_address": "192.168.204.101",
    }
}

# FAKE SUBCLOUD DATA (SITE1)
FAKE_SITE1_SUBCLOUD1_ID = 11
FAKE_SITE1_SUBCLOUD1_REGION_NAME = FAKE_SUBCLOUD1_REGION_NAME
FAKE_SITE1_SUBCLOUD1_DEPLOY_STATUS = consts.DEPLOY_STATE_DONE
FAKE_SITE1_SUBCLOUD1_MANAGEMENT_STATE = dccommon_consts.MANAGEMENT_MANAGED
FAKE_SITE1_SUBCLOUD1_PEER_GROUP_ID = FAKE_SITE1_PEER_GROUP_ID
FAKE_SITE1_SUBCLOUD1_DATA = {
    "id": FAKE_SITE1_SUBCLOUD1_ID,
    "name": FAKE_SUBCLOUD1_NAME,
    "region-name": FAKE_SITE1_SUBCLOUD1_REGION_NAME,
    "deploy-status": FAKE_SITE1_SUBCLOUD1_DEPLOY_STATUS,
    "management-state": FAKE_SITE1_SUBCLOUD1_MANAGEMENT_STATE,
    "peer_group_id": FAKE_SITE1_SUBCLOUD1_PEER_GROUP_ID,
    "rehome_data": json.dumps(FAKE_REHOME_DATA1),
}
FAKE_SITE1_SUBCLOUD2_ID = 12
FAKE_SITE1_SUBCLOUD2_REGION_NAME = FAKE_SUBCLOUD2_REGION_NAME
FAKE_SITE1_SUBCLOUD2_DEPLOY_STATUS = consts.DEPLOY_STATE_DONE
FAKE_SITE1_SUBCLOUD2_MANAGEMENT_STATE = dccommon_consts.MANAGEMENT_MANAGED
FAKE_SITE1_SUBCLOUD2_PEER_GROUP_ID = FAKE_SITE1_PEER_GROUP_ID
FAKE_SITE1_SUBCLOUD2_DATA = {
    "id": FAKE_SITE1_SUBCLOUD2_ID,
    "name": FAKE_SUBCLOUD2_NAME,
    "region-name": FAKE_SITE1_SUBCLOUD2_REGION_NAME,
    "deploy-status": FAKE_SITE1_SUBCLOUD2_DEPLOY_STATUS,
    "management-state": FAKE_SITE1_SUBCLOUD2_MANAGEMENT_STATE,
    "peer_group_id": FAKE_SITE1_SUBCLOUD2_PEER_GROUP_ID,
    # To test syncing rehome_data from site1(remote) to site0(local),
    # we set the rehome_data to data3 instead of data2 for remote subcloud2
    "rehome_data": json.dumps(FAKE_REHOME_DATA3),
}


class TestPeerGroupAudit(DCManagerTestCase):
    def setUp(self):
        super().setUp()

        self.mock_log = self._mock_object(peer_group_audit_manager, "LOG")
        self.mock_subcloud_manager = self._mock_object(
            subcloud_manager, "SubcloudManager"
        )
        self._mock_peer_monitor_manager_get_peer_dc_client()

        self.pm = peer_group_audit_manager.PeerGroupAuditManager(
            self.mock_subcloud_manager, FAKE_SITE1_PEER_GROUP_ID
        )

    def _mock_peer_monitor_manager_get_peer_dc_client(self):
        """Mock peer_monitor_manager's get_peer_dc_client"""

        self.mock_get_peer_dc_client = self._mock_object(
            peer_group_audit_manager.SystemPeerManager, "get_peer_dc_client"
        )

        self.peer = tpm.TestPeerMonitor.create_system_peer_static(
            self.ctx, peer_name="SystemPeer1"
        )
        self.peer_group = tsm.TestSystemPeerManager.create_subcloud_peer_group_static(
            self.ctx, peer_group_name="SubcloudPeerGroup1"
        )
        # Create local dc subcloud1 mock data in database
        self.subcloud1 = tsm.TestSystemPeerManager.create_subcloud_with_pg_static(
            self.ctx,
            peer_group_id=self.peer_group.id,
            rehome_data=json.dumps(FAKE_REHOME_DATA1),
            name=FAKE_SUBCLOUD1_NAME,
            region_name=FAKE_SUBCLOUD1_REGION_NAME,
            deploy_status=consts.DEPLOY_STATE_REHOME_PENDING,
        )
        # Create local dc subcloud2 mock data in database
        self.subcloud2 = tsm.TestSystemPeerManager.create_subcloud_with_pg_static(
            self.ctx,
            peer_group_id=self.peer_group.id,
            rehome_data=json.dumps(FAKE_REHOME_DATA2),
            name=FAKE_SUBCLOUD2_NAME,
            region_name=FAKE_SUBCLOUD2_REGION_NAME,
            deploy_status=consts.DEPLOY_STATE_REHOME_PENDING,
        )
        # Create local dc subcloud3 mock data in database
        self.subcloud3 = tsm.TestSystemPeerManager.create_subcloud_with_pg_static(
            self.ctx,
            peer_group_id=self.peer_group.id,
            rehome_data=json.dumps(FAKE_REHOME_DATA3),
            name=FAKE_SUBCLOUD3_NAME,
            region_name=FAKE_SUBCLOUD3_REGION_NAME,
            deploy_status=consts.DEPLOY_STATE_REHOME_PENDING,
        )
        # Remote subclouds
        self.peer_subcloud1 = copy.deepcopy(FAKE_SITE1_SUBCLOUD1_DATA)
        self.peer_subcloud2 = copy.deepcopy(FAKE_SITE1_SUBCLOUD2_DATA)
        # Remote peer group
        self.remote_peer_group = copy.deepcopy(FAKE_SITE1_PEER_GROUP_DATA)
        self.remote_peer_group2 = copy.deepcopy(FAKE_SITE2_PEER_GROUP_DATA)

        self.mock_update_sync_status = self._mock_object(
            SystemPeerManager, "update_sync_status"
        )
        self.mock_get_local_system = self._mock_object(utils, "get_local_system")

    def run_audit(self, remote_peer_group=None):
        remote_peer_group = remote_peer_group or self.remote_peer_group
        self.mock_dc_client = mock.MagicMock()
        self.mock_get_peer_dc_client.return_value = self.mock_dc_client()
        self.mock_dc_client().get_subcloud_list_by_peer_group.return_value = [
            self.peer_subcloud1,
            self.peer_subcloud2,
        ]
        self.mock_dc_client().get_system_peer.return_value = mock.MagicMock()
        peer_group_assoc = (
            self.mock_dc_client().get_peer_group_association_with_peer_id_and_pg_id
        )
        peer_group_assoc.return_value = {
            "sync-status": consts.ASSOCIATION_SYNC_STATUS_OUT_OF_SYNC
        }
        self.pm._set_local_subcloud_to_secondary = mock.MagicMock(
            wraps=self.pm._set_local_subcloud_to_secondary
        )
        self.pm.audit(self.peer, remote_peer_group, self.peer_group)
        return self.pm

    def set_subcloud_rehome_failed(self, subcloud):
        subcloud["deploy-status"] = consts.DEPLOY_STATE_REHOME_FAILED
        subcloud["management-state"] = dccommon_consts.MANAGEMENT_UNMANAGED

    def test_audit_migration_complete_with_all_success(self):
        pm = self.run_audit()

        # Verify all of three local subclouds are set as secondary,
        # even including subcloud3, which is deleted afterward
        self.assertEqual(3, pm._set_local_subcloud_to_secondary.call_count)
        # Verify that the rehome_data of the local site subcloud2 is updated
        # from data2 to data3, syncing from the remote site subcloud2
        self.assertEqual(
            json.dumps(FAKE_REHOME_DATA3),
            db_api.subcloud_get(self.ctx, self.subcloud2.id).rehome_data,
        )
        # Verify that the subcloud3 is deleted because it doesn't
        # exist in the peer site
        self.mock_subcloud_manager.delete_subcloud.assert_called_with(
            pm.context, self.subcloud3.id
        )
        # Verify that the system leader id is updated to the peer site uuid
        self.assertEqual(
            tpm.FAKE_SITE1_SYSTEM_UUID,
            db_api.subcloud_peer_group_get(
                self.ctx, self.peer_group.id
            ).system_leader_id,
        )
        # Verify that the migration status of the remote peer group is updated
        # to None since the migration completed
        self.mock_dc_client().update_subcloud_peer_group.assert_called_with(
            self.remote_peer_group.get("peer_group_name"), migration_status=None
        )
        # Verify that the PGA sync status is updated to in-sync
        self.mock_update_sync_status.assert_called_with(
            pm.context,
            self.peer,
            consts.ASSOCIATION_SYNC_STATUS_IN_SYNC,
            self.peer_group,
            self.remote_peer_group,
        )

    def test_audit_migration_complete_with_partial_failure(self):
        # Remove local subcloud3
        db_api.subcloud_destroy(self.ctx, self.subcloud3.id)
        # Remote subclouds: subcloud1 success and subcloud2 failed
        self.set_subcloud_rehome_failed(self.peer_subcloud2)

        pm = self.run_audit()

        # Verify that only subcloud1, the successful one, is set as secondary
        self.assertEqual(1, pm._set_local_subcloud_to_secondary.call_count)
        self.mock_subcloud_manager.delete_subcloud.assert_not_called()
        # Verify that the local subcloud2 is also set to rehome-failed
        self.assertEqual(
            consts.DEPLOY_STATE_REHOME_FAILED,
            db_api.subcloud_get(self.ctx, self.subcloud2.id).deploy_status,
        )
        # Verify that the system leader id is updated to the peer site uuid
        self.assertEqual(
            tpm.FAKE_SITE1_SYSTEM_UUID,
            db_api.subcloud_peer_group_get(
                self.ctx, self.peer_group.id
            ).system_leader_id,
        )
        # Verify that the migration status of the remote peer group is updated
        # to None since the migration completed
        self.mock_dc_client().update_subcloud_peer_group.assert_called_with(
            self.remote_peer_group.get("peer_group_name"), migration_status=None
        )
        # Verify that the PGA sync status remains out-of-sync due to rehome failure
        self.mock_update_sync_status.assert_not_called()

    def test_audit_migration_complete_with_all_failed(self):
        # Remove local subcloud3
        db_api.subcloud_destroy(self.ctx, self.subcloud3.id)
        # Remote subclouds: both failed
        self.set_subcloud_rehome_failed(self.peer_subcloud1)
        self.set_subcloud_rehome_failed(self.peer_subcloud2)

        pm = self.run_audit()

        # Verify that none of the subclouds are set as secondary,
        # as all of them are rehome-failed.
        pm._set_local_subcloud_to_secondary.assert_not_called()
        self.mock_subcloud_manager.delete_subcloud.assert_not_called()
        # Verify that the local subclouds are also set to rehome-failed
        self.assertEqual(
            consts.DEPLOY_STATE_REHOME_FAILED,
            db_api.subcloud_get(self.ctx, self.subcloud1.id).deploy_status,
        )
        self.assertEqual(
            consts.DEPLOY_STATE_REHOME_FAILED,
            db_api.subcloud_get(self.ctx, self.subcloud2.id).deploy_status,
        )
        # Verify that the system leader id is updated to the peer site uuid
        self.assertEqual(
            tpm.FAKE_SITE1_SYSTEM_UUID,
            db_api.subcloud_peer_group_get(
                self.ctx, self.peer_group.id
            ).system_leader_id,
        )
        # Verify that the migration status of the remote peer group is updated
        # to None since the migration completed
        self.mock_dc_client().update_subcloud_peer_group.assert_called_with(
            self.remote_peer_group.get("peer_group_name"), migration_status=None
        )
        # Verify that the PGA sync status remains out-of-sync due to rehome failure
        self.mock_update_sync_status.assert_not_called()

    def test_audit_subcloud_management_state_managed(self):
        db_api.subcloud_update(self.ctx, self.subcloud3.id, management_state="managed")
        self.run_audit(self.remote_peer_group2)
        self.mock_subcloud_manager.update_subcloud.assert_called()
        expected_calls = [
            # Subcloud1 and 2 are already unmanaged,
            # only the deploy_status should be updated
            mock.call(
                mock.ANY,
                self.subcloud1.id,
                deploy_status=consts.DEPLOY_STATE_REHOME_PENDING,
            ),
            mock.call(
                mock.ANY,
                self.subcloud2.id,
                deploy_status=consts.DEPLOY_STATE_REHOME_PENDING,
            ),
            # Subcloud3 is managed, so it should also be umanaged
            mock.call(
                mock.ANY,
                self.subcloud3.id,
                management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
                deploy_status=consts.DEPLOY_STATE_REHOME_PENDING,
            ),
        ]
        self.mock_subcloud_manager.update_subcloud.assert_has_calls(expected_calls)

    def test_send_audit_peer_group(self):
        response = self.pm.send_audit_peer_group([self.peer], self.peer_group)
        self.mock_get_peer_dc_client.assert_called()
        self.mock_get_peer_dc_client().audit_subcloud_peer_group.assert_called()
        self.assertEqual(
            response, self.mock_get_peer_dc_client().audit_subcloud_peer_group()
        )

    def test_send_audit_peer_group_exception(self):
        self.mock_get_peer_dc_client.side_effect = Exception("boom")
        self.pm.send_audit_peer_group([self.peer], self.peer_group)
        self.mock_log.exception.assert_called_once_with(
            "Failed to send audit request for peer group "
            f"{self.peer_group.peer_group_name} to DC: {self.peer.peer_name}"
        )

    def test_audit_fail_to_unmanage(self):
        self.mock_subcloud_manager.update_subcloud.side_effect = Exception("boom")
        self.assertRaisesRegex(
            Exception, "boom", self.run_audit, self.remote_peer_group2
        )

    @mock.patch.object(peer_group_audit_manager.PeerGroupAuditManager, "audit")
    def test_audit_peer_group_from_system(self, mock_audit):
        self.pm.audit_peer_group_from_system(
            self.peer, self.peer_group, self.peer_group
        )
        mock_audit.assert_called_with(self.peer, self.peer_group, self.peer_group)

    def test_audit_update_subcloud_exception(self):
        db_api.subcloud_update(
            self.ctx,
            self.subcloud1.id,
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
        )
        self.mock_subcloud_manager.update_subcloud.side_effect = Exception("boom")
        self.assertRaisesRegex(
            Exception, "boom", self.run_audit, self.remote_peer_group
        )

    def test_audit_failed_to_get_system_peer(self):
        self.mock_get_peer_dc_client().get_system_peer.side_effect = Exception("boom")
        self.pm.audit(self.peer, self.remote_peer_group, self.peer_group)
        self.mock_log.exception.assert_called_once_with(
            f"Failed to get subclouds of peer group None from DC: {self.peer.peer_name}"
        )

    def test_audit_clear_fault_exception(self):
        self.pm.fm_api = mock.MagicMock()
        self.pm.fm_api.clear_fault.side_effect = Exception("boom")
        self.remote_peer_group["group_priority"] = 0
        self.run_audit()
        self.mock_log.exception.assert_called_once_with(
            f"Problem clearing fault [peer_group={self.peer_group.peer_group_name},"
            f"peer={self.peer.peer_uuid}], alarm_id=280.005"
        )

    def test_audit_set_fault(self):
        self.pm.fm_api = mock.MagicMock()
        self.run_audit()
        self.pm.fm_api.set_fault.assert_called()

    def test_audit_quit(self):
        self.peer_group = tsm.TestSystemPeerManager.create_subcloud_peer_group_static(
            self.ctx,
            peer_group_name="SubcloudPeerGroup2",
            migration_status=consts.PEER_GROUP_MIGRATING,
        )
        self.run_audit()
        self.mock_log.info.assert_called_with(
            "Local peer group in migrating state, quit audit"
        )

    def test_audit_delete_subcloud_exception(self):
        self.mock_subcloud_manager.delete_subcloud.side_effect = Exception("boom")
        self.assertRaisesRegex(
            Exception, "boom", self.run_audit, self.remote_peer_group
        )
