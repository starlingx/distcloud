#
# Copyright (c) 2024-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import threading

import mock
from oslo_utils import uuidutils

from dccommon import consts as dccommon_consts
from dccommon.scheduler import ThreadGroupManager
from dcorch.common import consts
from dcorch.db import api as db_api
from dcorch.engine import generic_sync_worker_manager
from dcorch.tests import base
from dcorch.tests import utils

SUBCLOUD_SYNC_LIST = [
    ("subcloud1", dccommon_consts.ENDPOINT_TYPE_IDENTITY, "192.168.1.11", "24.09", "1"),
    ("subcloud1", dccommon_consts.ENDPOINT_TYPE_PLATFORM, "192.168.1.11", "24.09", "1"),
    ("subcloud2", dccommon_consts.ENDPOINT_TYPE_IDENTITY, "192.168.1.12", "24.09", "2"),
    ("subcloud2", dccommon_consts.ENDPOINT_TYPE_PLATFORM, "192.168.1.12", "24.09", "2"),
]


class TestGenericSyncWorkerManager(base.OrchestratorTestCase):
    def setUp(self):
        super().setUp()

        self.engine_id = uuidutils.generate_uuid()
        self.gswm = generic_sync_worker_manager.GenericSyncWorkerManager(self.engine_id)

        # Mock sync_object_class_map
        mock_sync_object_class_map = self._mock_object(
            generic_sync_worker_manager, "sync_object_class_map"
        )
        mock_sync_object_class_map.return_value = {
            dccommon_consts.ENDPOINT_TYPE_PLATFORM: mock.MagicMock(),
            dccommon_consts.ENDPOINT_TYPE_IDENTITY: mock.MagicMock(),
            dccommon_consts.ENDPOINT_TYPE_IDENTITY_OS: mock.MagicMock(),
        }

        # Mock ThreadGroupManager start
        self.mock_thread_start = self._mock_object(ThreadGroupManager, "start")

    def test_init(self):
        self.assertIsNotNone(self.gswm)

    def test_create_sync_objects(self):
        sync_objs = self.gswm.create_sync_objects(
            "subcloud1", base.CAPABILITIES, "192.168.1.11", "24.09", "1"
        )

        # Verify both endpoint types have corresponding sync object
        self.assertEqual(len(sync_objs), 2)
        self.assertIn(dccommon_consts.ENDPOINT_TYPE_PLATFORM, sync_objs)
        self.assertIn(dccommon_consts.ENDPOINT_TYPE_IDENTITY, sync_objs)

    def test_update_subcloud_state(self):
        utils.create_subcloud_static(
            self.ctx,
            name="subcloud1",
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            initial_sync_state=consts.INITIAL_SYNC_STATE_REQUESTED,
        )

        # Update all states
        self.gswm.update_subcloud_state(
            self.ctx,
            "subcloud1",
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
            availability_status=dccommon_consts.AVAILABILITY_OFFLINE,
            initial_sync_state=consts.INITIAL_SYNC_STATE_COMPLETED,
        )

        # Compare all states (match)
        match = self.gswm.subcloud_state_matches(
            "subcloud1",
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
            availability_status=dccommon_consts.AVAILABILITY_OFFLINE,
            initial_sync_state=consts.INITIAL_SYNC_STATE_COMPLETED,
        )
        self.assertTrue(match)

        # Update one state
        self.gswm.update_subcloud_state(
            self.ctx,
            "subcloud1",
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
        )

        # Compare all states (match)
        match = self.gswm.subcloud_state_matches(
            "subcloud1",
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            initial_sync_state=consts.INITIAL_SYNC_STATE_COMPLETED,
        )
        self.assertTrue(match)

    def test_sync_subclouds(self):
        self.gswm._sync_subcloud = mock.MagicMock()

        self.gswm.sync_subclouds(self.ctx, SUBCLOUD_SYNC_LIST)

        # Verify 4 threads started, one for each endpoint_type of a subcloud
        for subcloud_name, endpoint_type, ip, version, id in SUBCLOUD_SYNC_LIST:
            self.mock_thread_start.assert_any_call(
                self.gswm._sync_subcloud,
                mock.ANY,
                subcloud_name,
                endpoint_type,
                ip,
                version,
                id,
            )

    def test_run_sync_audit(self):
        self.gswm._audit_subcloud = mock.MagicMock()

        self.gswm.run_sync_audit(self.ctx, SUBCLOUD_SYNC_LIST)

        # Verify 4 threads started, one for each endpoint_type of a subcloud
        for subcloud_name, endpoint_type, ip, version, id in SUBCLOUD_SYNC_LIST:
            self.mock_thread_start.assert_any_call(
                self.gswm._audit_subcloud,
                mock.ANY,
                subcloud_name,
                endpoint_type,
                mock.ANY,
            )

    def test_sync_request(self):
        subcloud1 = utils.create_subcloud_static(
            self.ctx,
            name="subcloud1",
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            initial_sync_state=consts.INITIAL_SYNC_STATE_NONE,
        )
        utils.create_subcloud_sync_static(
            self.ctx,
            subcloud1.region_name,
            dccommon_consts.ENDPOINT_TYPE_IDENTITY,
            subcloud_id=subcloud1.id,
        )

        subcloud2 = utils.create_subcloud_static(
            self.ctx,
            name="subcloud2",
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            initial_sync_state=consts.INITIAL_SYNC_STATE_FAILED,
        )
        utils.create_subcloud_sync_static(
            self.ctx,
            subcloud2.region_name,
            dccommon_consts.ENDPOINT_TYPE_IDENTITY,
            vsubcloud_id=subcloud2.id,
        )

        self.gswm.sync_request(self.ctx, dccommon_consts.ENDPOINT_TYPE_IDENTITY)

        # Verify the sync_request of the subclouds were updated to requested
        subcloud_sync = db_api.subcloud_sync_get(
            self.ctx, "subcloud1", dccommon_consts.ENDPOINT_TYPE_IDENTITY
        )
        self.assertEqual(consts.SYNC_STATUS_REQUESTED, subcloud_sync.sync_request)
        subcloud_sync = db_api.subcloud_sync_get(
            self.ctx, "subcloud2", dccommon_consts.ENDPOINT_TYPE_IDENTITY
        )
        self.assertEqual(consts.SYNC_STATUS_REQUESTED, subcloud_sync.sync_request)


class TestGenericSyncWorkerManagerAuditSubcloud(base.OrchestratorTestCase):
    """Tests for _audit_subcloud using a real ThreadGroupManager thread."""

    def setUp(self):
        super().setUp()

        self.engine_id = uuidutils.generate_uuid()
        self.gswm = generic_sync_worker_manager.GenericSyncWorkerManager(self.engine_id)
        self.mock_log = self._mock_object(generic_sync_worker_manager, "LOG")

        # Use a short timeout so the timeout path runs fast
        mock_patch_timeout = mock.patch.object(
            generic_sync_worker_manager, "AUDIT_TIMEOUT", 0.1
        )
        mock_patch_timeout.start()
        self.addCleanup(mock_patch_timeout.stop)

        subcloud = utils.create_subcloud_static(self.ctx, name="subcloud1")
        utils.create_subcloud_sync_static(
            self.ctx,
            subcloud.region_name,
            dccommon_consts.ENDPOINT_TYPE_IDENTITY,
            subcloud_id=subcloud.id,
            audit_status=consts.AUDIT_STATUS_IN_PROGRESS,
        )

        self.sync_obj = mock.MagicMock()

    def _get_audit_status(self):
        return db_api.subcloud_sync_get(
            self.ctx, "subcloud1", dccommon_consts.ENDPOINT_TYPE_IDENTITY
        ).audit_status

    def _audit_subcloud(self):
        self.gswm._audit_subcloud(
            self.ctx,
            "subcloud1",
            dccommon_consts.ENDPOINT_TYPE_IDENTITY,
            self.sync_obj,
        )

    def test_audit_subcloud_succeeds(self):
        self._audit_subcloud()

        self.sync_obj.run_sync_audit.assert_called_once_with(self.engine_id)
        self.assertEqual(consts.AUDIT_STATUS_COMPLETED, self._get_audit_status())
        self.mock_log.exception.assert_not_called()

    def test_audit_subcloud_fails_when_audit_raises(self):
        self.sync_obj.run_sync_audit.side_effect = Exception("boom")

        self._audit_subcloud()

        self.assertEqual(consts.AUDIT_STATUS_FAILED, self._get_audit_status())
        self.mock_log.exception.assert_called_once_with(
            "Audit failed for subcloud1/identity: boom"
        )

    def test_audit_subcloud_fails_when_audit_times_out(self):
        # Block the audit until the test finishes so it exceeds AUDIT_TIMEOUT
        release_audit = threading.Event()
        self.addCleanup(release_audit.set)

        def _blocking_audit(engine_id):
            release_audit.wait(timeout=10)

        self.sync_obj.run_sync_audit.side_effect = _blocking_audit

        self._audit_subcloud()

        # _audit_subcloud must return on timeout without waiting for the
        # audit thread to finish
        self.assertFalse(release_audit.is_set())
        self.sync_obj.run_sync_audit.assert_called_once_with(self.engine_id)
        self.assertEqual(consts.AUDIT_STATUS_FAILED, self._get_audit_status())
        self.mock_log.exception.assert_called_once_with(
            "Audit timed out for subcloud1/identity."
        )
