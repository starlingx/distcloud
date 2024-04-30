#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock
from oslo_service import threadgroup
from oslo_utils import uuidutils

from dccommon import consts as dccommon_consts
from dcorch.common import consts
from dcorch.engine import generic_sync_worker_manager
from dcorch.tests import base
from dcorch.tests import utils

SUBCLOUD_SYNC_LIST = [
    ('subcloud1', dccommon_consts.ENDPOINT_TYPE_IDENTITY),
    ('subcloud1', dccommon_consts.ENDPOINT_TYPE_PLATFORM),
    ('subcloud2', dccommon_consts.ENDPOINT_TYPE_IDENTITY),
    ('subcloud2', dccommon_consts.ENDPOINT_TYPE_PLATFORM)
]


class TestGenericSyncWorkerManager(base.OrchestratorTestCase):
    def setUp(self):
        super(TestGenericSyncWorkerManager, self).setUp()
        self.engine_id = uuidutils.generate_uuid()
        self.gswm = generic_sync_worker_manager.GenericSyncWorkerManager(
            self.engine_id)

        # Mock sync_object_class_map
        p = mock.patch.object(generic_sync_worker_manager,
                              'sync_object_class_map',
                              {dccommon_consts.ENDPOINT_TYPE_PLATFORM:
                               mock.MagicMock(),
                               dccommon_consts.ENDPOINT_TYPE_IDENTITY:
                               mock.MagicMock(),
                               dccommon_consts.ENDPOINT_TYPE_IDENTITY_OS:
                               mock.MagicMock()})
        self.mock_sync_object_class_map = p.start()
        self.addCleanup(mock.patch.stopall)

        # Mock thread
        p = mock.patch.object(threadgroup, 'Thread')
        self.mock_thread = p.start()
        self.addCleanup(p.stop)

        # Mock ThreadGroupManager start
        p = mock.patch('dcorch.engine.scheduler.ThreadGroupManager.start')
        self.mock_thread_start = p.start()
        self.mock_thread_start.return_value = self.mock_thread
        self.addCleanup(p.stop)

    def test_init(self):
        self.assertIsNotNone(self.gswm)

    def test_create_sync_objects(self):
        sync_objs = self.gswm.create_sync_objects('subcloud1', base.CAPABILITES)

        # Verify both endpoint types have corresponding sync object
        self.assertEqual(len(sync_objs), 2)
        self.assertIn(dccommon_consts.ENDPOINT_TYPE_PLATFORM, sync_objs)
        self.assertIn(dccommon_consts.ENDPOINT_TYPE_IDENTITY, sync_objs)

    def test_update_subcloud_state(self):
        utils.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            initial_sync_state=consts.INITIAL_SYNC_STATE_REQUESTED)

        # Update all states
        self.gswm.update_subcloud_state(
            self.ctx,
            'subcloud1',
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
            availability_status=dccommon_consts.AVAILABILITY_OFFLINE,
            initial_sync_state=consts.INITIAL_SYNC_STATE_COMPLETED)

        # Compare all states (match)
        match = self.gswm.subcloud_state_matches(
            'subcloud1',
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
            availability_status=dccommon_consts.AVAILABILITY_OFFLINE,
            initial_sync_state=consts.INITIAL_SYNC_STATE_COMPLETED)
        self.assertTrue(match)

        # Update one state
        self.gswm.update_subcloud_state(
            self.ctx,
            'subcloud1',
            availability_status=dccommon_consts.AVAILABILITY_ONLINE)

        # Compare all states (match)
        match = self.gswm.subcloud_state_matches(
            'subcloud1',
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            initial_sync_state=consts.INITIAL_SYNC_STATE_COMPLETED)
        self.assertTrue(match)

    def test_sync_subclouds(self):
        self.gswm._sync_subcloud = mock.MagicMock()

        self.gswm.sync_subclouds(self.ctx, SUBCLOUD_SYNC_LIST)

        # Verify 4 threads started, one for each endpoint_type of a subcloud
        for subcloud_name, endpoint_type in SUBCLOUD_SYNC_LIST:
            self.mock_thread_start.assert_any_call(
                self.gswm._sync_subcloud,
                mock.ANY,
                subcloud_name,
                endpoint_type)

    def test_run_sync_audit(self):
        self.gswm._audit_subcloud = mock.MagicMock()

        self.gswm.run_sync_audit(self.ctx, SUBCLOUD_SYNC_LIST)

        # Verify 4 threads started, one for each endpoint_type of a subcloud
        for subcloud_name, endpoint_type in SUBCLOUD_SYNC_LIST:
            self.mock_thread_start.assert_any_call(
                self.gswm._audit_subcloud,
                mock.ANY,
                subcloud_name,
                endpoint_type,
                mock.ANY)
