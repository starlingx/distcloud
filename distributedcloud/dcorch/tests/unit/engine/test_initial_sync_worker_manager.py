#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock
from oslo_service import threadgroup
from oslo_utils import uuidutils

from dcorch.common import consts
from dcorch.db.sqlalchemy import api as db_api
from dcorch.engine import initial_sync_worker_manager
from dcorch.tests import base
from dcorch.tests import utils


class FakeSyncObject(object):
    def __init__(self):
        # sc_admin_session is used when attempting to close the session
        self.sc_admin_session = mock.MagicMock()

    def initial_sync(self):
        pass

    def enable(self):
        pass


class FakeGSWM(object):
    def __init__(self, ctx, engine_id):
        self.ctx = ctx
        self.engine_id = engine_id

    def update_subcloud_state(
        self, ctx, subcloud_name, initial_sync_state=None, subsequent_sync=None
    ):
        values = dict()

        if initial_sync_state:
            values["initial_sync_state"] = initial_sync_state
        if subsequent_sync:
            values["subsequent_sync"] = subsequent_sync

        db_api.subcloud_update(ctx, subcloud_name, values=values)

    def create_sync_objects(
        self,
        subcloud_name,
        capabilities,
        management_ip,
        software_version,
    ):
        sync_objs = {}
        endpoint_type_list = capabilities.get("endpoint_types", None)
        if endpoint_type_list:
            for endpoint_type in endpoint_type_list:
                sync_obj = FakeSyncObject()
                sync_objs.update({endpoint_type: sync_obj})
        return sync_objs

    def subcloud_state_matches(
        self,
        subcloud_name,
        management_state=None,
        availability_status=None,
        initial_sync_state=None,
    ):
        # compare subcloud states
        match = True
        sc = db_api.subcloud_get(self.ctx, subcloud_name)
        if management_state is not None and sc.management_state != management_state:
            match = False
        if (
            match
            and availability_status is not None
            and sc.availability_status != availability_status
        ):
            match = False
        if (
            match
            and initial_sync_state is not None
            and sc.initial_sync_state != initial_sync_state
        ):
            match = False
        return match


class TestInitialSyncWorkerManager(base.OrchestratorTestCase):
    def setUp(self):
        super().setUp()

        self.engine_id = uuidutils.generate_uuid()
        self.fake_gswm = FakeGSWM(self.ctx, self.engine_id)
        self.iswm = initial_sync_worker_manager.InitialSyncWorkerManager(
            self.fake_gswm, self.engine_id
        )

        # Mock eventlet
        p = mock.patch("eventlet.greenthread.spawn_after")
        self.mock_eventlet_spawn_after = p.start()
        self.addCleanup(p.stop)

        # Mock FernetKeyManager distribute_Keys
        p = mock.patch(
            "dcorch.engine.fernet_key_manager.FernetKeyManager.distribute_keys"
        )
        self.mock_distribute_keys = p.start()
        self.addCleanup(p.stop)

        # Mock db_api subcloud_sync_update
        p = mock.patch("dcorch.db.api.subcloud_sync_update")
        self.mock_subcloud_sync_update = p.start()
        self.addCleanup(p.stop)

        # Mock thread
        p = mock.patch.object(threadgroup, "Thread")
        self.mock_thread = p.start()
        self.addCleanup(p.stop)

        # Mock ThreadGroupManager start
        p = mock.patch("dcorch.engine.scheduler.ThreadGroupManager.start")
        self.mock_thread_start = p.start()
        self.mock_thread_start.return_value = self.mock_thread
        self.addCleanup(p.stop)

    def test_init(self):
        self.assertIsNotNone(self.iswm)

    def test_initial_sync_subcloud(self):
        subcloud = utils.create_subcloud_static(
            self.ctx,
            name="subcloud1",
            initial_sync_state=consts.INITIAL_SYNC_STATE_REQUESTED,
            management_ip="192.168.1.11",
        )
        self.assertIsNotNone(subcloud)

        # Initial sync the subcloud
        self.iswm._initial_sync_subcloud(
            self.ctx,
            subcloud.region_name,
            base.CAPABILITIES,
            subcloud.management_ip,
            subcloud.software_version,
            False,
        )

        self.mock_distribute_keys.assert_called_once()

        # Verify subcloud_sync_update called twice due to two endpoint types
        self.assertEqual(2, self.mock_subcloud_sync_update.call_count)

        # Verify the initial sync was completed
        subcloud = db_api.subcloud_get(self.ctx, "subcloud1")
        self.assertEqual(
            subcloud.initial_sync_state, consts.INITIAL_SYNC_STATE_COMPLETED
        )

    def test_initial_sync_subcloud_not_required(self):
        subcloud = utils.create_subcloud_static(
            self.ctx,
            name="subcloud1",
            initial_sync_state="",
            management_ip="192.168.1.11",
        )
        self.assertIsNotNone(subcloud)

        self.iswm.initial_sync = mock.MagicMock()

        # Initial sync the subcloud
        self.iswm._initial_sync_subcloud(
            self.ctx,
            subcloud.region_name,
            base.CAPABILITIES,
            subcloud.management_ip,
            subcloud.software_version,
            False,
        )

        # Verify that the initial sync steps were not done
        self.iswm.initial_sync.assert_not_called()
        self.mock_distribute_keys.assert_not_called()
        self.mock_subcloud_sync_update.assert_not_called()

        # Verify the initial sync state was not changed
        subcloud = db_api.subcloud_get(self.ctx, "subcloud1")
        self.assertEqual(subcloud.initial_sync_state, "")

    def test_initial_sync_subcloud_when_subsequent_sync(self):
        subcloud = utils.create_subcloud_static(
            self.ctx,
            name="subcloud1",
            initial_sync_state=consts.INITIAL_SYNC_STATE_REQUESTED,
            management_ip="192.168.1.11",
        )
        self.assertIsNotNone(subcloud)

        self.iswm.initial_sync = mock.MagicMock()

        # Initial sync the subcloud
        self.iswm._initial_sync_subcloud(
            self.ctx,
            subcloud.region_name,
            base.CAPABILITIES,
            subcloud.management_ip,
            subcloud.software_version,
            True,
        )

        self.iswm.initial_sync.assert_not_called()
        self.mock_distribute_keys.assert_called_once()

        # Verify subcloud_sync_update called twice due to two endpoint types
        self.assertEqual(2, self.mock_subcloud_sync_update.call_count)

        # Verify the initial sync was completed
        subcloud = db_api.subcloud_get(self.ctx, "subcloud1")
        self.assertEqual(
            subcloud.initial_sync_state, consts.INITIAL_SYNC_STATE_COMPLETED
        )

    def test_initial_sync_subcloud_failed(self):
        subcloud = utils.create_subcloud_static(
            self.ctx,
            name="subcloud1",
            initial_sync_state=consts.INITIAL_SYNC_STATE_REQUESTED,
            management_ip="192.168.1.11",
        )
        self.assertIsNotNone(subcloud)

        self.iswm.enable_subcloud = mock.MagicMock()
        # Force a failure
        self.mock_distribute_keys.side_effect = Exception("fake_exception")

        # Initial sync the subcloud
        self.iswm._initial_sync_subcloud(
            self.ctx,
            subcloud.region_name,
            base.CAPABILITIES,
            subcloud.management_ip,
            subcloud.software_version,
            False,
        )

        # Verify the initial sync was failed
        subcloud = db_api.subcloud_get(self.ctx, "subcloud1")
        self.assertEqual(subcloud.initial_sync_state, consts.INITIAL_SYNC_STATE_FAILED)

        # Verify that the subcloud was not enabled
        self.iswm.enable_subcloud.assert_not_called()

        # Verify the initial sync was retried
        self.mock_eventlet_spawn_after.assert_called_with(
            initial_sync_worker_manager.SYNC_FAIL_HOLD_OFF, mock.ANY, "subcloud1"
        )

    def test_reattempt_sync(self):
        utils.create_subcloud_static(
            self.ctx,
            name="subcloud1",
            initial_sync_state=consts.INITIAL_SYNC_STATE_NONE,
        )
        utils.create_subcloud_static(
            self.ctx,
            name="subcloud2",
            initial_sync_state=consts.INITIAL_SYNC_STATE_FAILED,
        )

        # Reattempt sync success
        self.iswm._reattempt_sync("subcloud2")

        # Verify the subcloud is in the correct initial sync state
        subcloud = db_api.subcloud_get(self.ctx, "subcloud2")
        self.assertEqual(
            subcloud.initial_sync_state, consts.INITIAL_SYNC_STATE_REQUESTED
        )

        # Reattempt sync when not needed
        self.iswm._reattempt_sync("subcloud1")

        # Verify the subcloud is in the correct initial sync state
        subcloud = db_api.subcloud_get(self.ctx, "subcloud1")
        self.assertEqual(subcloud.initial_sync_state, consts.INITIAL_SYNC_STATE_NONE)

    def test_initial_sync_subclouds(self):
        subcloud1 = utils.create_subcloud_static(
            self.ctx,
            name="subcloud1",
            initial_sync_state="",
            management_ip="192.168.1.11",
        )
        subcloud2 = utils.create_subcloud_static(
            self.ctx,
            name="subcloud2",
            initial_sync_state="",
            management_ip="192.168.1.12",
        )
        subcloud_capabilities = {
            subcloud1.region_name: (
                base.CAPABILITIES,
                subcloud1.management_ip,
                subcloud1.software_version,
                False,
            ),
            subcloud2.region_name: (
                base.CAPABILITIES,
                subcloud2.management_ip,
                subcloud2.software_version,
                False,
            ),
        }

        self.iswm.initial_sync_subclouds(self.ctx, subcloud_capabilities)

        # Verify 2 threads started, one for each of the subcloud
        self.mock_thread_start.assert_any_call(
            self.iswm._initial_sync_subcloud,
            mock.ANY,
            subcloud1.region_name,
            base.CAPABILITIES,
            subcloud1.management_ip,
            subcloud1.software_version,
            False,
        )
        self.mock_thread_start.assert_called_with(
            self.iswm._initial_sync_subcloud,
            mock.ANY,
            subcloud2.region_name,
            base.CAPABILITIES,
            subcloud2.management_ip,
            subcloud2.software_version,
            False,
        )
