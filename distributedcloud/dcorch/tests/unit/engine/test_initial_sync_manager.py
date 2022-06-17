# Copyright (c) 2020-2022 Wind River Systems, Inc.
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

import mock

from dccommon import consts as dccommon_consts
from dcorch.common import consts
from dcorch.db.sqlalchemy import api as db_api
from dcorch.engine import initial_sync_manager

from dcorch.tests import base
from oslo_utils import uuidutils


class FakeGSM(object):
    def __init__(self, ctx):
        self.ctx = ctx
        self.initial_sync = mock.MagicMock()
        self.enable_subcloud = mock.MagicMock()
        self.init_subcloud_sync_audit = mock.MagicMock()

    def update_subcloud_state(self, name, initial_sync_state):
        db_api.subcloud_update(
            self.ctx,
            name,
            values={'initial_sync_state': initial_sync_state})

    def subcloud_state_matches(self, name, initial_sync_state):
        subcloud = db_api.subcloud_get(self.ctx, name)
        return subcloud.initial_sync_state == initial_sync_state


class FakeFKM(object):
    def __init__(self):
        self.distribute_keys = mock.MagicMock()


class TestInitialSyncManager(base.OrchestratorTestCase):
    def setUp(self):
        super(TestInitialSyncManager, self).setUp()
        self.engine_id = uuidutils.generate_uuid()

        # Mock eventlet
        p = mock.patch('eventlet.greenthread.spawn_after')
        self.mock_eventlet_spawn_after = p.start()
        self.addCleanup(p.stop)

        # Mock the context
        p = mock.patch.object(initial_sync_manager, 'context')
        self.mock_context = p.start()
        self.mock_context.get_admin_context.return_value = self.ctx
        self.addCleanup(p.stop)

        # Mock the GSM and FKM
        self.fake_gsm = FakeGSM(self.ctx)
        self.fake_fkm = FakeFKM()

    @staticmethod
    def create_subcloud_static(ctxt, name, **kwargs):
        values = {
            'software_version': '10.04',
            'availability_status': dccommon_consts.AVAILABILITY_ONLINE,
        }
        values.update(kwargs)
        return db_api.subcloud_create(ctxt, name, values=values)

    def test_init(self):
        ism = initial_sync_manager.InitialSyncManager(self.fake_gsm,
                                                      self.fake_fkm)
        self.assertIsNotNone(ism)
        self.assertEqual(self.ctx, ism.context)

    def test_init_actions(self):

        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            initial_sync_state=consts.INITIAL_SYNC_STATE_NONE)
        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud2',
            initial_sync_state=consts.INITIAL_SYNC_STATE_IN_PROGRESS)
        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud3',
            initial_sync_state=consts.INITIAL_SYNC_STATE_FAILED)
        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud4',
            initial_sync_state=consts.INITIAL_SYNC_STATE_REQUESTED)

        ism = initial_sync_manager.InitialSyncManager(self.fake_gsm,
                                                      self.fake_fkm)

        # Perform init actions
        ism.init_actions(self.engine_id)

        # Verify the subclouds are in the correct initial sync state
        subcloud = db_api.subcloud_get(self.ctx, 'subcloud1')
        self.assertEqual(subcloud.initial_sync_state,
                         consts.INITIAL_SYNC_STATE_NONE)
        subcloud = db_api.subcloud_get(self.ctx, 'subcloud2')
        self.assertEqual(subcloud.initial_sync_state,
                         consts.INITIAL_SYNC_STATE_REQUESTED)
        subcloud = db_api.subcloud_get(self.ctx, 'subcloud3')
        self.assertEqual(subcloud.initial_sync_state,
                         consts.INITIAL_SYNC_STATE_REQUESTED)
        subcloud = db_api.subcloud_get(self.ctx, 'subcloud4')
        self.assertEqual(subcloud.initial_sync_state,
                         consts.INITIAL_SYNC_STATE_REQUESTED)

    def test_initial_sync_subcloud(self):

        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            initial_sync_state=consts.INITIAL_SYNC_STATE_REQUESTED)
        self.assertIsNotNone(subcloud)

        ism = initial_sync_manager.InitialSyncManager(self.fake_gsm,
                                                      self.fake_fkm)

        # Initial sync the subcloud
        ism._initial_sync_subcloud(self.ctx,
                                   self.engine_id,
                                   subcloud.region_name, None, None)

        # Verify that the initial sync steps were done
        self.fake_gsm.initial_sync.assert_called_with(self.ctx,
                                                      subcloud.region_name)
        self.fake_fkm.distribute_keys.assert_called_with(self.ctx,
                                                         subcloud.region_name)

        # Verify that the subcloud was enabled
        self.fake_gsm.enable_subcloud.assert_called_with(self.ctx,
                                                         subcloud.region_name)

        # Verify the initial sync was completed
        subcloud = db_api.subcloud_get(self.ctx, 'subcloud1')
        self.assertEqual(subcloud.initial_sync_state,
                         consts.INITIAL_SYNC_STATE_COMPLETED)

    def test_initial_sync_subcloud_not_required(self):

        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            initial_sync_state='')
        self.assertIsNotNone(subcloud)

        ism = initial_sync_manager.InitialSyncManager(self.fake_gsm,
                                                      self.fake_fkm)

        # Initial sync the subcloud
        ism._initial_sync_subcloud(self.ctx,
                                   self.engine_id,
                                   subcloud.region_name, None, None)

        # Verify that the initial sync steps were not done
        self.fake_gsm.initial_sync.assert_not_called()

        # Verify the initial sync state was not changed
        subcloud = db_api.subcloud_get(self.ctx, 'subcloud1')
        self.assertEqual(subcloud.initial_sync_state, '')

    def test_initial_sync_subcloud_failed(self):

        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            initial_sync_state=consts.INITIAL_SYNC_STATE_REQUESTED)
        self.assertIsNotNone(subcloud)

        ism = initial_sync_manager.InitialSyncManager(self.fake_gsm,
                                                      self.fake_fkm)

        # Force a failure
        self.fake_gsm.initial_sync.side_effect = Exception('fake_exception')

        # Initial sync the subcloud
        ism._initial_sync_subcloud(self.ctx,
                                   self.engine_id,
                                   subcloud.region_name, None, None)

        # Verify the initial sync was failed
        subcloud = db_api.subcloud_get(self.ctx, 'subcloud1')
        self.assertEqual(subcloud.initial_sync_state,
                         consts.INITIAL_SYNC_STATE_FAILED)

        # Verify that the subcloud was not enabled
        self.fake_gsm.enable_subcloud.assert_not_called()

        # Verify the initial sync was retried
        self.mock_eventlet_spawn_after.assert_called_with(
            initial_sync_manager.SYNC_FAIL_HOLD_OFF, mock.ANY, 'subcloud1')

    def test_reattempt_sync(self):

        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            initial_sync_state=consts.INITIAL_SYNC_STATE_NONE)
        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud2',
            initial_sync_state=consts.INITIAL_SYNC_STATE_FAILED)

        ism = initial_sync_manager.InitialSyncManager(self.fake_gsm,
                                                      self.fake_fkm)

        # Reattempt sync success
        ism._reattempt_sync('subcloud2')

        # Verify the subcloud is in the correct initial sync state
        subcloud = db_api.subcloud_get(self.ctx, 'subcloud2')
        self.assertEqual(subcloud.initial_sync_state,
                         consts.INITIAL_SYNC_STATE_REQUESTED)

        # Reattempt sync when not needed
        ism._reattempt_sync('subcloud1')

        # Verify the subcloud is in the correct initial sync state
        subcloud = db_api.subcloud_get(self.ctx, 'subcloud1')
        self.assertEqual(subcloud.initial_sync_state,
                         consts.INITIAL_SYNC_STATE_NONE)
