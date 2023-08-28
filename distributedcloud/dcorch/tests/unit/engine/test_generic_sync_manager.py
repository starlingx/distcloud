# Copyright (c) 2020-2022, 2024 Wind River Systems, Inc.
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
from oslo_utils import uuidutils

from dccommon import consts as dccommon_consts
from dcorch.common import consts
from dcorch.common import exceptions
from dcorch.db.sqlalchemy import api as db_api
from dcorch.engine import generic_sync_manager
from dcorch.engine.sync_services import sysinv
from dcorch.tests import base


class FakeSyncThread(object):
    def __init__(self):
        self.start = mock.MagicMock()


class TestGenericSyncManager(base.OrchestratorTestCase):
    def setUp(self):
        super(TestGenericSyncManager, self).setUp()
        self.engine_id = uuidutils.generate_uuid()

        # Mock the sysinv sync methods
        self.fake_sync_thread_sysinv = FakeSyncThread()
        p = mock.patch.object(sysinv, 'SysinvSyncThread')
        self.mock_sync_service_sysinv = p.start()
        self.mock_sync_service_sysinv.return_value = self.fake_sync_thread_sysinv
        self.addCleanup(p.stop)

    @staticmethod
    def create_subcloud_static(ctxt, name, **kwargs):
        values = {
            'software_version': '10.04',
            'management_state': dccommon_consts.MANAGEMENT_MANAGED,
            'availability_status': dccommon_consts.AVAILABILITY_ONLINE,
            'initial_sync_state': '',
            'capabilities': {},
        }
        values.update(kwargs)
        return db_api.subcloud_create(ctxt, name, values=values)

    def test_init(self):
        gsm = generic_sync_manager.GenericSyncManager(self.engine_id)
        self.assertIsNotNone(gsm)

    def test_init_from_db(self):

        self.create_subcloud_static(
            self.ctx,
            name='subcloud1')
        self.create_subcloud_static(
            self.ctx,
            name='subcloud2')
        self.create_subcloud_static(
            self.ctx,
            name='subcloud3')

        gsm = generic_sync_manager.GenericSyncManager(self.engine_id)

        # Initialize from the DB
        gsm.init_from_db(self.ctx)

        # Verify the engines were created
        self.assertEqual(gsm.sync_objs['subcloud1'], {})
        self.assertEqual(gsm.sync_objs['subcloud2'], {})
        self.assertEqual(gsm.sync_objs['subcloud3'], {})

    def test_subcloud_state_matches(self):

        self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            initial_sync_state=consts.INITIAL_SYNC_STATE_REQUESTED)

        gsm = generic_sync_manager.GenericSyncManager(self.engine_id)

        # Initialize from the DB
        gsm.init_from_db(self.ctx)

        # Compare all states (match)
        match = gsm.subcloud_state_matches(
            'subcloud1',
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            initial_sync_state=consts.INITIAL_SYNC_STATE_REQUESTED)
        self.assertTrue(match)

        # Compare all states (not a match)
        match = gsm.subcloud_state_matches(
            'subcloud1',
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            availability_status=dccommon_consts.AVAILABILITY_OFFLINE,
            initial_sync_state=consts.INITIAL_SYNC_STATE_REQUESTED)
        self.assertFalse(match)

        # Compare one state (match)
        match = gsm.subcloud_state_matches(
            'subcloud1',
            availability_status=dccommon_consts.AVAILABILITY_ONLINE)
        self.assertTrue(match)

        # Compare one state (not a match)
        match = gsm.subcloud_state_matches(
            'subcloud1',
            initial_sync_state='')
        self.assertFalse(match)

    def test_subcloud_state_matches_missing(self):

        self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            initial_sync_state=consts.INITIAL_SYNC_STATE_REQUESTED)

        gsm = generic_sync_manager.GenericSyncManager(self.engine_id)

        # Initialize from the DB
        gsm.init_from_db(self.ctx)

        # Compare all states for missing subcloud
        self.assertRaises(
            exceptions.SubcloudNotFound,
            gsm.subcloud_state_matches,
            'subcloud2',
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            initial_sync_state=consts.INITIAL_SYNC_STATE_REQUESTED)

    def test_update_subcloud_state(self):

        self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            initial_sync_state=consts.INITIAL_SYNC_STATE_REQUESTED)

        gsm = generic_sync_manager.GenericSyncManager(self.engine_id)

        # Initialize from the DB
        gsm.init_from_db(self.ctx)

        # Update all states
        gsm.update_subcloud_state(
            'subcloud1',
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
            availability_status=dccommon_consts.AVAILABILITY_OFFLINE,
            initial_sync_state=consts.INITIAL_SYNC_STATE_COMPLETED)

        # Compare all states (match)
        match = gsm.subcloud_state_matches(
            'subcloud1',
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
            availability_status=dccommon_consts.AVAILABILITY_OFFLINE,
            initial_sync_state=consts.INITIAL_SYNC_STATE_COMPLETED)
        self.assertTrue(match)

        # Update one state
        gsm.update_subcloud_state(
            'subcloud1',
            availability_status=dccommon_consts.AVAILABILITY_ONLINE)

        # Compare all states (match)
        match = gsm.subcloud_state_matches(
            'subcloud1',
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            initial_sync_state=consts.INITIAL_SYNC_STATE_COMPLETED)
        self.assertTrue(match)

    def test_update_subcloud_state_missing(self):

        self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            initial_sync_state=consts.INITIAL_SYNC_STATE_REQUESTED)

        gsm = generic_sync_manager.GenericSyncManager(self.engine_id)

        # Initialize from the DB
        gsm.init_from_db(self.ctx)

        # Update all states for missing subcloud
        self.assertRaises(
            exceptions.SubcloudNotFound,
            gsm.update_subcloud_state,
            'subcloud2',
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            initial_sync_state=consts.INITIAL_SYNC_STATE_REQUESTED)
