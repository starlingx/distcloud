# Copyright (c) 2020-2022, 2024-2025 Wind River Systems, Inc.
# All Rights Reserved.
#
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

import math
import mock
from oslo_config import cfg

from dcorch.common import consts
from dcorch.db import api as db_api
from dcorch.engine import initial_sync_manager
from dcorch.rpc import client
from dcorch.tests import base
from dcorch.tests import utils

CONF = cfg.CONF


class TestInitialSyncManager(base.OrchestratorTestCase):
    def setUp(self):
        super().setUp()

        # Mock the DCorch engine-worker API client
        self.mock_rpc_client = self._mock_object(client, "EngineWorkerClient")

    def test_init(self):
        ism = initial_sync_manager.InitialSyncManager()
        self.assertIsNotNone(ism)

    def test_init_actions(self):
        utils.create_subcloud_static(
            self.ctx,
            name="subcloud1",
            initial_sync_state=consts.INITIAL_SYNC_STATE_NONE,
        )
        utils.create_subcloud_static(
            self.ctx,
            name="subcloud2",
            initial_sync_state=consts.INITIAL_SYNC_STATE_IN_PROGRESS,
        )
        utils.create_subcloud_static(
            self.ctx,
            name="subcloud3",
            initial_sync_state=consts.INITIAL_SYNC_STATE_FAILED,
        )
        utils.create_subcloud_static(
            self.ctx,
            name="subcloud4",
            initial_sync_state=consts.INITIAL_SYNC_STATE_REQUESTED,
        )
        utils.create_subcloud_static(
            self.ctx,
            name="subcloud5",
            initial_sync_state=consts.INITIAL_SYNC_STATE_IN_PROGRESS,
        )

        ism = initial_sync_manager.InitialSyncManager()

        # Perform init actions
        ism.init_actions()

        # Verify the subclouds are in the correct initial sync state
        subcloud = db_api.subcloud_get(self.ctx, "subcloud1")
        self.assertEqual(subcloud.initial_sync_state, consts.INITIAL_SYNC_STATE_NONE)
        subcloud = db_api.subcloud_get(self.ctx, "subcloud2")
        self.assertEqual(
            subcloud.initial_sync_state, consts.INITIAL_SYNC_STATE_REQUESTED
        )
        subcloud = db_api.subcloud_get(self.ctx, "subcloud3")
        self.assertEqual(
            subcloud.initial_sync_state, consts.INITIAL_SYNC_STATE_REQUESTED
        )
        subcloud = db_api.subcloud_get(self.ctx, "subcloud4")
        self.assertEqual(
            subcloud.initial_sync_state, consts.INITIAL_SYNC_STATE_REQUESTED
        )
        subcloud = db_api.subcloud_get(self.ctx, "subcloud5")
        self.assertEqual(
            subcloud.initial_sync_state, consts.INITIAL_SYNC_STATE_REQUESTED
        )

    def test_initial_sync_subclouds(self):
        # Create subcloud1 not eligible for initial sync due to initial_sync_state
        utils.create_subcloud_static(
            self.ctx,
            name="subcloud1",
            initial_sync_state=consts.INITIAL_SYNC_STATE_IN_PROGRESS,
        )
        chunks = list()
        chunk_num = -1
        # Create 21 eligible subclouds
        for i in range(2, 23):
            if (i - 1) % CONF.workers == 1:
                chunk_num += 1
                chunks.insert(chunk_num, dict())
            subcloud = utils.create_subcloud_static(
                self.ctx,
                name="subcloud" + str(i),
                initial_sync_state=consts.INITIAL_SYNC_STATE_REQUESTED,
                management_ip="192.168.1." + str(i),
            )
            chunks[chunk_num][subcloud.region_name] = (
                base.CAPABILITIES,
                subcloud.management_ip,
                subcloud.software_version,
                subcloud.id,
                False,
            )

        ism = initial_sync_manager.InitialSyncManager()

        # Perform initial sync for subclouds
        ism._initial_sync_subclouds()

        # Verify the number of chunks
        self.assertEqual(math.ceil(21 / CONF.workers), len(chunks))
        # Verify a thread started for each chunk of subclouds
        for chunk in chunks:
            self.mock_rpc_client().initial_sync_subclouds.assert_any_call(
                mock.ANY, chunk
            )
