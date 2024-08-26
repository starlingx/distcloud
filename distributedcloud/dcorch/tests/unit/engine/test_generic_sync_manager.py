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

from datetime import timedelta
import math
import mock
from oslo_config import cfg
from oslo_utils import timeutils

from dccommon import consts as dccommon_consts
from dcorch.common import consts
from dcorch.db.sqlalchemy import api as db_api
from dcorch.engine import generic_sync_manager
from dcorch.tests import base
from dcorch.tests import utils

CONF = cfg.CONF


class TestGenericSyncManager(base.OrchestratorTestCase):
    def setUp(self):
        super(TestGenericSyncManager, self).setUp()

        # Mock the DCorch engine-worker API client
        p = mock.patch("dcorch.rpc.client.EngineWorkerClient")
        self.mock_dcorch_api = p.start()
        self.addCleanup(p.stop)

    def test_init(self):
        gsm = generic_sync_manager.GenericSyncManager()
        self.assertIsNotNone(gsm)

    def test_process_subclouds(self):
        # Create a list including 22 (subcloud, endpoint_type) pairs and
        # distribute them into chunks based on the number of workers.
        subcloud_sync_list = list()
        chunks = list()
        chunk_num = -1
        for i in range(1, 23):
            region_name = "subcloud" + str(i)
            subcloud_sync_identity = (
                region_name,
                dccommon_consts.ENDPOINT_TYPE_IDENTITY,
            )
            subcloud_sync_list.append(subcloud_sync_identity)
            if (i - 1) % CONF.workers == 0:
                chunk_num += 1
                chunks.insert(chunk_num, list())
            chunks[chunk_num].append(subcloud_sync_identity)

        gsm = generic_sync_manager.GenericSyncManager()

        rpc_method = mock.MagicMock()
        rpc_method.__name__ = "mock_rpc_method"
        gsm._process_subclouds(rpc_method, subcloud_sync_list)

        # Verify the number of chunks
        self.assertEqual(math.ceil(len(subcloud_sync_list) / CONF.workers), len(chunks))
        # Verify rpc call for each chunk of subclouds
        for chunk in chunks:
            rpc_method.assert_any_call(mock.ANY, chunk)

    def test_sync_subclouds(self):
        # Create subcloud1 not eligible for sync due to initial_sync_state
        utils.create_subcloud_static(
            self.ctx,
            name="subcloud1",
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            initial_sync_state=consts.INITIAL_SYNC_STATE_FAILED,
        )
        utils.create_subcloud_sync_static(
            self.ctx,
            name="subcloud1",
            endpoint_type=dccommon_consts.ENDPOINT_TYPE_IDENTITY,
            sync_request=consts.SYNC_STATUS_REQUESTED,
        )
        utils.create_subcloud_sync_static(
            self.ctx,
            name="subcloud1",
            endpoint_type=dccommon_consts.ENDPOINT_TYPE_PLATFORM,
            sync_request=consts.SYNC_STATUS_REQUESTED,
        )
        # Create subcloud2 not eligible for sync due to sync_request
        utils.create_subcloud_static(
            self.ctx,
            name="subcloud2",
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            initial_sync_state=consts.INITIAL_SYNC_STATE_COMPLETED,
        )
        utils.create_subcloud_sync_static(
            self.ctx,
            name="subcloud2",
            endpoint_type=dccommon_consts.ENDPOINT_TYPE_IDENTITY,
            sync_request=consts.SYNC_STATUS_IN_PROGRESS,
        )
        utils.create_subcloud_sync_static(
            self.ctx,
            name="subcloud2",
            endpoint_type=dccommon_consts.ENDPOINT_TYPE_PLATFORM,
            sync_request=consts.SYNC_STATUS_IN_PROGRESS,
        )
        # Create 22 eligible subclouds
        subcloud_sync_list = []
        for i in range(3, 25):
            subcloud = utils.create_subcloud_static(
                self.ctx,
                name="subcloud" + str(i),
                management_state=dccommon_consts.MANAGEMENT_MANAGED,
                availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                initial_sync_state=consts.INITIAL_SYNC_STATE_COMPLETED,
                management_ip="10.10.10." + str(i),
            )
            utils.create_subcloud_sync_static(
                self.ctx,
                name="subcloud" + str(i),
                endpoint_type=dccommon_consts.ENDPOINT_TYPE_IDENTITY,
                sync_request="requested",
            )
            subcloud_sync_list.append(
                (
                    subcloud.region_name,
                    dccommon_consts.ENDPOINT_TYPE_IDENTITY,
                    subcloud.management_ip,
                    subcloud.software_version,
                )
            )
            utils.create_subcloud_sync_static(
                self.ctx,
                name="subcloud" + str(i),
                endpoint_type=dccommon_consts.ENDPOINT_TYPE_PLATFORM,
                sync_request="requested",
            )
            subcloud_sync_list.append(
                (
                    subcloud.region_name,
                    dccommon_consts.ENDPOINT_TYPE_PLATFORM,
                    subcloud.management_ip,
                    subcloud.software_version,
                )
            )

        gsm = generic_sync_manager.GenericSyncManager()
        gsm._process_subclouds = mock.MagicMock()
        gsm.sync_subclouds()

        gsm._process_subclouds.assert_called_once_with(
            self.mock_dcorch_api().sync_subclouds, subcloud_sync_list
        )

        # Verify the sync_request of the subclouds were updated to in-progress
        for i in range(3, 25):
            subcloud_sync_identity = db_api.subcloud_sync_get(
                self.ctx, "subcloud" + str(i), dccommon_consts.ENDPOINT_TYPE_IDENTITY
            )
            self.assertEqual(
                consts.SYNC_STATUS_IN_PROGRESS, subcloud_sync_identity.sync_request
            )
            subcloud_sync_platform = db_api.subcloud_sync_get(
                self.ctx, "subcloud" + str(i), dccommon_consts.ENDPOINT_TYPE_PLATFORM
            )
            self.assertEqual(
                consts.SYNC_STATUS_IN_PROGRESS, subcloud_sync_platform.sync_request
            )

    def test_run_sync_audit(self):
        # Create subcloud1 not eligible for audit due to initial_sync_state
        utils.create_subcloud_static(
            self.ctx,
            name="subcloud1",
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            initial_sync_state=consts.INITIAL_SYNC_STATE_FAILED,
        )
        utils.create_subcloud_sync_static(
            self.ctx,
            name="subcloud1",
            endpoint_type=dccommon_consts.ENDPOINT_TYPE_IDENTITY,
            audit_status=consts.AUDIT_STATUS_NONE,
        )
        utils.create_subcloud_sync_static(
            self.ctx,
            name="subcloud1",
            endpoint_type=dccommon_consts.ENDPOINT_TYPE_PLATFORM,
            audit_status=consts.AUDIT_STATUS_NONE,
        )
        # Create subcloud2 not eligible for audit due to management_state
        utils.create_subcloud_static(
            self.ctx,
            name="subcloud2",
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
        )
        utils.create_subcloud_sync_static(
            self.ctx,
            name="subcloud2",
            endpoint_type=dccommon_consts.ENDPOINT_TYPE_IDENTITY,
            audit_status=consts.AUDIT_STATUS_FAILED,
        )
        utils.create_subcloud_sync_static(
            self.ctx,
            name="subcloud2",
            endpoint_type=dccommon_consts.ENDPOINT_TYPE_PLATFORM,
            audit_status=consts.AUDIT_STATUS_FAILED,
        )
        # Create 22 eligible subclouds
        subcloud_sync_list = []
        for i in range(3, 25):
            subcloud = utils.create_subcloud_static(
                self.ctx,
                name="subcloud" + str(i),
                management_state=dccommon_consts.MANAGEMENT_MANAGED,
                availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                initial_sync_state=consts.INITIAL_SYNC_STATE_COMPLETED,
                management_ip="10.10.10." + str(i),
            )
            last_audit_time = timeutils.utcnow() - timedelta(
                seconds=generic_sync_manager.AUDIT_INTERVAL
            )
            utils.create_subcloud_sync_static(
                self.ctx,
                name="subcloud" + str(i),
                endpoint_type=dccommon_consts.ENDPOINT_TYPE_IDENTITY,
                audit_status=consts.AUDIT_STATUS_COMPLETED,
                last_audit_time=last_audit_time,
            )
            subcloud_sync_list.append(
                (
                    subcloud.region_name,
                    dccommon_consts.ENDPOINT_TYPE_IDENTITY,
                    subcloud.management_ip,
                    subcloud.software_version,
                )
            )
            utils.create_subcloud_sync_static(
                self.ctx,
                name="subcloud" + str(i),
                endpoint_type=dccommon_consts.ENDPOINT_TYPE_PLATFORM,
                audit_status=consts.AUDIT_STATUS_COMPLETED,
                last_audit_time=last_audit_time,
            )
            subcloud_sync_list.append(
                (
                    subcloud.region_name,
                    dccommon_consts.ENDPOINT_TYPE_PLATFORM,
                    subcloud.management_ip,
                    subcloud.software_version,
                )
            )

        gsm = generic_sync_manager.GenericSyncManager()
        gsm._process_subclouds = mock.MagicMock()
        gsm.run_sync_audit()

        gsm._process_subclouds.assert_called_once_with(
            self.mock_dcorch_api().run_sync_audit, subcloud_sync_list
        )

        # Verify the audit_status of the subclouds were updated to in-progress
        for i in range(3, 25):
            subcloud_sync_identity = db_api.subcloud_sync_get(
                self.ctx, "subcloud" + str(i), dccommon_consts.ENDPOINT_TYPE_IDENTITY
            )
            self.assertEqual(
                consts.AUDIT_STATUS_IN_PROGRESS, subcloud_sync_identity.audit_status
            )
            subcloud_sync_platform = db_api.subcloud_sync_get(
                self.ctx, "subcloud" + str(i), dccommon_consts.ENDPOINT_TYPE_PLATFORM
            )
            self.assertEqual(
                consts.AUDIT_STATUS_IN_PROGRESS, subcloud_sync_platform.audit_status
            )
