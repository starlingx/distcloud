# Copyright (c) 2017-2025 Wind River Systems, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
import mock

from oslo_config import cfg

from dccommon import consts as dccommon_consts
from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common.scheduler import ThreadGroupManager
from dcmanager.db import api as db_api
from dcmanager.orchestrator import orchestrator_worker
from dcmanager.orchestrator.states.base import BaseState
from dcmanager.tests.base import DCManagerTestCase
from dcmanager.tests.unit.common import fake_strategy
from dcmanager.tests.unit.common import fake_subcloud

CONF = cfg.CONF


class TestSwUpdate(DCManagerTestCase):
    def setUp(self):
        super().setUp()

        self.strategy_step = None
        self.strategy_type = consts.SW_UPDATE_TYPE_SOFTWARE

        # Mock the context
        mock_get_admin_context = self._mock_object(context, "get_admin_context")
        mock_get_admin_context.return_value = self.ctx

        self._mock_object(ThreadGroupManager, "start")
        self._mock_object(orchestrator_worker, "ManagerOrchestratorClient")

        # Mock the clients defined in the base state class
        self.keystone_client = mock.MagicMock()
        self.sysinv_client = mock.MagicMock()
        self.software_client = mock.MagicMock()
        self.vim_client = mock.MagicMock()
        self.fm_client = mock.MagicMock()

        self.snapshot_supported_version = mock.patch.object(
            consts, "SNAPSHOT_SUPPORTED_VERSION", "10.10"
        )
        self.mock_snapshot_supported_version = self.snapshot_supported_version.start()
        self.addCleanup(self.snapshot_supported_version.stop)

        clients = {
            "get_keystone_client": self.keystone_client,
            "get_sysinv_client": self.sysinv_client,
            "get_software_client": self.software_client,
            "get_vim_client": self.vim_client,
            "get_fm_client": self.fm_client,
        }

        for key, value in clients.items():
            mock_get_keystone_client = self._mock_object(BaseState, key)
            mock_get_keystone_client.return_value = value

        # construct an upgrade orch thread
        self.worker = self.setup_orch_worker()

        self.subcloud = self._setup_subcloud()

    def setup_orch_worker(self):
        # mock the software orch thread
        return orchestrator_worker.OrchestratorWorker()

    def _setup_subcloud(self, deploy_status=consts.DEPLOY_STATE_INSTALLED):
        subcloud_id = fake_subcloud.create_fake_subcloud(
            self.ctx,
            deploy_status=deploy_status,
        ).id
        return db_api.subcloud_update(
            self.ctx,
            subcloud_id,
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
        )

    def _setup_and_assert(self, next_state):
        # invoke the strategy state operation on the orch thread
        self.worker._perform_state_action(
            self.strategy_type, self.subcloud.region_name, self.strategy_step
        )

        # Verify the transition to the expected next state
        self.assert_step_updated(self.strategy_step.subcloud_id, next_state)

    def _assert_error(self, error_message):
        strategy_step = db_api.strategy_step_get(self.ctx, self.subcloud.id)
        self.assertEqual(error_message, strategy_step.details)

    def setup_strategy_step(self, subcloud_id, strategy_state):
        fake_strategy.create_fake_strategy_step(
            self.ctx, subcloud_id=subcloud_id, state=strategy_state
        )
        return db_api.strategy_step_get(self.ctx, subcloud_id)

    def assert_step_updated(self, subcloud_id, update_state):
        self.worker._bulk_update_subcloud_and_strategy_steps()
        step = db_api.strategy_step_get(self.ctx, subcloud_id)
        self.assertEqual(update_state, step.state)
