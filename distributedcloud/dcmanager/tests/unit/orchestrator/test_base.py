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
from oslo_config import cfg

from dccommon import consts as dccommon_consts
from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common.scheduler import ThreadGroupManager
from dcmanager.db import api as db_api
from dcmanager.orchestrator import orchestrator_worker
from dcmanager.orchestrator.states.base import BaseState
from dcmanager.tests import base
from dcmanager.tests.unit.common import fake_strategy
from dcmanager.tests.unit.common import fake_subcloud
from dcmanager.tests.unit.fakes import FakeVimClient
from dcmanager.tests.unit.orchestrator.states.fakes import FakeFmClient
from dcmanager.tests.unit.orchestrator.states.fakes import FakeKeystoneClient
from dcmanager.tests.unit.orchestrator.states.fakes import FakeSoftwareClient
from dcmanager.tests.unit.orchestrator.states.fakes import FakeSysinvClient

CONF = cfg.CONF


class TestSwUpdate(base.DCManagerTestCase):

    DEFAULT_STRATEGY_TYPE = consts.SW_UPDATE_TYPE_SOFTWARE

    def setUp(self):
        super().setUp()

        # Mock the context
        mock_get_admin_context = self._mock_object(context, "get_admin_context")
        mock_get_admin_context.return_value = self.ctx

        self._mock_object(ThreadGroupManager, "start")
        self._mock_object(orchestrator_worker, "ManagerOrchestratorClient")

        # Mock the clients defined in the base state class
        self.keystone_client = FakeKeystoneClient()
        self.sysinv_client = FakeSysinvClient()
        self.software_client = FakeSoftwareClient()
        self.vim_client = FakeVimClient()
        self.fm_client = FakeFmClient()

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
        self.worker = self.setup_orch_worker(self.DEFAULT_STRATEGY_TYPE)

    def setup_orch_worker(self, strategy_type):
        worker = orchestrator_worker.OrchestratorWorker()

        # sw_update_manager.SoftwareOrchThread.stopped = lambda x: False
        # mock the software orch thread

        return worker

    def setup_subcloud(self, deploy_status=consts.DEPLOY_STATE_INSTALLED):
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

    def delete_subcloud(self, subcloud_id):
        return db_api.subcloud_destroy(self.ctx, subcloud_id)

    def setup_strategy_step(self, subcloud_id, strategy_state):
        fake_strategy.create_fake_strategy_step(
            self.ctx, subcloud_id=subcloud_id, state=strategy_state
        )
        return db_api.strategy_step_get(self.ctx, subcloud_id)

    def clean_strategy_steps(self):
        return db_api.strategy_step_destroy_all(self.ctx)

    def assert_step_updated(self, subcloud_id, update_state):
        self.worker._bulk_update_subcloud_and_strategy_steps()
        step = db_api.strategy_step_get(self.ctx, subcloud_id)
        self.assertEqual(update_state, step.state)

    def assert_step_details(self, subcloud_id, details):
        self.worker._bulk_update_subcloud_and_strategy_steps()
        step = db_api.strategy_step_get(self.ctx, subcloud_id)
        self.assertEqual(details, step.details)

    # utility methods to help assert the value of any subcloud attribute
    def assert_subcloud_attribute(self, subcloud_id, attr_name, expected_val):
        subcloud = db_api.subcloud_get(self.ctx, subcloud_id)
        self.assertEqual(expected_val, subcloud[attr_name])

    def assert_subcloud_software_version(self, subcloud_id, expected_val):
        self.assert_subcloud_attribute(subcloud_id, "software_version", expected_val)

    def assert_subcloud_deploy_status(self, subcloud_id, expected_val):
        self.assert_subcloud_attribute(subcloud_id, "deploy_status", expected_val)
