# Copyright (c) 2017-2024 Wind River Systems, Inc.
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
from dcmanager.db.sqlalchemy import api as db_api
from dcmanager.orchestrator.states.base import BaseState
from dcmanager.orchestrator import sw_update_manager
from dcmanager.tests import base
from dcmanager.tests.unit.common import fake_strategy
from dcmanager.tests.unit.common import fake_subcloud
from dcmanager.tests.unit.fakes import FakeVimClient
from dcmanager.tests.unit.orchestrator.states.fakes import FakeFmClient
from dcmanager.tests.unit.orchestrator.states.fakes import FakeKeystoneClient
from dcmanager.tests.unit.orchestrator.states.fakes import FakePatchingClient
from dcmanager.tests.unit.orchestrator.states.fakes import FakeSoftwareClient
from dcmanager.tests.unit.orchestrator.states.fakes import FakeSysinvClient
from dcmanager.tests.unit.orchestrator.test_sw_update_manager import FakeOrchThread

CONF = cfg.CONF


class TestSwUpdate(base.DCManagerTestCase):

    DEFAULT_STRATEGY_TYPE = consts.SW_UPDATE_TYPE_SOFTWARE

    def setUp(self):
        super().setUp()

        # construct an upgrade orch thread
        self.worker = self.setup_orch_worker(self.DEFAULT_STRATEGY_TYPE)

        # Mock the context
        mock_get_admin_context = self._mock_object(context, "get_admin_context")
        mock_get_admin_context.return_value = self.ctx

        # Mock the clients defined in the base state class
        self.keystone_client = FakeKeystoneClient()
        self.sysinv_client = FakeSysinvClient()
        self.software_client = FakeSoftwareClient()
        self.patching_client = FakePatchingClient()
        self.vim_client = FakeVimClient()
        self.fm_client = FakeFmClient()

        clients = {
            "get_keystone_client": self.keystone_client,
            "get_sysinv_client": self.sysinv_client,
            "get_software_client": self.software_client,
            "get_patching_client": self.patching_client,
            "get_vim_client": self.vim_client,
            "get_fm_client": self.fm_client,
        }

        for key, value in clients.items():
            mock_get_keystone_client = self._mock_object(BaseState, key)
            mock_get_keystone_client.return_value = value

    def setup_orch_worker(self, strategy_type):
        worker = None

        # There are many orch threads. Only one needs to be setup based on type
        if strategy_type == consts.SW_UPDATE_TYPE_SOFTWARE:
            sw_update_manager.SoftwareOrchThread.stopped = lambda x: False
            worker = sw_update_manager.SoftwareOrchThread(mock.Mock(), mock.Mock())
        else:
            # mock the software orch thread
            mock_software_orch_thread = self._mock_object(
                sw_update_manager, "SoftwareOrchThread"
            )
            mock_software_orch_thread.return_value = FakeOrchThread()

        if strategy_type == consts.SW_UPDATE_TYPE_PATCH:
            sw_update_manager.PatchOrchThread.stopped = lambda x: False
            worker = sw_update_manager.PatchOrchThread(mock.Mock(), mock.Mock())
        else:
            # mock the patch orch thread
            mock_sw_patch_orch_thread = self._mock_object(
                sw_update_manager, "PatchOrchThread"
            )
            mock_sw_patch_orch_thread.return_value = FakeOrchThread()

        if strategy_type == consts.SW_UPDATE_TYPE_FIRMWARE:
            sw_update_manager.FwUpdateOrchThread.stopped = lambda x: False
            worker = sw_update_manager.FwUpdateOrchThread(mock.Mock(), mock.Mock())
        else:
            # mock the firmware orch thread
            mock_fw_update_orch_thread = self._mock_object(
                sw_update_manager, "FwUpdateOrchThread"
            )
            mock_fw_update_orch_thread.return_value = FakeOrchThread()

        if strategy_type == consts.SW_UPDATE_TYPE_KUBERNETES:
            sw_update_manager.KubeUpgradeOrchThread.stopped = lambda x: False
            worker = sw_update_manager.KubeUpgradeOrchThread(mock.Mock(), mock.Mock())
        else:
            # mock the kube upgrade orch thread
            mock_kube_upgrade_orch_thread = self._mock_object(
                sw_update_manager, "KubeUpgradeOrchThread"
            )
            mock_kube_upgrade_orch_thread.return_value = FakeOrchThread()

        if strategy_type == consts.SW_UPDATE_TYPE_KUBE_ROOTCA_UPDATE:
            sw_update_manager.KubeRootcaUpdateOrchThread.stopped = lambda x: False
            worker = sw_update_manager.KubeRootcaUpdateOrchThread(
                mock.Mock(), mock.Mock()
            )
        else:
            # mock the kube rootca update orch thread
            mock_kube_rootca_update_orch_thread = self._mock_object(
                sw_update_manager, "KubeRootcaUpdateOrchThread"
            )
            mock_kube_rootca_update_orch_thread.return_value = FakeOrchThread()

        if strategy_type == consts.SW_UPDATE_TYPE_PRESTAGE:
            sw_update_manager.PrestageOrchThread.stopped = lambda x: False
            worker = sw_update_manager.PrestageOrchThread(mock.Mock(), mock.Mock())
        else:
            # mock the prestage orch thread
            mock_prestage_orch_thread = self._mock_object(
                sw_update_manager, "PrestageOrchThread"
            )
            mock_prestage_orch_thread.return_value = FakeOrchThread()

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
        step = db_api.strategy_step_get(self.ctx, subcloud_id)
        self.assertEqual(update_state, step.state)

    def assert_step_details(self, subcloud_id, details):
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
