# Copyright (c) 2017-2022 Wind River Systems, Inc.
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
from dcmanager.tests.unit.orchestrator.states.fakes import FakeSysinvClient
from dcmanager.tests.unit.orchestrator.test_sw_update_manager import FakeOrchThread
from dcmanager.tests import utils

CONF = cfg.CONF


class TestSwUpdate(base.DCManagerTestCase):

    DEFAULT_STRATEGY_TYPE = consts.SW_UPDATE_TYPE_UPGRADE

    def setUp(self):
        super(TestSwUpdate, self).setUp()

        # construct an upgrade orch thread
        self.worker = self.setup_orch_worker(self.DEFAULT_STRATEGY_TYPE)

        # Mock the context
        self.ctxt = utils.dummy_context()
        p = mock.patch.object(context, 'get_admin_context')
        self.mock_get_admin_context = p.start()
        self.mock_get_admin_context.return_value = self.ctx
        self.addCleanup(p.stop)

        # Mock the keystone client defined in the base state class
        self.keystone_client = FakeKeystoneClient()
        p = mock.patch.object(BaseState, 'get_keystone_client')
        self.mock_keystone_client = p.start()
        self.mock_keystone_client.return_value = self.keystone_client
        self.addCleanup(p.stop)

        # Mock the sysinv client defined in the base state class
        self.sysinv_client = FakeSysinvClient()
        p = mock.patch.object(BaseState, 'get_sysinv_client')
        self.mock_sysinv_client = p.start()
        self.mock_sysinv_client.return_value = self.sysinv_client
        self.addCleanup(p.stop)

        # Mock the patching client defined in the base state class
        self.patching_client = FakePatchingClient()
        p = mock.patch.object(BaseState, 'get_patching_client')
        self.mock_patching_client = p.start()
        self.mock_patching_client.return_value = self.patching_client
        self.addCleanup(p.stop)

        # Mock the vim client defined in the base state class
        self.vim_client = FakeVimClient()
        p = mock.patch.object(BaseState, 'get_vim_client')
        self.mock_vim_client = p.start()
        self.mock_vim_client.return_value = self.vim_client
        self.addCleanup(p.stop)

        # Mock the fm client defined in the base state class
        self.fm_client = FakeFmClient()
        p = mock.patch.object(BaseState, 'get_fm_client')
        self.mock_fm_client = p.start()
        self.mock_fm_client.return_value = self.fm_client
        self.addCleanup(p.stop)

    def setup_orch_worker(self, strategy_type):
        worker = None
        mock_strategy_lock = mock.Mock()
        mock_dcmanager_audit_api = mock.Mock()
        # There are many orch threads. Only one needs to be setup based on type
        if strategy_type == consts.SW_UPDATE_TYPE_UPGRADE:
            sw_update_manager.SwUpgradeOrchThread.stopped = lambda x: False
            worker = \
                sw_update_manager.SwUpgradeOrchThread(mock_strategy_lock,
                                                      mock_dcmanager_audit_api)
        else:
            # mock the upgrade orch thread
            self.fake_sw_upgrade_orch_thread = FakeOrchThread()
            p = mock.patch.object(sw_update_manager, 'SwUpgradeOrchThread')
            self.mock_sw_upgrade_orch_thread = p.start()
            self.mock_sw_upgrade_orch_thread.return_value = \
                self.fake_sw_upgrade_orch_thread
            self.addCleanup(p.stop)

        if strategy_type == consts.SW_UPDATE_TYPE_PATCH:
            sw_update_manager.PatchOrchThread.stopped = lambda x: False
            worker = \
                sw_update_manager.PatchOrchThread(mock_strategy_lock,
                                                  mock_dcmanager_audit_api)
        else:
            # mock the patch orch thread
            self.fake_sw_patch_orch_thread = FakeOrchThread()
            p = mock.patch.object(sw_update_manager, 'PatchOrchThread')
            self.mock_sw_patch_orch_thread = p.start()
            self.mock_sw_patch_orch_thread.return_value = \
                self.fake_sw_patch_orch_thread
            self.addCleanup(p.stop)

        if strategy_type == consts.SW_UPDATE_TYPE_FIRMWARE:
            sw_update_manager.FwUpdateOrchThread.stopped = lambda x: False
            worker = \
                sw_update_manager.FwUpdateOrchThread(mock_strategy_lock,
                                                     mock_dcmanager_audit_api)
        else:
            # mock the firmware orch thread
            self.fake_fw_update_orch_thread = FakeOrchThread()
            p = mock.patch.object(sw_update_manager, 'FwUpdateOrchThread')
            self.mock_fw_update_orch_thread = p.start()
            self.mock_fw_update_orch_thread.return_value = \
                self.fake_fw_update_orch_thread
            self.addCleanup(p.stop)

        if strategy_type == consts.SW_UPDATE_TYPE_KUBERNETES:
            sw_update_manager.KubeUpgradeOrchThread.stopped = lambda x: False
            worker = sw_update_manager.KubeUpgradeOrchThread(
                mock_strategy_lock,
                mock_dcmanager_audit_api)
        else:
            # mock the kube upgrade orch thread
            self.fake_kube_upgrade_orch_thread = FakeOrchThread()
            p = mock.patch.object(sw_update_manager, 'KubeUpgradeOrchThread')
            self.mock_kube_upgrade_orch_thread = p.start()
            self.mock_kube_upgrade_orch_thread.return_value = \
                self.fake_kube_upgrade_orch_thread
            self.addCleanup(p.stop)

        if strategy_type == consts.SW_UPDATE_TYPE_KUBE_ROOTCA_UPDATE:
            sw_update_manager.KubeRootcaUpdateOrchThread.stopped = \
                lambda x: False
            worker = sw_update_manager.KubeRootcaUpdateOrchThread(
                mock_strategy_lock,
                mock_dcmanager_audit_api)
        else:
            # mock the kube rootca update orch thread
            self.fake_kube_rootca_update_orch_thread = FakeOrchThread()
            p = mock.patch.object(sw_update_manager,
                                  'KubeRootcaUpdateOrchThread')
            self.mock_kube_rootca_update_orch_thread = p.start()
            self.mock_kube_rootca_update_orch_thread.return_value = \
                self.fake_kube_rootca_update_orch_thread
            self.addCleanup(p.stop)

        if strategy_type == consts.SW_UPDATE_TYPE_PRESTAGE:
            sw_update_manager.PrestageOrchThread.stopped = lambda x: False
            worker = \
                sw_update_manager.PrestageOrchThread(mock_strategy_lock,
                                                     mock_dcmanager_audit_api)
        else:
            # mock the prestage orch thread
            self.fake_prestage_orch_thread = FakeOrchThread()
            p = mock.patch.object(sw_update_manager, 'PrestageOrchThread')
            self.mock_prestage_orch_thread = p.start()
            self.mock_prestage_orch_thread.return_value = \
                self.fake_prestage_orch_thread
            self.addCleanup(p.stop)

        return worker

    def setup_subcloud(self):
        subcloud_id = fake_subcloud.create_fake_subcloud(
            self.ctx,
            deploy_status=consts.DEPLOY_STATE_INSTALLED,
        ).id
        return db_api.subcloud_update(
            self.ctx,
            subcloud_id,
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE)

    def setup_strategy_step(self, strategy_state):
        fake_strategy.create_fake_strategy_step(
            self.ctx,
            subcloud_id=self.subcloud.id,
            state=strategy_state)
        return db_api.strategy_step_get(self.ctx, self.subcloud.id)

    def assert_step_updated(self, subcloud_id, update_state):
        step = db_api.strategy_step_get(self.ctx, subcloud_id)
        self.assertEqual(step.state, update_state)

    # utility methods to help assert the value of any subcloud attribute
    def assert_subcloud_attribute(self, subcloud_id, attr_name, expected_val):
        subcloud = db_api.subcloud_get(self.ctx, subcloud_id)
        self.assertEqual(subcloud[attr_name], expected_val)

    def assert_subcloud_software_version(self, subcloud_id, expected_val):
        self.assert_subcloud_attribute(subcloud_id,
                                       'software_version',
                                       expected_val)

    def assert_subcloud_deploy_status(self, subcloud_id, expected_val):
        self.assert_subcloud_attribute(subcloud_id,
                                       'deploy_status',
                                       expected_val)
