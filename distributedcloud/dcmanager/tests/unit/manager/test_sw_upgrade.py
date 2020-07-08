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
# Copyright (c) 2017-2020 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#
import copy
import mock

from oslo_config import cfg

from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.manager import sw_update_manager
from dcmanager.manager import sw_upgrade_orch_thread
from dcmanager.tests import base
from dcmanager.tests.unit.manager.test_sw_update_manager import FakeOrchThread
from dcmanager.tests.unit.manager.test_sw_update_manager \
    import StrategyStep
from dcmanager.tests.unit.manager.test_sw_update_manager \
    import Subcloud
from dcmanager.tests import utils

CONF = cfg.CONF
FAKE_ID = '1'
FAKE_SW_UPDATE_DATA = {
    "type": consts.SW_UPDATE_TYPE_PATCH,
    "subcloud-apply-type": consts.SUBCLOUD_APPLY_TYPE_PARALLEL,
    "max-parallel-subclouds": "2",
    "stop-on-failure": "true",
    "state": consts.SW_UPDATE_STATE_INITIAL
}

FAKE_STRATEGY_STEP_DATA = {
    "id": 1,
    "subcloud_id": 1,
    "stage": 1,
    "state": consts.STRATEGY_STATE_INITIAL,
    "details": '',
    "subcloud": None
}


class TestSwUpgrade(base.DCManagerTestCase):
    def setUp(self):
        super(TestSwUpgrade, self).setUp()

        # construct an upgrade orch thread
        self.worker = self.setup_upgrade_worker()

        # Mock the context
        self.ctxt = utils.dummy_context()
        p = mock.patch.object(context, 'get_admin_context')
        self.mock_get_admin_context = p.start()
        self.mock_get_admin_context.return_value = self.ctx
        self.addCleanup(p.stop)

        # Mock the patch thread. It is not used for any upgrade tests
        self.fake_patch_orch_thread = FakeOrchThread()
        p = mock.patch.object(sw_update_manager, 'PatchOrchThread')
        self.mock_patch_orch_thread = p.start()
        self.mock_patch_orch_thread.return_value = \
            self.fake_patch_orch_thread
        self.addCleanup(p.stop)

        # Mock db_api
        p = mock.patch.object(sw_upgrade_orch_thread, 'db_api')
        self.mock_db_api = p.start()
        self.addCleanup(p.stop)

    def setup_strategy_step(self, strategy_state):
        data = copy.copy(FAKE_STRATEGY_STEP_DATA)
        data['state'] = strategy_state
        data['subcloud'] = Subcloud(1,
                                    'subcloud1', 1,
                                    is_managed=True,
                                    is_online=True)
        fake_strategy_step = StrategyStep(**data)
        return fake_strategy_step

    def setup_upgrade_worker(self):
        sw_update_manager.SwUpgradeOrchThread.stopped = lambda x: False
        mock_strategy_lock = mock.Mock()
        mock_dcmanager_audit_api = mock.Mock()
        worker = sw_update_manager.SwUpgradeOrchThread(mock_strategy_lock,
                                                       mock_dcmanager_audit_api)
        return worker

    def assert_step_updated(self, subcloud_id, update_state):
        self.mock_db_api.strategy_step_update.assert_called_with(
            mock.ANY,
            subcloud_id,
            state=update_state,
            details=mock.ANY,
            started_at=mock.ANY,
            finished_at=mock.ANY,
        )
