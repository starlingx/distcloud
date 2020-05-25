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

MISSING_LICENSE_RESPONSE = {
    u'content': u'',
    u'error': u'License file not found. A license may not have been installed.'
}

LICENSE_VALID_RESPONSE = {
    u'content': u'A valid license',
    u'error': u''
}

ALTERNATE_LICENSE_RESPONSE = {
    u'content': u'A different valid license',
    u'error': u''
}


class FakeSysinvClient(object):

    def __init__(self):
        super(FakeSysinvClient, self).__init__()
        self.get_license = mock.MagicMock()
        self.install_license = mock.MagicMock()


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

        # Mock the sysinv client
        self.fake_sysinv_client = FakeSysinvClient()
        p = mock.patch.object(sw_upgrade_orch_thread.SwUpgradeOrchThread,
                              'get_sysinv_client')
        self.mock_sysinv_client = p.start()
        self.mock_sysinv_client.return_value = self.fake_sysinv_client
        self.addCleanup(p.stop)

        # Mock db_api
        p = mock.patch.object(sw_upgrade_orch_thread, 'db_api')
        self.mock_db_api = p.start()
        self.addCleanup(p.stop)

    def setup_strategy_step(self, strategy_state):
        data = copy.copy(FAKE_STRATEGY_STEP_DATA)
        data['state'] = strategy_state
        data['subcloud'] = Subcloud(1,
                                    'subcloud1',
                                    is_managed=True,
                                    is_online=True)
        fake_strategy_step = StrategyStep(**data)
        return fake_strategy_step

    def setup_upgrade_worker(self):
        sw_update_manager.SwUpgradeOrchThread.stopped = lambda x: False
        mock_strategy_lock = mock.Mock()
        worker = sw_update_manager.SwUpgradeOrchThread(mock_strategy_lock)
        worker.get_ks_client = mock.Mock()
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


class TestSwUpgradeLicenseStage(TestSwUpgrade):

    def setUp(self):
        super(TestSwUpgradeLicenseStage, self).setUp()
        self.strategy_step = \
            self.setup_strategy_step(consts.STRATEGY_STATE_INSTALLING_LICENSE)

    def test_upgrade_subcloud_license_install_failure(self):
        # Test the install subcloud license step where the system controller
        # license is valid, and the subcloud license install fails

        # Order of get_license calls:
        # first license query is to system controller
        # second license query is to subcloud (should be missing)
        self.fake_sysinv_client.get_license.side_effect = \
            [LICENSE_VALID_RESPONSE,
             MISSING_LICENSE_RESPONSE]

        # Simulate a license install failure on the subcloud
        self.fake_sysinv_client.install_license.return_value = \
            MISSING_LICENSE_RESPONSE

        self.worker.install_subcloud_license(self.strategy_step)

        # verify the license install was invoked
        self.fake_sysinv_client.install_license.assert_called()

        # Verify a install_license failure leads to a state failure
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_upgrade_subcloud_license_install_success(self):
        # Test the install subcloud license step where the system controller
        # license is valid, and the subcloud installation succeeds

        # Order of get_license calls:
        # first license query is to system controller
        # second license query is to subcloud (should be missing)
        self.fake_sysinv_client.get_license.side_effect = \
            [LICENSE_VALID_RESPONSE,
             MISSING_LICENSE_RESPONSE]

        # A license install should return a success
        self.fake_sysinv_client.install_license.return_value = \
            LICENSE_VALID_RESPONSE

        self.worker.install_subcloud_license(self.strategy_step)

        # verify the license install was invoked
        self.fake_sysinv_client.install_license.assert_called()

        # On success, the next state after installing license is importing load
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_IMPORTING_LOAD)

    def test_upgrade_subcloud_license_skip_existing(self):
        # Test the install subcloud license step where the system controller
        # license is valid, and the subcloud already has the same license

        # Order of get_license calls:
        # first license query is to system controller
        # second license query is to subcloud
        self.fake_sysinv_client.get_license.side_effect = \
            [LICENSE_VALID_RESPONSE,
             LICENSE_VALID_RESPONSE]
        self.worker.install_subcloud_license(self.strategy_step)

        # A license install should not have been attempted due to the license
        # already being up to date
        self.fake_sysinv_client.install_license.assert_not_called()
        # On success, the next state after installing license is importing load
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_IMPORTING_LOAD)

    def test_upgrade_subcloud_license_overrides_mismatched_license(self):
        # Test the install subcloud license step where the system controller
        # license is valid, and the subcloud has a differnt license which
        # should be overridden

        # Order of get_license calls:
        # first license query is to system controller
        # second license query is to subcloud (should be valid but different)
        self.fake_sysinv_client.get_license.side_effect = \
            [LICENSE_VALID_RESPONSE,
             ALTERNATE_LICENSE_RESPONSE]

        # A license install should return a success
        self.fake_sysinv_client.install_license.return_value = \
            LICENSE_VALID_RESPONSE

        self.worker.install_subcloud_license(self.strategy_step)

        # verify the license install was invoked
        self.fake_sysinv_client.install_license.assert_called()

        # On success, the next state after installing license is importing load
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_IMPORTING_LOAD)

    def test_upgrade_subcloud_license_skip_when_no_sys_controller_lic(self):
        # Test the install subcloud license step is skipped and proceeds
        # to the next state when there is no license on system controller

        # Only makes one query to system controller
        self.fake_sysinv_client.get_license.side_effect = \
            [MISSING_LICENSE_RESPONSE, ]
        # Test the install subcloud license stage
        self.worker.install_subcloud_license(self.strategy_step)

        # A license install should proceed to the next state without
        # calling a license install
        self.fake_sysinv_client.install_license.assert_not_called()
        # Skip license install and move to next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_IMPORTING_LOAD)

    def test_upgrade_subcloud_license_handle_failure(self):
        # Test the install subcloud license step where the system controller
        # license is valid, and the subcloud license install fails

        # Order of get_license calls:
        # first license query is to system controller
        # second license query is to subcloud (should be missing)
        self.fake_sysinv_client.get_license.side_effect = \
            [LICENSE_VALID_RESPONSE,
             MISSING_LICENSE_RESPONSE]

        # Simulate a license install failure on the subcloud
        self.fake_sysinv_client.install_license.return_value = \
            MISSING_LICENSE_RESPONSE

        self.worker.install_subcloud_license(self.strategy_step)

        # verify the license install was invoked
        self.fake_sysinv_client.install_license.assert_called()

        # Verify a install_license failure leads to a state failure
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_upgrade_subcloud_license_installs(self):
        # Test the install subcloud license step where the system controller
        # license is valid, and the subcloud installation succeeds

        # Order of get_license calls:
        # first license query is to system controller
        # second license query is to subcloud (should be missing)
        self.fake_sysinv_client.get_license.side_effect = \
            [LICENSE_VALID_RESPONSE,
             MISSING_LICENSE_RESPONSE]

        # A license install should return a success
        self.fake_sysinv_client.install_license.return_value = \
            LICENSE_VALID_RESPONSE

        self.worker.install_subcloud_license(self.strategy_step)

        # verify the license install was invoked
        self.fake_sysinv_client.install_license.assert_called()

        # On success, the next state after installing license is importing load
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_IMPORTING_LOAD)
