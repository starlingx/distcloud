#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock

from dcmanager.manager.states.base import BaseState
from sysinv.common import constants as sysinv_constants

from dcmanager.tests.unit.manager.test_sw_upgrade import TestSwUpgrade

CURRENT_LOAD = '20.01'
UPDATED_LOAD = '20.06'


class FakeKeystoneClient(object):
    def __init__(self):
        self.session = mock.MagicMock()


class FakeSysinvClient(object):
    def __init__(self):
        pass


class FakeController(object):
    def __init__(self,
                 host_id=1,
                 hostname='controller-0',
                 administrative=sysinv_constants.ADMIN_UNLOCKED,
                 availability=sysinv_constants.AVAILABILITY_AVAILABLE,
                 ihost_action=None,
                 target_load=CURRENT_LOAD,
                 task=None):
        self.id = host_id
        self.hostname = hostname
        self.administrative = administrative
        self.availability = availability
        self.ihost_action = ihost_action
        self.target_load = target_load
        self.task = task


class TestSwUpgradeState(TestSwUpgrade):
    def setUp(self):
        super(TestSwUpgradeState, self).setUp()

        # Mock the host environment.
        self.controller_0 = self.fake_controller('controller-0')

        # Mock the keystone client defined in the base upgrade state class
        self.keystone_client = FakeKeystoneClient()
        p = mock.patch.object(BaseState, 'get_keystone_client')
        self.mock_keystone_client = p.start()
        self.mock_keystone_client.return_value = self.keystone_client
        self.addCleanup(p.stop)

        # Mock the sysinv client defined in the base upgrade state class
        self.sysinv_client = FakeSysinvClient()
        p = mock.patch.object(BaseState, 'get_sysinv_client')
        self.mock_sysinv_client = p.start()
        self.mock_sysinv_client.return_value = self.sysinv_client
        self.addCleanup(p.stop)

    def fake_controller(self, hostname):
        return FakeController(hostname=hostname)
