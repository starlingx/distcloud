#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock
import uuid

from dcmanager.manager.states.base import BaseState
from sysinv.common import constants as sysinv_constants

from dcmanager.tests.unit.manager.test_sw_upgrade import TestSwUpgrade

PREVIOUS_VERSION = '12.34'
UPGRADED_VERSION = '56.78'


class FakeKeystoneClient(object):
    def __init__(self):
        self.session = mock.MagicMock()


class FakeLoad(object):
    def __init__(self,
                 obj_id,
                 compatible_version='N/A',
                 required_patches='N/A',
                 software_version=PREVIOUS_VERSION,
                 state='active',
                 created_at=None,
                 updated_at=None):
        self.id = obj_id
        self.uuid = uuid.uuid4()
        self.required_patches = required_patches
        self.software_version = software_version
        self.state = state
        self.created_at = created_at
        self.updated_at = updated_at


class FakeSystem(object):
    def __init__(self,
                 obj_id=1,
                 software_version=UPGRADED_VERSION):
        self.id = obj_id
        self.uuid = uuid.uuid4()
        self.software_version = software_version


class FakeUpgrade(object):
    def __init__(self,
                 obj_id=1,
                 state='completed',
                 from_release=PREVIOUS_VERSION,
                 to_release=UPGRADED_VERSION):
        self.id = obj_id
        self.uuid = uuid.uuid4()
        self.state = state
        self.from_release = from_release
        self.to_release = to_release
        self.links = []


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
                 target_load=UPGRADED_VERSION,
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
