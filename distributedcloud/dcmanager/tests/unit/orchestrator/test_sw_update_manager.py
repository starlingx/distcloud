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
# Copyright (c) 2017 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#
import copy
import mock
from os import path as os_path
import threading

from oslo_config import cfg

from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common import exceptions
from dcmanager.db.sqlalchemy import api as db_api
from dcmanager.orchestrator import patch_orch_thread
from dcmanager.orchestrator import sw_update_manager
from dcmanager.tests import base
from dcmanager.tests import utils
from dcorch.common import consts as dcorch_consts


CONF = cfg.CONF
FAKE_ID = '1'
FAKE_SW_UPDATE_DATA = {
    "type": consts.SW_UPDATE_TYPE_PATCH,
    "subcloud-apply-type": consts.SUBCLOUD_APPLY_TYPE_PARALLEL,
    "max-parallel-subclouds": "2",
    "stop-on-failure": "true",
    "force": "false",
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


def compare_call_with_unsorted_list(call, unsorted_list):
    call_args, _ = call
    return call_args[0].sort() == unsorted_list.sort()


class Subcloud(object):
    def __init__(self, id, name, group_id, is_managed, is_online):
        self.id = id
        self.name = name
        self.software_version = '12.04'
        self.group_id = group_id
        if is_managed:
            self.management_state = consts.MANAGEMENT_MANAGED
        else:
            self.management_state = consts.MANAGEMENT_UNMANAGED
        if is_online:
            self.availability_status = consts.AVAILABILITY_ONLINE
        else:
            self.availability_status = consts.AVAILABILITY_OFFLINE


class StrategyStep(object):
    def __init__(self, id=1, subcloud_id=1, stage=1,
                 state=consts.STRATEGY_STATE_INITIAL, details='',
                 subcloud=None, subcloud_name=None):
        self.id = id
        self.subcloud_id = subcloud_id
        self.stage = stage
        self.state = state
        self.details = details
        self.subcloud = subcloud
        self.subcloud_name = subcloud_name


class Load(object):
    def __init__(self, software_version):
        self.software_version = software_version
        self.state = consts.ACTIVE_LOAD_STATE


class FakePatchingClientOutOfSync(mock.Mock):
    def __init__(self, region, session):
        super(FakePatchingClientOutOfSync, self).__init__()
        self.region = region
        self.session = session

    def query(self):
        if self.region == 'RegionOne':
            return {'DC.1': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    'DC.2': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    'DC.3': {'sw_version': '17.07',
                             'repostate': 'Committed',
                             'patchstate': 'Committed'},
                    'DC.4': {'sw_version': '17.07',
                             'repostate': 'Available',
                             'patchstate': 'Available'},
                    'DC.8': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    }
        elif self.region == 'subcloud1':
            return {'DC.1': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    'DC.2': {'sw_version': '17.07',
                             'repostate': 'Available',
                             'patchstate': 'Available'},
                    'DC.3': {'sw_version': '17.07',
                             'repostate': 'Available',
                             'patchstate': 'Partial-Remove'},
                    'DC.5': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    'DC.6': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Partial-Apply'},
                    }
        else:
            return {}

    def query_hosts(self):
        return []


class FakePatchingClientSubcloudCommitted(mock.Mock):
    def __init__(self, region, session):
        super(FakePatchingClientSubcloudCommitted, self).__init__()
        self.region = region
        self.session = session

    def query(self):
        if self.region == 'RegionOne':
            return {'DC.1': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    'DC.2': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    'DC.3': {'sw_version': '17.07',
                             'repostate': 'Committed',
                             'patchstate': 'Committed'},
                    'DC.4': {'sw_version': '17.07',
                             'repostate': 'Available',
                             'patchstate': 'Available'},
                    'DC.8': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    }
        elif self.region == 'subcloud1':
            return {'DC.1': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    'DC.2': {'sw_version': '17.07',
                             'repostate': 'Available',
                             'patchstate': 'Available'},
                    'DC.3': {'sw_version': '17.07',
                             'repostate': 'Available',
                             'patchstate': 'Partial-Remove'},
                    'DC.5': {'sw_version': '17.07',
                             'repostate': 'Committed',
                             'patchstate': 'Committed'},
                    'DC.6': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Partial-Apply'},
                    }
        else:
            return {}

    def query_hosts(self):
        return []


class FakePatchingClientSubcloudUnknown(mock.Mock):
    def __init__(self, region, session):
        super(FakePatchingClientSubcloudUnknown, self).__init__()
        self.region = region
        self.session = session

    def query(self):
        if self.region == 'RegionOne':
            return {'DC.1': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    'DC.2': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    'DC.3': {'sw_version': '17.07',
                             'repostate': 'Committed',
                             'patchstate': 'Committed'},
                    'DC.4': {'sw_version': '17.07',
                             'repostate': 'Available',
                             'patchstate': 'Available'},
                    'DC.8': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    }
        elif self.region == 'subcloud1':
            return {'DC.1': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    'DC.2': {'sw_version': '17.07',
                             'repostate': 'Available',
                             'patchstate': 'Available'},
                    'DC.3': {'sw_version': '17.07',
                             'repostate': 'Available',
                             'patchstate': 'Partial-Remove'},
                    'DC.5': {'sw_version': '17.07',
                             'repostate': 'Unknown',
                             'patchstate': 'Unknown'},
                    'DC.6': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Partial-Apply'},
                    }
        else:
            return {}

    def query_hosts(self):
        return []


class FakePatchingClientFinish(mock.Mock):
    def __init__(self, region, session):
        super(FakePatchingClientFinish, self).__init__()
        self.region = region
        self.session = session

    def query(self, state=None):
        if self.region == 'RegionOne':
            if state == 'committed':
                return {'DC.2': {'sw_version': '17.07',
                                 'repostate': 'Committed',
                                 'patchstate': 'Committed'},
                        'DC.3': {'sw_version': '17.07',
                                 'repostate': 'Committed',
                                 'patchstate': 'Committed'},
                        'DC.4': {'sw_version': '17.07',
                                 'repostate': 'Committed',
                                 'patchstate': 'Committed'},
                        }
            else:
                return {'DC.1': {'sw_version': '17.07',
                                 'repostate': 'Applied',
                                 'patchstate': 'Applied'},
                        'DC.2': {'sw_version': '17.07',
                                 'repostate': 'Committed',
                                 'patchstate': 'Committed'},
                        'DC.3': {'sw_version': '17.07',
                                 'repostate': 'Committed',
                                 'patchstate': 'Committed'},
                        'DC.4': {'sw_version': '17.07',
                                 'repostate': 'Committed',
                                 'patchstate': 'Committed'},
                        'DC.8': {'sw_version': '17.07',
                                 'repostate': 'Available',
                                 'patchstate': 'Available'},
                        }
        elif self.region == 'subcloud1':
            return {'DC.1': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    'DC.2': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    'DC.3': {'sw_version': '17.07',
                             'repostate': 'Applied',
                             'patchstate': 'Applied'},
                    'DC.4': {'sw_version': '17.07',
                             'repostate': 'Committed',
                             'patchstate': 'Committed'},
                    'DC.5': {'sw_version': '17.07',
                             'repostate': 'Available',
                             'patchstate': 'Available'},
                    'DC.6': {'sw_version': '17.07',
                             'repostate': 'Available',
                             'patchstate': 'Available'},
                    }
        else:
            return {}

    def query_hosts(self):
        return []


class FakeSysinvClientOneLoad(object):
    def __init__(self, region, session):
        self.loads = [Load('17.07')]

    def get_loads(self):
        return self.loads


class Controller(object):
    def __init__(self, hostname):
        self.hostname = hostname


# All orch_threads can be mocked the same way
class FakeOrchThread(object):
    def __init__(self):
        # Mock methods that are called in normal execution of this thread
        self.start = mock.MagicMock()


class FakeDCManagerAuditAPI(object):

    def __init__(self):
        self.trigger_patch_audit = mock.MagicMock()


class TestSwUpdateManager(base.DCManagerTestCase):
    @staticmethod
    def create_subcloud(ctxt, name, group_id, is_managed, is_online):
        values = {
            "name": name,
            "description": "subcloud1 description",
            "location": "subcloud1 location",
            'software_version': "18.03",
            "management_subnet": "192.168.101.0/24",
            "management_gateway_ip": "192.168.101.1",
            "management_start_ip": "192.168.101.3",
            "management_end_ip": "192.168.101.4",
            "systemcontroller_gateway_ip": "192.168.204.101",
            'deploy_status': "not-deployed",
            'openstack_installed': False,
            'group_id': group_id,
            'data_install': 'data from install',
        }
        subcloud = db_api.subcloud_create(ctxt, **values)
        if is_managed:
            state = consts.MANAGEMENT_MANAGED
            subcloud = db_api.subcloud_update(ctxt, subcloud.id,
                                              management_state=state)
        if is_online:
            status = consts.AVAILABILITY_ONLINE
            subcloud = db_api.subcloud_update(ctxt, subcloud.id,
                                              availability_status=status)
        return subcloud

    @staticmethod
    def create_subcloud_group(ctxt, name, update_apply_type,
                              max_parallel_subclouds):
        values = {
            "name": name,
            "description": "subcloud1 description",
            "update_apply_type": update_apply_type,
            "max_parallel_subclouds": max_parallel_subclouds,
        }
        return db_api.subcloud_group_create(ctxt, **values)

    @staticmethod
    def create_subcloud_status(ctxt, subcloud_id,
                               endpoint=None, status=None):
        if endpoint:
            endpoint_type = endpoint
        else:
            endpoint_type = dcorch_consts.ENDPOINT_TYPE_PATCHING
        if status:
            sync_status = status
        else:
            sync_status = consts.SYNC_STATUS_OUT_OF_SYNC

        values = {
            "subcloud_id": subcloud_id,
            "endpoint_type": endpoint_type,
        }
        subcloud_status = db_api.subcloud_status_create(ctxt, **values)
        subcloud_status = db_api.subcloud_status_update(ctxt,
                                                        subcloud_id,
                                                        endpoint_type,
                                                        sync_status)
        return subcloud_status

    @staticmethod
    def create_strategy(ctxt, strategy_type, state):
        values = {
            "type": strategy_type,
            "subcloud_apply_type": consts.SUBCLOUD_APPLY_TYPE_PARALLEL,
            "max_parallel_subclouds": 2,
            "stop_on_failure": True,
            "state": state,
        }
        return db_api.sw_update_strategy_create(ctxt, **values)

    @staticmethod
    def create_strategy_step(ctxt, state):
        values = {
            "subcloud_id": 1,
            "stage": 1,
            "state": state,
            "details": "Dummy details",
        }
        return db_api.strategy_step_create(ctxt, **values)

    def setUp(self):
        super(TestSwUpdateManager, self).setUp()
        # Mock the context
        self.ctxt = utils.dummy_context()
        p = mock.patch.object(context, 'get_admin_context')
        self.mock_get_admin_context = p.start()
        self.mock_get_admin_context.return_value = self.ctx
        self.addCleanup(p.stop)

        # Note: mock where an item is used, not where it comes from
        self.fake_sw_upgrade_orch_thread = FakeOrchThread()
        p = mock.patch.object(sw_update_manager, 'SwUpgradeOrchThread')
        self.mock_sw_upgrade_orch_thread = p.start()
        self.mock_sw_upgrade_orch_thread.return_value = \
            self.fake_sw_upgrade_orch_thread
        self.addCleanup(p.stop)

        self.fake_fw_update_orch_thread = FakeOrchThread()
        p = mock.patch.object(sw_update_manager, 'FwUpdateOrchThread')
        self.mock_fw_update_orch_thread = p.start()
        self.mock_fw_update_orch_thread.return_value = \
            self.fake_fw_update_orch_thread
        self.addCleanup(p.stop)

        # Mock the dcmanager audit API
        self.fake_dcmanager_audit_api = FakeDCManagerAuditAPI()
        p = mock.patch('dcmanager.audit.rpcapi.ManagerAuditClient')
        self.mock_dcmanager_audit_api = p.start()
        self.mock_dcmanager_audit_api.return_value = \
            self.fake_dcmanager_audit_api
        self.addCleanup(p.stop)

        # Fake subcloud groups
        # Group 1 exists by default in database with max_parallel 2 and
        # apply_type parallel
        self.fake_group2 = self.create_subcloud_group(self.ctxt,
                                                      "Group2",
                                                      consts.SUBCLOUD_APPLY_TYPE_SERIAL,
                                                      2)
        self.fake_group3 = self.create_subcloud_group(self.ctxt,
                                                      "Group3",
                                                      consts.SUBCLOUD_APPLY_TYPE_PARALLEL,
                                                      2)
        self.fake_group4 = self.create_subcloud_group(self.ctxt,
                                                      "Group4",
                                                      consts.SUBCLOUD_APPLY_TYPE_SERIAL,
                                                      2)
        self.fake_group5 = self.create_subcloud_group(self.ctxt,
                                                      "Group5",
                                                      consts.SUBCLOUD_APPLY_TYPE_PARALLEL,
                                                      2)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    def test_init(self, mock_patch_orch_thread):
        um = sw_update_manager.SwUpdateManager()
        self.assertIsNotNone(um)
        self.assertEqual('sw_update_manager', um.service_name)
        self.assertEqual('localhost', um.host)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    @mock.patch.object(sw_update_manager, 'db_api')
    def test_create_sw_update_strategy_no_subclouds(
            self, mock_db_api, mock_patch_orch_thread):
        mock_db_api.sw_update_strategy_get.side_effect = \
            exceptions.NotFound()
        um = sw_update_manager.SwUpdateManager()
        um.create_sw_update_strategy(self.ctxt, payload=FAKE_SW_UPDATE_DATA)
        mock_db_api.sw_update_strategy_create.assert_called_once()

        expected_calls = [
            mock.call(mock.ANY,
                      None,
                      stage=1,
                      state=consts.STRATEGY_STATE_INITIAL,
                      details=''),
        ]
        mock_db_api.strategy_step_create.assert_has_calls(
            expected_calls)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    def test_create_sw_update_strategy_parallel(
            self, mock_patch_orch_thread):

        # Create fake subclouds and respective status
        # Subcloud1 will be patched
        fake_subcloud1 = self.create_subcloud(self.ctxt, 'subcloud1', 1,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud1.id)

        # Subcloud2 will not be patched because not managed
        fake_subcloud2 = self.create_subcloud(self.ctxt, 'subcloud2', 1,
                                              is_managed=False, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud2.id)

        # Subcloud3 will be patched
        fake_subcloud3 = self.create_subcloud(self.ctxt, 'subcloud3', 1,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud3.id)

        # Subcloud4 will not be patched because patching is in sync
        fake_subcloud4 = self.create_subcloud(self.ctxt, 'subcloud4', 2,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt,
                                    fake_subcloud4.id,
                                    None,
                                    consts.SYNC_STATUS_IN_SYNC)
        # Subcloud5 will be patched
        fake_subcloud5 = self.create_subcloud(self.ctxt, 'subcloud5', 2,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud5.id)

        # Subcloud6 will be patched
        fake_subcloud6 = self.create_subcloud(self.ctxt, 'subcloud6', 3,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud6.id)

        # Subcloud7 will be patched
        fake_subcloud7 = self.create_subcloud(self.ctxt, 'subcloud7', 3,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud7.id)

        um = sw_update_manager.SwUpdateManager()
        strategy_dict = um.create_sw_update_strategy(self.ctxt, payload=FAKE_SW_UPDATE_DATA)

        # Assert that values passed through CLI are used instead of group values
        self.assertEqual(strategy_dict['max-parallel-subclouds'], 2)
        self.assertEqual(strategy_dict['subcloud-apply-type'],
                         consts.SUBCLOUD_APPLY_TYPE_PARALLEL)

        # Verify the strategy step list
        subcloud_ids = [None, 1, 3, 5, 6, 7]
        stage = [1, 2, 2, 3, 4, 4]
        strategy_step_list = db_api.strategy_step_get_all(self.ctxt)
        for index, strategy_step in enumerate(strategy_step_list):
            self.assertEqual(subcloud_ids[index], strategy_step.subcloud_id)
            self.assertEqual(stage[index], strategy_step.stage)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    def test_create_sw_update_strategy_serial(
            self, mock_patch_orch_thread):

        # Create fake subclouds and respective status
        # Subcloud1 will be patched
        fake_subcloud1 = self.create_subcloud(self.ctxt, 'subcloud1', 1,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud1.id)

        # Subcloud2 will not be patched because not managed
        fake_subcloud2 = self.create_subcloud(self.ctxt, 'subcloud2', 1,
                                              is_managed=False, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud2.id)

        # Subcloud3 will be patched
        fake_subcloud3 = self.create_subcloud(self.ctxt, 'subcloud3', 1,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud3.id)

        # Subcloud4 will not be patched because patching is in sync
        fake_subcloud4 = self.create_subcloud(self.ctxt, 'subcloud4', 2,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt,
                                    fake_subcloud4.id,
                                    None,
                                    consts.SYNC_STATUS_IN_SYNC)
        # Subcloud5 will be patched
        fake_subcloud5 = self.create_subcloud(self.ctxt, 'subcloud5', 2,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud5.id)

        # Subcloud6 will be patched
        fake_subcloud6 = self.create_subcloud(self.ctxt, 'subcloud6', 3,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud6.id)

        # Subcloud7 will be patched
        fake_subcloud7 = self.create_subcloud(self.ctxt, 'subcloud7', 3,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud7.id)

        um = sw_update_manager.SwUpdateManager()
        data = copy.copy(FAKE_SW_UPDATE_DATA)
        data["subcloud-apply-type"] = consts.SUBCLOUD_APPLY_TYPE_SERIAL
        strategy_dict = um.create_sw_update_strategy(self.ctxt, payload=data)

        # Assert that values passed through CLI are used instead of group values
        self.assertEqual(strategy_dict['max-parallel-subclouds'], 2)
        self.assertEqual(strategy_dict['subcloud-apply-type'],
                         consts.SUBCLOUD_APPLY_TYPE_SERIAL)

        # Verify the strategy step list
        subcloud_ids = [None, 1, 3, 5, 6, 7]
        stage = [1, 2, 3, 4, 5, 6]
        strategy_step_list = db_api.strategy_step_get_all(self.ctxt)
        for index, strategy_step in enumerate(strategy_step_list):
            self.assertEqual(subcloud_ids[index], strategy_step.subcloud_id)
            self.assertEqual(stage[index], strategy_step.stage)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    def test_create_sw_update_strategy_using_group_apply_type(
            self, mock_patch_orch_thread):

        # Create fake subclouds and respective status
        # Subcloud1 will be patched
        fake_subcloud1 = self.create_subcloud(self.ctxt, 'subcloud1', 1,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud1.id)

        # Subcloud2 will not be patched because not managed
        fake_subcloud2 = self.create_subcloud(self.ctxt, 'subcloud2', 1,
                                              is_managed=False, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud2.id)

        # Subcloud3 will be patched
        fake_subcloud3 = self.create_subcloud(self.ctxt, 'subcloud3', 1,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud3.id)

        # Subcloud4 will not be patched because patching is in sync
        fake_subcloud4 = self.create_subcloud(self.ctxt, 'subcloud4', 2,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt,
                                    fake_subcloud4.id,
                                    None,
                                    consts.SYNC_STATUS_IN_SYNC)
        # Subcloud5 will be patched
        fake_subcloud5 = self.create_subcloud(self.ctxt, 'subcloud5', 2,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud5.id)

        # Subcloud6 will be patched
        fake_subcloud6 = self.create_subcloud(self.ctxt, 'subcloud6', 3,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud6.id)

        # Subcloud7 will be patched
        fake_subcloud7 = self.create_subcloud(self.ctxt, 'subcloud7', 3,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud7.id)

        # Subcloud8 will be patched
        fake_subcloud8 = self.create_subcloud(self.ctxt, 'subcloud8', 4,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud8.id)

        # Subcloud9 will be patched
        fake_subcloud9 = self.create_subcloud(self.ctxt, 'subcloud9', 4,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud9.id)

        # Subcloud10 will be patched
        fake_subcloud10 = self.create_subcloud(self.ctxt, 'subcloud10', 4,
                                               is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud10.id)

        # Subcloud11 will be patched
        fake_subcloud11 = self.create_subcloud(self.ctxt, 'subcloud11', 5,
                                               is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud11.id)

        # Subcloud12 will be patched
        fake_subcloud12 = self.create_subcloud(self.ctxt, 'subcloud12', 5,
                                               is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud12.id)

        # Subcloud13 will be patched
        fake_subcloud13 = self.create_subcloud(self.ctxt, 'subcloud13', 5,
                                               is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud13.id)

        data = copy.copy(FAKE_SW_UPDATE_DATA)
        del data['subcloud-apply-type']

        um = sw_update_manager.SwUpdateManager()
        strategy_dict = um.create_sw_update_strategy(self.ctxt, payload=data)

        # Assert that group values are being used for subcloud_apply_type
        self.assertEqual(strategy_dict['subcloud-apply-type'], None)

        # Assert that values passed through CLI are used instead of
        # group values for max_parallel_subclouds
        self.assertEqual(strategy_dict['max-parallel-subclouds'], 2)

        # Verify the strategy step list
        subcloud_ids = [None, 1, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        stage = [1, 2, 2, 3, 4, 4, 5, 6, 7, 8, 8, 9]
        strategy_step_list = db_api.strategy_step_get_all(self.ctxt)
        for index, strategy_step in enumerate(strategy_step_list):
            self.assertEqual(subcloud_ids[index], strategy_step.subcloud_id)
            self.assertEqual(stage[index], strategy_step.stage)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    def test_create_sw_update_strategy_using_group_max_parallel(
            self, mock_patch_orch_thread):

        # Create fake subclouds and respective status
        # Subcloud1 will be patched
        fake_subcloud1 = self.create_subcloud(self.ctxt, 'subcloud1', 1,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud1.id)

        # Subcloud2 will not be patched because not managed
        fake_subcloud2 = self.create_subcloud(self.ctxt, 'subcloud2', 1,
                                              is_managed=False, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud2.id)

        # Subcloud3 will be patched
        fake_subcloud3 = self.create_subcloud(self.ctxt, 'subcloud3', 1,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud3.id)

        # Subcloud4 will not be patched because patching is in sync
        fake_subcloud4 = self.create_subcloud(self.ctxt, 'subcloud4', 2,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt,
                                    fake_subcloud4.id,
                                    None,
                                    consts.SYNC_STATUS_IN_SYNC)
        # Subcloud5 will be patched
        fake_subcloud5 = self.create_subcloud(self.ctxt, 'subcloud5', 2,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud5.id)

        # Subcloud6 will be patched
        fake_subcloud6 = self.create_subcloud(self.ctxt, 'subcloud6', 3,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud6.id)

        # Subcloud7 will be patched
        fake_subcloud7 = self.create_subcloud(self.ctxt, 'subcloud7', 3,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud7.id)

        # Subcloud8 will be patched
        fake_subcloud8 = self.create_subcloud(self.ctxt, 'subcloud8', 4,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud8.id)

        # Subcloud9 will be patched
        fake_subcloud9 = self.create_subcloud(self.ctxt, 'subcloud9', 4,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud9.id)

        # Subcloud10 will be patched
        fake_subcloud10 = self.create_subcloud(self.ctxt, 'subcloud10', 4,
                                               is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud10.id)

        # Subcloud11 will be patched
        fake_subcloud11 = self.create_subcloud(self.ctxt, 'subcloud11', 5,
                                               is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud11.id)

        # Subcloud12 will be patched
        fake_subcloud12 = self.create_subcloud(self.ctxt, 'subcloud12', 5,
                                               is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud12.id)

        # Subcloud13 will be patched
        fake_subcloud13 = self.create_subcloud(self.ctxt, 'subcloud13', 5,
                                               is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud13.id)

        data = copy.copy(FAKE_SW_UPDATE_DATA)
        del data['max-parallel-subclouds']

        um = sw_update_manager.SwUpdateManager()
        strategy_dict = um.create_sw_update_strategy(self.ctxt, payload=data)

        # Assert that values passed through CLI are used instead of
        # group values for max_parallel_subclouds
        self.assertEqual(strategy_dict['subcloud-apply-type'],
                         consts.SUBCLOUD_APPLY_TYPE_PARALLEL)

        # Assert that group values are being used for subcloud_apply_type
        self.assertEqual(strategy_dict['max-parallel-subclouds'], None)

        # Verify the strategy step list
        subcloud_ids = [None, 1, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        stage = [1, 2, 2, 3, 4, 4, 5, 5, 6, 7, 7, 8]
        strategy_step_list = db_api.strategy_step_get_all(self.ctxt)
        for index, strategy_step in enumerate(strategy_step_list):
            self.assertEqual(subcloud_ids[index], strategy_step.subcloud_id)
            self.assertEqual(stage[index], strategy_step.stage)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    def test_create_sw_update_strategy_using_all_group_values(
            self, mock_patch_orch_thread):

        # Create fake subclouds and respective status
        # Subcloud1 will be patched
        fake_subcloud1 = self.create_subcloud(self.ctxt, 'subcloud1', 1,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud1.id)

        # Subcloud2 will not be patched because not managed
        fake_subcloud2 = self.create_subcloud(self.ctxt, 'subcloud2', 1,
                                              is_managed=False, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud2.id)

        # Subcloud3 will be patched
        fake_subcloud3 = self.create_subcloud(self.ctxt, 'subcloud3', 1,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud3.id)

        # Subcloud4 will not be patched because patching is in sync
        fake_subcloud4 = self.create_subcloud(self.ctxt, 'subcloud4', 2,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt,
                                    fake_subcloud4.id,
                                    None,
                                    consts.SYNC_STATUS_IN_SYNC)
        # Subcloud5 will be patched
        fake_subcloud5 = self.create_subcloud(self.ctxt, 'subcloud5', 2,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud5.id)

        # Subcloud6 will be patched
        fake_subcloud6 = self.create_subcloud(self.ctxt, 'subcloud6', 3,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud6.id)

        # Subcloud7 will be patched
        fake_subcloud7 = self.create_subcloud(self.ctxt, 'subcloud7', 3,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud7.id)

        # Subcloud8 will be patched
        fake_subcloud8 = self.create_subcloud(self.ctxt, 'subcloud8', 4,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud8.id)

        # Subcloud9 will be patched
        fake_subcloud9 = self.create_subcloud(self.ctxt, 'subcloud9', 4,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud9.id)

        # Subcloud10 will be patched
        fake_subcloud10 = self.create_subcloud(self.ctxt, 'subcloud10', 4,
                                               is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud10.id)

        # Subcloud11 will be patched
        fake_subcloud11 = self.create_subcloud(self.ctxt, 'subcloud11', 5,
                                               is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud11.id)

        # Subcloud12 will be patched
        fake_subcloud12 = self.create_subcloud(self.ctxt, 'subcloud12', 5,
                                               is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud12.id)

        # Subcloud13 will be patched
        fake_subcloud13 = self.create_subcloud(self.ctxt, 'subcloud13', 5,
                                               is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud13.id)

        data = copy.copy(FAKE_SW_UPDATE_DATA)
        del data['subcloud-apply-type']
        del data['max-parallel-subclouds']

        um = sw_update_manager.SwUpdateManager()
        strategy_dict = um.create_sw_update_strategy(self.ctxt, payload=data)

        # Assert that group values are being used
        self.assertEqual(strategy_dict['max-parallel-subclouds'], None)
        self.assertEqual(strategy_dict['subcloud-apply-type'], None)

        # Verify the strategy step list
        subcloud_ids = [None, 1, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        stage = [1, 2, 2, 3, 4, 4, 5, 6, 7, 8, 8, 9]
        strategy_step_list = db_api.strategy_step_get_all(self.ctxt)
        for index, strategy_step in enumerate(strategy_step_list):
            self.assertEqual(subcloud_ids[index], strategy_step.subcloud_id)
            self.assertEqual(stage[index], strategy_step.stage)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    def test_create_sw_update_strategy_unknown_sync_status(
            self, mock_patch_orch_thread):
        # Create fake subclouds and respective status
        # Subcloud1 will be patched
        fake_subcloud1 = self.create_subcloud(self.ctxt, 'subcloud1', 1,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud1.id)

        # Subcloud2 will not be patched because not managed
        fake_subcloud2 = self.create_subcloud(self.ctxt, 'subcloud2', 1,
                                              is_managed=False, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud2.id)

        # Subcloud3 will be patched
        fake_subcloud3 = self.create_subcloud(self.ctxt, 'subcloud3', 1,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud3.id)

        # Subcloud4 will not be patched because patching is in sync
        fake_subcloud4 = self.create_subcloud(self.ctxt, 'subcloud4', 2,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt,
                                    fake_subcloud4.id,
                                    None,
                                    consts.SYNC_STATUS_UNKNOWN)

        um = sw_update_manager.SwUpdateManager()
        self.assertRaises(exceptions.BadRequest,
                          um.create_sw_update_strategy,
                          self.ctxt, payload=FAKE_SW_UPDATE_DATA)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    def test_create_sw_update_strategy_offline_subcloud_no_force(
            self, mock_patch_orch_thread):

        # Create fake subclouds and respective status
        # Subcloud1 will not be included in the strategy as it's offline
        fake_subcloud1 = self.create_subcloud(self.ctxt, 'subcloud1', 1,
                                              is_managed=True, is_online=False)
        self.create_subcloud_status(self.ctxt, fake_subcloud1.id)

        # Subcloud2 will be included in the strategy as it's online
        fake_subcloud2 = self.create_subcloud(self.ctxt, 'subcloud2', 1,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud2.id)

        # Subcloud3 will be included in the strategy as it's online
        fake_subcloud3 = self.create_subcloud(self.ctxt, 'subcloud3', 1,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud3.id)

        # Subcloud3 will be included in the strategy as it's online
        fake_subcloud4 = self.create_subcloud(self.ctxt, 'subcloud4', 1,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud4.id)

        um = sw_update_manager.SwUpdateManager()
        data = copy.copy(FAKE_SW_UPDATE_DATA)
        data["type"] = consts.SW_UPDATE_TYPE_UPGRADE
        data["max-parallel-subclouds"] = 10
        strategy_dict = um.create_sw_update_strategy(self.ctxt, payload=data)

        # Assert that values passed through CLI are used instead of group values
        self.assertEqual(strategy_dict['max-parallel-subclouds'], 10)
        self.assertEqual(strategy_dict['subcloud-apply-type'],
                         consts.SUBCLOUD_APPLY_TYPE_PARALLEL)
        self.assertEqual(strategy_dict['type'], consts.SW_UPDATE_TYPE_UPGRADE)

        # Verify the strategy step list
        subcloud_ids = [None, 2, 3, 4]
        stage = [1, 2]
        strategy_step_list = db_api.strategy_step_get_all(self.ctxt)
        for index, strategy_step in enumerate(strategy_step_list):
            self.assertEqual(subcloud_ids[index], strategy_step.subcloud_id)
            self.assertEqual(stage[index], strategy_step.stage)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    def test_create_sw_update_strategy_not_in_sync_offline_subcloud_with_force_upgrade(
            self, mock_patch_orch_thread):

        # This test verifies the offline subcloud is added to the strategy
        # because force option is specified in the upgrade request.
        fake_subcloud1 = self.create_subcloud(self.ctxt, 'subcloud1', 1,
                                              is_managed=True, is_online=False)
        self.create_subcloud_status(self.ctxt,
                                    fake_subcloud1.id,
                                    dcorch_consts.ENDPOINT_TYPE_LOAD,
                                    consts.SYNC_STATUS_UNKNOWN)

        um = sw_update_manager.SwUpdateManager()
        data = copy.copy(FAKE_SW_UPDATE_DATA)
        data["type"] = consts.SW_UPDATE_TYPE_UPGRADE
        data["force"] = True
        data["cloud_name"] = 'subcloud1'

        strategy_dict = um.create_sw_update_strategy(self.ctxt, payload=data)

        # Assert that values passed through CLI are used instead of group values
        self.assertEqual(strategy_dict['subcloud-apply-type'],
                         consts.SUBCLOUD_APPLY_TYPE_PARALLEL)
        self.assertEqual(strategy_dict['type'], consts.SW_UPDATE_TYPE_UPGRADE)

        # Verify the strategy step list
        subcloud_ids = [None, 1]
        stage = [1, 2]
        strategy_step_list = db_api.strategy_step_get_all(self.ctxt)
        for index, strategy_step in enumerate(strategy_step_list):
            self.assertEqual(subcloud_ids[index], strategy_step.subcloud_id)
            self.assertEqual(stage[index], strategy_step.stage)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    def test_create_sw_update_strategy_in_sync_offline_subcloud_with_force_upgrade(
            self, mock_patch_orch_thread):

        # This test verifies that a bad request exception is raised even
        # though force option is specified in the request because the load sync
        # status of the offline subcloud is in-sync.
        fake_subcloud1 = self.create_subcloud(self.ctxt, 'subcloud1', 1,
                                              is_managed=True, is_online=False)
        self.create_subcloud_status(self.ctxt,
                                    fake_subcloud1.id,
                                    dcorch_consts.ENDPOINT_TYPE_LOAD,
                                    consts.SYNC_STATUS_IN_SYNC)

        um = sw_update_manager.SwUpdateManager()
        data = copy.copy(FAKE_SW_UPDATE_DATA)
        data["type"] = consts.SW_UPDATE_TYPE_UPGRADE
        data["force"] = True
        data["cloud_name"] = 'subcloud1'

        self.assertRaises(exceptions.BadRequest,
                          um.create_sw_update_strategy,
                          self.ctxt, payload=data)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    def test_create_sw_update_strategy_online_subcloud_with_force_upgrade(
            self, mock_patch_orch_thread):

        # This test verifies that the force option has no effect in
        # upgrade creation strategy if the subcloud is online. A bad request
        # exception will be raised if the subcloud load sync status is
        # unknown.
        fake_subcloud1 = self.create_subcloud(self.ctxt, 'subcloud1', 1,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt,
                                    fake_subcloud1.id,
                                    dcorch_consts.ENDPOINT_TYPE_LOAD,
                                    consts.SYNC_STATUS_UNKNOWN)

        um = sw_update_manager.SwUpdateManager()
        data = copy.copy(FAKE_SW_UPDATE_DATA)
        data["type"] = consts.SW_UPDATE_TYPE_UPGRADE
        data["force"] = True
        data["cloud_name"] = 'subcloud1'

        self.assertRaises(exceptions.BadRequest,
                          um.create_sw_update_strategy,
                          self.ctxt, payload=data)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    def test_create_sw_update_strategy_offline_subcloud_with_force_patching(
            self, mock_patch_orch_thread):

        # This test verifies that the force option has no effect in
        # patching creation strategy even though the subcloud is offline
        fake_subcloud1 = self.create_subcloud(self.ctxt, 'subcloud1', 1,
                                              is_managed=True, is_online=False)
        self.create_subcloud_status(self.ctxt, fake_subcloud1.id)

        um = sw_update_manager.SwUpdateManager()
        data = copy.copy(FAKE_SW_UPDATE_DATA)
        data["force"] = True
        data["cloud_name"] = 'subcloud1'
        strategy_dict = um.create_sw_update_strategy(self.ctxt, payload=data)

        # Assert that values passed through CLI are used instead of group values
        self.assertEqual(strategy_dict['subcloud-apply-type'],
                         consts.SUBCLOUD_APPLY_TYPE_PARALLEL)

        # Verify the strategy step list
        subcloud_ids = [None]
        stage = [1]
        strategy_step_list = db_api.strategy_step_get_all(self.ctxt)
        for index, strategy_step in enumerate(strategy_step_list):
            self.assertEqual(subcloud_ids[index], strategy_step.subcloud_id)
            self.assertEqual(stage[index], strategy_step.stage)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    def test_delete_sw_update_strategy(self, mock_patch_orch_thread):
        self.create_strategy(self.ctxt,
                             consts.SW_UPDATE_TYPE_PATCH,
                             consts.SW_UPDATE_STATE_INITIAL)
        um = sw_update_manager.SwUpdateManager()
        deleted_strategy = um.delete_sw_update_strategy(self.ctxt)
        self.assertEqual(deleted_strategy['state'],
                         consts.SW_UPDATE_STATE_DELETING)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    def test_delete_sw_update_strategy_scoped(self, mock_patch_orch_thread):
        self.create_strategy(self.ctxt,
                             consts.SW_UPDATE_TYPE_PATCH,
                             consts.SW_UPDATE_STATE_INITIAL)
        um = sw_update_manager.SwUpdateManager()
        deleted_strategy = um.delete_sw_update_strategy(
            self.ctxt,
            update_type=consts.SW_UPDATE_TYPE_PATCH)
        self.assertEqual(deleted_strategy['state'],
                         consts.SW_UPDATE_STATE_DELETING)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    def test_delete_sw_update_strategy_bad_scope(self, mock_patch_orch_thread):
        self.create_strategy(self.ctxt,
                             consts.SW_UPDATE_TYPE_PATCH,
                             consts.SW_UPDATE_STATE_INITIAL)
        um = sw_update_manager.SwUpdateManager()
        # the strategy is PATCH. The delete for UPGRADE should fail
        self.assertRaises(exceptions.NotFound,
                          um.delete_sw_update_strategy,
                          self.ctx,
                          update_type=consts.SW_UPDATE_TYPE_UPGRADE)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    def test_delete_sw_update_strategy_invalid_state(
            self, mock_patch_orch_thread):
        # Create fake strategy
        self.create_strategy(self.ctxt,
                             consts.SW_UPDATE_TYPE_PATCH,
                             consts.SW_UPDATE_STATE_APPLYING)
        um = sw_update_manager.SwUpdateManager()
        self.assertRaises(exceptions.BadRequest,
                          um.delete_sw_update_strategy,
                          self.ctxt)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    def test_apply_sw_update_strategy(self,
                                      mock_patch_orch_thread):
        # Create fake strategy
        self.create_strategy(self.ctxt,
                             consts.SW_UPDATE_TYPE_PATCH,
                             consts.SW_UPDATE_STATE_INITIAL)

        um = sw_update_manager.SwUpdateManager()
        updated_strategy = um.apply_sw_update_strategy(self.ctxt)
        self.assertEqual(updated_strategy['state'], consts.SW_UPDATE_STATE_APPLYING)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    def test_apply_sw_update_strategy_invalid_state(
            self, mock_patch_orch_thread):
        # Create fake strategy
        self.create_strategy(self.ctxt,
                             consts.SW_UPDATE_TYPE_PATCH,
                             consts.SW_UPDATE_STATE_APPLYING)
        um = sw_update_manager.SwUpdateManager()
        self.assertRaises(exceptions.BadRequest,
                          um.apply_sw_update_strategy,
                          self.ctxt)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    def test_abort_sw_update_strategy(
            self, mock_patch_orch_thread):
        # Create fake strategy
        self.create_strategy(self.ctxt,
                             consts.SW_UPDATE_TYPE_PATCH,
                             consts.SW_UPDATE_STATE_APPLYING)

        um = sw_update_manager.SwUpdateManager()
        aborted_strategy = um.abort_sw_update_strategy(self.ctxt)
        self.assertEqual(aborted_strategy['state'], consts.SW_UPDATE_STATE_ABORT_REQUESTED)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    def test_abort_sw_update_strategy_invalid_state(
            self, mock_patch_orch_thread):
        # Create fake strategy
        self.create_strategy(self.ctxt,
                             consts.SW_UPDATE_TYPE_PATCH,
                             consts.SW_UPDATE_STATE_COMPLETE)

        um = sw_update_manager.SwUpdateManager()
        self.assertRaises(exceptions.BadRequest,
                          um.apply_sw_update_strategy,
                          self.ctxt)

    @mock.patch.object(patch_orch_thread, 'SysinvClient')
    @mock.patch.object(os_path, 'isfile')
    @mock.patch.object(patch_orch_thread, 'PatchingClient')
    @mock.patch.object(threading, 'Thread')
    @mock.patch.object(patch_orch_thread, 'db_api')
    def test_update_subcloud_patches(
            self, mock_db_api, mock_threading,
            mock_patching_client, mock_os_path_isfile, mock_sysinv_client):

        mock_patching_client.side_effect = FakePatchingClientOutOfSync
        mock_os_path_isfile.return_value = True
        fake_subcloud = Subcloud(1, 'subcloud1', 1,
                                 is_managed=True, is_online=True)
        data = copy.copy(FAKE_STRATEGY_STEP_DATA)
        data['state'] = consts.STRATEGY_STATE_UPDATING_PATCHES
        data['subcloud'] = fake_subcloud
        data['subcloud_name'] = 'subcloud1'
        fake_strategy_step = StrategyStep(**data)
        mock_sysinv_client.side_effect = FakeSysinvClientOneLoad
        FakePatchingClientOutOfSync.apply = mock.Mock()
        FakePatchingClientOutOfSync.remove = mock.Mock()
        FakePatchingClientOutOfSync.upload = mock.Mock()
        sw_update_manager.PatchOrchThread.stopped = lambda x: False
        mock_strategy_lock = mock.Mock()
        pot = sw_update_manager.PatchOrchThread(mock_strategy_lock,
                                                self.fake_dcmanager_audit_api)
        pot.get_ks_client = mock.Mock()
        pot.update_subcloud_patches(fake_strategy_step)

        assert(compare_call_with_unsorted_list(
            FakePatchingClientOutOfSync.remove.call_args_list[0],
            ['DC.5', 'DC.6']
        ))
        FakePatchingClientOutOfSync.upload.assert_called_with(
            [consts.PATCH_VAULT_DIR + '/17.07/DC.8.patch'])
        assert(compare_call_with_unsorted_list(
            FakePatchingClientOutOfSync.apply.call_args_list[0],
            ['DC.2', 'DC.3', 'DC.8']
        ))
        mock_db_api.strategy_step_update.assert_called_with(
            mock.ANY,
            fake_strategy_step.subcloud_id,
            state=consts.STRATEGY_STATE_CREATING_STRATEGY,
            details=mock.ANY,
            started_at=mock.ANY,
            finished_at=mock.ANY,
        )

    @mock.patch.object(patch_orch_thread, 'SysinvClient')
    @mock.patch.object(os_path, 'isfile')
    @mock.patch.object(patch_orch_thread, 'PatchingClient')
    @mock.patch.object(threading, 'Thread')
    @mock.patch.object(patch_orch_thread, 'db_api')
    def test_update_subcloud_patches_bad_committed(
            self, mock_db_api, mock_threading,
            mock_patching_client, mock_os_path_isfile, mock_sysinv_client):

        mock_os_path_isfile.return_value = True
        fake_subcloud = Subcloud(1, 'subcloud1', 1,
                                 is_managed=True, is_online=True)
        data = copy.copy(FAKE_STRATEGY_STEP_DATA)
        data['state'] = consts.STRATEGY_STATE_UPDATING_PATCHES
        data['subcloud'] = fake_subcloud
        fake_strategy_step = StrategyStep(**data)
        mock_patching_client.side_effect = FakePatchingClientSubcloudCommitted
        mock_sysinv_client.side_effect = FakeSysinvClientOneLoad
        FakePatchingClientOutOfSync.apply = mock.Mock()
        FakePatchingClientOutOfSync.remove = mock.Mock()
        FakePatchingClientOutOfSync.upload = mock.Mock()
        sw_update_manager.PatchOrchThread.stopped = lambda x: False
        mock_strategy_lock = mock.Mock()
        pot = sw_update_manager.PatchOrchThread(mock_strategy_lock,
                                                self.fake_dcmanager_audit_api)
        pot.get_ks_client = mock.Mock()
        pot.update_subcloud_patches(fake_strategy_step)

        mock_db_api.strategy_step_update.assert_called_with(
            mock.ANY,
            fake_strategy_step.subcloud_id,
            state=consts.STRATEGY_STATE_FAILED,
            details=mock.ANY,
            started_at=mock.ANY,
            finished_at=mock.ANY,
        )

    @mock.patch.object(patch_orch_thread, 'SysinvClient')
    @mock.patch.object(os_path, 'isfile')
    @mock.patch.object(patch_orch_thread, 'PatchingClient')
    @mock.patch.object(threading, 'Thread')
    @mock.patch.object(patch_orch_thread, 'db_api')
    def test_update_subcloud_patches_bad_state(
            self, mock_db_api, mock_threading,
            mock_patching_client, mock_os_path_isfile, mock_sysinv_client):

        mock_os_path_isfile.return_value = True
        fake_subcloud = Subcloud(1, 'subcloud1', 1,
                                 is_managed=True, is_online=True)
        data = copy.copy(FAKE_STRATEGY_STEP_DATA)
        data['state'] = consts.STRATEGY_STATE_UPDATING_PATCHES
        data['subcloud'] = fake_subcloud
        fake_strategy_step = StrategyStep(**data)
        mock_patching_client.side_effect = FakePatchingClientSubcloudUnknown
        mock_sysinv_client.side_effect = FakeSysinvClientOneLoad
        FakePatchingClientOutOfSync.apply = mock.Mock()
        FakePatchingClientOutOfSync.remove = mock.Mock()
        FakePatchingClientOutOfSync.upload = mock.Mock()
        sw_update_manager.PatchOrchThread.stopped = lambda x: False
        mock_strategy_lock = mock.Mock()
        pot = sw_update_manager.PatchOrchThread(mock_strategy_lock,
                                                self.fake_dcmanager_audit_api)
        pot.get_ks_client = mock.Mock()
        pot.update_subcloud_patches(fake_strategy_step)

        mock_db_api.strategy_step_update.assert_called_with(
            mock.ANY,
            fake_strategy_step.subcloud_id,
            state=consts.STRATEGY_STATE_FAILED,
            details=mock.ANY,
            started_at=mock.ANY,
            finished_at=mock.ANY,
        )

    @mock.patch.object(os_path, 'isfile')
    @mock.patch.object(patch_orch_thread, 'PatchingClient')
    @mock.patch.object(threading, 'Thread')
    @mock.patch.object(patch_orch_thread, 'db_api')
    def test_finish(
            self, mock_db_api, mock_threading,
            mock_patching_client, mock_os_path_isfile):

        mock_os_path_isfile.return_value = True
        fake_subcloud = Subcloud(1, 'subcloud1', 1,
                                 is_managed=True, is_online=True)
        data = copy.copy(FAKE_STRATEGY_STEP_DATA)
        data['state'] = consts.STRATEGY_STATE_UPDATING_PATCHES
        data['subcloud'] = fake_subcloud
        fake_strategy_step = StrategyStep(**data)
        mock_patching_client.side_effect = FakePatchingClientFinish
        FakePatchingClientFinish.delete = mock.Mock()
        FakePatchingClientFinish.commit = mock.Mock()
        sw_update_manager.PatchOrchThread.stopped = lambda x: False
        mock_strategy_lock = mock.Mock()
        pot = sw_update_manager.PatchOrchThread(mock_strategy_lock,
                                                self.fake_dcmanager_audit_api)
        pot.get_ks_client = mock.Mock()
        pot.finish(fake_strategy_step)

        assert(compare_call_with_unsorted_list(
            FakePatchingClientFinish.delete.call_args_list[0],
            ['DC.5', 'DC.6']
        ))
        assert(compare_call_with_unsorted_list(
            FakePatchingClientFinish.commit.call_args_list[0],
            ['DC.2', 'DC.3']
        ))
        mock_db_api.strategy_step_update.assert_called_with(
            mock.ANY,
            fake_strategy_step.subcloud_id,
            state=consts.STRATEGY_STATE_COMPLETE,
            details=mock.ANY,
            started_at=mock.ANY,
            finished_at=mock.ANY,
        )
