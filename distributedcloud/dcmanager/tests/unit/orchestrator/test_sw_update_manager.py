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

import base64
import copy
import mock
from os import path as os_path
import threading

from oslo_config import cfg

from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common import exceptions
from dcmanager.common import prestage
from dcmanager.db.sqlalchemy import api as db_api
from dcmanager.orchestrator import patch_orch_thread
from dcmanager.orchestrator import sw_update_manager

from dcmanager.tests import base
from dcmanager.tests.unit.common import fake_strategy
from dcmanager.tests.unit.common import fake_subcloud
from dcmanager.tests import utils
from dcorch.common import consts as dcorch_consts


OAM_FLOATING_IP = '10.10.10.12'
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

FAKE_SW_PRESTAGE_DATA = {
    "type": consts.SW_UPDATE_TYPE_PRESTAGE,
    "subcloud-apply-type": consts.SUBCLOUD_APPLY_TYPE_PARALLEL,
    "max-parallel-subclouds": "2",
    "stop-on-failure": "true",
    "force": "false",
    "state": consts.SW_UPDATE_STATE_INITIAL,
}

FAKE_STRATEGY_STEP_DATA = {
    "id": 1,
    "subcloud_id": 1,
    "stage": 1,
    "state": consts.STRATEGY_STATE_INITIAL,
    "details": '',
    "subcloud": None
}

health_report_no_mgmt_alarm = \
    "System Health:\n \
    All hosts are provisioned: [Fail]\n \
    1 Unprovisioned hosts\n \
    All hosts are unlocked/enabled: [OK]\n \
    All hosts have current configurations: [OK]\n \
    All hosts are patch current: [OK]\n \
    No alarms: [OK]\n \
    All kubernetes nodes are ready: [OK]\n \
    All kubernetes control plane pods are ready: [OK]"


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
    def __init__(self, region, session, endpoint):
        super(FakePatchingClientOutOfSync, self).__init__()
        self.region = region
        self.session = session
        self.endpoint = endpoint

    def query(self, state=None):
        if state == 'Committed':
            if self.region == consts.DEFAULT_REGION_NAME:
                return {'DC.3': {'sw_version': '17.07',
                                 'repostate': 'Committed',
                                 'patchstate': 'Committed'}
                        }
            else:
                return {}
        else:
            if self.region == consts.DEFAULT_REGION_NAME:
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
    def __init__(self, region, session, endpoint):
        super(FakePatchingClientSubcloudCommitted, self).__init__()
        self.region = region
        self.session = session
        self.endpoint = endpoint

    def query(self, state=None):
        if state == 'Committed':
            if self.region == consts.DEFAULT_REGION_NAME:
                return {'DC.3': {'sw_version': '17.07',
                                 'repostate': 'Committed',
                                 'patchstate': 'Committed'}
                        }
            elif self.region == 'subcloud1':
                return {'DC.5': {'sw_version': '17.07',
                                 'repostate': 'Committed',
                                 'patchstate': 'Committed'},

                        }
            else:
                return {}
        else:
            if self.region == consts.DEFAULT_REGION_NAME:
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
    def __init__(self, region, session, endpoint):
        super(FakePatchingClientSubcloudUnknown, self).__init__()
        self.region = region
        self.session = session
        self.endpoint = endpoint

    def query(self, state=None):
        if state == 'Committed':
            if self.region == consts.DEFAULT_REGION_NAME:
                return {'DC.3': {'sw_version': '17.07',
                                 'repostate': 'Committed',
                                 'patchstate': 'Committed'}
                        }
            else:
                return {}
        else:
            if self.region == consts.DEFAULT_REGION_NAME:
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


class FakePatchingClientAvailable(mock.Mock):
    def __init__(self, region, session, endpoint):
        super(FakePatchingClientAvailable, self).__init__()
        self.region = region
        self.session = session
        self.endpoint = endpoint

    def query(self, state=None):
        if self.region == consts.DEFAULT_REGION_NAME:
            if state == 'Committed':
                return {'DC.1': {'sw_version': '17.07',
                                 'repostate': 'Committed',
                                 'patchstate': 'Committed'},
                        }
            else:
                return {'DC.1': {'sw_version': '17.07',
                                 'repostate': 'Applied',
                                 'patchstate': 'Applied'},
                        }

        elif self.region == 'subcloud1':
            if state != 'Committed':
                return {'DC.1': {'sw_version': '17.07',
                                 'repostate': 'Available',
                                 'patchstate': 'Available'},
                        }

        else:
            return {}

    def query_hosts(self):
        return []


class FakePatchingClientFinish(mock.Mock):
    def __init__(self, region, session, endpoint):
        super(FakePatchingClientFinish, self).__init__()
        self.region = region
        self.session = session
        self.endpoint = endpoint

    def query(self, state=None):
        if self.region == consts.DEFAULT_REGION_NAME:
            if state == 'Committed':
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
            if state == 'Committed':
                return {'DC.4': {'sw_version': '17.07',
                                 'repostate': 'Committed',
                                 'patchstate': 'Committed'},
                        }
            else:
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
    def __init__(self, region, session, endpoint):
        self.region = region
        self.session = session
        self.endpoint = endpoint
        self.loads = [Load('17.07')]
        self.health_report =   \
            "System Health:\n \
            All hosts are provisioned: [Fail]\n \
            1 Unprovisioned hosts\n \
            All hosts are unlocked/enabled: [OK]\n \
            All hosts have current configurations: [OK]\n \
            All hosts are patch current: [OK]\n \
            No alarms: [OK]\n \
            All kubernetes nodes are ready: [OK]\n \
            All kubernetes control plane pods are ready: [OK]"

    def get_loads(self):
        return self.loads

    def get_system_health(self):
        return self.health_report


class FakeSysinvClientNoMgmtAffectAlarm(object):
    def __init__(self, region, session, endpoint):
        self.region = region
        self.session = session
        self.endpoint = endpoint
        self.loads = [Load('17.07')]
        self.no_mgmt_alarm = True

        self.health_report =   \
            "System Health:\n" \
            "All hosts are provisioned: [OK]\n" \
            "All hosts are unlocked/enabled: [OK]\n" \
            "All hosts have current configurations: [OK]\n" \
            "All hosts are patch current: [OK]\n" \
            "Ceph Storage Healthy: [OK]\n" \
            "No alarms: [Fail]\n" \
            "[1] alarms found, [0] of which are management affecting\n" \
            "All kubernetes nodes are ready: [OK]\n" \
            "All kubernetes control plane pods are ready: [OK]"

    def get_loads(self):
        return self.loads

    def get_system_health(self):
        return self.health_report


class FakeSysinvClientMgmtAffectAlarm(object):
    def __init__(self, region, session, endpoint):
        self.region = region
        self.session = session
        self.endpoint = endpoint
        self.loads = [Load('17.07')]
        self.no_mgmt_alarm = True

        self.health_report =   \
            "System Health:\n" \
            "All hosts are provisioned: [OK]\n" \
            "All hosts are unlocked/enabled: [OK]\n" \
            "All hosts have current configurations: [OK]\n" \
            "All hosts are patch current: [OK]\n" \
            "Ceph Storage Healthy: [OK]\n" \
            "No alarms: [Fail]\n" \
            "[1] alarms found, [1] of which are management affecting\n" \
            "All kubernetes nodes are ready: [OK]\n" \
            "All kubernetes control plane pods are ready: [OK]"

    def get_loads(self):
        return self.loads

    def get_system_health(self):
        return self.health_report


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

        self.fake_kube_upgrade_orch_thread = FakeOrchThread()
        p = mock.patch.object(sw_update_manager, 'KubeUpgradeOrchThread')
        self.mock_kube_upgrade_orch_thread = p.start()
        self.mock_kube_upgrade_orch_thread.return_value = \
            self.fake_kube_upgrade_orch_thread
        self.addCleanup(p.stop)

        self.fake_kube_rootca_update_orch_thread = FakeOrchThread()
        p = mock.patch.object(sw_update_manager, 'KubeRootcaUpdateOrchThread')
        self.mock_kube_rootca_update_orch_thread = p.start()
        self.mock_kube_rootca_update_orch_thread.return_value = \
            self.fake_kube_rootca_update_orch_thread
        self.addCleanup(p.stop)

        self.fake_prestage_orch_thread = FakeOrchThread()
        p = mock.patch.object(sw_update_manager, 'PrestageOrchThread')
        self.mock_prestage_orch_thread = p.start()
        self.mock_prestage_orch_thread.return_value = \
            self.fake_prestage_orch_thread
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
    def test_create_sw_update_strategy_no_subclouds(
            self, mock_patch_orch_thread):
        um = sw_update_manager.SwUpdateManager()
        response = um.create_sw_update_strategy(
            self.ctxt, payload=FAKE_SW_UPDATE_DATA)

        # Verify strategy was created as expected
        self.assertEqual(response['type'],
                         FAKE_SW_UPDATE_DATA['type'])

        # Verify strategy step was created as expected
        strategy_steps = db_api.strategy_step_get_all(self.ctx)
        self.assertEqual(strategy_steps[0]['state'],
                         consts.STRATEGY_STATE_INITIAL)
        self.assertEqual(strategy_steps[0]['stage'],
                         1)
        self.assertEqual(strategy_steps[0]['details'],
                         '')
        self.assertEqual(strategy_steps[0]['subcloud_id'],
                         None)
        self.assertRaises(exceptions.BadRequest,
                          um.create_sw_update_strategy,
                          self.ctxt, payload=FAKE_SW_UPDATE_DATA)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    def test_create_sw_update_strategy_for_a_single_group(
            self, mock_patch_orch_thread):
        # Create fake subclouds and respective status
        # Subcloud1 will be patched
        fake_subcloud1 = self.create_subcloud(self.ctxt, 'subcloud1',
                                              self.fake_group2.id,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud1.id)

        # Subcloud2 will not be patched because not managed
        fake_subcloud2 = self.create_subcloud(self.ctxt, 'subcloud2',
                                              self.fake_group2.id,
                                              is_managed=False, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud2.id)

        data = copy.copy(FAKE_SW_UPDATE_DATA)
        data['subcloud_group'] = str(self.fake_group2.id)
        um = sw_update_manager.SwUpdateManager()
        response = um.create_sw_update_strategy(
            self.ctxt, payload=data)

        # Verify strategy was created as expected using group values
        self.assertEqual(response['max-parallel-subclouds'], 2)
        self.assertEqual(response['subcloud-apply-type'],
                         consts.SUBCLOUD_APPLY_TYPE_SERIAL)
        self.assertEqual(response['type'],
                         FAKE_SW_UPDATE_DATA['type'])

        # Verify strategy step was created as expected
        strategy_steps = db_api.strategy_step_get_all(self.ctx)
        self.assertEqual(strategy_steps[0]['state'],
                         consts.STRATEGY_STATE_INITIAL)
        self.assertEqual(strategy_steps[0]['stage'],
                         1)
        self.assertEqual(strategy_steps[0]['details'],
                         '')
        self.assertEqual(strategy_steps[0]['subcloud_id'],
                         None)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    def test_create_sw_update_strategy_parallel_for_a_single_group(
            self, mock_patch_orch_thread):
        # Create fake subclouds and respective status
        fake_subcloud1 = self.create_subcloud(self.ctxt, 'subcloud1',
                                              self.fake_group3.id,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud1.id,
                                    endpoint=dcorch_consts.ENDPOINT_TYPE_LOAD)

        fake_subcloud2 = self.create_subcloud(self.ctxt, 'subcloud2',
                                              self.fake_group3.id,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud2.id,
                                    endpoint=dcorch_consts.ENDPOINT_TYPE_LOAD)

        data = copy.copy(FAKE_SW_UPDATE_DATA)
        data["type"] = consts.SW_UPDATE_TYPE_UPGRADE
        data['subcloud_group'] = str(self.fake_group3.id)
        um = sw_update_manager.SwUpdateManager()
        response = um.create_sw_update_strategy(
            self.ctxt, payload=data)

        # Verify strategy was created as expected using group values
        self.assertEqual(response['max-parallel-subclouds'], 2)
        self.assertEqual(response['subcloud-apply-type'],
                         consts.SUBCLOUD_APPLY_TYPE_PARALLEL)
        self.assertEqual(response['type'], consts.SW_UPDATE_TYPE_UPGRADE)

        # Verify the strategy step list
        subcloud_ids = [1, 2]
        stage = [1, 1]
        strategy_step_list = db_api.strategy_step_get_all(self.ctxt)
        for index, strategy_step in enumerate(strategy_step_list):
            self.assertEqual(subcloud_ids[index], strategy_step.subcloud_id)
            self.assertEqual(stage[index], strategy_step.stage)

    @mock.patch.object(prestage, 'initial_subcloud_validate')
    @mock.patch.object(prestage, 'global_prestage_validate')
    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    def test_create_sw_prestage_strategy_parallel_for_a_single_group(
            self,
            mock_patch_orch_thread,
            mock_global_prestage_validate,
            mock_initial_subcloud_validate):

        # Create fake subclouds and respective status
        fake_subcloud1 = self.create_subcloud(self.ctxt, 'subcloud1',
                                              self.fake_group3.id,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud1.id,
                                    endpoint=dcorch_consts.ENDPOINT_TYPE_LOAD)

        fake_subcloud2 = self.create_subcloud(self.ctxt, 'subcloud2',
                                              self.fake_group3.id,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud2.id,
                                    endpoint=dcorch_consts.ENDPOINT_TYPE_LOAD)

        mock_global_prestage_validate.return_value = None
        mock_initial_subcloud_validate.return_value = None

        data = copy.copy(FAKE_SW_PRESTAGE_DATA)
        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data['sysadmin_password'] = fake_password

        data['subcloud_group'] = str(self.fake_group3.id)
        um = sw_update_manager.SwUpdateManager()
        response = um.create_sw_update_strategy(
            self.ctxt, payload=data)

        # Verify strategy was created as expected using group values
        self.assertEqual(response['max-parallel-subclouds'], 2)
        self.assertEqual(response['subcloud-apply-type'],
                         consts.SUBCLOUD_APPLY_TYPE_PARALLEL)
        self.assertEqual(response['type'], consts.SW_UPDATE_TYPE_PRESTAGE)

        # Verify the strategy step list
        subcloud_ids = [1, 2]
        stage = [1, 1]
        strategy_step_list = db_api.strategy_step_get_all(self.ctxt)
        for index, strategy_step in enumerate(strategy_step_list):
            self.assertEqual(subcloud_ids[index], strategy_step.subcloud_id)
            self.assertEqual(stage[index], strategy_step.stage)

    @mock.patch.object(prestage, 'initial_subcloud_validate')
    @mock.patch.object(prestage, 'global_prestage_validate')
    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    def test_create_sw_prestage_strategy_load_in_sync_out_of_sync_unknown_and_no_load(
            self,
            mock_patch_orch_thread,
            mock_global_prestage_validate,
            mock_initial_subcloud_validate):

        # Create fake subclouds and respective status
        # Subcloud1 will be prestaged load in sync
        fake_subcloud1 = self.create_subcloud(self.ctxt, 'subcloud1', 1,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt,
                                    fake_subcloud1.id,
                                    dcorch_consts.ENDPOINT_TYPE_LOAD,
                                    consts.SYNC_STATUS_IN_SYNC)

        # Subcloud2 will not be prestaged because endpoint is None
        fake_subcloud2 = self.create_subcloud(self.ctxt, 'subcloud2', 1,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt,
                                    fake_subcloud2.id,
                                    None,
                                    consts.SYNC_STATUS_IN_SYNC)

        # Subcloud3 will be prestaged load out of sync
        fake_subcloud3 = self.create_subcloud(self.ctxt, 'subcloud3', 1,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt,
                                    fake_subcloud3.id,
                                    dcorch_consts.ENDPOINT_TYPE_LOAD,
                                    consts.SYNC_STATUS_OUT_OF_SYNC)

        # Subcloud2 will be prestaged sync unknown
        fake_subcloud4 = self.create_subcloud(self.ctxt, 'subcloud4', 2,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt,
                                    fake_subcloud4.id,
                                    dcorch_consts.ENDPOINT_TYPE_LOAD,
                                    consts.SYNC_STATUS_UNKNOWN)

        mock_global_prestage_validate.return_value = None
        mock_initial_subcloud_validate.return_value = None

        data = copy.copy(FAKE_SW_PRESTAGE_DATA)
        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data['sysadmin_password'] = fake_password

        um = sw_update_manager.SwUpdateManager()
        response = um.create_sw_update_strategy(
            self.ctxt, payload=data)

        # Verify strategy was created as expected using group values
        self.assertEqual(response['max-parallel-subclouds'], 2)
        self.assertEqual(response['subcloud-apply-type'],
                         consts.SUBCLOUD_APPLY_TYPE_PARALLEL)
        self.assertEqual(response['type'], consts.SW_UPDATE_TYPE_PRESTAGE)

        # Verify the strategy step list
        subcloud_ids = [1, 3, 4]
        stage = [1, 1, 2]
        strategy_step_list = db_api.strategy_step_get_all(self.ctxt)
        for index, strategy_step in enumerate(strategy_step_list):
            self.assertEqual(subcloud_ids[index], strategy_step.subcloud_id)
            self.assertEqual(stage[index], strategy_step.stage)

    @mock.patch.object(prestage, 'initial_subcloud_validate')
    @mock.patch.object(prestage, '_get_system_controller_upgrades')
    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    def test_create_sw_prestage_strategy_no_password(self,
                                                     mock_patch_orch_thread,
                                                     mock_controller_upgrade,
                                                     mock_initial_subcloud_validate):

        # Create fake subclouds and respective status
        fake_subcloud1 = self.create_subcloud(self.ctxt, 'subcloud1',
                                              self.fake_group3.id,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud1.id,
                                    endpoint=dcorch_consts.ENDPOINT_TYPE_LOAD)

        fake_subcloud2 = self.create_subcloud(self.ctxt, 'subcloud2',
                                              self.fake_group3.id,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud2.id,
                                    endpoint=dcorch_consts.ENDPOINT_TYPE_LOAD)

        mock_initial_subcloud_validate.return_value = None
        mock_controller_upgrade.return_value = list()

        data = copy.copy(FAKE_SW_PRESTAGE_DATA)
        data['sysadmin_password'] = ''
        data['subcloud_group'] = str(self.fake_group3.id)
        um = sw_update_manager.SwUpdateManager()

        self.assertRaises(exceptions.BadRequest,
                          um.create_sw_update_strategy,
                          self.ctxt, payload=data)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    def test_create_sw_update_strategy_cloud_name_not_exists(self,
                                                             mock_patch_orch_thread):
        # Create fake subclouds and respective status
        fake_subcloud1 = self.create_subcloud(self.ctxt, 'subcloud1',
                                              self.fake_group3.id,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud1.id)

        data = copy.copy(FAKE_SW_UPDATE_DATA)

        # Create a strategy with a cloud_name that doesn't exist
        data['cloud_name'] = 'subcloud2'
        um = sw_update_manager.SwUpdateManager()
        self.assertRaises(exceptions.BadRequest,
                          um.create_sw_update_strategy,
                          self.ctxt, payload=data)

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

    @mock.patch.object(prestage, 'initial_subcloud_validate')
    @mock.patch.object(prestage, '_get_system_controller_upgrades')
    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    def test_create_sw_prestage_strategy_parallel(self,
                                                  mock_patch_orch_thread,
                                                  mock_controller_upgrade,
                                                  mock_initial_subcloud_validate):

        # Create fake subclouds and respective status
        # Subcloud1 will be prestaged
        fake_subcloud1 = self.create_subcloud(self.ctxt, 'subcloud1', 1,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud1.id,
                                    endpoint=dcorch_consts.ENDPOINT_TYPE_LOAD)

        # Subcloud2 will not be prestaged because not managed
        fake_subcloud2 = self.create_subcloud(self.ctxt, 'subcloud2', 1,
                                              is_managed=False, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud2.id,
                                    endpoint=dcorch_consts.ENDPOINT_TYPE_LOAD)

        # Subcloud3 will be prestaged
        fake_subcloud3 = self.create_subcloud(self.ctxt, 'subcloud3', 1,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud3.id,
                                    endpoint=dcorch_consts.ENDPOINT_TYPE_LOAD)

        # Subcloud4 will not be prestaged because endpoint is None
        fake_subcloud4 = self.create_subcloud(self.ctxt, 'subcloud4', 2,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt,
                                    fake_subcloud4.id,
                                    None,
                                    consts.SYNC_STATUS_IN_SYNC)
        # Subcloud5 will be prestaged
        fake_subcloud5 = self.create_subcloud(self.ctxt, 'subcloud5', 2,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud5.id,
                                    endpoint=dcorch_consts.ENDPOINT_TYPE_LOAD)

        # Subcloud6 will be prestaged
        fake_subcloud6 = self.create_subcloud(self.ctxt, 'subcloud6', 3,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud6.id,
                                    endpoint=dcorch_consts.ENDPOINT_TYPE_LOAD)

        # Subcloud7 will be prestaged
        fake_subcloud7 = self.create_subcloud(self.ctxt, 'subcloud7', 3,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud7.id,
                                    endpoint=dcorch_consts.ENDPOINT_TYPE_LOAD)

        data = copy.copy(FAKE_SW_PRESTAGE_DATA)
        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data['sysadmin_password'] = fake_password

        um = sw_update_manager.SwUpdateManager()
        strategy_dict = um.create_sw_update_strategy(self.ctxt, payload=data)

        mock_initial_subcloud_validate.return_value = None
        mock_controller_upgrade.return_value = list()

        # Assert that values passed through CLI are used instead of group values
        self.assertEqual(strategy_dict['max-parallel-subclouds'], 2)
        self.assertEqual(strategy_dict['subcloud-apply-type'],
                         consts.SUBCLOUD_APPLY_TYPE_PARALLEL)

        # Verify the strategy step list
        subcloud_ids = [1, 3, 5, 6, 7]
        stage = [1, 1, 2, 3, 3]
        strategy_step_list = db_api.strategy_step_get_all(self.ctxt)
        subcloud_id_processed = []
        stage_processed = []
        for index, strategy_step in enumerate(strategy_step_list):
                subcloud_id_processed.append(strategy_step.subcloud_id)
                stage_processed.append(strategy_step.stage)
        self.assertEqual(subcloud_ids, subcloud_id_processed)
        self.assertEqual(stage, stage_processed)

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

        # Subcloud4 will not be patched because patching is not in sync
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

    @mock.patch.object(prestage, '_get_prestage_subcloud_info')
    @mock.patch.object(prestage, '_get_system_controller_upgrades')
    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    def test_create_sw_prestage_strategy_unknown_sync_status(
            self,
            mock_patch_orch_thread,
            mock_controller_upgrade,
            mock_prestage_subcloud_info):

        # Create fake subclouds and respective status
        # Subcloud1 will be prestaged
        fake_subcloud1 = self.create_subcloud(self.ctxt, 'subcloud1', 1,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud1.id)

        # Subcloud2 will not be prestaged because not managed
        fake_subcloud2 = self.create_subcloud(self.ctxt, 'subcloud2', 1,
                                              is_managed=False, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud2.id)

        # Subcloud3 will be prestaged
        fake_subcloud3 = self.create_subcloud(self.ctxt, 'subcloud3', 1,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud3.id)

        # Subcloud4 will not be prestaged because endpoint is None
        fake_subcloud4 = self.create_subcloud(self.ctxt, 'subcloud4', 2,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt,
                                    fake_subcloud4.id,
                                    None,
                                    consts.SYNC_STATUS_UNKNOWN)

        data = copy.copy(FAKE_SW_PRESTAGE_DATA)
        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data['sysadmin_password'] = fake_password

        mock_controller_upgrade.return_value = list()
        mock_prestage_subcloud_info.return_value = consts.SYSTEM_MODE_SIMPLEX, \
            health_report_no_mgmt_alarm, \
            OAM_FLOATING_IP

        um = sw_update_manager.SwUpdateManager()
        self.assertRaises(exceptions.BadRequest,
                          um.create_sw_update_strategy,
                          self.ctxt, payload=data)

    @mock.patch.object(prestage, '_get_prestage_subcloud_info')
    @mock.patch.object(prestage, '_get_system_controller_upgrades')
    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    def test_create_sw_prestage_strategy_duplex(self,
                                                mock_patch_orch_thread,
                                                mock_controller_upgrade,
                                                mock_prestage_subcloud_info):

        # Create fake subclouds and respective status
        # Subcloud1 will not be prestaged because later find out it is a duplex
        fake_subcloud = self.create_subcloud(self.ctxt, 'subcloud1', 1,
                                             is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt, fake_subcloud.id)

        data = copy.copy(FAKE_SW_PRESTAGE_DATA)
        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data['sysadmin_password'] = fake_password

        mock_controller_upgrade.return_value = list()
        mock_prestage_subcloud_info.return_value = consts.SYSTEM_MODE_DUPLEX, \
            health_report_no_mgmt_alarm, \
            OAM_FLOATING_IP

        um = sw_update_manager.SwUpdateManager()
        self.assertRaises(exceptions.BadRequest,
                          um.create_sw_update_strategy,
                          self.ctxt, payload=data)

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
        data["max-parallel-subclouds"] = 10
        strategy_dict = um.create_sw_update_strategy(self.ctxt, payload=data)

        # Assert that values passed through CLI are used instead of group values
        self.assertEqual(strategy_dict['max-parallel-subclouds'], 10)
        self.assertEqual(strategy_dict['subcloud-apply-type'],
                         consts.SUBCLOUD_APPLY_TYPE_PARALLEL)
        self.assertEqual(strategy_dict['type'], consts.SW_UPDATE_TYPE_PATCH)

        # Verify the strategy step list
        subcloud_ids = [None, 2, 3, 4]
        stage = [1, 2, 2, 2]
        strategy_step_list = db_api.strategy_step_get_all(self.ctxt)
        for index, strategy_step in enumerate(strategy_step_list):
            self.assertEqual(subcloud_ids[index], strategy_step.subcloud_id)
            self.assertEqual(stage[index], strategy_step.stage)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    def test_create_sw_update_strategy_with_force_option(
            self, mock_patch_orch_thread):

        # Subcloud 1 will be upgraded because force is true
        fake_subcloud1 = self.create_subcloud(self.ctxt, 'subcloud1', self.fake_group3.id,
                                              is_managed=True, is_online=False)
        self.create_subcloud_status(self.ctxt,
                                    fake_subcloud1.id,
                                    dcorch_consts.ENDPOINT_TYPE_LOAD,
                                    consts.SYNC_STATUS_OUT_OF_SYNC)

        # Subcloud 2 will be upgraded
        fake_subcloud2 = self.create_subcloud(self.ctxt, 'subcloud2', self.fake_group3.id,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt,
                                    fake_subcloud2.id,
                                    dcorch_consts.ENDPOINT_TYPE_LOAD,
                                    consts.SYNC_STATUS_OUT_OF_SYNC)

        # Subcloud 3 will not be upgraded because it is already load in-sync
        fake_subcloud3 = self.create_subcloud(self.ctxt, 'subcloud3', self.fake_group3.id,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt,
                                    fake_subcloud3.id,
                                    dcorch_consts.ENDPOINT_TYPE_LOAD,
                                    consts.SYNC_STATUS_IN_SYNC)

        data = copy.copy(FAKE_SW_UPDATE_DATA)
        data["type"] = consts.SW_UPDATE_TYPE_UPGRADE
        data["force"] = "true"
        data['subcloud_group'] = str(self.fake_group3.id)

        um = sw_update_manager.SwUpdateManager()
        strategy_dict = um.create_sw_update_strategy(self.ctxt, payload=data)

        # Assert that values passed through CLI are used instead of group values
        self.assertEqual(strategy_dict['subcloud-apply-type'],
                         consts.SUBCLOUD_APPLY_TYPE_PARALLEL)
        self.assertEqual(strategy_dict['type'], consts.SW_UPDATE_TYPE_UPGRADE)

        subcloud_ids = [1, 2]
        stage = [1, 1]
        strategy_step_list = db_api.strategy_step_get_all(self.ctxt)
        for index, strategy_step in enumerate(strategy_step_list):
            self.assertEqual(subcloud_ids[index], strategy_step.subcloud_id)
            self.assertEqual(stage[index], strategy_step.stage)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    def test_create_sw_update_strategy_without_force_option(
            self, mock_patch_orch_thread):

        # Subcloud 1 will not be upgraded
        fake_subcloud1 = self.create_subcloud(self.ctxt, 'subcloud1', self.fake_group3.id,
                                              is_managed=True, is_online=False)
        self.create_subcloud_status(self.ctxt,
                                    fake_subcloud1.id,
                                    dcorch_consts.ENDPOINT_TYPE_LOAD,
                                    consts.SYNC_STATUS_OUT_OF_SYNC)

        # Subcloud 2 will be upgraded
        fake_subcloud2 = self.create_subcloud(self.ctxt, 'subcloud2', self.fake_group3.id,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt,
                                    fake_subcloud2.id,
                                    dcorch_consts.ENDPOINT_TYPE_LOAD,
                                    consts.SYNC_STATUS_OUT_OF_SYNC)

        # Subcloud 3 will not be upgraded because it is already load in-sync
        fake_subcloud3 = self.create_subcloud(self.ctxt, 'subcloud3', self.fake_group3.id,
                                              is_managed=True, is_online=True)
        self.create_subcloud_status(self.ctxt,
                                    fake_subcloud3.id,
                                    dcorch_consts.ENDPOINT_TYPE_LOAD,
                                    consts.SYNC_STATUS_IN_SYNC)

        data = copy.copy(FAKE_SW_UPDATE_DATA)
        data["type"] = consts.SW_UPDATE_TYPE_UPGRADE
        data["force"] = "false"
        data['subcloud_group'] = str(self.fake_group3.id)

        um = sw_update_manager.SwUpdateManager()
        strategy_dict = um.create_sw_update_strategy(self.ctxt, payload=data)

        # Assert that values passed through CLI are used instead of group values
        self.assertEqual(strategy_dict['subcloud-apply-type'],
                         consts.SUBCLOUD_APPLY_TYPE_PARALLEL)
        self.assertEqual(strategy_dict['type'], consts.SW_UPDATE_TYPE_UPGRADE)

        subcloud_ids = [2]
        stage = [1]
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
        data["force"] = "true"
        data["cloud_name"] = 'subcloud1'

        strategy_dict = um.create_sw_update_strategy(self.ctxt, payload=data)

        # Assert that values passed through CLI are used instead of group values
        self.assertEqual(strategy_dict['subcloud-apply-type'],
                         consts.SUBCLOUD_APPLY_TYPE_PARALLEL)
        self.assertEqual(strategy_dict['type'], consts.SW_UPDATE_TYPE_UPGRADE)

        # Verify the strategy step list
        subcloud_ids = [1]
        stage = [1]
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
    def test_update_subcloud_patches_no_management_affected_alarm(
            self, mock_threading,
            mock_patching_client, mock_os_path_isfile, mock_sysinv_client):

        subcloud_id = fake_subcloud.create_fake_subcloud(self.ctx).id
        subcloud = db_api.subcloud_update(
            self.ctx,
            subcloud_id,
            management_state=consts.MANAGEMENT_MANAGED,
            availability_status=consts.AVAILABILITY_ONLINE)
        fake_strategy.create_fake_strategy_step(
            self.ctx,
            subcloud_id=subcloud.id,
            state=consts.STRATEGY_STATE_UPDATING_PATCHES)
        strategy_step = db_api.strategy_step_get_by_name(self.ctx, subcloud.name)

        mock_os_path_isfile.return_value = True
        mock_patching_client.side_effect = FakePatchingClientAvailable
        mock_sysinv_client.side_effect = FakeSysinvClientNoMgmtAffectAlarm

        FakePatchingClientAvailable.apply = mock.Mock()

        sw_update_manager.PatchOrchThread.stopped = lambda x: False
        mock_strategy_lock = mock.Mock()
        pot = sw_update_manager.PatchOrchThread(mock_strategy_lock,
                                                self.fake_dcmanager_audit_api)
        pot.get_ks_client = mock.Mock()

        # invoke get_region_one_patches once t update required attributes
        pot.get_region_one_patches()
        pot.update_subcloud_patches(strategy_step)

        # Verify that strategy step was updated
        updated_strategy_steps = db_api.strategy_step_get_all(self.ctx)
        self.assertEqual(updated_strategy_steps[0]['state'],
                         consts.STRATEGY_STATE_CREATING_STRATEGY)

    @mock.patch.object(patch_orch_thread, 'SysinvClient')
    @mock.patch.object(os_path, 'isfile')
    @mock.patch.object(patch_orch_thread, 'PatchingClient')
    @mock.patch.object(threading, 'Thread')
    def test_update_subcloud_patches_no_alarm(
            self, mock_threading,
            mock_patching_client, mock_os_path_isfile, mock_sysinv_client):

        subcloud_id = fake_subcloud.create_fake_subcloud(self.ctx).id
        subcloud = db_api.subcloud_update(
            self.ctx,
            subcloud_id,
            management_state=consts.MANAGEMENT_MANAGED,
            availability_status=consts.AVAILABILITY_ONLINE)
        fake_strategy.create_fake_strategy_step(
            self.ctx,
            subcloud_id=subcloud.id,
            state=consts.STRATEGY_STATE_UPDATING_PATCHES)
        strategy_step = db_api.strategy_step_get_by_name(self.ctx, subcloud.name)

        mock_os_path_isfile.return_value = True
        mock_patching_client.side_effect = FakePatchingClientAvailable
        mock_sysinv_client.side_effect = FakeSysinvClientOneLoad

        FakePatchingClientAvailable.apply = mock.Mock()

        sw_update_manager.PatchOrchThread.stopped = lambda x: False
        mock_strategy_lock = mock.Mock()
        pot = sw_update_manager.PatchOrchThread(mock_strategy_lock,
                                                self.fake_dcmanager_audit_api)
        pot.get_ks_client = mock.Mock()

        # invoke get_region_one_patches once t update required attributes
        pot.get_region_one_patches()
        pot.update_subcloud_patches(strategy_step)

        # Verify that strategy step was updated
        updated_strategy_steps = db_api.strategy_step_get_all(self.ctx)
        self.assertEqual(updated_strategy_steps[0]['state'],
                         consts.STRATEGY_STATE_CREATING_STRATEGY)

    @mock.patch.object(patch_orch_thread, 'SysinvClient')
    @mock.patch.object(os_path, 'isfile')
    @mock.patch.object(patch_orch_thread, 'PatchingClient')
    @mock.patch.object(threading, 'Thread')
    def test_update_subcloud_patches_management_affected_alarm(
            self, mock_threading,
            mock_patching_client, mock_os_path_isfile, mock_sysinv_client):

        subcloud_id = fake_subcloud.create_fake_subcloud(self.ctx).id
        subcloud = db_api.subcloud_update(
            self.ctx,
            subcloud_id,
            management_state=consts.MANAGEMENT_MANAGED,
            availability_status=consts.AVAILABILITY_ONLINE)
        fake_strategy.create_fake_strategy_step(
            self.ctx,
            subcloud_id=subcloud.id,
            state=consts.STRATEGY_STATE_UPDATING_PATCHES)
        strategy_step = db_api.strategy_step_get_by_name(self.ctx, subcloud.name)

        mock_os_path_isfile.return_value = True
        mock_patching_client.side_effect = FakePatchingClientAvailable
        mock_sysinv_client.side_effect = FakeSysinvClientMgmtAffectAlarm

        FakePatchingClientAvailable.apply = mock.Mock()

        sw_update_manager.PatchOrchThread.stopped = lambda x: False
        mock_strategy_lock = mock.Mock()
        pot = sw_update_manager.PatchOrchThread(mock_strategy_lock,
                                                self.fake_dcmanager_audit_api)
        pot.get_ks_client = mock.Mock()

        # invoke get_region_one_patches once t update required attributes
        pot.get_region_one_patches()
        pot.update_subcloud_patches(strategy_step)

        # Verify that strategy step was updated
        updated_strategy_steps = db_api.strategy_step_get_all(self.ctx)
        self.assertEqual(updated_strategy_steps[0]['state'],
                         consts.STRATEGY_STATE_FAILED)

    @mock.patch.object(patch_orch_thread, 'SysinvClient')
    @mock.patch.object(os_path, 'isfile')
    @mock.patch.object(patch_orch_thread, 'PatchingClient')
    @mock.patch.object(threading, 'Thread')
    def test_update_subcloud_patches(
            self, mock_threading,
            mock_patching_client, mock_os_path_isfile, mock_sysinv_client):

        subcloud_id = fake_subcloud.create_fake_subcloud(self.ctx).id
        subcloud = db_api.subcloud_update(
            self.ctx,
            subcloud_id,
            management_state=consts.MANAGEMENT_MANAGED,
            availability_status=consts.AVAILABILITY_ONLINE)
        fake_strategy.create_fake_strategy_step(
            self.ctx,
            subcloud_id=subcloud.id,
            state=consts.STRATEGY_STATE_UPDATING_PATCHES)
        strategy_step = db_api.strategy_step_get_by_name(self.ctx, subcloud.name)

        mock_patching_client.side_effect = FakePatchingClientOutOfSync
        mock_os_path_isfile.return_value = True
        mock_sysinv_client.side_effect = FakeSysinvClientOneLoad
        FakePatchingClientOutOfSync.apply = mock.Mock()
        FakePatchingClientOutOfSync.remove = mock.Mock()
        FakePatchingClientOutOfSync.upload = mock.Mock()
        sw_update_manager.PatchOrchThread.stopped = lambda x: False
        mock_strategy_lock = mock.Mock()
        pot = sw_update_manager.PatchOrchThread(mock_strategy_lock,
                                                self.fake_dcmanager_audit_api)
        pot.get_ks_client = mock.Mock()
        # invoke get_region_one_patches once to update required attributes
        pot.get_region_one_patches()
        pot.update_subcloud_patches(strategy_step)

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

        # Verify that strategy step was updated
        updated_strategy_steps = db_api.strategy_step_get_all(self.ctx)
        self.assertEqual(updated_strategy_steps[0]['state'],
                         consts.STRATEGY_STATE_CREATING_STRATEGY)

    @mock.patch.object(patch_orch_thread, 'SysinvClient')
    @mock.patch.object(os_path, 'isfile')
    @mock.patch.object(patch_orch_thread, 'PatchingClient')
    @mock.patch.object(threading, 'Thread')
    def test_update_subcloud_patches_bad_committed(
            self, mock_threading,
            mock_patching_client, mock_os_path_isfile, mock_sysinv_client):

        subcloud_id = fake_subcloud.create_fake_subcloud(self.ctx).id
        subcloud = db_api.subcloud_update(
            self.ctx,
            subcloud_id,
            management_state=consts.MANAGEMENT_MANAGED,
            availability_status=consts.AVAILABILITY_ONLINE)
        fake_strategy.create_fake_strategy_step(
            self.ctx,
            subcloud_id=subcloud.id,
            state=consts.STRATEGY_STATE_UPDATING_PATCHES)
        strategy_step = db_api.strategy_step_get_by_name(self.ctx, subcloud.name)

        mock_os_path_isfile.return_value = True
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
        # invoke get_region_one_patches once to update required attributes
        pot.get_region_one_patches()
        pot.update_subcloud_patches(strategy_step)

        # Verify that strategy step was updated
        updated_strategy_steps = db_api.strategy_step_get_all(self.ctx)
        self.assertEqual(updated_strategy_steps[0]['state'],
                         consts.STRATEGY_STATE_FAILED)

    @mock.patch.object(patch_orch_thread, 'SysinvClient')
    @mock.patch.object(os_path, 'isfile')
    @mock.patch.object(patch_orch_thread, 'PatchingClient')
    @mock.patch.object(threading, 'Thread')
    def test_update_subcloud_patches_bad_state(
            self, mock_threading,
            mock_patching_client, mock_os_path_isfile, mock_sysinv_client):

        subcloud_id = fake_subcloud.create_fake_subcloud(self.ctx).id
        subcloud = db_api.subcloud_update(
            self.ctx,
            subcloud_id,
            management_state=consts.MANAGEMENT_MANAGED,
            availability_status=consts.AVAILABILITY_ONLINE)
        fake_strategy.create_fake_strategy_step(
            self.ctx,
            subcloud_id=subcloud.id,
            state=consts.STRATEGY_STATE_UPDATING_PATCHES)
        strategy_step = db_api.strategy_step_get_by_name(self.ctx, subcloud.name)

        mock_os_path_isfile.return_value = True
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
        # invoke get_region_one_patches once to update required attributes
        pot.get_region_one_patches()
        pot.update_subcloud_patches(strategy_step)

        # Verify that strategy step was updated
        updated_strategy_steps = db_api.strategy_step_get_all(self.ctx)
        self.assertEqual(updated_strategy_steps[0]['state'],
                         consts.STRATEGY_STATE_FAILED)

    @mock.patch.object(os_path, 'isfile')
    @mock.patch.object(patch_orch_thread, 'PatchingClient')
    @mock.patch.object(threading, 'Thread')
    def test_finish(
            self, mock_threading,
            mock_patching_client, mock_os_path_isfile):

        subcloud_id = fake_subcloud.create_fake_subcloud(self.ctx).id
        subcloud = db_api.subcloud_update(
            self.ctx,
            subcloud_id,
            management_state=consts.MANAGEMENT_MANAGED,
            availability_status=consts.AVAILABILITY_ONLINE)
        fake_strategy.create_fake_strategy_step(
            self.ctx,
            subcloud_id=subcloud.id,
            state=consts.STRATEGY_STATE_UPDATING_PATCHES)
        strategy_step = db_api.strategy_step_get_by_name(self.ctx, subcloud.name)

        mock_os_path_isfile.return_value = True
        mock_patching_client.side_effect = FakePatchingClientFinish
        FakePatchingClientFinish.delete = mock.Mock()
        FakePatchingClientFinish.commit = mock.Mock()
        sw_update_manager.PatchOrchThread.stopped = lambda x: False
        mock_strategy_lock = mock.Mock()
        pot = sw_update_manager.PatchOrchThread(mock_strategy_lock,
                                                self.fake_dcmanager_audit_api)
        pot.get_ks_client = mock.Mock()
        # invoke get_region_one_patches once to update required attributes
        pot.get_region_one_patches()
        pot.finish(strategy_step)

        assert(compare_call_with_unsorted_list(
            FakePatchingClientFinish.delete.call_args_list[0],
            ['DC.5', 'DC.6']
        ))
        assert(compare_call_with_unsorted_list(
            FakePatchingClientFinish.commit.call_args_list[0],
            ['DC.2', 'DC.3']
        ))

        # Verify that strategy step was updated
        updated_strategy_steps = db_api.strategy_step_get_all(self.ctx)
        self.assertEqual(updated_strategy_steps[0]['state'],
                         consts.STRATEGY_STATE_COMPLETE)

    @mock.patch.object(patch_orch_thread, 'PatchingClient')
    def test_get_region_one_patches(self, mock_patching_client):
        mock_strategy_lock = mock.Mock()
        mock_patching_client.side_effect = FakePatchingClientOutOfSync
        pot = patch_orch_thread.PatchOrchThread(mock_strategy_lock,
                                                self.fake_dcmanager_audit_api)
        pot.get_ks_client = mock.Mock()
        pot.get_region_one_patches()

        regionone_patches = dict()
        regionone_patches = \
            FakePatchingClientOutOfSync(
                consts.DEFAULT_REGION_NAME, mock.Mock(), mock.Mock()).query()
        regionone_applied_patch_ids = [
            patch_id for patch_id in regionone_patches.keys()
            if regionone_patches[patch_id]['repostate'] in [
                'Applied', 'Committed']]

        # Verify the update of regionone_patches attribute
        self.assertEqual(pot.regionone_patches, regionone_patches)
        # Verify the update of regionone_applied_patch_ids attribute
        self.assertEqual(pot.regionone_applied_patch_ids,
                         regionone_applied_patch_ids)

        regionone_committed_patches = \
            FakePatchingClientOutOfSync(
                consts.DEFAULT_REGION_NAME, mock.Mock(), mock.Mock()
            ).query('Committed')
        regionone_committed_patch_ids = [
            patch_id for patch_id in regionone_committed_patches]
        # Verify the update of regionone_committed_patch_ids attribute
        self.assertEqual(pot.regionone_committed_patch_ids,
                         regionone_committed_patch_ids)
