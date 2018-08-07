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

from oslo_config import cfg
from oslo_utils import timeutils

from dcorch.common import consts as dcorch_consts

from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.manager import sw_update_manager
from dcmanager.tests import base
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


def compare_call_with_unsorted_list(call, unsorted_list):
    call_args, _ = call
    return call_args[0].sort() == unsorted_list.sort()


class Subcloud(object):
    def __init__(self, id, name, is_managed, is_online):
        self.id = id
        self.name = name
        self.software_version = '12.04'
        if is_managed:
            self.management_state = consts.MANAGEMENT_MANAGED
        else:
            self.management_state = consts.MANAGEMENT_UNMANAGED
        if is_online:
            self.availability_status = consts.AVAILABILITY_ONLINE
        else:
            self.availability_status = consts.AVAILABILITY_OFFLINE


class SubcloudStatus(object):
    def __init__(self, endpoint_type=None, sync_status=None):
        if endpoint_type:
            self.endpoint_type = endpoint_type
        else:
            self.endpoint_type = dcorch_consts.ENDPOINT_TYPE_PATCHING
        if sync_status:
            self.sync_status = sync_status
        else:
            self.sync_status = consts.SYNC_STATUS_OUT_OF_SYNC


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


class SwUpdateStrategy(object):
    def __init__(self, id, data):
        self.id = id
        self.type = data['type']
        self.subcloud_apply_type = data['subcloud-apply-type']
        self.max_parallel_subclouds = int(data['max-parallel-subclouds'])
        if data['stop-on-failure'] == 'true':
            self.stop_on_failure = True
        else:
            self.stop_on_failure = False
        self.state = data['state']
        self.created_at = timeutils.utcnow()
        self.updated_at = timeutils.utcnow()


class TestSwUpdateManager(base.DCManagerTestCase):
    def setUp(self):
        super(TestSwUpdateManager, self).setUp()
        self.ctxt = utils.dummy_context()

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    @mock.patch.object(sw_update_manager, 'context')
    def test_init(self, mock_context, mock_patch_orch_thread):
        mock_context.get_admin_context.return_value = self.ctxt
        um = sw_update_manager.SwUpdateManager()
        self.assertIsNotNone(um)
        self.assertEqual('sw_update_manager', um.service_name)
        self.assertEqual('localhost', um.host)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    @mock.patch.object(sw_update_manager, 'context')
    @mock.patch.object(sw_update_manager, 'db_api')
    def test_create_sw_update_strategy_no_subclouds(
            self, mock_db_api, mock_context, mock_patch_orch_thread):
        mock_context.get_admin_context.return_value = self.ctxt
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
    @mock.patch.object(sw_update_manager, 'context')
    @mock.patch.object(sw_update_manager, 'db_api')
    def test_create_sw_update_strategy_parallel(
            self, mock_db_api, mock_context, mock_patch_orch_thread):
        mock_context.get_admin_context.return_value = self.ctxt
        mock_db_api.sw_update_strategy_get.side_effect = \
            exceptions.NotFound()

        # Will be patched
        fake_subcloud1 = Subcloud(1, 'subcloud1',
                                  is_managed=True, is_online=True)
        fake_status1 = SubcloudStatus()
        # Not patched because not managed
        fake_subcloud2 = Subcloud(2, 'subcloud2',
                                  is_managed=False, is_online=True)
        fake_status2 = SubcloudStatus()
        # Will be patched
        fake_subcloud3 = Subcloud(3, 'subcloud3',
                                  is_managed=True, is_online=True)
        fake_status3 = SubcloudStatus()
        # Not patched because patching is in sync
        fake_subcloud4 = Subcloud(4, 'subcloud4',
                                  is_managed=True, is_online=True)
        fake_status4 = SubcloudStatus(
            sync_status=consts.SYNC_STATUS_IN_SYNC
        )
        # Will be patched
        fake_subcloud5 = Subcloud(5, 'subcloud5',
                                  is_managed=True, is_online=True)
        fake_status5 = SubcloudStatus()
        # Will be patched
        fake_subcloud6 = Subcloud(6, 'subcloud6',
                                  is_managed=True, is_online=True)
        fake_status6 = SubcloudStatus()

        mock_db_api.subcloud_get_all_with_status.return_value = [
            (fake_subcloud1, fake_status1),
            (fake_subcloud2, fake_status2),
            (fake_subcloud3, fake_status3),
            (fake_subcloud4, fake_status4),
            (fake_subcloud5, fake_status5),
            (fake_subcloud6, fake_status6),
        ]

        um = sw_update_manager.SwUpdateManager()
        um.create_sw_update_strategy(self.ctxt, payload=FAKE_SW_UPDATE_DATA)
        mock_db_api.sw_update_strategy_create.assert_called_once()

        expected_calls = [
            mock.call(mock.ANY,
                      None,
                      stage=1,
                      state=consts.STRATEGY_STATE_INITIAL,
                      details=''),
            mock.call(mock.ANY,
                      1,
                      stage=2,
                      state=consts.STRATEGY_STATE_INITIAL,
                      details=''),
            mock.call(mock.ANY,
                      3,
                      stage=2,
                      state=consts.STRATEGY_STATE_INITIAL,
                      details=''),
            mock.call(mock.ANY,
                      5,
                      stage=3,
                      state=consts.STRATEGY_STATE_INITIAL,
                      details=''),
            mock.call(mock.ANY,
                      6,
                      stage=3,
                      state=consts.STRATEGY_STATE_INITIAL,
                      details=''),
        ]
        mock_db_api.strategy_step_create.assert_has_calls(
            expected_calls)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    @mock.patch.object(sw_update_manager, 'context')
    @mock.patch.object(sw_update_manager, 'db_api')
    def test_create_sw_update_strategy_serial(
            self, mock_db_api, mock_context, mock_patch_orch_thread):
        mock_context.get_admin_context.return_value = self.ctxt
        mock_db_api.sw_update_strategy_get.side_effect = \
            exceptions.NotFound()

        # Will be patched
        fake_subcloud1 = Subcloud(1, 'subcloud1',
                                  is_managed=True, is_online=True)
        fake_status1 = SubcloudStatus()
        # Not patched because not managed
        fake_subcloud2 = Subcloud(2, 'subcloud2',
                                  is_managed=False, is_online=True)
        fake_status2 = SubcloudStatus()
        # Will be patched
        fake_subcloud3 = Subcloud(3, 'subcloud3',
                                  is_managed=True, is_online=True)
        fake_status3 = SubcloudStatus()
        # Not patched because patching is in sync
        fake_subcloud4 = Subcloud(4, 'subcloud4',
                                  is_managed=True, is_online=True)
        fake_status4 = SubcloudStatus(
            sync_status=consts.SYNC_STATUS_IN_SYNC
        )
        # Will be patched
        fake_subcloud5 = Subcloud(5, 'subcloud5',
                                  is_managed=True, is_online=True)
        fake_status5 = SubcloudStatus()
        # Will be patched
        fake_subcloud6 = Subcloud(6, 'subcloud6',
                                  is_managed=True, is_online=True)
        fake_status6 = SubcloudStatus()

        mock_db_api.subcloud_get_all_with_status.return_value = [
            (fake_subcloud1, fake_status1),
            (fake_subcloud2, fake_status2),
            (fake_subcloud3, fake_status3),
            (fake_subcloud4, fake_status4),
            (fake_subcloud5, fake_status5),
            (fake_subcloud6, fake_status6),
        ]

        um = sw_update_manager.SwUpdateManager()
        data = copy.copy(FAKE_SW_UPDATE_DATA)
        data["subcloud-apply-type"] = consts.SUBCLOUD_APPLY_TYPE_SERIAL
        um.create_sw_update_strategy(self.ctxt, payload=data)
        mock_db_api.sw_update_strategy_create.assert_called_once()

        expected_calls = [
            mock.call(mock.ANY,
                      None,
                      stage=1,
                      state=consts.STRATEGY_STATE_INITIAL,
                      details=''),
            mock.call(mock.ANY,
                      1,
                      stage=2,
                      state=consts.STRATEGY_STATE_INITIAL,
                      details=''),
            mock.call(mock.ANY,
                      3,
                      stage=3,
                      state=consts.STRATEGY_STATE_INITIAL,
                      details=''),
            mock.call(mock.ANY,
                      5,
                      stage=4,
                      state=consts.STRATEGY_STATE_INITIAL,
                      details=''),
            mock.call(mock.ANY,
                      6,
                      stage=5,
                      state=consts.STRATEGY_STATE_INITIAL,
                      details=''),
        ]
        mock_db_api.strategy_step_create.assert_has_calls(
            expected_calls)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    @mock.patch.object(sw_update_manager, 'context')
    @mock.patch.object(sw_update_manager, 'db_api')
    def test_create_sw_update_strategy_unknown_sync_status(
            self, mock_db_api, mock_context, mock_patch_orch_thread):
        mock_context.get_admin_context.return_value = self.ctxt
        mock_db_api.sw_update_strategy_get.side_effect = \
            exceptions.NotFound()

        # Will be patched
        fake_subcloud1 = Subcloud(1, 'subcloud1',
                                  is_managed=True, is_online=True)
        fake_status1 = SubcloudStatus()
        # Not patched because not managed
        fake_subcloud2 = Subcloud(2, 'subcloud2',
                                  is_managed=False, is_online=True)
        fake_status2 = SubcloudStatus()
        # Will be patched
        fake_subcloud3 = Subcloud(3, 'subcloud3',
                                  is_managed=True, is_online=True)
        fake_status3 = SubcloudStatus()
        # Will fail creation because sync status is unknown
        fake_subcloud4 = Subcloud(4, 'subcloud4',
                                  is_managed=True, is_online=True)
        fake_status4 = SubcloudStatus(
            sync_status=consts.SYNC_STATUS_UNKNOWN
        )
        mock_db_api.subcloud_get_all_with_status.return_value = [
            (fake_subcloud1, fake_status1),
            (fake_subcloud2, fake_status2),
            (fake_subcloud3, fake_status3),
            (fake_subcloud4, fake_status4),
        ]

        um = sw_update_manager.SwUpdateManager()
        self.assertRaises(exceptions.BadRequest,
                          um.create_sw_update_strategy,
                          self.ctxt, payload=FAKE_SW_UPDATE_DATA)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    @mock.patch.object(sw_update_manager, 'context')
    @mock.patch.object(sw_update_manager, 'db_api')
    def test_delete_sw_update_strategy(self, mock_db_api, mock_context,
                                       mock_patch_orch_thread):
        mock_context.get_admin_context.return_value = self.ctxt
        fake_sw_update_strategy = SwUpdateStrategy(FAKE_ID,
                                                   FAKE_SW_UPDATE_DATA)
        mock_db_api.sw_update_strategy_get.return_value = \
            fake_sw_update_strategy
        um = sw_update_manager.SwUpdateManager()
        um.delete_sw_update_strategy(self.ctxt)
        mock_db_api.sw_update_strategy_update.assert_called_with(
            mock.ANY, state=consts.SW_UPDATE_STATE_DELETING)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    @mock.patch.object(sw_update_manager, 'context')
    @mock.patch.object(sw_update_manager, 'db_api')
    def test_delete_sw_update_strategy_invalid_state(
            self, mock_db_api, mock_context, mock_patch_orch_thread):
        data = copy.copy(FAKE_SW_UPDATE_DATA)
        data['state'] = consts.SW_UPDATE_STATE_APPLYING
        mock_context.get_admin_context.return_value = self.ctxt
        fake_sw_update_strategy = SwUpdateStrategy(FAKE_ID,
                                                   data)
        mock_db_api.sw_update_strategy_get.return_value = \
            fake_sw_update_strategy
        um = sw_update_manager.SwUpdateManager()
        self.assertRaises(exceptions.BadRequest,
                          um.delete_sw_update_strategy,
                          self.ctxt)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    @mock.patch.object(sw_update_manager, 'context')
    @mock.patch.object(sw_update_manager, 'db_api')
    def test_apply_sw_update_strategy(self, mock_db_api, mock_context,
                                      mock_patch_orch_thread):
        mock_context.get_admin_context.return_value = self.ctxt
        fake_sw_update_strategy = SwUpdateStrategy(FAKE_ID,
                                                   FAKE_SW_UPDATE_DATA)
        mock_db_api.sw_update_strategy_get.return_value = \
            fake_sw_update_strategy
        um = sw_update_manager.SwUpdateManager()
        um.apply_sw_update_strategy(self.ctxt)
        mock_db_api.sw_update_strategy_update.assert_called_with(
            mock.ANY, state=consts.SW_UPDATE_STATE_APPLYING)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    @mock.patch.object(sw_update_manager, 'context')
    @mock.patch.object(sw_update_manager, 'db_api')
    def test_apply_sw_update_strategy_invalid_state(
            self, mock_db_api, mock_context, mock_patch_orch_thread):
        data = copy.copy(FAKE_SW_UPDATE_DATA)
        data['state'] = consts.SW_UPDATE_STATE_APPLYING
        mock_context.get_admin_context.return_value = self.ctxt
        fake_sw_update_strategy = SwUpdateStrategy(FAKE_ID,
                                                   data)
        mock_db_api.sw_update_strategy_get.return_value = \
            fake_sw_update_strategy
        um = sw_update_manager.SwUpdateManager()
        self.assertRaises(exceptions.BadRequest,
                          um.apply_sw_update_strategy,
                          self.ctxt)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    @mock.patch.object(sw_update_manager, 'context')
    @mock.patch.object(sw_update_manager, 'db_api')
    def test_abort_sw_update_strategy(
            self, mock_db_api, mock_context, mock_patch_orch_thread):
        data = copy.copy(FAKE_SW_UPDATE_DATA)
        data['state'] = consts.SW_UPDATE_STATE_APPLYING
        mock_context.get_admin_context.return_value = self.ctxt
        fake_sw_update_strategy = SwUpdateStrategy(FAKE_ID,
                                                   data)
        mock_db_api.sw_update_strategy_get.return_value = \
            fake_sw_update_strategy
        um = sw_update_manager.SwUpdateManager()
        um.abort_sw_update_strategy(self.ctxt)
        mock_db_api.sw_update_strategy_update.assert_called_with(
            mock.ANY, state=consts.SW_UPDATE_STATE_ABORT_REQUESTED)

    @mock.patch.object(sw_update_manager, 'PatchOrchThread')
    @mock.patch.object(sw_update_manager, 'context')
    @mock.patch.object(sw_update_manager, 'db_api')
    def test_abort_sw_update_strategy_invalid_state(
            self, mock_db_api, mock_context, mock_patch_orch_thread):
        data = copy.copy(FAKE_SW_UPDATE_DATA)
        data['state'] = consts.SW_UPDATE_STATE_COMPLETE
        mock_context.get_admin_context.return_value = self.ctxt
        fake_sw_update_strategy = SwUpdateStrategy(FAKE_ID,
                                                   data)
        mock_db_api.sw_update_strategy_get.return_value = \
            fake_sw_update_strategy
        um = sw_update_manager.SwUpdateManager()
        self.assertRaises(exceptions.BadRequest,
                          um.apply_sw_update_strategy,
                          self.ctxt)

    @mock.patch.object(sw_update_manager, 'SysinvClient')
    @mock.patch.object(sw_update_manager, 'os')
    @mock.patch.object(sw_update_manager, 'PatchingClient')
    @mock.patch.object(sw_update_manager, 'threading')
    @mock.patch.object(sw_update_manager, 'context')
    @mock.patch.object(sw_update_manager, 'db_api')
    def test_update_subcloud_patches(
            self, mock_db_api, mock_context, mock_threading,
            mock_patching_client, mock_os, mock_sysinv_client):

        mock_os.path.isfile.return_value = True
        fake_subcloud = Subcloud(1, 'subcloud1',
                                 is_managed=True, is_online=True)
        data = copy.copy(FAKE_STRATEGY_STEP_DATA)
        data['state'] = consts.STRATEGY_STATE_UPDATING_PATCHES
        data['subcloud'] = fake_subcloud
        data['subcloud_name'] = 'subcloud1'
        mock_context.get_admin_context.return_value = self.ctxt
        fake_strategy_step = StrategyStep(**data)
        mock_patching_client.side_effect = FakePatchingClientOutOfSync
        mock_sysinv_client.side_effect = FakeSysinvClientOneLoad
        FakePatchingClientOutOfSync.apply = mock.Mock()
        FakePatchingClientOutOfSync.remove = mock.Mock()
        FakePatchingClientOutOfSync.upload = mock.Mock()
        sw_update_manager.PatchOrchThread.stopped = lambda x: False
        pot = sw_update_manager.PatchOrchThread()
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

    @mock.patch.object(sw_update_manager, 'SysinvClient')
    @mock.patch.object(sw_update_manager, 'os')
    @mock.patch.object(sw_update_manager, 'PatchingClient')
    @mock.patch.object(sw_update_manager, 'threading')
    @mock.patch.object(sw_update_manager, 'context')
    @mock.patch.object(sw_update_manager, 'db_api')
    def test_update_subcloud_patches_bad_committed(
            self, mock_db_api, mock_context, mock_threading,
            mock_patching_client, mock_os, mock_sysinv_client):

        mock_os.path.isfile.return_value = True
        fake_subcloud = Subcloud(1, 'subcloud1',
                                 is_managed=True, is_online=True)
        data = copy.copy(FAKE_STRATEGY_STEP_DATA)
        data['state'] = consts.STRATEGY_STATE_UPDATING_PATCHES
        data['subcloud'] = fake_subcloud
        mock_context.get_admin_context.return_value = self.ctxt
        fake_strategy_step = StrategyStep(**data)
        mock_patching_client.side_effect = FakePatchingClientSubcloudCommitted
        mock_sysinv_client.side_effect = FakeSysinvClientOneLoad
        FakePatchingClientOutOfSync.apply = mock.Mock()
        FakePatchingClientOutOfSync.remove = mock.Mock()
        FakePatchingClientOutOfSync.upload = mock.Mock()
        sw_update_manager.PatchOrchThread.stopped = lambda x: False
        pot = sw_update_manager.PatchOrchThread()
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

    @mock.patch.object(sw_update_manager, 'SysinvClient')
    @mock.patch.object(sw_update_manager, 'os')
    @mock.patch.object(sw_update_manager, 'PatchingClient')
    @mock.patch.object(sw_update_manager, 'threading')
    @mock.patch.object(sw_update_manager, 'context')
    @mock.patch.object(sw_update_manager, 'db_api')
    def test_update_subcloud_patches_bad_state(
            self, mock_db_api, mock_context, mock_threading,
            mock_patching_client, mock_os, mock_sysinv_client):

        mock_os.path.isfile.return_value = True
        fake_subcloud = Subcloud(1, 'subcloud1',
                                 is_managed=True, is_online=True)
        data = copy.copy(FAKE_STRATEGY_STEP_DATA)
        data['state'] = consts.STRATEGY_STATE_UPDATING_PATCHES
        data['subcloud'] = fake_subcloud
        mock_context.get_admin_context.return_value = self.ctxt
        fake_strategy_step = StrategyStep(**data)
        mock_patching_client.side_effect = FakePatchingClientSubcloudUnknown
        mock_sysinv_client.side_effect = FakeSysinvClientOneLoad
        FakePatchingClientOutOfSync.apply = mock.Mock()
        FakePatchingClientOutOfSync.remove = mock.Mock()
        FakePatchingClientOutOfSync.upload = mock.Mock()
        sw_update_manager.PatchOrchThread.stopped = lambda x: False
        pot = sw_update_manager.PatchOrchThread()
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

    @mock.patch.object(sw_update_manager, 'os')
    @mock.patch.object(sw_update_manager, 'PatchingClient')
    @mock.patch.object(sw_update_manager, 'threading')
    @mock.patch.object(sw_update_manager, 'context')
    @mock.patch.object(sw_update_manager, 'db_api')
    def test_finish(
            self, mock_db_api, mock_context, mock_threading,
            mock_patching_client, mock_os):

        mock_os.path.isfile.return_value = True
        fake_subcloud = Subcloud(1, 'subcloud1',
                                 is_managed=True, is_online=True)
        data = copy.copy(FAKE_STRATEGY_STEP_DATA)
        data['state'] = consts.STRATEGY_STATE_UPDATING_PATCHES
        data['subcloud'] = fake_subcloud
        mock_context.get_admin_context.return_value = self.ctxt
        fake_strategy_step = StrategyStep(**data)
        mock_patching_client.side_effect = FakePatchingClientFinish
        FakePatchingClientFinish.delete = mock.Mock()
        FakePatchingClientFinish.commit = mock.Mock()
        sw_update_manager.PatchOrchThread.stopped = lambda x: False
        pot = sw_update_manager.PatchOrchThread()
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
