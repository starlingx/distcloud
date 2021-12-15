# Copyright (c) 2021 Wind River Systems, Inc.
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

from dccommon.drivers.openstack import sdk_platform as sdk
from dcmanager.audit import alarm_aggregation
from dcmanager.common import exceptions
from dcmanager.db.sqlalchemy import api as db_api

from dcmanager.tests import base
from dcmanager.tests import utils


class FakeFmAlarmSummarySubcloud1(object):
    def __init__(self):
        self.critical = 1
        self.major = 2
        self.minor = 3
        self.warnings = 4


class FakeFmAlarmSummarySubcloud2(object):
    def __init__(self):
        self.critical = 0
        self.major = 1
        self.minor = 2
        self.warnings = 3


class FakeFmAlarmSummarySubcloud3(object):
    def __init__(self):
        self.critical = 0
        self.major = 0
        self.minor = 0
        self.warnings = 1


class FakeFmClientSubcloud1(object):
    def get_alarm_summary(self):
        summary_list = []
        summary_list.append(FakeFmAlarmSummarySubcloud1())
        return summary_list


class FakeFmClientSubcloud2(object):
    def get_alarm_summary(self):
        summary_list = []
        summary_list.append(FakeFmAlarmSummarySubcloud2())
        return summary_list


class FakeFmClientSubcloud3(object):
    def get_alarm_summary(self):
        summary_list = []
        summary_list.append(FakeFmAlarmSummarySubcloud3())
        return summary_list


class FakeFmClientSubcloud4(object):
    def get_alarm_summary(self):
        raise exceptions.SubcloudNotFound(subcloud_id='subcloud4')


class FakeOpenStackDriver(object):
    def __init__(self, region_name='RegionOne'):
        fm_clients = {'subcloud1': FakeFmClientSubcloud1,
                      'subcloud2': FakeFmClientSubcloud2,
                      'subcloud3': FakeFmClientSubcloud3,
                      'subcloud4': FakeFmClientSubcloud4}
        self.fm_client = fm_clients[region_name]()


class TestAlarmAggregation(base.DCManagerTestCase):
    def setUp(self):
        super(TestAlarmAggregation, self).setUp()
        self.ctxt = utils.dummy_context()

    def test_init(self):
        aam = alarm_aggregation.AlarmAggregation(self.ctxt)
        self.assertIsNotNone(aam)
        self.assertEqual(self.ctxt, aam.context)

    @staticmethod
    def alarms_to_dict(alarms):
        return {'critical_alarms': alarms.critical_alarms,
                'major_alarms': alarms.major_alarms,
                'minor_alarms': alarms.minor_alarms,
                'warnings': alarms.warnings,
                'cloud_status': alarms.cloud_status,
                }

    @mock.patch.object(alarm_aggregation, 'LOG')
    @mock.patch.object(sdk, 'OpenStackDriver')
    def test_update_alarm_summary(self, mock_openstack_driver,
                                  mock_logging):
        mock_openstack_driver.side_effect = FakeOpenStackDriver
        aam = alarm_aggregation.AlarmAggregation(self.ctxt)

        fake_openstackdriver = FakeOpenStackDriver('subcloud1')
        db_api.subcloud_alarms_create(self.ctx, 'subcloud1', values={})
        aam.update_alarm_summary('subcloud1', fake_openstackdriver.fm_client)
        alarms = db_api.subcloud_alarms_get(self.ctx, 'subcloud1')
        self.assertEqual(self.alarms_to_dict(alarms),
                         {'critical_alarms': 1,
                          'major_alarms': 2,
                          'minor_alarms': 3,
                          'warnings': 4,
                          'cloud_status': 'critical'}
                         )

        fake_openstackdriver = FakeOpenStackDriver('subcloud2')
        db_api.subcloud_alarms_create(self.ctx, 'subcloud2', values={})
        aam.update_alarm_summary('subcloud2', fake_openstackdriver.fm_client)
        alarms = db_api.subcloud_alarms_get(self.ctx, 'subcloud2')
        self.assertEqual(self.alarms_to_dict(alarms),
                         {'critical_alarms': 0,
                          'major_alarms': 1,
                          'minor_alarms': 2,
                          'warnings': 3,
                          'cloud_status': 'degraded'}
                         )

        fake_openstackdriver = FakeOpenStackDriver('subcloud3')
        db_api.subcloud_alarms_create(self.ctx, 'subcloud3', values={})
        aam.update_alarm_summary('subcloud3', fake_openstackdriver.fm_client)
        alarms = db_api.subcloud_alarms_get(self.ctx, 'subcloud3')
        self.assertEqual(self.alarms_to_dict(alarms),
                         {'critical_alarms': 0,
                          'major_alarms': 0,
                          'minor_alarms': 0,
                          'warnings': 1,
                          'cloud_status': 'OK'}
                         )

        fake_openstackdriver = FakeOpenStackDriver('subcloud4')
        aam.update_alarm_summary('subcloud4', fake_openstackdriver.fm_client)
        mock_logging.error.assert_called_with('Failed to update alarms for '
                                              'subcloud4 error: Subcloud with '
                                              'id subcloud4 doesn\'t exist.')
