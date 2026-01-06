# Copyright (c) 2021, 2024-2025 Wind River Systems, Inc.
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

from dcmanager.audit import alarm_aggregation
from dcmanager.common.exceptions import InternalError
from dcmanager.db import api as db_api
from dcmanager.tests.base import DCManagerTestCase


class FakeFmAlarmSummary(object):
    def __init__(self, critical, major, minor, warnings):
        self.critical = critical
        self.major = major
        self.minor = minor
        self.warnings = warnings


class FakeFmClient(FakeFmAlarmSummary):
    def __init__(self, critical, major, minor, warnings):
        super().__init__(critical, major, minor, warnings)

    def get_alarm_summary(self):
        return [
            FakeFmAlarmSummary(self.critical, self.major, self.minor, self.warnings)
        ]


class TestAlarmAggregation(DCManagerTestCase):
    def setUp(self):
        super().setUp()

        self.aam = alarm_aggregation.AlarmAggregation(self.ctx)

    def build_alarm_summary(
        self,
        alarms=None,
        critical=None,
        major=None,
        minor=None,
        warnings=None,
        status=None,
    ):
        if alarms:
            critical = alarms.critical_alarms
            major = alarms.major_alarms
            minor = alarms.minor_alarms
            warnings = alarms.warnings
            status = alarms.cloud_status

        return {
            "critical_alarms": critical,
            "major_alarms": major,
            "minor_alarms": minor,
            "warnings": warnings,
            "cloud_status": status,
        }

    def _test_get_alarm_summary(self, critical, major, minor, warnings, status):
        db_api.subcloud_alarms_create(self.ctx, "subcloud1", values={})
        alarms_summary = self.aam.get_alarm_summary(
            FakeFmClient(critical, major, minor, warnings), "subcloud1"
        )
        self.aam.update_alarm_summary("subcloud1", alarms_summary)

        alarms = db_api.subcloud_alarms_get(self.ctx, "subcloud1")
        self.assertEqual(
            self.build_alarm_summary(alarms),
            self.build_alarm_summary(None, critical, major, minor, warnings, status),
        )

    def test_get_alarm_summary_critical_status(self):
        self._test_get_alarm_summary(1, 2, 3, 4, "critical")

    def test_get_alarm_summary_degraded_status(self):
        self._test_get_alarm_summary(0, 1, 2, 3, "degraded")

    def test_get_alarm_summary_ok_status(self):
        self._test_get_alarm_summary(0, 0, 0, 1, "OK")

    def test_get_alarm_summary_exception(self):
        mock_logging = self._mock_object(alarm_aggregation, "LOG")

        fake_fm_client = mock.MagicMock()
        fake_fm_client.get_alarm_summary.side_effect = InternalError()

        self.assertRaises(
            InternalError, self.aam.get_alarm_summary, fake_fm_client, "subcloud1"
        )
        mock_logging.error.assert_called_with(
            "Subcloud: subcloud1. Failed to get alarms. Error: Error when "
            "performing operation"
        )

    def test_update_alarm_summary_exception(self):
        mock_logging = self._mock_object(alarm_aggregation, "LOG")

        alarms_summary = self.aam.get_alarm_summary(
            FakeFmClient(0, 0, 0, 0), "subcloud4"
        )
        self.aam.update_alarm_summary("subcloud4", alarms_summary)

        mock_logging.error.assert_called_with(
            "Failed to update alarms for subcloud4. Error: Subcloud with "
            "name subcloud4 doesn't exist."
        )
