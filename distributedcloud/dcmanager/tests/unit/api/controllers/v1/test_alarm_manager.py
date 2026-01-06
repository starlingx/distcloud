# Copyright (c) 2020-2025 Wind River Systems, Inc.
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

from dcmanager.db import api as db_api
from dcmanager.tests.unit.api.test_root_controller import DCManagerApiTest
from dcmanager.tests import utils


class BaseTestSubcloudAlarmController(DCManagerApiTest):
    """Base class for testing the SubcloudAlarmController"""

    def setUp(self):
        super().setUp()

        self.url = "/v1.0/alarms"


class TestSubcloudAlarmController(BaseTestSubcloudAlarmController):
    """Test class for SubcloudAlarmController"""

    def setUp(self):
        super().setUp()

    def test_unmapped_method(self):
        """Test requesting an unmapped method results in success with null content"""

        self.method = self.app.put

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(response.text, "null")


class TestSubcloudAlarmControllerGet(BaseTestSubcloudAlarmController):
    """Test class for get requests"""

    def setUp(self):
        super().setUp()

        self.method = self.app.get

    def test_get_succeeds(self):
        """Test get succeeds"""

        subcloud1_values = {
            "uuid": utils.UUID2,
            "critical_alarms": 1,
            "major_alarms": 2,
            "minor_alarms": 3,
            "warnings": 0,
            "cloud_status": "critical",
        }

        subcloud2_values = {
            "uuid": utils.UUID3,
            "critical_alarms": 0,
            "major_alarms": 2,
            "minor_alarms": 3,
            "warnings": 4,
            "cloud_status": "degraded",
        }

        subcloud_summary = [
            {"region_name": "subcloud1", **subcloud1_values},
            {"region_name": "subcloud2", **subcloud2_values},
        ]

        db_api.subcloud_alarms_create(self.ctx, "subcloud2", values=subcloud2_values)
        db_api.subcloud_alarms_create(self.ctx, "subcloud1", values=subcloud1_values)

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(subcloud_summary, response.json.get("alarm_summary"))
