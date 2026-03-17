# Copyright (c) 2017 Ericsson AB.
# Copyright (c) 2017-2022, 2024, 2026 Wind River Systems, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

from oslo_log import log as logging
from pecan import expose

from dcmanager.api.controllers import restcomm
from dcmanager.api.policies import alarm_manager as alarm_manager_policy
from dcmanager.api import policy
from dcmanager.db import api as db_api

LOG = logging.getLogger(__name__)


class SubcloudAlarmController(object):
    VERSION_ALIASES = {
        "Newton": "1.0",
    }

    def __init__(self, *args, **kwargs):
        super(SubcloudAlarmController, self).__init__(*args, **kwargs)

    @expose(generic=True, template="json")
    def index(self):
        # Route the request to specific methods with parameters
        pass

    def _get_alarm_aggregates(self):
        summary = []
        context = restcomm.extract_context_from_environ()
        alarms = db_api.subcloud_alarms_get_all(context)
        for alarm in alarms:
            alarm_dict = {
                "region_name": alarm["name"],
                "uuid": alarm["uuid"],
                "critical_alarms": alarm["critical_alarms"],
                "major_alarms": alarm["major_alarms"],
                "minor_alarms": alarm["minor_alarms"],
                "warnings": alarm["warnings"],
                "cloud_status": alarm["cloud_status"],
            }
            summary.append(alarm_dict)
        return {"alarm_summary": summary}

    @index.when(method="GET", template="json")
    def get(self):
        """Get alarm summary for all subclouds

        ---
        get:
          summary: Get alarm summary for all subclouds
          description: >-
            Retrieve aggregated alarm information for all
            subclouds including critical, major, minor
            alarms, warnings and status
          operationId: getAlarmSummary
          tags:
          - alarms
          responses:
            200:
              description: Alarm summary retrieved successfully
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      alarm_summary:
                        $ref: '#/components/schemas/alarm_summary'
                  example:
                    alarm_summary:
                    - region_name: subcloud1-stx-latest
                      uuid: ae2e7141-eed1-4b48-856a-743feb0a7b80
                      critical_alarms: 0
                      major_alarms: 0
                      minor_alarms: 0
                      warnings: 0
                      cloud_status: OK
            500:
              description: Internal server error
        """
        policy.authorize(
            alarm_manager_policy.POLICY_ROOT % "get",
            {},
            restcomm.extract_credentials_for_policy(),
        )
        return self._get_alarm_aggregates()
