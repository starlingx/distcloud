# Copyright (c) 2017 Ericsson AB.
# Copyright (c) 2017-2022, 2024 Wind River Systems, Inc.
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
        """Get List of alarm summarys"""
        policy.authorize(
            alarm_manager_policy.POLICY_ROOT % "get",
            {},
            restcomm.extract_credentials_for_policy(),
        )
        return self._get_alarm_aggregates()
