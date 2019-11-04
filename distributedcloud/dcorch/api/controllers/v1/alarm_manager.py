# Copyright (c) 2017 Ericsson AB.
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

from dcorch.api.controllers import restcomm
from dcorch.db import api as db_api
from dcorch.rpc import client as rpc_client

from oslo_log import log as logging

from pecan import expose

LOG = logging.getLogger(__name__)


class SubcloudAlarmController(object):
    VERSION_ALIASES = {
        'Newton': '1.0',
    }

    def __init__(self, *args, **kwargs):
        super(SubcloudAlarmController, self).__init__(*args, **kwargs)
        self.rpc_client = rpc_client.EngineClient()

    # to do the version compatibility for future purpose
    def _determine_version_cap(self, target):
        version_cap = 1.0
        return version_cap

    @expose(generic=True, template='json')
    def index(self):
        # Route the request to specific methods with parameters
        pass

    def _get_alarm_aggregates(self):
        context = restcomm.extract_context_from_environ()
        alarms = db_api.subcloud_alarms_get_all(context)
        summary = []
        for alarm in alarms:
            alarm_dict = {'region_name': alarm['region_name'],
                          'uuid': alarm['uuid'],
                          'critical_alarms': alarm['critical_alarms'],
                          'major_alarms': alarm['major_alarms'],
                          'minor_alarms': alarm['minor_alarms'],
                          'warnings': alarm['warnings'],
                          'cloud_status': alarm['cloud_status']}
            summary.append(alarm_dict)
        return summary

    @index.when(method='GET', template='json')
    def get(self, project):
        """Get List of alarm summarys

        """
        return self._get_alarm_aggregates()

    def _get_alarm_summary(self):
        context = restcomm.extract_context_from_environ()
        alarms = db_api.subcloud_alarms_get_all(context)
        summary = {'critical': 0,
                   'degraded': 0,
                   'ok': 0,
                   'unreachable': 0}
        for alarm in alarms:
            summary[alarm['cloud_status']] += 1
        return summary

    @index.when(method='summary', template='json')
    def summary(self, project):
        """Get an agregate of all subcloud status

        :param project: UUID the project.
        """
        return self._get_alarm_summary()
