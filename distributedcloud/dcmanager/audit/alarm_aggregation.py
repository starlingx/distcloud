# Copyright (c) 2020-2021 Wind River Systems, Inc.
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

from dcmanager.common import consts
from dcmanager.db import api as db_api

from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class AlarmAggregation(object):
    """Methods related to alarm aggregation"""

    def __init__(self, context):
        self.context = context

    def update_alarm_summary(self, name, fm_client):
        LOG.debug("Updating alarm summary for %s" % name)
        try:
            alarms = fm_client.get_alarm_summary()
            alarm_updates = {'critical_alarms': alarms[0].critical,
                             'major_alarms': alarms[0].major,
                             'minor_alarms': alarms[0].minor,
                             'warnings': alarms[0].warnings}
            alarm_updates = self._set_cloud_status(alarm_updates)
            db_api.subcloud_alarms_update(self.context, name, alarm_updates)
        except Exception as e:
            LOG.error('Failed to update alarms for %s error: %s' % (name, e))

    def _set_cloud_status(self, alarm_dict):
        if (alarm_dict.get('critical_alarms') > 0):
            status = consts.ALARM_CRITICAL_STATUS
        elif (alarm_dict.get('major_alarms') > 0) or\
             (alarm_dict.get('minor_alarms') > 0):
            status = consts.ALARM_DEGRADED_STATUS
        else:
            status = consts.ALARM_OK_STATUS
        alarm_dict['cloud_status'] = status
        return alarm_dict
