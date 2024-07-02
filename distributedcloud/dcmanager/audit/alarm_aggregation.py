# Copyright (c) 2020-2021, 2024 Wind River Systems, Inc.
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

from dccommon.drivers.openstack.fm import FmClient
from dccommon.utils import log_subcloud_msg
from dcmanager.common import consts
from dcmanager.db import api as db_api

LOG = logging.getLogger(__name__)


class AlarmAggregation(object):
    """Methods related to alarm aggregation"""

    def __init__(self, context):
        self.context = context

    @classmethod
    def get_alarm_summary(cls, fm_client: FmClient, name: str = None):
        msg = "Getting alarm summary"
        log_subcloud_msg(LOG.debug, msg, name)
        try:
            alarms = fm_client.get_alarm_summary()
            alarm_updates = {
                'critical_alarms': alarms[0].critical,
                'major_alarms': alarms[0].major,
                'minor_alarms': alarms[0].minor,
                'warnings': alarms[0].warnings
            }
            alarm_updates = cls._set_cloud_status(alarm_updates)
            return alarm_updates
        except Exception as e:
            msg = f"Failed to get alarms. Error: {e}"
            log_subcloud_msg(LOG.error, msg, name)

    def update_alarm_summary(self, name: str, alarm_updates: dict):
        LOG.debug(f"Updating alarm summary for {name}")
        try:
            db_api.subcloud_alarms_update(self.context, name, alarm_updates)
        except Exception as e:
            LOG.error(f"Failed to update alarms for {name}. Error: {e}")

    @staticmethod
    def _set_cloud_status(alarm_dict):
        if alarm_dict.get('critical_alarms') > 0:
            status = consts.ALARM_CRITICAL_STATUS
        elif (alarm_dict.get('major_alarms') > 0) or \
                (alarm_dict.get('minor_alarms') > 0):
            status = consts.ALARM_DEGRADED_STATUS
        else:
            status = consts.ALARM_OK_STATUS
        alarm_dict['cloud_status'] = status
        return alarm_dict
