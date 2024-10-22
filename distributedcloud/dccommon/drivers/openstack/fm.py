# Copyright (c) 2018-2021, 2024 Wind River Systems, Inc.
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
#

import fmclient
from keystoneauth1 import session as ks_session
from oslo_log import log

from dccommon import consts as dccommon_consts
from dccommon.drivers import base

LOG = log.getLogger(__name__)
API_VERSION = "1"


class FmClient(base.DriverBase):
    """Fault Management driver."""

    def __init__(
        self,
        region: str,
        session: ks_session.Session,
        endpoint_type=dccommon_consts.KS_ENDPOINT_DEFAULT,
        endpoint: str = None,
        token: str = None,
    ):
        self.region_name = region

        # If the token is specified, use it instead of using the session
        if token:
            if not endpoint:
                endpoint = session.get_endpoint(
                    service_type=dccommon_consts.ENDPOINT_TYPE_FM,
                    region_name=region,
                    interface=endpoint_type,
                )
            session = None

        self.fm = fmclient.Client(
            API_VERSION,
            session=session,
            region_name=region,
            endpoint_type=endpoint_type,
            endpoint=endpoint,
            auth_token=token,
        )

    def get_alarm_summary(self):
        """Get this region alarm summary"""
        try:
            LOG.debug("get_alarm_summary region %s" % self.region_name)
            alarms = self.fm.alarm.summary()
        except Exception as e:
            LOG.error("get_alarm_summary exception={}".format(e))
            raise e
        return alarms

    def get_alarms_by_id(self, alarm_id):
        """Get list of this region alarms for a particular alarm_id"""
        try:
            LOG.debug("get_alarms_by_id %s, region %s" % (alarm_id, self.region_name))
            alarms = self.fm.alarm.list(
                q=fmclient.common.options.cli_to_array("alarm_id=" + alarm_id),
                include_suppress=True,
            )
        except Exception as e:
            LOG.error("get_alarms_by_id exception={}".format(e))
            raise e
        return alarms

    def get_alarms_by_ids(self, alarm_id_list):
        """Get list of this region alarms for a list of alarm_ids"""
        try:
            LOG.debug(
                "get_alarms_by_ids %s, region %s" % (alarm_id_list, self.region_name)
            )
            # fm api does not support querying two alarm IDs at once so make
            # multiple calls and join the list
            alarms = []
            for alarm_id in alarm_id_list:
                alarms.extend(
                    self.fm.alarm.list(
                        q=fmclient.common.options.cli_to_array("alarm_id=" + alarm_id),
                        include_suppress=True,
                    )
                )
        except Exception as e:
            LOG.error("get_alarms_by_ids exception={}".format(e))
            raise e
        return alarms

    def get_alarms(self):
        """Get this region alarms"""

        try:
            LOG.debug("get_alarms region %s" % self.region_name)
            alarms = self.fm.alarm.list(include_suppress=True)
        except Exception as e:
            LOG.error("get_alarms exception={}".format(e))
            raise e
        return alarms
