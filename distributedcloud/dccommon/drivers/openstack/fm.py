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
# Copyright (c) 2018-2020 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

from oslo_log import log

import fmclient

from dccommon import consts as dccommon_consts
from dccommon.drivers import base
from dccommon import exceptions


LOG = log.getLogger(__name__)
API_VERSION = '1'


class FmClient(base.DriverBase):
    """Fault Management driver."""

    def __init__(self, region, session,
                 endpoint_type=dccommon_consts.KS_ENDPOINT_DEFAULT):
        self.region_name = region
        try:
            self.fm = fmclient.Client(API_VERSION,
                                      session=session,
                                      region_name=region,
                                      endpoint_type=endpoint_type)
        except exceptions.ServiceUnavailable:
            raise

    def get_alarm_summary(self):
        """Get this region alarm summary

        """
        try:
            LOG.debug("get_alarm_summary region %s" % self.region_name)
            alarms = self.fm.alarm.summary()
        except Exception as e:
            LOG.error("get_alarm_summary exception={}".format(e))
            raise e
        return alarms
