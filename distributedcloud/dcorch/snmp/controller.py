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

import collections
import datetime
from dccommon import consts as dccommon_consts
from dcorch.common import context
from dcorch.rpc import client as rpc_client
from multiprocessing import Queue
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class Controller(object):

    system_throttle_timers = {}
    system_last_updates = {}
    system_in_delay = {}
    system_trap_tstamps = {}

    def __init__(self, systems, cfg):
        self.cfg = cfg
        self.event_queue = Queue()
        self.rpc_client = rpc_client.EngineClient()
        self.throttle_threshold = self.cfg.snmp.throttle_threshold
        for i in systems:
            self._add_system(i)

    def send_notification(self, system):
        LOG.debug("Sending update request for %s" % (system))
        try:
            ctx = context.get_admin_context()
            self.rpc_client.update_alarm_summary(ctx, system)
        except Exception:
            LOG.error('Failed to send update for system %s' % system)
            return
        self.system_last_updates[system] = datetime.datetime.now()

    def _add_system(self, system):
        # Arbitrarily distant last update, ensures first trap updates
        self.system_last_updates[system] = datetime.datetime(1989, 3, 9)
        self.system_throttle_timers[system] = None
        self.system_in_delay[system] = False
        self.system_trap_tstamps[system] = collections.deque()

    def handle_trap(self, system, msg):
        if system == dccommon_consts.CLOUD_0:
            return
        if not (system in self.system_last_updates):
            self._add_system(system)
        tstamp = datetime.datetime.utcnow()
        self.system_trap_tstamps[system].append(tstamp)
        # we throttle the notification in the following condiftions
        #   1. system is already being throttled (ignores notification)
        #   2. If more than throttle_threshold traps have come within
        #      delay_time and we last updated within delay_time
        # otherwise we request an update for the system
        if len(self.system_trap_tstamps[system]) > self.throttle_threshold:
            self.system_trap_tstamps[system].popleft()
        if self.system_in_delay[system]:
            LOG.debug("No action for %s , msg: %s. Already in delay" %
                      (system, msg))
            return
        if self._should_throttle_notification(system, tstamp):
            delta = (tstamp -
                     self.system_last_updates[system]).total_seconds()
            if delta > self.cfg.snmp.delay_time:
                self.send_notification(system)
            else:
                notification_time = self.system_last_updates[system] +\
                    datetime.timedelta(0, self.cfg.snmp.delay_time)
                self.system_throttle_timers[system] = notification_time
        else:
            self.send_notification(system)

    def _should_throttle_notification(self, system, new_trap_tstamp):
        d = self.system_trap_tstamps[system]
        if len(d) < self.throttle_threshold:
            return False
        if d[0] < new_trap_tstamp -\
                datetime.timedelta(0, self.cfg.snmp.delay_time):
            return False
        return True

    def handle_delayed_notifications(self):
        curr_time = datetime.datetime.utcnow()
        for system, notify_time in self.system_throttle_timers.items():
            if notify_time is not None:
                if curr_time > notify_time:
                    self.send_notification(system)
                    self.system_throttle_timers[system] = None
                    self.system_in_delay[system] = False
