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

from oslo_log import log as logging
import threading
import time

LOG = logging.getLogger(__name__)


class QueueMonitor(threading.Thread):
    def __init__(self, controller, snmp_process):
        super(QueueMonitor, self).__init__()
        self.snmp_process = snmp_process
        self.controller = controller
        self._stop = threading.Event()

    def read_queue(self):
        while not self.stopped():
            item = None
            try:
                item = self.controller.event_queue.get(True, 0.1)
            except Exception:
                item = ""
            if item == "":
                time.sleep(0.1)
            else:
                system = item[0]
                msg = item[1]
                if not (system is None):
                    self.controller.handle_trap(system, msg)
            self.controller.handle_delayed_notifications()
            if not self.snmp_process.is_alive():
                break
        LOG.info("Stopping Queue Managment Thread")

    def stopped(self):
        return self._stop.isSet()

    def stop(self):
        self._stop.set()

    def run(self):
        self.read_queue()
