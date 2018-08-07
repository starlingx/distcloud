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

from controller import Controller
from multiprocessing import Process
from oslo_log import log as logging
from oslo_service import service
from queue_monitor import QueueMonitor
from snmp_server import SNMPTrapServer

LOG = logging.getLogger(__name__)


class SNMPService(service.Service):

    def __init__(self, cfg):
        super(SNMPService, self).__init__()
        cont = Controller([], cfg.CONF)
        self.snmp_server = Process(target=self.launch_SNMP_server,
                                   args=(cont.event_queue, cfg.CONF))
        self.snmp_server.start()
        self.queue_thread = QueueMonitor(cont, self.snmp_server)
        LOG.info('Starting Queue Monitor Thread')
        self.queue_thread.start()
        self.queue_thread.join()

    def launch_SNMP_server(self, q, config):
        trap_server = SNMPTrapServer(controller=q, cfg=config)
        LOG.info('Starting SNMP Server Thread')
        trap_server.run()

    def end(self):
        self.queue_thread.stop()
        self.snmp_server.stop()
