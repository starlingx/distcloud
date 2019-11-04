# Copyright 2016 Ericsson AB
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
from netaddr import IPAddress
from oslo_log import log as logging
from pysnmp.carrier.asynsock.dgram import udp
from pysnmp.carrier.asynsock.dgram import udp6
from pysnmp.entity import config
from pysnmp.entity import engine
from pysnmp.entity.rfc3413 import ntfrcv
import threading

LOG = logging.getLogger(__name__)


class SNMPTrapServer(threading.Thread):

    def __init__(self, controller, cfg):
        threading.Thread.__init__(self)
        self.controller = controller
        self.cfg = cfg
        self.snmp_engine = engine.SnmpEngine()
        self.count = 0
        # Transport setup
        ipv4 = True
        if IPAddress(self.cfg.snmp.snmp_ip).version == 6:
            ipv4 = False
        # Transport setup
        if ipv4:
            # UDP over IPv4, first listening interface/port
            config.addSocketTransport(
                self.snmp_engine,
                udp.domainName + (1,),
                udp.UdpTransport().openServerMode((self.cfg.snmp.snmp_ip,
                                                   self.cfg.snmp.snmp_port))
            )
        else:
            # UDP over IPv6, first listening interface/port
            config.addSocketTransport(
                self.snmp_engine,
                udp6.domainName + (1,),
                udp6.Udp6Transport().openServerMode((self.cfg.snmp.snmp_ip,
                                                     self.cfg.snmp.snmp_port))
            )
        # SecurityName <-> CommunityName mapping
        config.addV1System(self.snmp_engine,
                           self.cfg.snmp.snmp_sec_area,
                           self.cfg.snmp.snmp_comm_str)

        ntfrcv.NotificationReceiver(self.snmp_engine, self.cb_fun)

    def cb_fun(self, snmp_engine,
               state_reference,
               context_engine_id, context_name,
               var_binds,
               cb_ctx):
        transport_domain, transport_address = \
            self.snmp_engine.msgAndPduDsp.getTransportInfo(state_reference)
        LOG.info('Notification received from %s' % (transport_address[0]))
        system_oid = '1.3.6.1.4.1.731.1.1.1.1.1.1.4'
        for oid, val in var_binds:
            if str(oid) == system_oid:
                system = ""
                try:
                    system = self.parse_system_line(str(val))
                except Exception:
                    return
                self.controller.put((system, self.count))
                # Used as a buffer clearing object for the Queue
                # Without this the lock is not released on the payload object
                # and get() returns nothing on the other end
                # leaving 1 item in the queue
                self.controller.put((None, None))
                self.count += 1
                return

    def parse_system_line(self, system_line):
        line_split = system_line.split('.')
        system_split = line_split[0].split('=')
        return system_split[1]

    def run(self):
        self.snmp_engine.transportDispatcher.jobStarted(1)
        LOG.info('SNMP Transport Dispatcher Job Started')
        try:
            self.snmp_engine.transportDispatcher.runDispatcher()
        except Exception:
            self.snmp_engine.transportDispatcher.closeDispatcher()
            raise

    def stop(self):
        self.snmp_engine.transportDispatcher.jobFinished(1)
        self.snmp_engine.transportDispatcher.closeDispatcher()
