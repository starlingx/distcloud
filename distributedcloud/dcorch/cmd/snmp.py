#!/usr/bin/env python
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

"""
DC Orchestrators SNMP Server.
"""

from dcorch.common import messaging
from dcorch.snmp import service as snmp_engine
from dcorch.snmp import snmp_config

from oslo_config import cfg
from oslo_log import log as logging

import sys

LOG = logging.getLogger('dcorch.snmp')


def main():
    snmp_config.init(sys.argv[1:])
    cfg.CONF(project='dcorch', prog='dcorch-snmp')
    logging.setup(cfg.CONF, 'dcorch-snmp')
    logging.set_defaults()
    messaging.setup()

    snmp_engine.SNMPService(cfg)


if __name__ == '__main__':
    main()
