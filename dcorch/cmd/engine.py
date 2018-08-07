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
DC Orchestrators Engine Server.
"""

import eventlet
eventlet.monkey_patch()

from oslo_config import cfg
from oslo_i18n import _lazy
from oslo_log import log as logging
from oslo_service import service

from dcmanager.common import messaging as dmanager_messaging
from dcorch.common import config
from dcorch.common import consts
from dcorch.common import messaging
from dcorch.engine import service as engine

_lazy.enable_lazy()
config.register_options()
LOG = logging.getLogger('dcorch.engine')


def main():
    logging.register_options(cfg.CONF)
    cfg.CONF(project='dcorch', prog='dcorch-engine')
    logging.setup(cfg.CONF, 'dcorch-engine')
    logging.set_defaults()
    messaging.setup()
    dmanager_messaging.setup()

    srv = engine.EngineService(cfg.CONF.host,
                               consts.TOPIC_ORCH_ENGINE)
    launcher = service.launch(cfg.CONF,
                              srv, workers=cfg.CONF.workers)
    # the following periodic tasks are intended serve as HA checking
    # srv.create_periodic_tasks()
    launcher.wait()

if __name__ == '__main__':
    main()
