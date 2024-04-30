#!/usr/bin/env python
# Copyright (c) 2024 Wind River Systems, Inc.
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

"""
DC Orchestrators Engine Server.
"""

import eventlet
eventlet.monkey_patch()

# pylint: disable=wrong-import-position
from oslo_config import cfg  # noqa: E402
from oslo_i18n import _lazy  # noqa: E402
from oslo_log import log as logging  # noqa: E402
from oslo_service import service  # noqa: E402

from dcorch.common import config  # noqa: E402
from dcorch.common import messaging  # noqa: E402
from dcorch.engine import service as engine  # noqa: E402
# pylint: enable=wrong-import-position

_lazy.enable_lazy()
config.register_options()
LOG = logging.getLogger('dcorch.engine')


def main():
    logging.register_options(cfg.CONF)
    cfg.CONF(project='dcorch', prog='dcorch-engine')
    logging.setup(cfg.CONF, 'dcorch-engine')
    logging.set_defaults()
    messaging.setup()

    LOG.info("Launching dcorch-engine, host=%s ...", cfg.CONF.host)

    srv = engine.EngineService()
    launcher = service.launch(cfg.CONF, srv)
    # the following periodic tasks are intended serve as HA checking
    # srv.create_periodic_tasks()
    launcher.wait()


if __name__ == '__main__':
    main()
