#!/usr/bin/env python
# Copyright (c) 2017-2021, 2024 Wind River Systems, Inc.
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

"""
DC Manager Engine Server.
"""

import eventlet

eventlet.monkey_patch()

# pylint: disable=wrong-import-position
from oslo_config import cfg  # noqa: E402
from oslo_i18n import _lazy  # noqa: E402
from oslo_log import log as logging  # noqa: E402
from oslo_service import service  # noqa: E402

from dcmanager.common import config  # noqa: E402
from dcmanager.common import consts  # noqa: E402
from dcmanager.common import messaging  # noqa: E402
from dcorch.common import messaging as dcorch_messaging  # noqa: E402

# pylint: enable=wrong-import-position

_lazy.enable_lazy()
config.register_options()
config.register_keystone_options()
LOG = logging.getLogger("dcmanager.engine")


def main():
    logging.register_options(cfg.CONF)
    cfg.CONF(project="dcmanager", prog="dcmanager-engine")
    logging.setup(cfg.CONF, "dcmanager-engine")
    logging.set_defaults()
    messaging.setup()
    dcorch_messaging.setup()

    from dcmanager.manager import service as manager

    srv = manager.DCManagerService(cfg.CONF.host, consts.TOPIC_DC_MANAGER)
    launcher = service.launch(cfg.CONF, srv, workers=cfg.CONF.workers)

    LOG.info("Starting...")
    LOG.debug("Configuration:")
    cfg.CONF.log_opt_values(LOG, logging.DEBUG)

    # the following periodic tasks are intended serve as HA checking
    # srv.create_periodic_tasks()
    launcher.wait()


if __name__ == "__main__":
    main()
