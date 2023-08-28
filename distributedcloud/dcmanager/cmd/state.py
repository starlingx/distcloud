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
#
# Copyright (c) 2022, 2024 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

"""
DC Manager State Engine Server.
"""

import eventlet
eventlet.monkey_patch()

# pylint: disable=wrong-import-position
from oslo_config import cfg  # noqa: E402
from oslo_i18n import _lazy  # noqa: E402
from oslo_log import log as logging  # noqa: E402
from oslo_service import service  # noqa: E402

from dcmanager.common import config  # noqa: E402
from dcmanager.common import messaging  # noqa: E402
from dcorch.common import messaging as dcorch_messaging  # noqa: E402
# pylint: enable=wrong-import-position

_lazy.enable_lazy()
config.register_options()
config.register_keystone_options()
LOG = logging.getLogger('dcmanager.state')


def main():
    logging.register_options(cfg.CONF)
    cfg.CONF(project='dcmanager', prog='dcmanager-state')
    logging.setup(cfg.CONF, 'dcmanager-state')
    logging.set_defaults()
    messaging.setup()
    dcorch_messaging.setup()

    from dcmanager.state import service as state

    # Override values from /etc/dcmanager/dcmanager.conf specific
    # to dcmanager-state:
    cfg.CONF.set_override('max_pool_size', 10, group='database')
    cfg.CONF.set_override('max_overflow', 100, group='database')
    LOG.info("Starting...")
    LOG.debug("Configuration:")
    cfg.CONF.log_opt_values(LOG, logging.DEBUG)

    LOG.info("Launching service, host=%s, state_workers=%s ...",
             cfg.CONF.host, cfg.CONF.state_workers)
    srv = state.DCManagerStateService(cfg.CONF.host)
    launcher = service.launch(cfg.CONF, srv, workers=cfg.CONF.state_workers)
    launcher.wait()


if __name__ == '__main__':
    main()
