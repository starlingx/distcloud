# Copyright (c) 2021 Wind River Systems, Inc.
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
DC Manager Audit Service.
"""

import eventlet
eventlet.monkey_patch()

from oslo_config import cfg
from oslo_i18n import _lazy
from oslo_log import log as logging
from oslo_service import service

from dcmanager.common import config
from dcmanager.common import messaging


_lazy.enable_lazy()
config.register_options()
config.register_keystone_options()
LOG = logging.getLogger('dcmanager.audit')

CONF = cfg.CONF


def main():
    logging.register_options(CONF)
    CONF(project='dcmanager', prog='dcmanager-audit')
    logging.setup(cfg.CONF, 'dcmanager-audit')
    logging.set_defaults()
    messaging.setup()

    from dcmanager.audit import service as audit

    srv = audit.DCManagerAuditService()
    launcher = service.launch(cfg.CONF,
                              srv, workers=CONF.audit_workers)

    LOG.info("Starting...")
    LOG.debug("Configuration:")
    cfg.CONF.log_opt_values(LOG, logging.DEBUG)

    launcher.wait()

if __name__ == '__main__':
    main()
