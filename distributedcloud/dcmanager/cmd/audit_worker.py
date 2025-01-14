# Copyright (c) 2021, 2024 Wind River Systems, Inc.
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
DC Manager Audit Worker Service.
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
LOG = logging.getLogger("dcmanager.audit-worker")

CONF = cfg.CONF


def main():
    logging.register_options(CONF)
    CONF(project="dcmanager", prog="dcmanager-audit-worker")
    logging.setup(cfg.CONF, "dcmanager-audit-worker")
    logging.set_defaults()
    messaging.setup()
    dcorch_messaging.setup()

    from dcmanager.audit import service as audit

    # Override values from /etc/dcmanager/dcmanager.conf specific
    # to dcmanager-audit-worker:
    cfg.CONF.set_override("http_discovery_timeout", 5, group="endpoint_cache")

    srv = audit.DCManagerAuditWorkerService()
    launcher = service.launch(cfg.CONF, srv, workers=CONF.audit_worker_workers)

    LOG.info("Starting...")
    LOG.debug("Configuration:")
    cfg.CONF.log_opt_values(LOG, logging.DEBUG)

    launcher.wait()


if __name__ == "__main__":
    main()
