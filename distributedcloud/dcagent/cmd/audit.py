#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
DC Agent Periodic Audit Service.
"""

import sys

import eventlet

eventlet.monkey_patch()

# pylint: disable=wrong-import-position
from oslo_config import cfg  # noqa: E402
from oslo_i18n import _lazy  # noqa: E402
from oslo_log import log as logging  # noqa: E402
from oslo_service import service as oslo_service  # noqa: E402
from oslo_service import systemd  # noqa: E402
from oslo_service import wsgi  # noqa: E402

from dcagent.api import api_config  # noqa: E402
from dcagent.api import app  # noqa: E402
from dcagent.common.audit_manager import PeriodicAudit  # noqa: E402
from dcagent.common import config  # noqa: E402

# pylint: enable=wrong-import-position

_lazy.enable_lazy()
config.register_options()
LOG = logging.getLogger("dcagent")
CONF = cfg.CONF

WORKERS = 1


def main():
    api_config.init(sys.argv[1:])
    api_config.setup_logging()
    application = app.setup_app()
    host = CONF.bind_host
    port = CONF.bind_port

    LOG.info(f"Server on http://{host}:{port} with {WORKERS} worker")
    systemd.notify_once()
    service = wsgi.Server(CONF, "DCAgent", application, host, port)
    app.serve(service, CONF, WORKERS)

    srv = PeriodicAudit()
    launcher = oslo_service.launch(cfg.CONF, srv, workers=WORKERS)

    LOG.info("Starting Dcagent...")
    cfg.CONF.log_opt_values(LOG, logging.DEBUG)

    launcher.wait()


if __name__ == "__main__":
    main()
