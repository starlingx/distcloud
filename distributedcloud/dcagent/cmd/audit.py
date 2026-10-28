#
# Copyright (c) 2024, 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
DC Agent Periodic Audit Service.
"""

import sys
import threading


from oslo_service.backend import BackendType  # noqa: E402
from oslo_service.backend import init_backend  # noqa: E402

init_backend(BackendType.THREADING)

# pylint: disable=wrong-import-position
from oslo_config import cfg  # noqa: E402
from oslo_i18n import _lazy  # noqa: E402
from oslo_log import log as logging  # noqa: E402

from dcagent.api import api_config  # noqa: E402
from dcagent.api import app  # noqa: E402
from dcagent.common.audit_manager import PeriodicAudit  # noqa: E402
from dcagent.common import config  # noqa: E402
from dccommon.wsgi import DCApplication  # noqa: E402

# pylint: enable=wrong-import-position

_lazy.enable_lazy()
config.register_options()
LOG = logging.getLogger("dcagent")
CONF = cfg.CONF

WORKERS = 1


def _start_periodic_audit(worker):
    """Start the PeriodicAudit in a daemon thread inside the gunicorn worker.

    This runs in the same process as the WSGI handler so they share
    the in-process cache (CachedSysinvClient._results, etc.).
    """
    thread = threading.Thread(target=PeriodicAudit, daemon=True)
    thread.start()


def main():
    api_config.init(sys.argv[1:])
    api_config.setup_logging()
    application = app.setup_app()
    host = CONF.bind_host
    port = CONF.bind_port

    LOG.info(f"Server on http://{host}:{port} with {WORKERS} worker")
    LOG.info("Starting Dcagent...")
    cfg.CONF.log_opt_values(LOG, logging.DEBUG)

    service = DCApplication(
        application,
        "dcagent-api",
        host,
        port,
        workers=WORKERS,
        post_worker_init_hook=_start_periodic_audit,
    )
    service.run()


if __name__ == "__main__":
    main()
