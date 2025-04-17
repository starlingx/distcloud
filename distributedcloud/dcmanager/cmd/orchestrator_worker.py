# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
DC Manager Orchestrator Worker Service.
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

CONF = cfg.CONF
LOG = logging.getLogger("dcmanager.orchestrator-worker")


def main():
    _lazy.enable_lazy()
    config.register_options()
    config.register_keystone_options()
    logging.register_options(CONF)
    CONF(project="dcmanager", prog="dcmanager-orchestrator-worker")
    logging.setup(CONF, "dcmanager-orchestrator-worker")
    logging.set_defaults()
    messaging.setup()
    dcorch_messaging.setup()

    from dcmanager.orchestrator import service as orchestrator

    srv = orchestrator.DCManagerOrchestratorWorkerService()
    launcher = service.launch(CONF, srv, workers=cfg.CONF.orch_worker_workers)

    LOG.info("Starting...")
    LOG.debug("Configuration:")
    CONF.log_opt_values(LOG, logging.DEBUG)

    launcher.wait()


if __name__ == "__main__":
    main()
