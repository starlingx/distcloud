#!/usr/bin/env python
#
# Copyright (c) 2024, 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
DC Orchestrators Engine Server.
"""

from oslo_service.backend import BackendType  # noqa: E402
from oslo_service.backend import init_backend  # noqa: E402

init_backend(BackendType.THREADING)

# pylint: disable=wrong-import-position,ungrouped-imports
from oslo_config import cfg  # noqa: E402
from oslo_i18n import _lazy  # noqa: E402
from oslo_log import log as logging  # noqa: E402
from oslo_service import service  # noqa: E402

from dcmanager.common import messaging as dmanager_messaging  # noqa: E402
from dcorch.common import config  # noqa: E402
from dcorch.common import messaging  # noqa: E402
from dcorch.engine import service as engine  # noqa: E402

# pylint: enable=wrong-import-position

_lazy.enable_lazy()
config.register_options()
LOG = logging.getLogger("dcorch.engine-worker")


def main():
    logging.register_options(cfg.CONF)
    cfg.CONF(project="dcorch", prog="dcorch-engine-worker")
    logging.setup(cfg.CONF, "dcorch-engine-worker")
    logging.set_defaults()
    messaging.setup()
    dmanager_messaging.setup()

    LOG.info(
        "Launching dcorch-engine-worker, host=%s, workers=%s ...",
        cfg.CONF.host,
        cfg.CONF.workers,
    )

    srv = engine.EngineWorkerService()
    launcher = service.launch(cfg.CONF, srv, workers=cfg.CONF.workers)
    launcher.wait()


if __name__ == "__main__":
    main()
