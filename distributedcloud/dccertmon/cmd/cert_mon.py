#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
DC Certificate Monitor Service
"""
import eventlet

eventlet.monkey_patch()

# pylint: disable=wrong-import-position
from oslo_config import cfg  # noqa: E402
from oslo_i18n import _lazy  # noqa: E402
from oslo_log import log as logging  # noqa: E402
from oslo_service import service  # noqa: E402

from dccertmon.common import config  # noqa: E402
from dcmanager.common import messaging  # noqa: E402

# pylint: enable=wrong-import-position

_lazy.enable_lazy()

LOG = logging.getLogger("dccertmon")
CONF = cfg.CONF


def main():
    config.generate_config()
    logging.register_options(CONF)
    CONF(project="dccertmon")
    config.register_config_opts()

    logging.set_defaults()
    logging.setup(CONF, "dccertmon")
    messaging.setup()

    from dccertmon.common import service as dc_cert_mon

    srv = dc_cert_mon.CertificateMonitorService()
    launcher = service.launch(cfg.CONF, srv)

    LOG.info("Starting...")
    LOG.debug("Configuration:")
    cfg.CONF.log_opt_values(LOG, logging.DEBUG)

    launcher.wait()


if __name__ == "__main__":
    main()
