#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Routines for configuring DC agent, largely copied from Neutron
"""

import sys

from oslo_config import cfg
from oslo_log import log as logging

from dcagent.common.i18n import _
from dcagent.common import version

LOG = logging.getLogger(__name__)

common_opts = [
    cfg.StrOpt("bind_host", default="0.0.0.0", help=_("The host IP to bind to")),
    cfg.IntOpt("bind_port", default=8325, help=_("The port to bind to")),
    cfg.IntOpt("api_workers", default=1, help=_("number of api workers")),
    cfg.StrOpt(
        "auth_strategy", default="keystone", help=_("The type of authentication to use")
    ),
]


def init(args, **kwargs):
    # Register the configuration options
    cfg.CONF.register_opts(common_opts)

    logging.register_options(cfg.CONF)

    cfg.CONF(
        args=args,
        project="dcagent",
        version="%%(prog)s %s" % version.version_info.release_string(),
        **kwargs
    )


def setup_logging():
    """Sets up the logging options for a log with supplied name."""
    product_name = "dcagent"
    logging.setup(cfg.CONF, product_name)
    LOG.info("Logging enabled!")
    LOG.info(
        "%(prog)s version %(version)s",
        {"prog": sys.argv[0], "version": version.version_info.release_string()},
    )
    LOG.debug("command line: %s", " ".join(sys.argv))


def reset_service():
    # Reset worker in case SIGHUP is called.
    # Note that this is called only in case a service is running in daemon mode.
    setup_logging()

    # TODO(vgluzrom) enforce policy later
    # policy.refresh()


def test_init():
    # Register the configuration options
    cfg.CONF.register_opts(common_opts)
    try:
        logging.register_options(cfg.CONF)
    except cfg.ArgsAlreadyParsedError:
        pass
    setup_logging()


def list_opts():
    yield None, common_opts
