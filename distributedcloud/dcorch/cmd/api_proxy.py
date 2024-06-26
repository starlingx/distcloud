# Copyright 2015 Huawei Technologies Co., Ltd.
# Copyright (c) 2018-2022, 2024 Wind River Systems, Inc.
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

# Much of this module is based on the work of the Ironic team
# see http://git.openstack.org/cgit/openstack/ironic/tree/ironic/cmd/api.py

import logging as std_logging
import os
import sys

import eventlet

eventlet.monkey_patch(os=False)

# pylint: disable=wrong-import-position
from oslo_config import cfg  # noqa: E402
from oslo_log import log as logging  # noqa: E402
from oslo_service import systemd  # noqa: E402
from oslo_service import wsgi  # noqa: E402

from dccommon import consts  # noqa: E402
from dcmanager.common import messaging as dcmanager_messaging  # noqa: E402
from dcorch.api import api_config  # noqa: E402
from dcorch.api import app  # noqa: E402
from dcorch.api.proxy.common import constants  # noqa: E402
from dcorch.api.proxy.common import utils  # noqa: E402
from dcorch.common import config  # noqa: E402
from dcorch.common import messaging  # noqa: E402

# pylint: enable=wrong-import-position

proxy_opts = [
    cfg.StrOpt(
        "bind_host", default="0.0.0.0", help="IP address for api proxy to listen"
    ),
    cfg.IntOpt("bind_port", default=28774, help="listen port for api proxy"),
    cfg.StrOpt(
        "sync_endpoint",
        default=None,
        help="The endpoint type for the enqueued sync work",
    ),
]

proxy_cli_opts = [
    cfg.StrOpt("type", default="compute", help="Type of the proxy service"),
]

CONF = cfg.CONF

config.register_options()
CONF.register_cli_opts(proxy_cli_opts)

LOG = logging.getLogger("dcorch.api.proxy")


def make_tempdir(tempdir):
    if not os.path.isdir(tempdir):
        os.makedirs(tempdir)
    os.environ["TMPDIR"] = tempdir


def main():
    api_config.init(sys.argv[1:])
    api_config.setup_logging()

    messaging.setup()
    dcmanager_messaging.setup()

    if CONF.type not in consts.ENDPOINT_TYPES_LIST:
        LOG.error("Unsupported endpoint type: (%s)", CONF.type)
        sys.exit(1)

    CONF.register_opts(proxy_opts, CONF.type)

    application = app.load_paste_app()

    host, port = utils.get_host_port_options(CONF)
    workers = CONF.api_workers

    if workers < 1:
        LOG.warning("Wrong worker number, worker = %(workers)s", workers)
        workers = 1

    LOG.info(
        "Server on http://%(host)s:%(port)s with %(workers)s",
        {"host": host, "port": port, "workers": workers},
    )
    systemd.notify_once()

    # For patching and platorm, create a temp directory under /scratch
    # and set TMPDIR environment variable to this directory, so that
    # the file created using tempfile will not use the default directory.
    if CONF.type == consts.ENDPOINT_TYPE_PATCHING:
        make_tempdir(constants.ENDPOINT_TYPE_PATCHING_TMPDIR)
    elif CONF.type == consts.ENDPOINT_TYPE_PLATFORM:
        make_tempdir(constants.ENDPOINT_TYPE_PLATFORM_TMPDIR)

    service = wsgi.Server(CONF, CONF.prog, application, host, port)

    app.serve(service, CONF, workers)

    LOG.info("Starting...")
    LOG.debug("Configuration:")
    CONF.log_opt_values(LOG, std_logging.DEBUG)

    app.wait()


if __name__ == "__main__":
    main()
