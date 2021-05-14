# Copyright 2015 Huawei Technologies Co., Ltd.
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


import eventlet
eventlet.monkey_patch(os=False)

import os
import sys

from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import systemd
from oslo_service import wsgi

import logging as std_logging

from dcmanager.common import messaging as dcmanager_messaging
from dcorch.api import api_config
from dcorch.api import app
from dcorch.api.proxy.common import constants

from dcorch.common import config
from dcorch.common import consts
from dcorch.common import messaging

from dcorch.api.proxy.common import utils

proxy_opts = [
    cfg.StrOpt('bind_host',
               default="0.0.0.0",
               help='IP address for api proxy to listen'),
    cfg.IntOpt('bind_port',
               default=28774,
               help='listen port for api proxy'),
    cfg.StrOpt('sync_endpoint',
               default=None,
               help='The endpoint type for the enqueued sync work'),
]

proxy_cli_opts = [
    cfg.StrOpt('type',
               default="compute",
               help='Type of the proxy service'),
]

CONF = cfg.CONF

config.register_options()
CONF.register_cli_opts(proxy_cli_opts)

LOG = logging.getLogger('dcorch.api.proxy')


def make_tempdir(tempdir):
    if not os.path.isdir(tempdir):
        os.makedirs(tempdir)
    os.environ['TMPDIR'] = tempdir


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

    LOG.info("Server on http://%(host)s:%(port)s with %(workers)s",
             {'host': host, 'port': port, 'workers': workers})
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


if __name__ == '__main__':
    main()
