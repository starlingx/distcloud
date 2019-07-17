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
#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

# Much of this module is based on the work of the Ironic team
# see http://git.openstack.org/cgit/openstack/ironic/tree/ironic/cmd/api.py


import sys

import eventlet
eventlet.monkey_patch(os=False)

from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import systemd
from oslo_service import wsgi

import logging as std_logging

from dcmanager.api import api_config
from dcmanager.api import app

from dcmanager.common import config
from dcmanager.common import messaging
from dcorch.common import messaging as dcorch_messaging
CONF = cfg.CONF
config.register_options()
LOG = logging.getLogger('dcmanager.api')


def main():
    api_config.init(sys.argv[1:])
    api_config.setup_logging()
    application = app.setup_app()

    host = CONF.bind_host
    port = CONF.bind_port
    workers = CONF.api_workers

    if workers < 1:
        LOG.warning("Wrong worker number, worker = %(workers)s", workers)
        workers = 1

    LOG.info("Server on http://%(host)s:%(port)s with %(workers)s",
             {'host': host, 'port': port, 'workers': workers})
    messaging.setup()
    dcorch_messaging.setup()
    systemd.notify_once()
    service = wsgi.Server(CONF, "DCManager", application, host, port)

    app.serve(service, CONF, workers)

    LOG.info("Configuration:")
    CONF.log_opt_values(LOG, std_logging.INFO)

    app.wait()


if __name__ == '__main__':
    main()
