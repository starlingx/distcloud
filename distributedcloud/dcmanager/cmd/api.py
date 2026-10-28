# Copyright 2015 Huawei Technologies Co., Ltd.
# Copyright (c) 2017, 2019, 2021, 2024, 2026 Wind River Systems, Inc.
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

# Much of this module is based on the work of the Ironic team
# see http://git.openstack.org/cgit/openstack/ironic/tree/ironic/cmd/api.py


import logging as std_logging
import sys


from oslo_service.backend import BackendType  # noqa: E402
from oslo_service.backend import init_backend  # noqa: E402

init_backend(BackendType.THREADING)

# pylint: disable=wrong-import-position
from oslo_config import cfg  # noqa: E402
from oslo_log import log as logging  # noqa: E402

from dccommon.wsgi import DCApplication  # noqa: E402
from dcmanager.api import api_config  # noqa: E402
from dcmanager.api import app  # noqa: E402
from dcmanager.common import config  # noqa: E402
from dcmanager.common import messaging  # noqa: E402
from dcorch.common import messaging as dcorch_messaging  # noqa: E402

# pylint: enable=wrong-import-position

CONF = cfg.CONF
config.register_options()
LOG = logging.getLogger("dcmanager.api")


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

    LOG.info(
        "Server on http://%(host)s:%(port)s with %(workers)s",
        {"host": host, "port": port, "workers": workers},
    )
    messaging.setup()
    dcorch_messaging.setup()
    service = DCApplication(application, "dcmanager-api", host, port, workers=workers)

    LOG.info("Starting...")
    LOG.debug("Configuration:")
    CONF.log_opt_values(LOG, std_logging.DEBUG)

    service.run()


if __name__ == "__main__":
    main()
