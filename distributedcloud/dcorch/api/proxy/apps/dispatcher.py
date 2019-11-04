# Copyright 2017 Wind River
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import webob.dec
import webob.exc

from oslo_config import cfg
from oslo_log import log as logging

from dcorch.api.proxy.common import utils

LOG = logging.getLogger(__name__)

dispatch_opts = [
    cfg.StrOpt('remote_host',
               default="192.168.204.2",
               help='remote host for api proxy to forward the request'),
    cfg.IntOpt('remote_port',
               default=18774,
               help='listen port for remote host'),
]

CONF = cfg.CONF
CONF.register_opts(dispatch_opts, CONF.type)


class APIDispatcher(object):
    """WSGI middleware that dispatch an incoming requests to a remote

    WSGI apps.
    """

    def __init__(self, app):
        self._remote_host, self._remote_port = \
            utils.get_remote_host_port_options(CONF)
        self.app = app

    @webob.dec.wsgify
    def __call__(self, req):
        """Route the incoming request to a remote host"""
        LOG.debug("APIDispatcher dispatch the request to remote host: (%s), "
                  "port: (%d)" % (self._remote_host, self._remote_port))
        utils.set_request_forward_environ(req, self._remote_host,
                                          self._remote_port)
        return self.app
