# Copyright 2018 Wind River
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
from oslo_service.wsgi import Request

from dcorch.api.proxy.apps.proxy import Proxy
from dcorch.api.proxy.common.service import Middleware
from dcorch.api.proxy.common import utils
from dcorch.common import consts

LOG = logging.getLogger(__name__)

filter_opts = [
    cfg.StrOpt('user_header',
               default=consts.TOPIC_ORCH_ENGINE,
               help='An application specific header'),
]

CONF = cfg.CONF

CONF.register_opts(filter_opts)


class ApiFiller(Middleware):
    """WSGI middleware that filters the API requests from the

    pipeline via an application specific header

    """

    def __init__(self, app, conf):
        self._default_dispatcher = Proxy()
        self._remote_host, self._remote_port = \
            utils.get_remote_host_port_options(CONF)
        super(ApiFiller, self).__init__(app)

    @webob.dec.wsgify(RequestClass=Request)
    def __call__(self, req):
        if ('HTTP_USER_HEADER' in req.environ and
                req.environ['HTTP_USER_HEADER'] == CONF.user_header):
            utils.set_request_forward_environ(req, self._remote_host,
                                              self._remote_port)
            LOG.debug("Forward dcorch-engine request to the API service")
            return self._default_dispatcher
        else:
            return self.application
