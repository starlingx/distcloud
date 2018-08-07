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
from oslo_service.wsgi import Request
from oslo_utils._i18n import _
from routes.middleware import RoutesMiddleware

from dcorch.api.proxy.common import constants
from dcorch.api.proxy.common.service import Middleware

LOG = logging.getLogger(__name__)

CONF = cfg.CONF


class Router(Middleware):
    """WSGI middleware that maps incoming requests to WSGI apps.

    """

    def __init__(self, app, conf, mapper, forwarder):

        """Create a router for the given routes.Mapper.

        """

        self.map = mapper
        self.forwarder = forwarder
        self._router = RoutesMiddleware(self._dispatch, self.map)
        super(Router, self).__init__(app)

    @webob.dec.wsgify(RequestClass=Request)
    def __call__(self, req):

        """Route the incoming request to a controller based on self.map.

        """

        return self._router

    @webob.dec.wsgify
    def _dispatch(self, req):

        """Called by self._router after matching the incoming request to a

        route and putting the information into req.environ.
        """

        match = req.environ['wsgiorg.routing_args'][1]
        if not match:
            if self.forwarder:
                return self.forwarder
            msg = _('The request is not allowed in System Controller')
            raise webob.exc.HTTPForbidden(explanation=msg)
        LOG.debug("Found match action!")
        app = match['controller']
        return app

    @staticmethod
    def _add_resource(mapper, controller, paths, tag, endpoint_type,
                      action=None, method=None):
        if action is None:
            action = tag
        if method is None:
            method = constants.ROUTE_METHOD_MAP[endpoint_type].get(tag)
        for path in paths:
            mapper.connect(path, controller=controller, action=action,
                           conditions=dict(method=method))
