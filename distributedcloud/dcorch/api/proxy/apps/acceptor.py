# Copyright 2017-2025 Wind River
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

from oslo_config import cfg
from oslo_log import log as logging
import routes

from dccommon import consts as dccommon_consts
from dcorch.api.proxy.apps.controller import IdentityAPIController
from dcorch.api.proxy.apps.controller import SysinvAPIController
from dcorch.api.proxy.apps.controller import USMAPIController
from dcorch.api.proxy.apps.controller import VersionController
from dcorch.api.proxy.apps.dispatcher import APIDispatcher
from dcorch.api.proxy.apps.router import Router
from dcorch.api.proxy.common import constants as proxy_consts

LOG = logging.getLogger(__name__)
CONF = cfg.CONF


class Acceptor(Router):

    def __init__(self, app, conf):
        self._default_dispatcher = APIDispatcher(app)
        self.forwarder_map = {
            dccommon_consts.ENDPOINT_TYPE_PLATFORM: self._default_dispatcher,
            dccommon_consts.ENDPOINT_TYPE_IDENTITY: self._default_dispatcher,
            dccommon_consts.ENDPOINT_TYPE_USM: self._default_dispatcher,
        }
        if CONF.type in self.forwarder_map:
            forwarder = self.forwarder_map[CONF.type]
        else:
            forwarder = None

        self.route_map = {
            dccommon_consts.ENDPOINT_TYPE_PLATFORM: self.add_platform_routes,
            dccommon_consts.ENDPOINT_TYPE_IDENTITY: self.add_identity_routes,
            dccommon_consts.ENDPOINT_TYPE_USM: self.add_usm_routes,
        }
        self._conf = conf
        mapper = routes.Mapper()
        self.add_routes(app, conf, mapper)
        super(Acceptor, self).__init__(app, conf, mapper, forwarder)

    def add_routes(self, app, conf, mapper):
        handler = self.route_map[CONF.type]
        handler(app, conf, mapper)

    def add_platform_routes(self, app, conf, mapper):
        api_controller = SysinvAPIController(app, conf)

        for key, value in proxy_consts.SYSINV_PATH_MAP.items():
            self._add_resource(mapper, api_controller, value, key, CONF.type)

    def add_identity_routes(self, app, conf, mapper):
        api_controller = IdentityAPIController(app, conf)

        for key, value in proxy_consts.IDENTITY_PATH_MAP.items():
            self._add_resource(mapper, api_controller, value, key, CONF.type)

    def add_usm_routes(self, app, conf, mapper):
        api_controller = USMAPIController(app, conf)

        for key, value in proxy_consts.USM_PATH_MAP.items():
            self._add_resource(mapper, api_controller, value, key, CONF.type)


class VersionAcceptor(Router):
    def __init__(self, app, conf):
        self._conf = conf
        mapper = routes.Mapper()
        api_controller = VersionController(app, conf)
        mapper.connect(
            proxy_consts.VERSION_ROOT,
            controller=api_controller,
            conditions=dict(method=["GET"]),
        )
        super(VersionAcceptor, self).__init__(app, conf, mapper, app)
