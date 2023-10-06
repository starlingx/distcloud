# Copyright 2018, 2021 Wind River
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

from dccommon import consts as dccommon_consts
from dcorch.api.proxy.apps.proxy import Proxy
from dcorch.api.proxy.common.service import Middleware
from dcorch.api.proxy.common import utils

LOG = logging.getLogger(__name__)

filter_opts = [
    cfg.StrOpt('user_header',
               default=dccommon_consts.USER_HEADER_VALUE,
               help='An application specific header'),
]

CONF = cfg.CONF

CONF.register_opts(filter_opts)


def is_load_import(content_type, url_path):
    if (content_type == "multipart/form-data" and
            url_path == "/v1/loads/import_load"):
        return True
    else:
        return False


class ApiFiller(Middleware):
    """WSGI middleware that filters the API requests from the

    pipeline via an application specific header, also it checks

    disk space available for multipart form-data import_load

    request, this can be extended for other multipart form-data


    """

    def __init__(self, app, conf):
        self._default_dispatcher = Proxy()
        self._remote_host, self._remote_port = \
            utils.get_remote_host_port_options(CONF)
        super(ApiFiller, self).__init__(app)

    @webob.dec.wsgify(RequestClass=Request)
    def __call__(self, req):
        # Only check space for load-import request
        if is_load_import(req.content_type, req.path):
            # 3 times the file size is needed:
            # 2 times on webob temporary copies
            # 1 time on internal temporary copy to be shared with sysinv
            if not utils.is_space_available("/scratch",
                                            3 * req.content_length):
                msg = _(
                    "Insufficient space on /scratch for request %s, "
                    "/scratch must have at least %d bytes of free space. "
                    "You can delete unused files from /scratch or increase the size of it "
                    "with: 'system host-fs-modify <hostname> scratch=<new_size_in_GiB>'"
                ) % (req.path, 3 * req.content_length)

                raise webob.exc.HTTPInternalServerError(explanation=msg)

        if ('HTTP_USER_HEADER' in req.environ and
                req.environ['HTTP_USER_HEADER'] == CONF.user_header):
            utils.set_request_forward_environ(req, self._remote_host,
                                              self._remote_port)
            LOG.debug("Forward dcorch-engine request to the API service")
            return self._default_dispatcher
        else:
            return self.application
