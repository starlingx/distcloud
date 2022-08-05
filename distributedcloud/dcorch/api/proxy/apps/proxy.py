# Copyright 2017-2022 Wind River
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

from dcorch.api.proxy.common.service import Application
from oslo_log import log as logging
from paste.proxy import TransparentProxy


LOG = logging.getLogger(__name__)

HEADERS = ['HTTP_X_DOMAIN_ID', 'HTTP_X_DOMAIN_NAME', 'HTTP_OPENSTACK_SYSTEM_SCOPE']


class Proxy(Application):
    """A proxy that sends the request just as it was given,

    including respecting HTTP_HOST, wsgi.url_scheme, etc.
    """

    def __init__(self):
        self.proxy_app = TransparentProxy()

    def __call__(self, environ, start_response):
        LOG.debug("Proxy the request to the remote host: (%s)", environ[
            'HTTP_HOST'])
        # The http/client.py added validation for illegal headers in python3
        # which doesn't allow None values. If we don't inject these headers
        # and set them to empty string here,
        # the keystonemiddleware/auth-token/_request.py will inject them and
        # set them to None, then the validation for illegal headers will raise
        # an TypeError due to the None values.
        for header in HEADERS:
            if not environ.get(header):
                environ[header] = ''
        result = self.proxy_app(environ, start_response)
        return result
