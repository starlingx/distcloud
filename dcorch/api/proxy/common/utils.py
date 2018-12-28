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

from dcorch.common import consts
from oslo_log import log as logging
from six.moves.urllib.parse import urlparse

LOG = logging.getLogger(__name__)


def get_host_port_options(cfg):
    if cfg.type == consts.ENDPOINT_TYPE_COMPUTE:
        return cfg.compute.bind_host, cfg.compute.bind_port
    elif cfg.type == consts.ENDPOINT_TYPE_PLATFORM:
        return cfg.platform.bind_host, cfg.platform.bind_port
    elif cfg.type == consts.ENDPOINT_TYPE_NETWORK:
        return cfg.network.bind_host, cfg.network.bind_port
    elif cfg.type == consts.ENDPOINT_TYPE_PATCHING:
        return cfg.patching.bind_host, cfg.patching.bind_port
    elif cfg.type == consts.ENDPOINT_TYPE_VOLUME:
        return cfg.volume.bind_host, cfg.volume.bind_port
    elif cfg.type == consts.ENDPOINT_TYPE_IDENTITY:
        return cfg.identity.bind_host, cfg.identity.bind_port
    else:
        LOG.error("Type: %s is undefined! Ignoring", cfg.type)
        return None, None


def get_remote_host_port_options(cfg):
    if cfg.type == consts.ENDPOINT_TYPE_COMPUTE:
        return cfg.compute.remote_host, cfg.compute.remote_port
    elif cfg.type == consts.ENDPOINT_TYPE_PLATFORM:
        return cfg.platform.remote_host, cfg.platform.remote_port
    elif cfg.type == consts.ENDPOINT_TYPE_NETWORK:
        return cfg.network.remote_host, cfg.network.remote_port
    elif cfg.type == consts.ENDPOINT_TYPE_PATCHING:
        return cfg.patching.remote_host, cfg.patching.remote_port
    elif cfg.type == consts.ENDPOINT_TYPE_VOLUME:
        return cfg.volume.remote_host, cfg.volume.remote_port
    elif cfg.type == consts.ENDPOINT_TYPE_IDENTITY:
        return cfg.identity.remote_host, cfg.identity.remote_port
    else:
        LOG.error("Type: %s is undefined! Ignoring", cfg.type)
        return None, None


def get_url_path_components(url):
    result = urlparse(url)
    return result.path.split('/')


def get_routing_match_arguments(environ):
    return environ['wsgiorg.routing_args'][1]


def get_routing_match_value(environ, key):
    match = get_routing_match_arguments(environ)
    if key in match:
        return match[key]
    else:
        LOG.info("(%s) is not available in routing match arguments.", key)
        for k, v in match.iteritems():
            LOG.info("Match key:(%s), value:(%s)", k, v)
        return None


def get_operation_type(environ):
    return environ['REQUEST_METHOD'].lower()


def get_id_from_query_string(environ, id):
    import six.moves.urllib.parse as six_urlparse
    params = six_urlparse.parse_qs(environ.get('QUERY_STRING', ''))
    return params.get(id, [None])[0]


def get_user_id(environ):
    return get_id_from_query_string(environ, 'user_id')


def show_usage(environ):
    return get_id_from_query_string(environ, 'usage') == 'True'


def get_tenant_id(environ):
    return get_routing_match_value(environ, 'tenant_id')


def set_request_forward_environ(req, remote_host, remote_port):
    req.environ['HTTP_X_FORWARDED_SERVER'] = req.environ.get(
        'HTTP_HOST', '')
    req.environ['HTTP_X_FORWARDED_SCHEME'] = req.environ['wsgi.url_scheme']
    req.environ['HTTP_HOST'] = remote_host + ':' + str(remote_port)
    req.environ['SERVER_NAME'] = remote_host
    req.environ['SERVER_PORT'] = remote_port
    if ('REMOTE_ADDR' in req.environ and 'HTTP_X_FORWARDED_FOR' not in
            req.environ):
        req.environ['HTTP_X_FORWARDED_FOR'] = req.environ['REMOTE_ADDR']
