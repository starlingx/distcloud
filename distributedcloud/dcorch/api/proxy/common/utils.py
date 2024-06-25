# Copyright 2017-2024 Wind River
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

from urllib.parse import urlparse

import base64
from cryptography import fernet
from keystoneauth1 import exceptions as keystone_exceptions
import msgpack
from oslo_log import log as logging
import psutil

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.sdk_platform import (
    OptimizedOpenStackDriver as OpenStackDriver
)
from dcorch.common import consts

LOG = logging.getLogger(__name__)


def is_space_available(partition, size):
    available_space = psutil.disk_usage(partition).free
    return False if available_space < size else True


def get_host_port_options(cfg):
    if cfg.type == consts.ENDPOINT_TYPE_COMPUTE:
        return cfg.compute.bind_host, cfg.compute.bind_port
    elif cfg.type == dccommon_consts.ENDPOINT_TYPE_PLATFORM:
        return cfg.platform.bind_host, cfg.platform.bind_port
    elif cfg.type == consts.ENDPOINT_TYPE_NETWORK:
        return cfg.network.bind_host, cfg.network.bind_port
    elif cfg.type == dccommon_consts.ENDPOINT_TYPE_SOFTWARE:
        return cfg.usm.bind_host, cfg.usm.bind_port
    elif cfg.type == dccommon_consts.ENDPOINT_TYPE_PATCHING:
        return cfg.patching.bind_host, cfg.patching.bind_port
    elif cfg.type == consts.ENDPOINT_TYPE_VOLUME:
        return cfg.volume.bind_host, cfg.volume.bind_port
    elif cfg.type == dccommon_consts.ENDPOINT_TYPE_IDENTITY:
        return cfg.identity.bind_host, cfg.identity.bind_port
    else:
        LOG.error("Type: %s is undefined! Ignoring", cfg.type)
        return None, None


def get_remote_host_port_options(cfg):
    if cfg.type == consts.ENDPOINT_TYPE_COMPUTE:
        return cfg.compute.remote_host, cfg.compute.remote_port
    elif cfg.type == dccommon_consts.ENDPOINT_TYPE_PLATFORM:
        return cfg.platform.remote_host, cfg.platform.remote_port
    elif cfg.type == consts.ENDPOINT_TYPE_NETWORK:
        return cfg.network.remote_host, cfg.network.remote_port
    elif cfg.type == dccommon_consts.ENDPOINT_TYPE_SOFTWARE:
        return cfg.usm.remote_host, cfg.usm.remote_port
    elif cfg.type == dccommon_consts.ENDPOINT_TYPE_PATCHING:
        return cfg.patching.remote_host, cfg.patching.remote_port
    elif cfg.type == consts.ENDPOINT_TYPE_VOLUME:
        return cfg.volume.remote_host, cfg.volume.remote_port
    elif cfg.type == dccommon_consts.ENDPOINT_TYPE_IDENTITY:
        return cfg.identity.remote_host, cfg.identity.remote_port
    else:
        LOG.error("Type: %s is undefined! Ignoring", cfg.type)
        return None, None


def get_sync_endpoint(cfg):
    if cfg.type == consts.ENDPOINT_TYPE_COMPUTE:
        return cfg.compute.sync_endpoint
    elif cfg.type == dccommon_consts.ENDPOINT_TYPE_PLATFORM:
        return cfg.platform.sync_endpoint
    elif cfg.type == consts.ENDPOINT_TYPE_NETWORK:
        return cfg.network.sync_endpoint
    elif cfg.type == dccommon_consts.ENDPOINT_TYPE_PATCHING:
        return cfg.patching.sync_endpoint
    elif cfg.type == consts.ENDPOINT_TYPE_VOLUME:
        return cfg.volume.sync_endpoint
    elif cfg.type == dccommon_consts.ENDPOINT_TYPE_IDENTITY:
        return cfg.identity.sync_endpoint
    else:
        LOG.error("Type: %s is undefined! Ignoring", cfg.type)
        return None


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
        for k, v in match.items():
            LOG.info("Match key:(%s), value:(%s)", k, v)
        return None


def get_operation_type(environ):
    return environ['REQUEST_METHOD'].lower()


def get_id_from_query_string(environ, id):
    import urllib.parse as six_urlparse
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


def _get_fernet_keys():
    """Get fernet keys from sysinv."""
    os_client = OpenStackDriver(
        region_name=dccommon_consts.CLOUD_0,
        region_clients=("sysinv",),
        thread_name="proxy",
    )
    try:
        key_list = os_client.sysinv_client.get_fernet_keys()
        return [str(getattr(key, 'key')) for key in key_list]
    except (keystone_exceptions.connection.ConnectTimeout,
            keystone_exceptions.ConnectFailure) as e:
        LOG.info("get_fernet_keys: cloud {} is not reachable [{}]"
                 .format(dccommon_consts.CLOUD_0, str(e)))
        OpenStackDriver.delete_region_clients(dccommon_consts.CLOUD_0)
        return None
    except (AttributeError, TypeError) as e:
        LOG.info("get_fernet_keys error {}".format(e))
        OpenStackDriver.delete_region_clients(
            dccommon_consts.CLOUD_0, clear_token=True
        )
        return None
    except Exception as e:
        LOG.exception(e)
        return None


def _restore_padding(token):
    """Restore padding based on token size.

    :param token: token to restore padding on
    :returns: token with correct padding
    """

    # Re-inflate the padding
    mod_returned = len(token) % 4
    if mod_returned:
        missing_padding = 4 - mod_returned
        token += b'=' * missing_padding
    return token


def _unpack_token(fernet_token, fernet_keys):
    """Attempt to unpack a token using the supplied Fernet keys.

    :param fernet_token: token to unpack
    :type fernet_token: string
    :param fernet_keys: a list consisting of keys in the repository
    :type fernet_keys: list
    :returns: the token payload
    """

    # create a list of fernet instances
    fernet_instances = [fernet.Fernet(key) for key in fernet_keys]
    # create a encryption/decryption object from the fernet keys
    crypt = fernet.MultiFernet(fernet_instances)

    # attempt to decode the token
    token = _restore_padding(bytes(fernet_token))
    serialized_payload = crypt.decrypt(token)
    payload = msgpack.unpackb(serialized_payload)

    # present token values
    return payload


def retrieve_token_audit_id(fernet_token):
    """Attempt to retrieve the audit id from the fernet token.

    :param fernet_token:
    :param keys_repository:
    :return: audit id in base64 encoded (without paddings)
    """

    audit_id = None
    fernet_keys = _get_fernet_keys()
    LOG.info("fernet_keys: {}".format(fernet_keys))

    if fernet_keys:
        unpacked_token = _unpack_token(fernet_token, fernet_keys)
        if unpacked_token:
            audit_id = unpacked_token[-1][0]
            audit_id = base64.urlsafe_b64encode(
                audit_id.encode('utf-8')).rstrip(b'=').decode('utf-8')

    return audit_id


def cleanup(environ):
    """Close any temp files that might have opened.

    :param environ: a request environment
    :return: None
    """

    if 'webob._parsed_post_vars' in environ:
        post_vars, body_file = environ['webob._parsed_post_vars']
        # the content is copied into a BytesIO or temporary file
        if not isinstance(body_file, bytes):
            body_file.close()
        for f in post_vars.keys():
            item = post_vars[f]
            if hasattr(item, 'file'):
                item.file.close()
