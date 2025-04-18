#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import json
import re
import socket
import ssl
import tempfile

from eventlet.green import subprocess

import netaddr

from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log
from oslo_serialization import base64
from oslo_utils import encodeutils

from six.moves.urllib.error import HTTPError
from six.moves.urllib.error import URLError
from six.moves.urllib.parse import urlparse
from six.moves.urllib.request import Request
from six.moves.urllib.request import urlopen

# pylint: disable=import-error
# TODO(srana): copy sys_kube to dccertmon/common
from sysinv.common import kubernetes as sys_kube

# pylint: enable=import-error

from dccertmon.common import constants
from dccertmon.common.keystone_objects import Token


DC_ROLE_TIMEOUT_SECONDS = 180
DC_ROLE_DELAY_SECONDS = 5

INVALID_SUBCLOUD_AUDIT_DEPLOY_STATES = [
    # Secondary subclouds should not be audited as they are expected
    # to be managed by a peer system controller (geo-redundancy feat.)
    "create-complete",
    "create-failed",
    "pre-rehome",
    "rehome-failed",
    "rehome-pending",
    "rehoming",
    "secondary",
    "secondary-failed",
]

# Subcloud sync status
ENDPOINT_TYPE_DC_CERT = "dc-cert"

SYNC_STATUS_UNKNOWN = "unknown"
SYNC_STATUS_IN_SYNC = "in-sync"
SYNC_STATUS_OUT_OF_SYNC = "out-of-sync"

DEPLOY_STATE_DONE = "complete"

MANAGEMENT_UNMANAGED = "unmanaged"
MANAGEMENT_MANAGED = "managed"

AVAILABILITY_OFFLINE = "offline"
AVAILABILITY_ONLINE = "online"

CERT_NAMESPACE_SYS_CONTROLLER = "dc-cert"
CERT_NAMESPACE_SUBCLOUD_CONTROLLER = "sc-cert"
DC_ROLE_UNDETECTED = "unknown"

ENDPOINT_LOCK_NAME = "sysinv-endpoints"
CERT_INSTALL_LOCK_NAME = "sysinv-certs"

LOG = log.getLogger(__name__)
CONF = cfg.CONF

dc_role = DC_ROLE_UNDETECTED

internal_token_cache = None
dc_token_cache = None


def verify_intermediate_ca_cert(ca_crt, tls_crt):
    with tempfile.NamedTemporaryFile() as tmpfile:
        tmpfile.write(ca_crt.encode("utf8"))
        tmpfile.flush()
        cmd = ["openssl", "verify", "-CAfile", tmpfile.name]
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )

        stdout, stderr = proc.communicate(input=tls_crt)
        proc.wait()
        if 0 == proc.returncode:
            return True
        else:
            LOG.info(
                "Provided intermediate CA cert is invalid\n%s\n%s\n%s"
                % (tls_crt, stdout, stderr)
            )
            return False


def update_admin_ep_cert(token, ca_crt, tls_crt, tls_key):
    service_type = "platform"
    service_name = "sysinv"
    sysinv_url = token.get_service_internal_url(service_type, service_name)
    api_cmd = sysinv_url + "/certificate/certificate_renew"
    api_cmd_payload = dict()
    api_cmd_payload["certtype"] = constants.CERTIFICATE_TYPE_ADMIN_ENDPOINT
    resp = rest_api_request(token, "POST", api_cmd, json.dumps(api_cmd_payload))

    if "result" in resp and resp["result"] == "OK":
        LOG.info("Update admin endpoint certificate request succeeded")
    else:
        LOG.error("Request response %s" % resp)
        raise Exception("Update admin endpoint certificate failed")


def verify_adminep_cert_chain():
    """Verify admin endpoint certificate chain & delete if invalid

    :param context: an admin context.
    :return: True/False if chain is valid

    * Retrieve ICA & AdminEP cert secrets from k8s
    * base64 decode ICA cert (tls.crt from SC_INTERMEDIATE_CA_SECRET_NAME)
    *   & adminep (tls.crt from SC_ADMIN_ENDPOINT_SECRET_NAME)
    *   & store the crts in tempfiles
    * Run openssl verify against RootCA to verify the chain
    """
    kube_op = sys_kube.KubeOperator()

    secret_ica = kube_op.kube_get_secret(
        constants.SC_INTERMEDIATE_CA_SECRET_NAME, CERT_NAMESPACE_SUBCLOUD_CONTROLLER
    )
    if "tls.crt" not in secret_ica.data:
        raise Exception(
            "%s tls.crt (ICA) data missing" % (constants.SC_INTERMEDIATE_CA_SECRET_NAME)
        )

    secret_adminep = kube_op.kube_get_secret(
        constants.SC_ADMIN_ENDPOINT_SECRET_NAME, CERT_NAMESPACE_SUBCLOUD_CONTROLLER
    )
    if "tls.crt" not in secret_adminep.data:
        raise Exception(
            "%s tls.crt data missing" % (constants.SC_ADMIN_ENDPOINT_SECRET_NAME)
        )

    txt_ca_crt = base64.decode_as_text(secret_ica.data["tls.crt"])
    txt_tls_crt = base64.decode_as_text(secret_adminep.data["tls.crt"])

    with tempfile.NamedTemporaryFile() as ca_tmpfile:
        ca_tmpfile.write(txt_ca_crt.encode("utf8"))
        ca_tmpfile.flush()
        with tempfile.NamedTemporaryFile() as adminep_tmpfile:
            adminep_tmpfile.write(txt_tls_crt.encode("utf8"))
            adminep_tmpfile.flush()

            cmd = [
                "openssl",
                "verify",
                "-CAfile",
                constants.DC_ROOT_CA_CERT_PATH,
                "-untrusted",
                ca_tmpfile.name,
                adminep_tmpfile.name,
            ]
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
            )
            stdout, stderr = proc.communicate()
            proc.wait()
            if 0 == proc.returncode:
                LOG.info("verify_adminep_cert_chain passed. Valid chain")
                return True
            else:
                LOG.info(
                    "verify_adminep_cert_chain: Chain is invalid\n%s\n%s"
                    % (stdout, stderr)
                )

                res = kube_op.kube_delete_secret(
                    constants.SC_ADMIN_ENDPOINT_SECRET_NAME,
                    CERT_NAMESPACE_SUBCLOUD_CONTROLLER,
                )
                LOG.info(
                    "Deleting AdminEP secret due to invalid chain. "
                    "%s:%s, result %s, msg %s",
                    CERT_NAMESPACE_SUBCLOUD_CONTROLLER,
                    constants.SC_ADMIN_ENDPOINT_SECRET_NAME,
                    res.status,
                    res.message,
                )
                return False


def dc_get_service_endpoint_url(
    token,
    service_name="dcmanager",
    service_type="dcmanager",
    region=constants.SYSTEM_CONTROLLER_REGION,
):
    """Pulls the dcmanager service internal URL from the given token."""
    url = token.get_service_internal_url(service_type, service_name, region)
    if url:
        LOG.debug("%s %s endpoint %s" % (region, service_name, url))
        return url
    else:
        LOG.error("Cannot find %s endpoint for %s" % (service_name, region))
        raise Exception("Cannot find %s endpoint for %s" % (service_name, region))


def update_subcloud_ca_cert(token, sc_name, sysinv_url, ca_crt, tls_crt, tls_key):

    api_cmd = sysinv_url + "/certificate/certificate_renew"
    api_cmd_payload = {
        "certtype": constants.CERTIFICATE_TYPE_ADMIN_ENDPOINT_INTERMEDIATE_CA,
        "root_ca_crt": ca_crt,
        "sc_ca_cert": tls_crt,
        "sc_ca_key": tls_key,
    }
    timeout = int(CONF.endpoint_cache.http_connect_timeout)

    resp = rest_api_request(
        token, "POST", api_cmd, json.dumps(api_cmd_payload), timeout=timeout
    )

    if "result" in resp and resp["result"] == "OK":
        LOG.info("Update %s intermediate CA cert request succeed" % sc_name)
    else:
        LOG.error("Request response %s" % resp)
        raise Exception("Update %s intermediate CA cert failed" % sc_name)


def get_subcloud(token, subcloud_name):
    api_url = dc_get_service_endpoint_url(token)
    api_cmd = api_url + "/subclouds/%s" % subcloud_name
    LOG.info("api_cmd %s" % api_cmd)
    resp = rest_api_request(token, "GET", api_cmd)

    return resp


def load_subclouds(resp, invalid_deploy_states=None):
    sc_list = []
    for obj in resp["subclouds"]:
        if invalid_deploy_states and obj["deploy-status"] in invalid_deploy_states:
            continue
        sc = {}
        sc["name"] = obj["name"]
        sc["region-name"] = obj["region-name"]
        sc["management-state"] = obj["management-state"]
        sc["availability-status"] = obj["availability-status"]
        sc["sync_status"] = obj["sync_status"]
        sc["management_ip"] = obj["management-start-ip"]
        for ss in obj["endpoint_sync_status"]:
            sc[ss["endpoint_type"]] = ss["sync_status"]
        sc_list.append(sc)

    return sc_list


def get_subclouds_from_dcmanager(token, invalid_deploy_states=None):
    api_url = dc_get_service_endpoint_url(token)
    api_cmd = api_url + "/subclouds"
    LOG.debug("api_cmd %s" % api_cmd)
    resp = rest_api_request(token, "GET", api_cmd)

    return load_subclouds(resp, invalid_deploy_states)


def is_subcloud_online(subcloud_name, token=None):
    """Check if subcloud is online."""
    if not token:
        token = get_cached_token()
    subcloud_info = get_subcloud(token, subcloud_name)
    if not subcloud_info:
        LOG.error("Cannot find subcloud %s" % subcloud_name)
        return False
    return subcloud_info["availability-status"] == AVAILABILITY_ONLINE


def query_subcloud_online_with_deploy_state(
    subcloud_name, invalid_deploy_states=None, token=None
):
    """Check if subcloud is online and not in an invalid deploy state."""
    if not token:
        token = get_cached_token()
    subcloud_info = get_subcloud(token, subcloud_name)
    if not subcloud_info:
        LOG.error("Cannot find subcloud %s" % subcloud_name)
        return False, None, None
    subcloud_valid_state = False
    if (
        invalid_deploy_states
        and subcloud_info["deploy-status"] in invalid_deploy_states
    ):
        subcloud_valid_state = False
    else:
        subcloud_valid_state = (
            subcloud_info["availability-status"] == AVAILABILITY_ONLINE
        )
    return (
        subcloud_valid_state,
        subcloud_info["availability-status"],
        subcloud_info["deploy-status"],
    )


def update_subcloud_status(token, subcloud_name, status):
    api_url = dc_get_service_endpoint_url(token)
    api_cmd = api_url + "/subclouds/%s/update_status" % subcloud_name
    api_cmd_payload = dict()
    api_cmd_payload["endpoint"] = ENDPOINT_TYPE_DC_CERT
    api_cmd_payload["status"] = status
    resp = rest_api_request(token, "PATCH", api_cmd, json.dumps(api_cmd_payload))

    if "result" in resp and resp["result"] == "OK":
        LOG.info("Updated subcloud %s status: %s" % (subcloud_name, status))
    else:
        LOG.error(
            "Failed to update subcloud %s status to '%s', resp=%s"
            % (subcloud_name, status, resp)
        )
        raise Exception("Update subcloud status failed, subcloud=%s" % subcloud_name)


def rest_api_request(token, method, api_cmd, api_cmd_payload=None, timeout=45):
    """Make a REST API request.

    Returns: response as a dictionary.
    """
    api_cmd_headers = {
        "Content-type": "application/json",
        "User-Agent": "cert-mon/1.0",
    }

    try:
        request_info = Request(api_cmd)
        request_info.get_method = lambda: method
        if token:
            request_info.add_header("X-Auth-Token", token.get_id())
        request_info.add_header("Accept", "application/json")

        if api_cmd_headers is not None:
            for header_type, header_value in api_cmd_headers.items():
                request_info.add_header(header_type, header_value)

        if api_cmd_payload is not None:
            request_info.data = encodeutils.safe_encode(api_cmd_payload)

        request = None
        try:
            request = urlopen(request_info, timeout=timeout)
            response = request.read()
        finally:
            if request:
                request.close()

        if response == "":
            response = json.loads("{}")
        else:
            response = json.loads(response)

    except HTTPError as e:
        if 401 == e.code:
            if token:
                token.set_expired()
        raise

    except URLError:
        LOG.error("Cannot access %s" % api_cmd)
        raise

    return response


def get_token():
    """Get token for the sysinv user."""

    keystone_conf = CONF.get("KEYSTONE_AUTHTOKEN")

    token = _get_token(
        keystone_conf.auth_url + "/v3/auth/tokens",
        keystone_conf.project_name,
        keystone_conf.username,
        keystone_conf.password,
        keystone_conf.user_domain_name,
        keystone_conf.project_domain_name,
        keystone_conf.region_name,
    )

    return token


def get_dc_token(region_name=constants.SYSTEM_CONTROLLER_REGION):
    """Get token for the dcmanager user.

    Note: Although region_name can be specified, the token used here is a
    "project-scoped" token (i.e., not specific to the subcloud/region name).
    A token obtained using one region_name can be re-used across any
    subcloud. We take advantage of this in our DC token caching strategy.
    """
    token = _get_token(
        CONF.endpoint_cache.auth_uri + "/auth/tokens",
        CONF.endpoint_cache.project_name,
        CONF.endpoint_cache.username,
        CONF.endpoint_cache.password,
        CONF.endpoint_cache.user_domain_name,
        CONF.endpoint_cache.project_domain_name,
        region_name,
    )
    return token


def _get_token(
    auth_url,
    auth_project,
    username,
    password,
    user_domain,
    project_domain,
    region_name,
    timeout=60,
):
    """Ask OpenStack Keystone for a token

    Returns: token object or None on failure
    """
    try:
        request_info = Request(auth_url)
        request_info.add_header("Content-type", "application/json")
        request_info.add_header("Accept", "application/json")
        payload = json.dumps(
            {
                "auth": {
                    "identity": {
                        "methods": ["password"],
                        "password": {
                            "user": {
                                "name": username,
                                "password": password,
                                "domain": {"name": user_domain},
                            }
                        },
                    },
                    "scope": {
                        "project": {
                            "name": auth_project,
                            "domain": {"name": project_domain},
                        }
                    },
                }
            }
        )

        request_info.data = encodeutils.safe_encode(payload)

        request = urlopen(request_info, timeout=timeout)
        # Identity API v3 returns token id in X-Subject-Token
        # response header.
        token_id = request.headers.get("X-Subject-Token")
        json_response = request.read()
        response = json.loads(json_response)
        request.close()

        # save the region name for service url lookup
        return Token(response, token_id, region_name)

    except HTTPError as e:
        LOG.error("%s, %s" % (e.code, e.read()))
        return None

    except URLError as e:
        LOG.error(e)
        return None


def get_subcloud_secrets():
    """Get subcloud name and ICA secret name pairs from k8s secret.

    Every subcloud comes with an ICA entry in k8s secret

    :return: dict of subcloud name and ICA secret name pairs.
    """
    secret_pattern = re.compile("-adminep-ca-certificate$")
    kube_op = sys_kube.KubeOperator()
    secret_list = kube_op.kube_list_secret(ENDPOINT_TYPE_DC_CERT)

    dict = {}
    for secret in secret_list:
        secret_name = secret.metadata.name
        m = secret_pattern.search(secret_name)
        if m:
            start = m.start()
            if start > 0:
                dict.update({secret_name[0 : m.start()]: secret_name})

    return dict


def get_subclouds():
    """Get name of all subclouds from k8s secret.

    Every subcloud comes with an ICA entry in k8s secret
    :return: list of subcloud names
    """

    subcloud_secrets = get_subcloud_secrets()
    return list(subcloud_secrets.keys())


def get_intermediate_ca_secret_name(sc):
    return "{}-adminep-ca-certificate".format(sc)


def get_sc_intermediate_ca_secret(sc):
    secret_name = get_intermediate_ca_secret_name(sc)
    kube_op = sys_kube.KubeOperator()
    return kube_op.kube_get_secret(secret_name, CERT_NAMESPACE_SYS_CONTROLLER)


def get_endpoint_certificate(endpoint, timeout_secs=10):
    url = urlparse(endpoint)
    host = url.hostname
    port = url.port
    if timeout_secs is not None and timeout_secs > 0:
        # The call to ssl.get_server_certificate blocks for a long time if the
        # server is not available. A timeout is not available in python 2.7.
        # See https://bugs.python.org/issue31870
        # Until the timeout=<val> option is available in
        # get_server_certificate(), we first check if the port is open
        # by connecting using a timeout, then we do the certificate check:
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=timeout_secs)
        except Exception:
            LOG.warn("get_endpoint_certificate: connection failed to %s:%s", host, port)
            raise
        finally:
            if sock is not None:
                sock.close()
    return ssl.get_server_certificate((host, port))


def get_dc_role():
    global dc_role
    if dc_role == DC_ROLE_UNDETECTED:
        token = get_cached_token()
        if not token:
            raise Exception("Failed to obtain keystone token")
        service_type = "platform"
        service_name = "sysinv"
        sysinv_url = token.get_service_internal_url(service_type, service_name)
        api_cmd = sysinv_url + "/isystems"
        res = rest_api_request(token, "GET", api_cmd)["isystems"]
        if len(res) == 1:
            system = res[0]
            dc_role = system["distributed_cloud_role"]
            LOG.debug("DC role: %s" % system)
        else:
            raise Exception("Failed to access system data")

    return dc_role


class TokenCache(object):
    """Simple token cache.

    This class holds one keystone token.
    """

    token_getters = {"internal": get_token, "dc": get_dc_token}

    def __init__(self, token_type):
        self._token = None
        self._token_type = token_type
        self._getter_func = self.token_getters[token_type]

    def get_token(self):
        """Get a new token if required; otherwise use the cached token."""
        if not self._token or self._token.is_expired():
            LOG.debug(
                "TokenCache %s, Acquiring new token, previous token: %s",
                self._token_type,
                self._token,
            )
            self._token = self._getter_func()
        else:
            LOG.debug(
                "TokenCache %s, Token is still valid, reusing token: %s",
                self._token_type,
                self._token,
            )
        return self._token


def get_internal_token_cache():
    global internal_token_cache
    if not internal_token_cache:
        internal_token_cache = TokenCache("internal")
    return internal_token_cache


def get_cached_token():
    return get_internal_token_cache().get_token()


def get_dc_token_cache():
    global dc_token_cache
    if not dc_token_cache:
        dc_token_cache = TokenCache("dc")
    return dc_token_cache


def get_cached_dc_token():
    return get_dc_token_cache().get_token()


class SubcloudSysinvEndpointCache(object):

    # Maps subcloud name to sysinv endpoint
    cached_endpoints = {}

    @classmethod
    @lockutils.synchronized(ENDPOINT_LOCK_NAME)
    def get_endpoint(cls, region_name: str, dc_token=None):
        """Retrieve the sysinv endpoint for the given region.

        :param region_name: The subcloud region name.
        :param dc_token: dcmanager token, if it's present and the endpoint is
            not already cached, the endpoint will be obtained by querying
            dcmanager.
        """
        endpoint = cls.cached_endpoints.get(region_name)
        if endpoint is None:
            if dc_token is None:
                LOG.error(f"Cannot find sysinv endpoint for {region_name}")
                raise Exception(f"Cannot find sysinv endpoint for {region_name}")

            # Try to get it from dcmanager, this should rarely happen as the
            # cache is already populated during dccert-mon audit during service
            # startup
            LOG.info("Unable to find cached sysinv endpoint, querying dcmanager")
            subcloud = get_subcloud(dc_token, region_name)
            endpoint = cls.build_endpoint(subcloud["management-start-ip"])
            cls.cached_endpoints[region_name] = endpoint

        return endpoint

    @classmethod
    @lockutils.synchronized(ENDPOINT_LOCK_NAME)
    def update_endpoints(cls, endpoints_dict: dict):
        """Update the cached endpoints with the provided dictionary.

        :param endpoints_dict: A dictionary mapping region names to endpoint
            URLs.
        """
        cls.cached_endpoints.update(endpoints_dict)

    @classmethod
    @lockutils.synchronized(ENDPOINT_LOCK_NAME)
    def cache_endpoints_by_ip(cls, subcloud_mgmt_ips: dict):
        """Cache endpoints based on management IPs.

        :param subcloud_mgmt_ips: A dictionary mapping region names to
            management IPs.
        """
        endpoints = {}

        for region, ip in subcloud_mgmt_ips.items():
            endpoints[region] = cls.build_endpoint(ip)

        cls.cached_endpoints.clear()
        cls.cached_endpoints.update(endpoints)

    @staticmethod
    def build_endpoint(ip: str):
        """Build the sysinv endpoint from the subcloud management IP.

        :param ip: The management IP of a subcloud.
        """
        formatted_ip = f"[{ip}]" if netaddr.IPAddress(ip).version == 6 else ip
        return f"https://{formatted_ip}:6386/v1"
