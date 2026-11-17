#
# Copyright (c) 2025-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from urllib.parse import urlparse

import json
import re
import socket
import ssl
import tempfile

import requests

import netaddr

from eventlet.green import subprocess
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log

from dccommon import consts as constants
from dccommon import endpoint_cache
from dccommon import kubeoperator as sys_kube

LOG = log.getLogger(__name__)
CONF = cfg.CONF


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
                "Provided intermediate CA cert is invalid\n"
                f"{tls_crt}\n{stdout}\n{stderr}"
            )
            return False


def update_subcloud_ca_cert(sc_name, sysinv_url, ca_crt, tls_crt, tls_key):
    admin_session = endpoint_cache.EndpointCache.get_admin_session()
    token = admin_session.get_token()

    api_url = f"{sysinv_url}/certificate/certificate_renew"
    payload = {
        "certtype": constants.CERTIFICATE_TYPE_ADMIN_ENDPOINT_INTERMEDIATE_CA,
        "root_ca_crt": ca_crt,
        "sc_ca_cert": tls_crt,
        "sc_ca_key": tls_key,
    }
    headers = {
        "Content-type": "application/json",
        "User-Agent": "cert-mon/1.0",
        "X-Auth-Token": token,
        "Accept": "application/json",
    }

    try:
        response = requests.post(
            api_url,
            headers=headers,
            json=payload,
            timeout=CONF.endpoint_cache.http_connect_timeout,
            verify=constants.DC_ROOT_CA_CERT_PATH,
        )
        response.raise_for_status()
        resp_data = response.json()

        if resp_data.get("result") == "OK":
            LOG.info(f"Update {sc_name} intermediate CA cert request succeeded")
        else:
            LOG.error(f"Request failed for {sc_name}: {resp_data}")
            raise Exception(f"Update {sc_name} intermediate CA cert failed")

    except requests.exceptions.RequestException as e:
        LOG.exception(f"Failed to update intermediate CA cert for {sc_name}: {e}")
        raise


def get_subcloud(subcloud_name):
    admin_session = endpoint_cache.EndpointCache.get_admin_session()
    token = admin_session.get_token()

    endpoint_url = admin_session.get_endpoint(
        service_type=constants.ENDPOINT_NAME_DCMANAGER,
        region_name=constants.SYSTEM_CONTROLLER_NAME,
        interface=constants.KS_ENDPOINT_ADMIN,
    )
    api_url = f"{endpoint_url}/subclouds/{subcloud_name}"

    headers = {
        "Content-type": "application/json",
        "User-Agent": "cert-mon/1.0",
        "X-Auth-Token": token,
        "Accept": "application/json",
    }

    try:
        response = requests.get(
            api_url,
            headers=headers,
            timeout=CONF.endpoint_cache.http_connect_timeout,
            verify=constants.DC_ROOT_CA_CERT_PATH,
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        LOG.exception(f"Failed to retrieve subcloud {subcloud_name}: {e}")
        raise


def _load_subclouds(resp, invalid_deploy_states=None):
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


def get_subclouds_from_dcmanager(invalid_deploy_states=None):
    """Retrieve the list of subclouds from dcmanager."""
    admin_session = endpoint_cache.EndpointCache.get_admin_session()
    api_url = admin_session.get_endpoint(
        service_type=constants.ENDPOINT_NAME_DCMANAGER,
        region_name=constants.SYSTEM_CONTROLLER_NAME,
        interface=constants.KS_ENDPOINT_ADMIN,
    )
    api_cmd = f"{api_url}/subclouds"
    LOG.debug(f"api_cmd {api_cmd}")

    resp = _rest_api_request(admin_session, "GET", api_cmd)

    return _load_subclouds(resp, invalid_deploy_states)


def is_subcloud_online(subcloud_name):
    """Check if subcloud is online."""
    subcloud_info = get_subcloud(subcloud_name)
    if not subcloud_info:
        LOG.error(f"Cannot find subcloud {subcloud_name}")
        return False
    return subcloud_info["availability-status"] == constants.AVAILABILITY_ONLINE


def query_subcloud_online_with_deploy_state(subcloud_name, invalid_deploy_states=None):
    """Check if subcloud is online and not in an invalid deploy state."""
    subcloud_info = get_subcloud(subcloud_name)
    if not subcloud_info:
        LOG.error(f"Cannot find subcloud {subcloud_name}")
        return False, None, None
    if (
        invalid_deploy_states
        and subcloud_info["deploy-status"] in invalid_deploy_states
    ):
        return (
            False,
            subcloud_info["availability-status"],
            subcloud_info["deploy-status"],
        )

    subcloud_valid_state = (
        subcloud_info["availability-status"] == constants.AVAILABILITY_ONLINE
    )
    return (
        subcloud_valid_state,
        subcloud_info["availability-status"],
        subcloud_info["deploy-status"],
    )


def update_subcloud_status(subcloud_name, status):
    admin_session = endpoint_cache.EndpointCache.get_admin_session()
    api_url = admin_session.get_endpoint(
        service_type=constants.ENDPOINT_NAME_DCMANAGER,
        region_name=constants.SYSTEM_CONTROLLER_NAME,
        interface=constants.KS_ENDPOINT_INTERNAL,
    )
    api_cmd = f"{api_url}/subclouds/{subcloud_name}/update_status"
    api_cmd_payload = {
        "endpoint": constants.ENDPOINT_TYPE_DC_CERT,
        "status": status,
    }

    resp = _rest_api_request(
        admin_session,
        "PATCH",
        api_cmd,
        api_cmd_payload,
        timeout=CONF.endpoint_cache.http_connect_timeout,
    )

    if resp.get("result") == "OK":
        LOG.info(f"Updated subcloud {subcloud_name} status: {status}")
    else:
        LOG.error(f"Failed response while updating subcloud {subcloud_name}: {resp}")
        raise Exception(f"Update subcloud status failed for {subcloud_name}")


def _rest_api_request(admin_session, method, api_cmd, api_cmd_payload=None, timeout=45):
    """Make a REST API request using KeystoneSessionManager.

    Returns: response as a dictionary.
    """
    headers = {
        "Content-type": "application/json",
        "User-Agent": "cert-mon/1.0",
        "Accept": "application/json",
        "X-Auth-Token": admin_session.get_token(),
    }

    try:
        response = requests.request(
            method=method,
            url=api_cmd,
            headers=headers,
            data=json.dumps(api_cmd_payload) if api_cmd_payload else None,
            timeout=timeout,
            verify=constants.DC_ROOT_CA_CERT_PATH,
        )
        response.raise_for_status()
        return response.json() if response.content else {}
    except requests.exceptions.HTTPError as e:
        LOG.error(f"HTTP error on {method} {api_cmd}: {e.response.text}")
        raise
    except requests.exceptions.RequestException as e:
        LOG.error(f"Error contacting {method} {api_cmd}: {str(e)}")
        raise


def get_subcloud_secrets():
    """Get subcloud name and ICA secret name pairs from k8s secret.

    Every subcloud comes with an ICA entry in k8s secret

    :return: dict of subcloud name and ICA secret name pairs.
    """
    secret_pattern = re.compile("-adminep-ca-certificate$")
    kube_op = sys_kube.KubeOperator()
    secret_list = kube_op.kube_list_secret(constants.ENDPOINT_TYPE_DC_CERT)

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
    return kube_op.kube_get_secret(secret_name, constants.CERT_NAMESPACE_SYS_CONTROLLER)


def get_endpoint_certificate(endpoint, timeout_secs=10):
    """Retrieve the SSL certificate from a remote endpoint.

    :param endpoint: URL (e.g. https://host:port)
    :param timeout_secs: connection timeout in seconds
    :returns: PEM-formatted certificate
    :raises: socket.error or ssl.SSLError on failure
    """
    url = urlparse(endpoint)
    host = url.hostname
    port = url.port

    context = ssl.create_default_context(cafile=constants.DC_ROOT_CA_CERT_PATH)
    # In Python 3.9, ssl.get_server_certificate() does not support a timeout.
    # See: https://bugs.python.org/issue31870
    # To enforce a timeout and avoid indefinite blocking when the endpoint is down,
    # we manually create a socket connection with a timeout and wrap it using SSL.
    # In Python 3.10+, this could be simplified using the `timeout=` parameter
    # in ssl.get_server_certificate().
    try:
        with socket.create_connection((host, port), timeout=timeout_secs) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                cert_pem = ssl.DER_cert_to_PEM_cert(cert_bin)
                return cert_pem
    except Exception:
        LOG.warning(f"get_endpoint_certificate: connection failed to {host}:{port}")
        raise


def get_endpoint_cert_chain(endpoint, timeout_secs=10):
    """Retrieve the full certificate chain served by a remote endpoint.

    Unlike get_endpoint_certificate(), which returns only the leaf certificate
    (ssl.getpeercert() exposes just the peer cert), this returns every
    certificate the server presents during the TLS handshake, i.e. the leaf
    followed by any intermediate CA(s). This is needed to inspect the
    intermediate CA the subcloud is actually serving.

    Implemented via "openssl s_client -showcerts" rather than
    ssl.SSLSocket.get_unverified_chain(), which is only public from Python
    3.13; the unit tests still run on Python 3.9.

    :param endpoint: URL (e.g. https://host:port)
    :param timeout_secs: connection timeout in seconds
    :returns: list of PEM-formatted certificates, leaf first. Empty list if
        the chain could not be retrieved.
    """
    url = urlparse(endpoint)
    host = url.hostname
    port = url.port

    # urlparse() strips the brackets from an IPv6 literal, but "openssl
    # s_client -connect" needs them to tell the address from the port.
    target = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    cmd = [
        "openssl",
        "s_client",
        "-connect",
        target,
        "-showcerts",
    ]
    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        stdout, _ = proc.communicate(input="", timeout=timeout_secs)
    except Exception as exc:
        # Includes a timeout. Stop and reap the child instead of leaving it
        # running (or as a zombie) after a failed attempt.
        LOG.warning(
            f"get_endpoint_cert_chain: failed to get the chain from "
            f"{host}:{port}: {type(exc).__name__}"
        )
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.communicate()
        return []

    chain = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        stdout,
        re.DOTALL,
    )
    return chain


def get_cert_serial(cert_pem):
    """Return the serial number of a PEM-encoded certificate.

    Only the first certificate is read: if cert_pem holds a bundle, openssl
    x509 parses the first PEM block and ignores the rest. Callers must pass
    the certificate to identify first.

    :param cert_pem: PEM-formatted certificate (str)
    :returns: serial number as an uppercase hex string, or None on failure.
    """
    if not cert_pem:
        return None
    cmd = ["openssl", "x509", "-noout", "-serial"]
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        stdout, stderr = proc.communicate(input=cert_pem)
        if proc.returncode != 0:
            LOG.warning(f"get_cert_serial: openssl failed: {stderr}")
            return None
    except Exception:
        LOG.warning("get_cert_serial: failed to parse certificate serial")
        return None

    # openssl prints "serial=ABCDEF..."
    out = stdout.strip()
    if "=" in out:
        return out.split("=", 1)[1].strip().upper()
    return out.strip().upper() or None


class SubcloudSysinvEndpointCache(object):

    # Maps subcloud name to sysinv endpoint
    cached_endpoints = {}

    @classmethod
    @lockutils.synchronized(constants.ENDPOINT_LOCK_NAME)
    def get_endpoint(cls, region_name: str):
        """Retrieve the sysinv endpoint for the given region.

        :param region_name: The subcloud region name.
        :param dc_token: dcmanager token, if it's present and the endpoint is
            not already cached, the endpoint will be obtained by querying
            dcmanager.
        """
        endpoint = cls.cached_endpoints.get(region_name)
        if endpoint is None:
            # Try to get it from dcmanager, this should rarely happen as the
            # cache is already populated during dccert-mon audit during service
            # startup
            LOG.info("Unable to find cached sysinv endpoint, querying dcmanager")
            subcloud = get_subcloud(region_name)
            endpoint = cls.build_endpoint(subcloud["management-start-ip"])
            cls.cached_endpoints[region_name] = endpoint

        return endpoint

    @classmethod
    @lockutils.synchronized(constants.ENDPOINT_LOCK_NAME)
    def update_endpoints(cls, endpoints_dict: dict):
        """Update the cached endpoints with the provided dictionary.

        :param endpoints_dict: A dictionary mapping region names to endpoint
            URLs.
        """
        cls.cached_endpoints.update(endpoints_dict)

    @classmethod
    @lockutils.synchronized(constants.ENDPOINT_LOCK_NAME)
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
