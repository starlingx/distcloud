#
# Copyright (c) 2025 Wind River Systems, Inc.
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
from oslo_serialization import base64

from dccertmon.common.keystone_objects import KeystoneSessionManager
from dccommon import consts as constants
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


def update_admin_ep_cert(ks_session_mgr, ca_crt, tls_crt, tls_key):
    """Update admin endpoint certificate using the sysinv API."""

    service_type = constants.ENDPOINT_TYPE_PLATFORM
    service_name = constants.ENDPOINT_NAME_SYSINV

    sysinv_url = ks_session_mgr.get_endpoint_url(
        service_type=service_type,
        service_name=service_name,
        interface=constants.KS_ENDPOINT_INTERNAL,
    )

    api_cmd = sysinv_url + "/certificate/certificate_renew"
    api_cmd_payload = {"certtype": constants.CERTIFICATE_TYPE_ADMIN_ENDPOINT}

    resp = rest_api_request(ks_session_mgr, "POST", api_cmd, api_cmd_payload)

    if "result" in resp and resp["result"] == "OK":
        LOG.info("Update admin endpoint certificate request succeeded")
    else:
        LOG.error(f"Request response {resp}")
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
        constants.SC_INTERMEDIATE_CA_SECRET_NAME,
        constants.CERT_NAMESPACE_SUBCLOUD_CONTROLLER,
    )
    if "tls.crt" not in secret_ica.data:
        raise Exception(
            f"{constants.SC_INTERMEDIATE_CA_SECRET_NAME} tls.crt (ICA) data missing"
        )

    secret_adminep = kube_op.kube_get_secret(
        constants.SC_ADMIN_ENDPOINT_SECRET_NAME,
        constants.CERT_NAMESPACE_SUBCLOUD_CONTROLLER,
    )
    if "tls.crt" not in secret_adminep.data:
        raise Exception(
            f"{(constants.SC_ADMIN_ENDPOINT_SECRET_NAME)} tls.crt data missing"
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
                    "verify_adminep_cert_chain: Chain is invalid\n"
                    f"{stdout}\n{stderr}"
                )

                kube_op.kube_delete_secret(
                    constants.SC_ADMIN_ENDPOINT_SECRET_NAME,
                    constants.CERT_NAMESPACE_SUBCLOUD_CONTROLLER,
                )
                LOG.info(
                    "Deleting AdminEP secret due to invalid chain. "
                    f"{constants.CERT_NAMESPACE_SUBCLOUD_CONTROLLER}:"
                    f"{constants.SC_ADMIN_ENDPOINT_SECRET_NAME}"
                )
                return False


def update_subcloud_ca_cert(ks_mgr, sc_name, sysinv_url, ca_crt, tls_crt, tls_key):
    token = ks_mgr.get_token()

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
        )
        response.raise_for_status()
        resp_data = response.json()

        if resp_data.get("result") == "OK":
            LOG.info(f"Update f{sc_name} intermediate CA cert request succeeded")
        else:
            LOG.error(f"Request failed for {sc_name}: {resp_data}")
            raise Exception(f"Update {sc_name} intermediate CA cert failed")

    except requests.exceptions.RequestException as e:
        LOG.exception(f"Failed to update intermediate CA cert for {sc_name}: {e}")
        raise


def get_subcloud(ks_mgr, subcloud_name):
    token = ks_mgr.get_token()

    endpoint_url = ks_mgr.get_endpoint_url(
        "dcmanager", region_name=constants.SYSTEM_CONTROLLER_NAME
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
            api_url, headers=headers, timeout=CONF.endpoint_cache.http_connect_timeout
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        LOG.exception(f"Failed to retrieve subcloud {subcloud_name}: {e}")
        raise


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


def get_subclouds_from_dcmanager(ks_mgr, invalid_deploy_states=None):
    """Retrieve the list of subclouds from dcmanager."""
    api_url = ks_mgr.get_endpoint_url(
        "dcmanager", region_name=constants.SYSTEM_CONTROLLER_NAME
    )
    api_cmd = f"{api_url}/subclouds"
    LOG.debug(f"api_cmd {api_cmd}")

    resp = rest_api_request(ks_mgr, "GET", api_cmd)

    return load_subclouds(resp, invalid_deploy_states)


def is_subcloud_online(subcloud_name, ks_mgr=None):
    """Check if subcloud is online."""
    if ks_mgr is None:
        ks_mgr = KeystoneSessionManager("endpoint_cache")

    subcloud_info = get_subcloud(ks_mgr, subcloud_name)
    if not subcloud_info:
        LOG.error(f"Cannot find subcloud {subcloud_name}")
        return False
    return subcloud_info["availability-status"] == constants.AVAILABILITY_ONLINE


def query_subcloud_online_with_deploy_state(
    subcloud_name, invalid_deploy_states=None, ks_mgr=None
):
    """Check if subcloud is online and not in an invalid deploy state."""
    if ks_mgr is None:
        ks_mgr = KeystoneSessionManager("endpoint_cache")

    subcloud_info = get_subcloud(ks_mgr, subcloud_name)
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


def update_subcloud_status(session_mgr, subcloud_name, status):
    api_url = session_mgr.get_endpoint_url(
        service_type="dcmanager",
        interface=constants.KS_ENDPOINT_INTERNAL,
        region_name=constants.SYSTEM_CONTROLLER_NAME,
    )
    api_cmd = f"{api_url}/subclouds/{subcloud_name}/update_status"
    api_cmd_payload = {
        "endpoint": constants.ENDPOINT_TYPE_DC_CERT,
        "status": status,
    }

    resp = rest_api_request(
        session_mgr,
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


def rest_api_request(session_mgr, method, api_cmd, api_cmd_payload=None, timeout=45):
    """Make a REST API request using KeystoneSessionManager.

    Returns: response as a dictionary.
    """
    headers = {
        "Content-type": "application/json",
        "User-Agent": "cert-mon/1.0",
        "Accept": "application/json",
        "X-Auth-Token": session_mgr.get_token(),
    }

    try:
        response = requests.request(
            method=method,
            url=api_cmd,
            headers=headers,
            data=json.dumps(api_cmd_payload) if api_cmd_payload else None,
            timeout=timeout,
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

    context = ssl.create_default_context()
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


def get_internal_keystone_session():
    return KeystoneSessionManager(auth_section="keystone_authtoken")


class SubcloudSysinvEndpointCache(object):

    # Maps subcloud name to sysinv endpoint
    cached_endpoints = {}

    @classmethod
    @lockutils.synchronized(constants.ENDPOINT_LOCK_NAME)
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
