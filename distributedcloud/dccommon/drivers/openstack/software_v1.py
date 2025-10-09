# Copyright (c) 2023-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from urllib import parse

from keystoneauth1.session import Session as keystone_session
from oslo_log import log
import requests

from dccommon import consts
from dccommon.drivers import base
from dccommon import exceptions
from dccommon import utils

LOG = log.getLogger(__name__)

# Proposed States
ABORTING = "aborting"
AVAILABLE = "available"
COMMITTED = "committed"
DEPLOYED = "deployed"
DEPLOYING = "deploying"
REMOVING = "removing"
UNAVAILABLE = "unavailable"

REST_DEFAULT_TIMEOUT = 900
REST_SHOW_TIMEOUT = 150
REST_DELETE_TIMEOUT = 300


# TODO(gherzman): Use the software_client instead of using the requests module
# https://opendev.org/starlingx/update/src/branch/master/software-client
class SoftwareClient(base.DriverBase):
    """Software V1 driver."""

    def __init__(
        self,
        session: keystone_session,
        region: str = None,
        endpoint: str = None,
        endpoint_type: str = None,
        token: str = None,
    ):
        if not (endpoint or region):
            error = "Either endpoint or region must be provided"
            raise exceptions.ClientException(client="Software", error=error)

        self.session = session
        self.endpoint = endpoint
        self.token = token

        if not self.endpoint:
            if not endpoint_type:
                endpoint_type = (
                    consts.KS_ENDPOINT_INTERNAL
                    if utils.is_system_controller_region(region)
                    else consts.KS_ENDPOINT_ADMIN
                )
            self.endpoint = session.get_endpoint(
                service_type=consts.ENDPOINT_TYPE_USM,
                region_name=region,
                interface=endpoint_type,
            )

        self.endpoint = parse.urljoin(self.endpoint, "/v1")
        self.headers = {"X-Auth-Token": self.token} if token else None

    def request(self, url: str, method: str, timeout: int):
        """Request directly if token is passed, otherwise use the session"""
        if self.token:
            return requests.request(
                method=method, url=url, headers=self.headers, timeout=timeout
            )
        return self.session.request(
            url, method=method, timeout=timeout, raise_exc=False
        )

    def list(self, timeout=REST_DEFAULT_TIMEOUT):
        """List releases"""
        url = self.endpoint + "/release"
        response = self.request(url, "GET", timeout)
        return self._handle_response(response, operation="List")

    def show(self, release, timeout=REST_SHOW_TIMEOUT):
        """Show release"""
        url = self.endpoint + f"/release/{release}"
        response = self.request(url, "GET", timeout)
        return self._handle_response(response, operation="Show")

    def delete(self, releases, timeout=REST_DELETE_TIMEOUT):
        """Delete release"""
        release_str = "/".join(releases)
        url = self.endpoint + f"/release/{release_str}"
        response = self.request(url, "DELETE", timeout)
        return self._handle_response(response, operation="Delete")

    def deploy_precheck(self, deployment, timeout=REST_DEFAULT_TIMEOUT):
        """Deploy precheck"""
        url = self.endpoint + f"/deploy/{deployment}/precheck"
        response = self.request(url, "POST", timeout)
        return self._handle_response(response, operation="Deploy precheck")

    def show_deploy(self, timeout=REST_DEFAULT_TIMEOUT):
        """Show deploy"""
        url = self.endpoint + "/deploy"
        response = self.request(url, "GET", timeout)
        return self._handle_response(response, operation="Show deploy")

    def deploy_delete(self, timeout=REST_DEFAULT_TIMEOUT):
        """Deploy delete

        This is the equivalent of 'software deploy delete' command.
        It will remove the current deployment and change the release from
        'deploying' to 'deployed'. If this is executed, the rollback
        procedure will not be available.
        """
        url = self.endpoint + "/deploy"
        response = self.request(url, "DELETE", timeout)
        return self._handle_response(response, operation="Deploy delete")

    def commit_patch(self, releases, timeout=REST_DEFAULT_TIMEOUT):
        """Commit patch"""
        release_str = "/".join(releases)
        url = self.endpoint + f"/commit_patch/{release_str}"
        response = self.request(url, "POST", timeout)
        return self._handle_response(response, operation="Commit patch")

    def _handle_response(self, response, operation):
        if response.status_code != 200:
            LOG.error(f"{operation} failed with RC: {response.status_code}")
            raise exceptions.ApiException(endpoint=operation, rc=response.status_code)
        data = response.json()
        # Data response could be a dict with an error key or a list
        if isinstance(data, dict) and data.get("error"):
            message = f"{operation} failed with error: {data.get('error')}"
            LOG.error(message)
            raise exceptions.SoftwareDataException(endpoint=response.url, error=message)
        return data
