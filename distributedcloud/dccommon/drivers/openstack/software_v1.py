# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


from oslo_log import log
import requests

from dccommon import consts
from dccommon.drivers import base
from dccommon import exceptions

LOG = log.getLogger(__name__)

# Proposed States
ABORTING = 'aborting'
AVAILABLE = 'available'
COMMITTED = 'committed'
DEPLOYED = 'deployed'
REMOVING = 'removing'
UNAVAILABLE = 'unavailable'

REST_DEFAULT_TIMEOUT = 900


class SoftwareClient(base.DriverBase):
    """Software V1 driver."""

    def __init__(self, region, session, endpoint=None):
        # Get an endpoint and token.
        if not endpoint:
            self.endpoint = session.get_endpoint(
                service_type='usm',
                region_name=region,
                interface=consts.KS_ENDPOINT_ADMIN)
        else:
            self.endpoint = endpoint

        # The usm systemcontroller endpoint ends with a slash but the regionone
        # and the subcloud endpoint don't. The slash is removed to standardize
        # with the other endpoints.
        self.endpoint = self.endpoint.rstrip('/') + '/v1'
        self.token = session.get_token()
        self.headers = {"X-Auth-Token": self.token}

    def list(self, timeout=REST_DEFAULT_TIMEOUT):
        """List releases"""
        url = self.endpoint + '/release'
        response = requests.get(url, headers=self.headers, timeout=timeout)
        return self._handle_response(response, operation="List")

    def show(self, release, timeout=REST_DEFAULT_TIMEOUT):
        """Show release"""
        url = self.endpoint + f"/release/{release}"
        response = requests.get(url, headers=self.headers, timeout=timeout)
        return self._handle_response(response, operation="Show")

    def delete(self, releases, timeout=REST_DEFAULT_TIMEOUT):
        """Delete release"""
        release_str = "/".join(releases)
        url = self.endpoint + f'/release/{release_str}'
        response = requests.delete(url, headers=self.headers, timeout=timeout)
        return self._handle_response(response, operation="Delete")

    def deploy_precheck(self, deployment, timeout=REST_DEFAULT_TIMEOUT):
        """Deploy precheck"""
        url = self.endpoint + f"/deploy/{deployment}/precheck"
        response = requests.post(url, headers=self.headers, timeout=timeout)
        return self._handle_response(response, operation="Deploy precheck")

    def commit_patch(self, releases, timeout=REST_DEFAULT_TIMEOUT):
        """Commit patch"""
        release_str = "/".join(releases)
        url = self.endpoint + f'/commit_patch/{release_str}'
        response = requests.post(url, headers=self.headers, timeout=timeout)
        return self._handle_response(response, operation="Commit patch")

    def _handle_response(self, response, operation):
        if response.status_code != 200:
            LOG.error(f"{operation} failed with RC: {response.status_code}")
            raise exceptions.ApiException(endpoint=operation,
                                          rc=response.status_code)
        data = response.json()
        # Data response could be a dict with an error key or a list
        if isinstance(data, dict) and data.get('error'):
            message = f"{operation} failed with error: {data.get('error')}"
            LOG.error(message)
            raise Exception(message)
        return data
