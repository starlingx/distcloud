#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from keystoneauth1.session import Session as keystone_session
from oslo_log import log
import requests

from dccommon import consts
from dccommon.drivers import base

LOG = log.getLogger(__name__)


DCAGENT_REST_DEFAULT_TIMEOUT = 900


class DcagentClient(base.DriverBase):
    """Dcagent V1 driver."""

    def __init__(
        self,
        region: str,
        session: keystone_session,
        endpoint: str = None,
    ):
        # Get an endpoint and token.
        if endpoint is None:
            self.endpoint = session.get_endpoint(
                service_type="dcagent",
                region_name=region,
                interface=consts.KS_ENDPOINT_ADMIN,
            )
        else:
            self.endpoint = endpoint

        self.token = session.get_token()

    def audit(self, audit_data, timeout=DCAGENT_REST_DEFAULT_TIMEOUT):
        """Audit subcloud"""
        url = self.endpoint + "/v1/dcaudit"
        headers = {"X-Auth-Token": self.token}
        response = requests.patch(
            url, headers=headers, json=audit_data, timeout=timeout
        )

        if response.status_code == 200:
            return response.json()
        message = f"Audit request failed with RC: {response.status_code}"
        LOG.error(message)
        raise Exception(message)
