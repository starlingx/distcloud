# Copyright 2016 Ericsson AB

# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#


from barbicanclient import client

from oslo_log import log

from dccommon import consts as dccommon_consts
from dccommon.drivers import base
from dccommon import exceptions


LOG = log.getLogger(__name__)
API_VERSION = 'v1'


class BarbicanClient(base.DriverBase):
    """Barbican driver.

    The session needs to be associated with synchronized 'services' project
    in order for the client to get the host bmc password.
    """

    def __init__(
            self, region, session, endpoint_type=dccommon_consts.KS_ENDPOINT_DEFAULT):

        try:
            self.barbican_client = client.Client(
                API_VERSION,
                session=session,
                region_name=region,
                interface=endpoint_type)

            self.region_name = region
        except exceptions.ServiceUnavailable:
            raise

    def get_host_bmc_password(self, host_uuid):
        """Get the Board Management Controller password corresponding to the host

        :param host_uuid The host uuid
        """

        secrets = self.barbican_client.secrets.list()
        for secret in secrets:
            if secret.name == host_uuid:
                secret_ref = secret.secret_ref
                break
        else:
            return

        secret = self.barbican_client.secrets.get(secret_ref)

        bmc_password = secret.payload

        return bmc_password
