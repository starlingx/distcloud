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
# Copyright (c) 2017 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

from oslo_log import log

from sysinv.common import constants as sysinv_constants

# from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.drivers import base

LOG = log.getLogger(__name__)
API_VERSION = '1'


class SysinvClient(base.DriverBase):
    """Sysinv V1 driver."""

    def __init__(self, region, session):
        try:
            # TOX cannot import cgts_client and all the dependencies therefore
            # the client is being lazy loaded since TOX doesn't actually
            # require the cgtsclient module.
            from cgtsclient import client

            # The sysinv client doesn't support a session, so we need to
            # get an endpoint and token.
            endpoint = session.get_endpoint(service_type='platform',
                                            region_name=region,
                                            interface='internal')
            token = session.get_token()

            self.sysinv_client = client.Client(API_VERSION,
                                               endpoint=endpoint,
                                               token=token)
        except exceptions.ServiceUnavailable:
            raise

    def get_controller_hosts(self):
        """Get a list of controller hosts."""
        return self.sysinv_client.ihost.list_personality(
            sysinv_constants.CONTROLLER)

    def get_management_interface(self, hostname):
        """Get the management interface for a host."""
        interfaces = self.sysinv_client.iinterface.list(hostname)
        for interface in interfaces:
            interface_networks = self.sysinv_client.interface_network.\
                list_by_interface(interface.uuid)
            for if_net in interface_networks:
                if if_net.network_type == sysinv_constants.NETWORK_TYPE_MGMT:
                    return interface

        # This can happen if the host is still being installed and has not
        # yet created its management interface.
        LOG.warning("Management interface on host %s not found" % hostname)
        return None

    def get_management_address_pool(self):
        """Get the management address pool for a host."""
        networks = self.sysinv_client.network.list()
        for network in networks:
            if network.type == sysinv_constants.NETWORK_TYPE_MGMT:
                address_pool_uuid = network.pool_uuid
                break
        else:
            LOG.error("Management address pool not found")
            raise exceptions.InternalError()

        return self.sysinv_client.address_pool.get(address_pool_uuid)

    def create_route(self, interface_uuid, network, prefix, gateway, metric):
        """Create a static route on an interface."""

        LOG.info("Creating route: interface: %s dest: %s/%s "
                 "gateway: %s metric %s" % (interface_uuid, network,
                                            prefix, gateway, metric))
        self.sysinv_client.route.create(interface_uuid=interface_uuid,
                                        network=network,
                                        prefix=prefix,
                                        gateway=gateway,
                                        metric=metric)

    def delete_route(self, interface_uuid, network, prefix, gateway, metric):
        """Delete a static route."""

        # Get the routes for this interface
        routes = self.sysinv_client.route.list_by_interface(interface_uuid)
        for route in routes:
            if (route.network == network and route.prefix == prefix and
                    route.gateway == gateway and route.metric == metric):
                LOG.info("Deleting route: interface: %s dest: %s/%s "
                         "gateway: %s metric %s" % (interface_uuid, network,
                                                    prefix, gateway, metric))
                self.sysinv_client.route.delete(route.uuid)
                return

        LOG.warning("Route not found: interface: %s dest: %s/%s gateway: %s "
                    "metric %s" % (interface_uuid, network, prefix, gateway,
                                   metric))

    def get_service_groups(self):
        """Get a list of service groups."""
        return self.sysinv_client.sm_servicegroup.list()

    def get_loads(self):
        """Get a list of loads."""
        return self.sysinv_client.load.list()
