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

from collections import defaultdict

from oslo_log import log

from dcorch.common import exceptions
from dcorch.drivers import base

from neutronclient.neutron import client

LOG = log.getLogger(__name__)
API_VERSION = '2.0'


class NeutronClient(base.DriverBase):
    """Neutron V2 driver."""
    def __init__(self, region, disabled_quotas, session, endpoint_type):
        try:
            self.neutron = client.Client(
                API_VERSION, session=session,
                region_name=region,
                endpoint_type=endpoint_type,
                )
            self.extension_list = self.neutron.list_extensions()
            self.disabled_quotas = disabled_quotas
            self.no_network = True if 'floatingip' in self.disabled_quotas \
                else False
            self.is_sec_group_enabled = self.is_extension_supported(
                'security-group')
        except exceptions.ServiceUnavailable:
            raise

    def get_resource_usages(self, project_id):
        """Calcualte resources usage and return the dict

        :param: project_id
        :return: resource usage dict
        """
        if not self.no_network:
            try:
                usages = defaultdict(dict)
                limits = self.neutron.show_quota_details(project_id)
                limits = limits['quota']
                for resource in limits:
                    # NOTE: May be able to remove "reserved" if
                    # neutron will never set it. Need to check.
                    usages[resource] = (limits[resource]['used'] +
                                        limits[resource]['reserved'])
                return usages
            except exceptions.InternalError:
                raise
            except AttributeError:
                # Dealing with neutronclient without show_quota_details(),
                # fall back to older code.
                try:
                    usages = defaultdict(dict)

                    opts = {'tenant_id': project_id}

                    networks = self.neutron.list_networks(**opts)['networks']
                    subnets = self.neutron.list_subnets(**opts)['subnets']
                    ports = self.neutron.list_ports(**opts)['ports']
                    routers = self.neutron.list_routers(**opts)['routers']
                    floatingips = self.neutron.list_floatingips(
                        **opts)['floatingips']

                    usages['network'] = len(networks)
                    usages['subnet'] = len(subnets)
                    usages['port'] = len(ports)
                    usages['router'] = len(routers)
                    usages['floatingip'] = len(floatingips)

                    if self.is_sec_group_enabled:
                        security_group_rules = \
                            self.neutron.list_security_group_rules(
                                **opts)['security_group_rules']
                        security_groups = self.neutron.list_security_groups(
                            **opts)['security_groups']
                        usages['security_group_rule'] = len(
                            security_group_rules)
                        usages['security_group'] = len(security_groups)
                    return usages
                except exceptions.InternalError:
                    raise

    def get_quota_limits(self, project_id):
        """Get the limits

        TODO: support the rest of the limits
        """
        try:
            resource_limit = {}
            if not self.no_network:
                limits = self.neutron.show_quota(project_id)
                resource_limit = limits['quota']
            return resource_limit
        except exceptions.InternalError:
            raise

    def update_quota_limits(self, project_id, new_quota):
        """Update the limits"""
        try:
            if not self.no_network:
                return self.neutron.update_quota(project_id,
                                                 {"quota": new_quota})
        except exceptions.InternalError:
            raise

    def delete_quota_limits(self, project_id):
        """Delete/Reset the limits"""
        try:
            if not self.no_network:
                return self.neutron.delete_quota(project_id)
        except exceptions.InternalError:
            raise

    def is_extension_supported(self, extension):
        for current_extension in self.extension_list['extensions']:
            if extension in current_extension['alias']:
                return True
        return False
