# Copyright 2016 Ericsson AB
# Copyright (c) 2018-2022 Wind River Systems, Inc.
#
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
import collections

from oslo_log import log

from dccommon import consts
from dcorch.common import exceptions
from dcorch.drivers import base

from novaclient import client

LOG = log.getLogger(__name__)
API_VERSION = '2.37'


class NovaClient(base.DriverBase):
    """Nova V2.37 driver."""

    def __init__(self, region, session, endpoint_type, disabled_quotas=None):
        try:
            self.nova_client = client.Client(API_VERSION,
                                             session=session,
                                             region_name=region,
                                             endpoint_type=endpoint_type)
            if disabled_quotas:
                self.enabled_quotas = list(set(consts.NOVA_QUOTA_FIELDS) -
                                           set(disabled_quotas))
                self.no_neutron = True if 'floatingips' in self.enabled_quotas \
                    or 'fixedips' in self.enabled_quotas else False
        except exceptions.ServiceUnavailable:
            raise

    def get_resource_usages(self, project_id, user_id):
        """Collect resource usages for a given project.

        :params: project_id
        :return: dictionary of corresponding resources with its usage
        TODO switch this over to using quotas API, support other resources.
        """
        try:
            # The API call does not give usage for keypair, fixed ips &
            # metadata items. Have raised a bug for that.
            quota_usage = self.nova_client.quotas.get(
                project_id, user_id=user_id, detail=True)
            quota_usage_dict = quota_usage.to_dict()
            del quota_usage_dict['id']
            resource_usage = collections.defaultdict(dict)
            for resource in quota_usage_dict:
                # Don't need to add in "reserved" here, it will always be zero.
                resource_usage[resource] = quota_usage_dict[resource]['in_use']

            # For time being, keypair is calculated in below manner.
            # This is actually not correct for projects, as keypair quotas
            # apply to users only, and across all projects.
            resource_usage['key_pairs'] = \
                len(self.nova_client.keypairs.list(user_id=user_id))
            return resource_usage
        except exceptions.InternalError:
            raise

    def get_quota_limits(self, project_id, user_id):
        """Collect resource limits for a given project.

        :params: project_id
        :return: dictionary of corresponding resources with its limit

        TODO: switch this over to using quotas API, support other resources.
        """
        try:
            quotas = self.nova_client.quotas.get(
                project_id, user_id=user_id, detail=False)
            quotas_dict = quotas.to_dict()
            del quotas_dict['id']
            return quotas_dict
        except exceptions.InternalError:
            raise

    def update_quota_limits(self, project_id, user_id, **new_quota):
        """Update quota limits for a given project.

        :params: project_id, dictionary with the quota limits to update
        :return: Nothing
        """
        try:
            if not self.no_neutron:
                if 'floating_ips' in new_quota:
                    del new_quota['floating_ips']
                if 'fixed_ips' in new_quota:
                    del new_quota['fixed_ips']
                if 'security_groups' in new_quota:
                    del new_quota['security_groups']
            return self.nova_client.quotas.update(project_id, user_id=user_id,
                                                  **new_quota)
        except exceptions.InternalError:
            raise

    def delete_quota_limits(self, project_id):
        """Delete/Reset quota limits for a given project.

        :params: project_id
        :return: Nothing
        """
        try:
            return self.nova_client.quotas.delete(project_id)
        except exceptions.InternalError:
            raise

    def get_keypairs(self, res_id):
        """Display keypair of the specified User.

        :params: resource_identifier
        :return: Keypair
        """
        try:
            keypair = self.nova_client.keypairs.get(res_id)
            LOG.info("Source Keypair: %s", keypair.name)
            return keypair

        except Exception as exception:
            LOG.error('Exception Occurred: %s', str(exception))
            pass

    def create_keypairs(self, force, keypair):
        """Create keypair for the specified User.

        :params: keypair, force
        :return: Creates a Keypair
        """
        if force:
            try:
                self.nova_client.keypairs.delete(keypair)
                LOG.info("Deleted Keypair: %s", keypair.name)
            except Exception as exception:
                LOG.error('Exception Occurred: %s', str(exception))
                pass
            LOG.info("Created Keypair: %s", keypair.name)
        return self.nova_client.keypairs. \
            create(keypair.name,
                   public_key=keypair.public_key)
