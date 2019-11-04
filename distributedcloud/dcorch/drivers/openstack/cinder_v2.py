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

from cinderclient import client

from dcorch.common import exceptions
from dcorch.drivers import base

LOG = log.getLogger(__name__)
API_VERSION = '2'


class CinderClient(base.DriverBase):
    """Cinder V2 driver."""

    def __init__(self, region, disabled_quotas, session, endpoint_type):
        try:
            self.cinder = client.Client(API_VERSION,
                                        session=session,
                                        region_name=region,
                                        endpoint_type=endpoint_type)
            self.no_volumes = True if 'volumes' in disabled_quotas else False
        except exceptions.ServiceUnavailable:
            raise

    def get_resource_usages(self, project_id):
        """Calculate resources usage and return the dict

        :param: project_id
        :return: resource usage dict

        TODO: support the rest of the quotas
        """
        if not self.no_volumes:
            try:
                quota_usage = self.cinder.quotas.get(
                    project_id, usage=True)
                quota_usage_dict = quota_usage.to_dict()
                del quota_usage_dict['id']
                resource_usage = defaultdict(dict)
                for resource in quota_usage_dict:
                    # NOTE: May be able to remove "reserved" if
                    # cinder will never set it. Need to check.
                    resource_usage[resource] = (
                        quota_usage_dict[resource]['in_use'] +
                        quota_usage_dict[resource]['reserved'])
                return resource_usage
            except exceptions.InternalError:
                raise

    def get_quota_limits(self, project_id):
        """Get the resource limits"""
        try:
            quotas = self.cinder.quotas.get(
                project_id, usage=False)
            quotas_dict = quotas.to_dict()
            del quotas_dict['id']
            return quotas_dict
        except exceptions.InternalError:
            raise

    def update_quota_limits(self, project_id, **new_quota):
        """Update the limits"""
        try:
            if not self.no_volumes:
                return self.cinder.quotas.update(project_id, **new_quota)
        except exceptions.InternalError:
            raise

    def delete_quota_limits(self, project_id):
        """Delete/Reset the limits"""
        try:
            if not self.no_volumes:
                return self.cinder.quotas.delete(project_id)
        except exceptions.InternalError:
            raise
