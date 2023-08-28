# Copyright 2016 Ericsson AB
# Copyright (c) 2021, 2024 Wind River Systems, Inc.
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

"""
OpenStack Driver
"""
import collections

from oslo_concurrency import lockutils
from oslo_log import log
from oslo_utils import timeutils

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.fm import FmClient
from dccommon.drivers.openstack.keystone_v3 import KeystoneClient
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient

# Gap, in seconds, to determine whether the given token is about to expire
STALE_TOKEN_DURATION = 60

LOG = log.getLogger(__name__)


class OpenStackDriver(object):

    os_clients_dict = collections.defaultdict(dict)
    _identity_tokens = {}

    @lockutils.synchronized('dcorch-openstackdriver')
    def __init__(self, region_name=dccommon_consts.VIRTUAL_MASTER_CLOUD,
                 auth_url=None):
        # Check if objects are cached and try to use those
        self.region_name = region_name

        if (region_name in OpenStackDriver._identity_tokens and
                (region_name in OpenStackDriver.os_clients_dict) and
                ('keystone' in OpenStackDriver.os_clients_dict[region_name])
                and self._is_token_valid(self.region_name)):
            self.keystone_client = \
                OpenStackDriver.os_clients_dict[region_name]['keystone']
        else:
            LOG.info("get new keystone client for %s" % region_name)
            self.keystone_client = KeystoneClient(region_name, auth_url)
            OpenStackDriver.os_clients_dict[region_name]['keystone'] = \
                self.keystone_client

        # self.disabled_quotas = self._get_disabled_quotas(region_name)
        if region_name in OpenStackDriver.os_clients_dict and \
                self._is_token_valid(region_name):
            LOG.info('Using cached OS client objects %s' % region_name)
            self.sysinv_client = OpenStackDriver.os_clients_dict[
                region_name]['sysinv']
            self.fm_client = OpenStackDriver.os_clients_dict[
                region_name]['fm']
        else:
            # Create new objects and cache them
            LOG.info("Creating fresh OS Clients objects %s" % region_name)
            OpenStackDriver.os_clients_dict[
                region_name] = collections.defaultdict(dict)

            try:
                sysinv_endpoint = self.keystone_client.endpoint_cache.get_endpoint(
                    'sysinv')
                self.sysinv_client = SysinvClient(region_name,
                                                  self.keystone_client.session,
                                                  endpoint=sysinv_endpoint)
                OpenStackDriver.os_clients_dict[region_name][
                    'sysinv'] = self.sysinv_client
            except Exception as exception:
                LOG.error('sysinv_client region %s error: %s' %
                          (region_name, str(exception)))

            try:
                self.fm_client = FmClient(
                    region_name,
                    self.keystone_client.session,
                    endpoint_type=dccommon_consts.KS_ENDPOINT_DEFAULT)
                OpenStackDriver.os_clients_dict[region_name][
                    'fm'] = self.fm_client
            except Exception as exception:
                LOG.error('fm_client region %s error: %s' %
                          (region_name, str(exception)))

    @classmethod
    @lockutils.synchronized('dcorch-openstackdriver')
    def delete_region_clients(cls, region_name, clear_token=False):
        LOG.warn("delete_region_clients=%s, clear_token=%s" %
                 (region_name, clear_token))
        if region_name in cls.os_clients_dict:
            del cls.os_clients_dict[region_name]
        if clear_token:
            OpenStackDriver._identity_tokens[region_name] = None

    def get_enabled_projects(self, id_only=True):
        try:
            return self.keystone_client.get_enabled_projects(id_only)
        except Exception as exception:
            LOG.error('Error Occurred: %s', str(exception))

    def get_project_by_name(self, projectname):
        try:
            return self.keystone_client.get_project_by_name(projectname)
        except Exception as exception:
            LOG.error('Error Occurred : %s', str(exception))

    def get_project_by_id(self, projectid):
        try:
            return self.keystone_client.get_project_by_id(projectid)
        except Exception as exception:
            LOG.error('Error Occurred : %s', str(exception))

    def get_enabled_users(self, id_only=True):
        try:
            return self.keystone_client.get_enabled_users(id_only)
        except Exception as exception:
            LOG.error('Error Occurred : %s', str(exception))

    def get_user_by_name(self, username):
        try:
            return self.keystone_client.get_user_by_name(username)
        except Exception as exception:
            LOG.error('Error Occurred : %s', str(exception))

    def get_user_by_id(self, userid):
        try:
            return self.keystone_client.get_user_by_id(userid)
        except Exception as exception:
            LOG.error('Error Occurred : %s', str(exception))

    def get_resource_usages(self, project_id, user_id):
        raise NotImplementedError

        # # If one of the resources is unavailable we still want to return
        # # any usage information we have for the others.
        # nova_usages = {}
        # neutron_usages = {}
        # cinder_usages = {}
        # try:
        #     nova_usages = self.nova_client.get_resource_usages(project_id,
        #                                                        user_id)
        #     if user_id is None:
        #         # neutron/cinder don't do per-user quotas/usage
        #         neutron_usages = self.neutron_client.get_resource_usages(
        #             project_id)
        #         cinder_usages = self.cinder_client.get_resource_usages(
        #             project_id)
        # except (exceptions.ConnectionRefused, exceptions.NotAuthorized,
        #         exceptions.TimeOut) as ex:
        #     # Delete the cached objects for that region
        #     LOG.error('Error Occurred: %s', ex.message)
        #     del OpenStackDriver.os_clients_dict[self.region_name]
        # except Exception as exception:
        #     LOG.error('Error Occurred: %s', exception.message)
        # return nova_usages, neutron_usages, cinder_usages

    def get_quota_limits(self, project_id, user_id):
        raise NotImplementedError

        # # If one of the resources is unavailable we still want to return
        # # any limit information we have for the others.
        # nova_limits = {}
        # neutron_limits = {}
        # cinder_limits = {}
        # try:
        #     nova_limits = self.nova_client.get_quota_limits(project_id,
        #                                                     user_id)
        #     if user_id is None:
        #         # neutron/cinder don't do per-user quotas/usage
        #         neutron_limits = self.neutron_client.get_quota_limits(
        #             project_id)
        #         cinder_limits = self.cinder_client.get_quota_limits(
        #             project_id)
        # except (exceptions.ConnectionRefused, exceptions.NotAuthorized,
        #         exceptions.TimeOut) as ex:
        #     LOG.error('Error Occurred: %s', ex.message)
        #     # Delete the cached objects for that region
        #     del OpenStackDriver.os_clients_dict[self.region_name]
        # except Exception as exception:
        #     LOG.error('Error Occurred: %s', exception.message)
        # return nova_limits, neutron_limits, cinder_limits

    def write_quota_limits(self, project_id, user_id, limits_to_write):
        raise NotImplementedError

        # try:
        #     self.nova_client.update_quota_limits(project_id, user_id,
        #                                          **limits_to_write['nova'])
        #     # Only nova supports per-user quotas.
        #     if user_id is None:
        #         self.cinder_client.update_quota_limits(
        #             project_id, **limits_to_write['cinder'])
        #         self.neutron_client.update_quota_limits(
        #             project_id, limits_to_write['neutron'])
        # except (exceptions.ConnectionRefused, exceptions.NotAuthorized,
        #         exceptions.TimeOut) as ex:
        #     LOG.error('Error Occurred: %s', ex.message)
        #     # Delete the cached objects for that region
        #     del OpenStackDriver.os_clients_dict[self.region_name]
        # except Exception as exception:
        #     LOG.error('Error Occurred: %s', exception.message)

    def delete_quota_limits(self, project_id):
        raise NotImplementedError

        # try:
        #     self.nova_client.delete_quota_limits(project_id)
        #     self.neutron_client.delete_quota_limits(project_id)
        #     self.cinder_client.delete_quota_limits(project_id)
        # except (exceptions.ConnectionRefused, exceptions.NotAuthorized,
        #         exceptions.TimeOut):
        #     # Delete the cached objects for that region
        #     del OpenStackDriver.os_clients_dict[self.region_name]
        # except Exception as exception:
        #     LOG.error('Error Occurred: %s', exception.message)

    def _get_disabled_quotas(self, region):
        raise NotImplementedError

        # disabled_quotas = []
        # if not self.keystone_client.is_service_enabled('volume') and \
        #         not self.keystone_client.is_service_enabled('volumev2'):
        #     disabled_quotas.extend(consts.CINDER_QUOTA_FIELDS)
        # # Neutron
        # if not self.keystone_client.is_service_enabled('network'):
        #     disabled_quotas.extend(consts.NEUTRON_QUOTA_FIELDS)
        # else:
        #     disabled_quotas.extend(['floating_ips', 'fixed_ips'])
        #     disabled_quotas.extend(['security_groups',
        #                             'security_group_rules'])
        # return disabled_quotas

    def get_all_regions_for_project(self, project_id):
        try:
            # Retrieve regions based on endpoint filter for the project.
            region_lists = self._get_filtered_regions(project_id)
            if not region_lists:
                # If endpoint filter is not used for the project, then
                # return all regions
                region_lists = KeystoneClient().endpoint_cache.get_all_regions()
            # nova, cinder, and neutron have no endpoints in consts.CLOUD_0
            if dccommon_consts.CLOUD_0 in region_lists:
                region_lists.remove(dccommon_consts.CLOUD_0)
            return region_lists
        except Exception as exception:
            LOG.error('Error Occurred: %s', str(exception))
            raise

    def _get_filtered_regions(self, project_id):
        return self.keystone_client.get_filtered_region(project_id)

    def _is_token_valid(self, region_name):
        try:
            keystone = \
                self.os_clients_dict[region_name]['keystone'].keystone_client
            if (not OpenStackDriver._identity_tokens
                    or region_name not in OpenStackDriver._identity_tokens
                    or not OpenStackDriver._identity_tokens[region_name]):
                identity_token = \
                    keystone.tokens.validate(keystone.session.get_token())
                OpenStackDriver._identity_tokens[region_name] = identity_token
                LOG.info("Got new token for subcloud %s, expires_at=%s" %
                         (region_name, identity_token['expires_at']))
                # Reset the cached dictionary
                OpenStackDriver.os_clients_dict[region_name] = \
                    collections.defaultdict(dict)
                return False
            keystone.tokens.validate(
                OpenStackDriver._identity_tokens[region_name])
        except Exception as exception:
            LOG.info('_is_token_valid handle: %s', str(exception))
            # Reset the cached dictionary
            OpenStackDriver.os_clients_dict[region_name] = \
                collections.defaultdict(dict)
            OpenStackDriver._identity_tokens[region_name] = None
            return False

        identity_token = OpenStackDriver._identity_tokens[region_name]
        expiry_time = timeutils.normalize_time(timeutils.parse_isotime(
            identity_token['expires_at']))
        if timeutils.is_soon(expiry_time, STALE_TOKEN_DURATION):
            LOG.info("The cached keystone token for subcloud %s will "
                     "expire soon %s" %
                     (region_name, identity_token['expires_at']))
            # Reset the cached dictionary
            OpenStackDriver.os_clients_dict[region_name] = \
                collections.defaultdict(dict)
            OpenStackDriver._identity_tokens[region_name] = None
            return False
        else:
            return True
