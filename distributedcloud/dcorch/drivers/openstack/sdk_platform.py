# Copyright 2017-2018 Wind River Inc

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

"""
OpenStack Driver
"""
import collections

from oslo_concurrency import lockutils
from oslo_log import log
from oslo_utils import timeutils

from dcorch.common import consts
from dcorch.drivers.openstack.fm import FmClient
from dcorch.drivers.openstack.keystone_v3 import KeystoneClient
from dcorch.drivers.openstack.sysinv_v1 import SysinvClient

# Gap, in seconds, to determine whether the given token is about to expire
STALE_TOKEN_DURATION = 60

LOG = log.getLogger(__name__)

LOCK_NAME = 'dcorch-openstackdriver-platform'


class OpenStackDriver(object):

    os_clients_dict = collections.defaultdict(dict)
    _identity_tokens = {}

    @lockutils.synchronized(LOCK_NAME)
    def __init__(self, region_name=consts.CLOUD_0, thread_name='dcorch',
                 auth_url=None):
        # Check if objects are cached and try to use those
        self.region_name = region_name
        self.sysinv_client = None
        self.fm_client = None

        if ((region_name in OpenStackDriver.os_clients_dict) and
                ('keystone' in self.os_clients_dict[region_name]) and
                self._is_token_valid(region_name)):
            self.keystone_client = \
                self.os_clients_dict[region_name]['keystone']
        else:
            LOG.info("get new keystone client for subcloud %s", region_name)
            try:
                self.keystone_client = KeystoneClient(region_name, auth_url)
                OpenStackDriver.os_clients_dict[region_name]['keystone'] =\
                    self.keystone_client
            except Exception as exception:
                LOG.error('keystone_client region %s error: %s' %
                          (region_name, exception.message))

        if ((region_name in OpenStackDriver.os_clients_dict) and
                (thread_name in OpenStackDriver.os_clients_dict[region_name])):

            if ('sysinv' in OpenStackDriver.os_clients_dict[region_name]
               [thread_name]):
                LOG.debug('Using cached OS sysinv client objects %s %s' %
                          (region_name, thread_name))
                self.sysinv_client = OpenStackDriver.os_clients_dict[
                    region_name][thread_name]['sysinv']

            if ('fm' in OpenStackDriver.os_clients_dict[region_name]
               [thread_name]):
                LOG.debug('Using cached OS fm client objects %s %s' %
                          (region_name, thread_name))
                self.fm_client = OpenStackDriver.os_clients_dict[
                    region_name][thread_name]['fm']
        else:
            OpenStackDriver.os_clients_dict[region_name][thread_name] = {}

        if self.sysinv_client is None:
            # Create new sysinv client object and cache it
            try:
                self.sysinv_client = SysinvClient(region_name,
                                                  self.keystone_client.session)
                (OpenStackDriver.os_clients_dict[region_name][thread_name]
                 ['sysinv']) = self.sysinv_client

            except Exception as exception:
                LOG.error('sysinv_client region %s thread %s error: %s' %
                          (region_name, thread_name, exception.message))

        if self.fm_client is None:
            # Create new fm client object and cache it
            try:
                self.fm_client = FmClient(
                    region_name,
                    self.keystone_client.session,
                    endpoint_type=consts.KS_ENDPOINT_DEFAULT)
                (OpenStackDriver.os_clients_dict[region_name][thread_name]
                 ['fm']) = self.fm_client
            except Exception as exception:
                LOG.error('fm_client region %s thread %s error: %s' %
                          (region_name, thread_name, exception.message))

    @classmethod
    @lockutils.synchronized(LOCK_NAME)
    def delete_region_clients(cls, region_name, clear_token=False):
        LOG.warn("delete_region_clients=%s, clear_token=%s" %
                 (region_name, clear_token))
        if region_name in cls.os_clients_dict:
            del cls.os_clients_dict[region_name]
        if clear_token:
            cls._identity_tokens[region_name] = None

    @classmethod
    @lockutils.synchronized(LOCK_NAME)
    def delete_region_clients_for_thread(cls, region_name, thread_name):
        LOG.debug("delete_region_clients=%s, thread_name=%s" %
                  (region_name, thread_name))
        if (region_name in cls.os_clients_dict and
                thread_name in cls.os_clients_dict[region_name]):
            del cls.os_clients_dict[region_name][thread_name]

    def _is_token_valid(self, region_name):
        try:
            keystone = \
                OpenStackDriver.os_clients_dict[region_name]['keystone'].\
                keystone_client
            if (not OpenStackDriver._identity_tokens
                    or region_name not in OpenStackDriver._identity_tokens
                    or not OpenStackDriver._identity_tokens[region_name]):
                OpenStackDriver._identity_tokens[region_name] = \
                    keystone.tokens.validate(keystone.session.get_token())
                LOG.info("Get new token for subcloud %s expires_at=%s" %
                         (region_name,
                          OpenStackDriver._identity_tokens[region_name]
                          ['expires_at']))
                # Reset the cached dictionary
                OpenStackDriver.os_clients_dict[region_name] = \
                    collections.defaultdict(dict)
                return False

            token = \
                keystone.tokens.validate(OpenStackDriver._identity_tokens
                                         [region_name])
            if token != OpenStackDriver._identity_tokens[region_name]:
                LOG.info("updating token %s to %s" %
                         (OpenStackDriver._identity_tokens[region_name],
                          token))
                OpenStackDriver._identity_tokens[region_name] = token
                OpenStackDriver.os_clients_dict[region_name] = \
                    collections.defaultdict(dict)
                return False

        except Exception as exception:
            LOG.info('_is_token_valid handle: %s', exception.message)
            # Reset the cached dictionary
            OpenStackDriver.os_clients_dict[region_name] = \
                collections.defaultdict(dict)
            OpenStackDriver._identity_tokens[region_name] = None
            return False

        expiry_time = timeutils.normalize_time(timeutils.parse_isotime(
            self._identity_tokens[region_name]['expires_at']))
        if timeutils.is_soon(expiry_time, STALE_TOKEN_DURATION):
            LOG.info("The cached keystone token for subcloud %s "
                     "will expire soon %s" %
                     (region_name,
                      OpenStackDriver._identity_tokens[region_name]
                      ['expires_at']))
            # Reset the cached dictionary
            OpenStackDriver.os_clients_dict[region_name] = \
                collections.defaultdict(dict)
            OpenStackDriver._identity_tokens[region_name] = None
            return False
        else:
            return True
