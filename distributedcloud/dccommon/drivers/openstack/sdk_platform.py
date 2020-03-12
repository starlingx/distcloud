# Copyright 2017-2020 Wind River Inc

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
import random

from oslo_concurrency import lockutils
from oslo_log import log
from oslo_utils import timeutils

from dccommon import consts
from dccommon.drivers.openstack.fm import FmClient
from dccommon.drivers.openstack.keystone_v3 import KeystoneClient
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon import exceptions


# Gap, in seconds, to determine whether the given token is about to expire
# These values are used to randomize the token early renewal duration and
# to distribute the new keystone creation to different audit cycles
STALE_TOKEN_DURATION_MIN = 40
STALE_TOKEN_DURATION_MAX = 120
STALE_TOKEN_DURATION_STEP = 20

KEYSTONE_CLIENT_NAME = 'keystone'
SYSINV_CLIENT_NAME = 'sysinv'
FM_CLIENT_NAME = 'fm'

LOG = log.getLogger(__name__)

LOCK_NAME = 'dc-openstackdriver-platform'

SUPPORTED_REGION_CLIENTS = [
    SYSINV_CLIENT_NAME,
    FM_CLIENT_NAME
]

# region client type and class mappings
region_client_class_map = {
    SYSINV_CLIENT_NAME: SysinvClient,
    FM_CLIENT_NAME: FmClient,
}


class OpenStackDriver(object):

    os_clients_dict = collections.defaultdict(dict)
    _identity_tokens = {}

    def __init__(self, region_name=consts.CLOUD_0, thread_name='dcorch',
                 auth_url=None, region_clients=SUPPORTED_REGION_CLIENTS):
        # Check if objects are cached and try to use those
        self.region_name = region_name
        self.keystone_client = None
        self.sysinv_client = None
        self.fm_client = None

        if region_clients:
            # check if the requested clients are in the supported client list
            result = all(c in SUPPORTED_REGION_CLIENTS for c in region_clients)
            if not result:
                message = ("Requested clients are not supported: %s" %
                           ' '.join(region_clients))
                LOG.error(message)
                raise exceptions.InvalidInputError

        self.get_cached_keystone_client(region_name)
        if self.keystone_client is None:
            LOG.info("get new keystone client for subcloud %s", region_name)
            try:
                self.keystone_client = KeystoneClient(region_name, auth_url)
                OpenStackDriver.update_region_clients(region_name,
                                                      KEYSTONE_CLIENT_NAME,
                                                      self.keystone_client)
            except Exception as exception:
                LOG.error('keystone_client region %s error: %s' %
                          (region_name, exception.message))
                raise exception

        if region_clients:
            self.get_cached_region_clients_for_thread(region_name,
                                                      thread_name,
                                                      region_clients)
            for client_name in region_clients:
                client_obj_name = client_name + '_client'
                if getattr(self, client_obj_name) is None:
                    # Create new client object and cache it
                    try:
                        client_object = region_client_class_map[client_name](
                            region_name, self.keystone_client.session)
                        setattr(self, client_obj_name, client_object)
                        OpenStackDriver.update_region_clients(region_name,
                                                              client_name,
                                                              client_object,
                                                              thread_name)
                    except Exception as exception:
                        LOG.error('Region %s client %s thread %s error: %s' %
                                  (region_name, client_name, thread_name,
                                   exception.message))
                        raise exception

    @lockutils.synchronized(LOCK_NAME)
    def get_cached_keystone_client(self, region_name):
        if ((region_name in OpenStackDriver.os_clients_dict) and
                (KEYSTONE_CLIENT_NAME in
                    OpenStackDriver.os_clients_dict[region_name]) and
                self._is_token_valid(region_name)):
            self.keystone_client = (OpenStackDriver.os_clients_dict
                                    [region_name][KEYSTONE_CLIENT_NAME])

    @lockutils.synchronized(LOCK_NAME)
    def get_cached_region_clients_for_thread(self, region_name, thread_name,
                                             clients):
        if ((region_name in OpenStackDriver.os_clients_dict) and
                (thread_name in OpenStackDriver.os_clients_dict[
                    region_name])):
            for client in clients:
                if client in (OpenStackDriver.os_clients_dict[region_name]
                              [thread_name]):
                    LOG.debug('Using cached OS %s client objects %s %s' %
                              (client, region_name, thread_name))
                    client_obj = (OpenStackDriver.os_clients_dict[region_name]
                                  [thread_name][client])
                    setattr(self, client + '_client', client_obj)
        else:
            OpenStackDriver.os_clients_dict[region_name][thread_name] = {}

    @classmethod
    @lockutils.synchronized(LOCK_NAME)
    def update_region_clients(cls, region_name, client_name, client_object,
                              thread_name=None):
        if thread_name is not None:
            cls.os_clients_dict[region_name][thread_name][client_name] = \
                client_object
        else:
            cls.os_clients_dict[region_name][client_name] = client_object

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
                    keystone.tokens.validate(keystone.session.get_token(),
                                             include_catalog=False)
                LOG.info("Token for subcloud %s expires_at=%s" %
                         (region_name,
                          OpenStackDriver._identity_tokens[region_name]
                          ['expires_at']))
            else:
                token = keystone.tokens.validate(
                    OpenStackDriver._identity_tokens[region_name],
                    include_catalog=False)
                if token != OpenStackDriver._identity_tokens[region_name]:
                    LOG.debug("%s: updating token %s to %s" %
                              (region_name,
                               OpenStackDriver._identity_tokens[region_name],
                               token))
                    OpenStackDriver._identity_tokens[region_name] = token

        except Exception as exception:
            LOG.info('_is_token_valid handle: %s', exception.message)
            # Reset the cached dictionary
            OpenStackDriver.os_clients_dict[region_name] = \
                collections.defaultdict(dict)
            OpenStackDriver._identity_tokens[region_name] = None
            return False

        expiry_time = timeutils.normalize_time(timeutils.parse_isotime(
            self._identity_tokens[region_name]['expires_at']))
        duration = random.randrange(STALE_TOKEN_DURATION_MIN,
                                    STALE_TOKEN_DURATION_MAX,
                                    STALE_TOKEN_DURATION_STEP)
        if timeutils.is_soon(expiry_time, duration):
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
