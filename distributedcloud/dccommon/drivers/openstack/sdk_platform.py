# Copyright 2017-2024 Wind River Inc

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
from typing import Callable
from typing import List

from keystoneauth1 import exceptions as keystone_exceptions
from oslo_concurrency import lockutils
from oslo_log import log

from dccommon import consts
from dccommon.drivers.openstack.barbican import BarbicanClient
from dccommon.drivers.openstack.fm import FmClient
from dccommon.drivers.openstack.keystone_v3 import KeystoneClient
from dccommon.drivers.openstack.keystone_v3 import OptimizedKeystoneClient
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon import exceptions
from dccommon.utils import is_token_expiring_soon

from dcdbsync.dbsyncclient.client import Client as dbsyncclient

KEYSTONE_CLIENT_NAME = "keystone"
SYSINV_CLIENT_NAME = "sysinv"
FM_CLIENT_NAME = "fm"
BARBICAN_CLIENT_NAME = "barbican"
DBSYNC_CLIENT_NAME = "dbsync"

LOG = log.getLogger(__name__)

LOCK_NAME = "dc-openstackdriver-platform"

SUPPORTED_REGION_CLIENTS = (
    SYSINV_CLIENT_NAME,
    FM_CLIENT_NAME,
    BARBICAN_CLIENT_NAME,
    DBSYNC_CLIENT_NAME,
)

# Region client type and class mappings
region_client_class_map = {
    SYSINV_CLIENT_NAME: SysinvClient,
    FM_CLIENT_NAME: FmClient,
    BARBICAN_CLIENT_NAME: BarbicanClient,
    DBSYNC_CLIENT_NAME: dbsyncclient,
}


class OpenStackDriver(object):

    os_clients_dict = collections.defaultdict(dict)
    _identity_tokens = {}

    def __init__(
        self,
        region_name=consts.CLOUD_0,
        thread_name="dcorch",
        auth_url=None,
        region_clients=SUPPORTED_REGION_CLIENTS,
        endpoint_type=consts.KS_ENDPOINT_DEFAULT,
    ):
        # Check if objects are cached and try to use those
        self.region_name = region_name
        self.keystone_client = None
        self.sysinv_client = None
        self.fm_client = None
        self.barbican_client = None
        self.dbsync_client = None

        if region_clients:
            # check if the requested clients are in the supported client list
            result = all(c in SUPPORTED_REGION_CLIENTS for c in region_clients)
            if not result:
                message = "Requested clients are not supported: %s" % " ".join(
                    region_clients
                )
                LOG.error(message)
                raise exceptions.InvalidInputError

        self.get_cached_keystone_client(region_name)
        if self.keystone_client is None:
            LOG.debug("get new keystone client for subcloud %s", region_name)
            try:
                self.keystone_client = KeystoneClient(region_name, auth_url)
            except keystone_exceptions.ConnectFailure as exc:
                LOG.error(
                    "keystone_client region %s error: %s" % (region_name, str(exc))
                )
                raise exc
            except keystone_exceptions.ConnectTimeout as exc:
                LOG.debug(
                    "keystone_client region %s error: %s" % (region_name, str(exc))
                )
                raise exc
            except keystone_exceptions.NotFound as exc:
                LOG.debug(
                    "keystone_client region %s error: %s" % (region_name, str(exc))
                )
                raise exc

            except Exception as exc:
                LOG.error(
                    "keystone_client region %s error: %s" % (region_name, str(exc))
                )
                raise exc

            OpenStackDriver.update_region_clients(
                region_name, KEYSTONE_CLIENT_NAME, self.keystone_client
            )
            # Clear client object cache
            if region_name != consts.CLOUD_0:
                OpenStackDriver.os_clients_dict[region_name] = collections.defaultdict(
                    dict
                )

        if region_clients:
            self.get_cached_region_clients_for_thread(
                region_name, thread_name, region_clients
            )
            for client_name in region_clients:
                client_obj_name = client_name + "_client"
                if getattr(self, client_obj_name) is None:
                    # Create new client object and cache it
                    try:
                        # Since SysinvClient (cgtsclient) does not support session,
                        # also pass the cached endpoint so it does not need to
                        # retrieve it from keystone.
                        if client_name == "sysinv":
                            sysinv_endpoint = (
                                self.keystone_client.endpoint_cache.get_endpoint(
                                    "sysinv"
                                )
                            )
                            client_object = region_client_class_map[client_name](
                                region=region_name,
                                session=self.keystone_client.session,
                                endpoint_type=endpoint_type,
                                endpoint=sysinv_endpoint,
                            )
                        else:
                            client_object = region_client_class_map[client_name](
                                region=region_name,
                                session=self.keystone_client.session,
                                endpoint_type=endpoint_type,
                            )
                        setattr(self, client_obj_name, client_object)
                        OpenStackDriver.update_region_clients(
                            region_name, client_name, client_object, thread_name
                        )
                    except Exception as exception:
                        LOG.error(
                            "Region %s client %s thread %s error: %s"
                            % (region_name, client_name, thread_name, str(exception))
                        )
                        raise exception

    @lockutils.synchronized(LOCK_NAME)
    def get_cached_keystone_client(self, region_name):
        if (
            (region_name in OpenStackDriver.os_clients_dict)
            and (KEYSTONE_CLIENT_NAME in OpenStackDriver.os_clients_dict[region_name])
            and self._is_token_valid(region_name)
        ):
            self.keystone_client = OpenStackDriver.os_clients_dict[region_name][
                KEYSTONE_CLIENT_NAME
            ]

    @lockutils.synchronized(LOCK_NAME)
    def get_cached_region_clients_for_thread(self, region_name, thread_name, clients):
        if (region_name in OpenStackDriver.os_clients_dict) and (
            thread_name in OpenStackDriver.os_clients_dict[region_name]
        ):
            for client in clients:
                if client in (
                    OpenStackDriver.os_clients_dict[region_name][thread_name]
                ):
                    LOG.debug(
                        "Using cached OS %s client objects %s %s"
                        % (client, region_name, thread_name)
                    )
                    client_obj = OpenStackDriver.os_clients_dict[region_name][
                        thread_name
                    ][client]
                    setattr(self, client + "_client", client_obj)
        else:
            OpenStackDriver.os_clients_dict[region_name][thread_name] = {}

    @classmethod
    @lockutils.synchronized(LOCK_NAME)
    def update_region_clients(
        cls, region_name, client_name, client_object, thread_name=None
    ):
        if thread_name is not None:
            cls.os_clients_dict[region_name][thread_name][client_name] = client_object
        else:
            cls.os_clients_dict[region_name][client_name] = client_object

    @classmethod
    @lockutils.synchronized(LOCK_NAME)
    def delete_region_clients(cls, region_name, clear_token=False):
        LOG.warn(
            "delete_region_clients=%s, clear_token=%s" % (region_name, clear_token)
        )
        if region_name in cls.os_clients_dict:
            del cls.os_clients_dict[region_name]
        if clear_token:
            cls._identity_tokens[region_name] = None

    @classmethod
    @lockutils.synchronized(LOCK_NAME)
    def delete_region_clients_for_thread(cls, region_name, thread_name):
        LOG.debug(
            "delete_region_clients=%s, thread_name=%s" % (region_name, thread_name)
        )
        if (
            region_name in cls.os_clients_dict
            and thread_name in cls.os_clients_dict[region_name]
        ):
            del cls.os_clients_dict[region_name][thread_name]

    def _is_token_valid(self, region_name):
        try:
            keystone = OpenStackDriver.os_clients_dict[region_name][
                "keystone"
            ].keystone_client
            if (
                not OpenStackDriver._identity_tokens
                or region_name not in OpenStackDriver._identity_tokens
                or not OpenStackDriver._identity_tokens[region_name]
            ):
                OpenStackDriver._identity_tokens[region_name] = (
                    keystone.tokens.validate(
                        keystone.session.get_token(), include_catalog=False
                    )
                )
                LOG.info(
                    "Token for subcloud %s expires_at=%s"
                    % (
                        region_name,
                        OpenStackDriver._identity_tokens[region_name]["expires_at"],
                    )
                )
        except Exception as exception:
            LOG.info(
                "_is_token_valid handle: region: %s error: %s"
                % (region_name, str(exception))
            )
            # Reset the cached dictionary
            OpenStackDriver.os_clients_dict[region_name] = collections.defaultdict(dict)
            OpenStackDriver._identity_tokens[region_name] = None
            return False

        token_expiring_soon = is_token_expiring_soon(
            token=self._identity_tokens[region_name]
        )

        # If token is expiring soon, reset cached dictionaries and return False.
        # Else return true.
        if token_expiring_soon:
            LOG.info(
                "The cached keystone token for subcloud %s will expire soon %s"
                % (
                    region_name,
                    OpenStackDriver._identity_tokens[region_name]["expires_at"],
                )
            )
            # Reset the cached dictionary
            OpenStackDriver.os_clients_dict[region_name] = collections.defaultdict(dict)
            OpenStackDriver._identity_tokens[region_name] = None
            return False
        else:
            return True


class OptimizedOpenStackDriver(object):
    """An OpenStack driver for managing external services clients.

    :param region_name: The name of the region. Defaults to "RegionOne".
    :type region_name: str
    :param thread_name: The name of the thread. Defaults to "dcorch".
    :type thread_name: str
    :param auth_url: The authentication URL.
    :type auth_url: str
    :param region_clients: The list of region clients to initialize.
    :type region_clients: list
    :param endpoint_type: The type of endpoint. Defaults to "admin".
    :type endpoint_type: str
    :param fetch_subcloud_ips: A function to fetch subcloud management IPs.
    :type fetch_subcloud_ips: Callable
    """

    os_clients_dict = collections.defaultdict(dict)
    _identity_tokens = {}

    def __init__(
        self,
        region_name: str = consts.CLOUD_0,
        thread_name: str = "dc",
        auth_url: str = None,
        region_clients: List[str] = SUPPORTED_REGION_CLIENTS,
        endpoint_type: str = consts.KS_ENDPOINT_DEFAULT,
        fetch_subcloud_ips: Callable = None,
    ):
        self.region_name = region_name
        self.keystone_client = None

        # These clients are created dynamically by initialize_region_clients
        self.sysinv_client = None
        self.fm_client = None
        self.barbican_client = None
        self.dbsync_client = None

        self.get_cached_keystone_client(region_name, auth_url, fetch_subcloud_ips)

        if self.keystone_client is None:
            self.initialize_keystone_client(auth_url, fetch_subcloud_ips)

            OptimizedOpenStackDriver.update_region_clients_cache(
                region_name, KEYSTONE_CLIENT_NAME, self.keystone_client
            )
            # Clear client object cache
            if region_name != consts.CLOUD_0:
                OptimizedOpenStackDriver.os_clients_dict[region_name] = (
                    collections.defaultdict(dict)
                )

        if region_clients:
            self.initialize_region_clients(region_clients, thread_name, endpoint_type)

    def initialize_region_clients(
        self, region_clients: List[str], thread_name: str, endpoint_type: str
    ) -> None:
        """Initialize region clients dynamically setting them as attributes

        :param region_clients: The list of region clients to initialize.
        :type region_clients: list
        :param thread_name: The name of the thread.
        :type thread_name: str
        :param endpoint_type: The type of endpoint.
        :type endpoint_type: str
        """
        self.get_cached_region_clients_for_thread(
            self.region_name, thread_name, region_clients
        )
        for client_name in region_clients:
            client_obj_name = f"{client_name}_client"

            # If the clien object already exists, do nothing
            if getattr(self, client_obj_name) is not None:
                continue

            # Create new client object and cache it
            try:
                try:
                    client_class = region_client_class_map[client_name]
                except KeyError as e:
                    msg = f"Requested region client is not supported: {client_name}"
                    LOG.error(msg)
                    raise exceptions.InvalidInputError from e

                args = {
                    "region": self.region_name,
                    "session": self.keystone_client.session,
                    "endpoint_type": endpoint_type,
                }

                # Since SysinvClient (cgtsclient) does not support session,
                # also pass the cached endpoint so it does not need to
                # retrieve it from keystone.
                if client_name == "sysinv":
                    args["endpoint"] = self.keystone_client.endpoint_cache.get_endpoint(
                        "sysinv"
                    )

                client_object = client_class(**args)

                # Store the new client
                setattr(self, client_obj_name, client_object)
                OptimizedOpenStackDriver.update_region_clients_cache(
                    self.region_name, client_name, client_object, thread_name
                )
            except Exception as exception:
                LOG.error(
                    f"Region {self.region_name} client {client_name} "
                    f"thread {thread_name} error: {str(exception)}"
                )
                raise exception

    def initialize_keystone_client(
        self, auth_url: str, fetch_subcloud_ips: Callable
    ) -> None:
        """Initialize a new Keystone client.

        :param auth_url: The authentication URL.
        :type auth_url: str
        :param fetch_subcloud_ips: A function to fetch subcloud management IPs.
        :type fetch_subcloud_ips: Callable
        """
        LOG.debug(f"get new keystone client for region {self.region_name}")
        try:
            self.keystone_client = OptimizedKeystoneClient(
                self.region_name, auth_url, fetch_subcloud_ips
            )
        except (
            keystone_exceptions.ConnectFailure,
            keystone_exceptions.ServiceUnavailable,
        ) as exception:
            LOG.error(
                f"keystone_client region {self.region_name} error: {str(exception)}"
            )
            raise exception
        except (
            keystone_exceptions.NotFound,
            keystone_exceptions.ConnectTimeout,
        ) as exception:
            LOG.debug(
                f"keystone_client region {self.region_name} error: {str(exception)}"
            )
            raise exception
        except Exception as exception:
            LOG.exception(
                f"Unable to get a new keystone client for region: {self.region_name}"
            )
            raise exception

    @lockutils.synchronized(LOCK_NAME)
    def get_cached_keystone_client(
        self, region_name: str, auth_url: str, fetch_subcloud_ips: Callable
    ) -> None:
        """Get the cached Keystone client if it exists

        :param region_name: The name of the region.
        :type region_name: str
        :param auth_url: The authentication URL.
        :type auth_url: str
        :param fetch_subcloud_ips: A function to fetch subcloud management IPs.
        :type fetch_subcloud_ips: Callable
        """
        os_clients_dict = OptimizedOpenStackDriver.os_clients_dict
        keystone_client = os_clients_dict.get(region_name, {}).get(KEYSTONE_CLIENT_NAME)

        # If there's a cached keystone client and the token is valid, use it
        if keystone_client and self._is_token_valid(region_name):
            self.keystone_client = keystone_client
        # Else if master region, create a new keystone client
        elif region_name in (consts.CLOUD_0, consts.VIRTUAL_MASTER_CLOUD):
            self.initialize_keystone_client(auth_url, fetch_subcloud_ips)
            os_clients_dict[region_name][KEYSTONE_CLIENT_NAME] = self.keystone_client

    @lockutils.synchronized(LOCK_NAME)
    def get_cached_region_clients_for_thread(
        self, region_name: str, thread_name: str, clients: List[str]
    ) -> None:
        """Get and assign the cached region clients as object attributes.

        Also initializes the os_clients_dict region and
        thread dictionaries if they don't already exist.

        :param region_name: The name of the region.
        :type region_name: str
        :param thread_name: The name of the thread.
        :type thread_name: str
        :param clients: The list of client names.
        :type clients: list
        """
        os_clients = OptimizedOpenStackDriver.os_clients_dict

        for client in clients:
            client_obj = (
                os_clients.setdefault(region_name, {})
                .setdefault(thread_name, {})
                .get(client)
            )
            if client_obj is not None:
                LOG.debug(
                    f"Using cached OS {client} client objects "
                    f"{region_name} {thread_name}"
                )
                setattr(self, f"{client}_client", client_obj)

    @classmethod
    @lockutils.synchronized(LOCK_NAME)
    def update_region_clients_cache(
        cls,
        region_name: str,
        client_name: str,
        client_object: object,
        thread_name: str = None,
    ) -> None:
        """Update the region clients cache.

        :param region_name: The name of the region.
        :type region_name: str
        :param client_name: The name of the client.
        :type client_name: str
        :param client_object: The client object.
        :param thread_name: The name of the thread. Defaults to None.
        :type thread_name: str
        """
        region_dict = cls.os_clients_dict[region_name]
        if thread_name is None:
            region_dict[client_name] = client_object
        else:
            region_dict[thread_name][client_name] = client_object

    @classmethod
    @lockutils.synchronized(LOCK_NAME)
    def delete_region_clients(cls, region_name: str, clear_token: bool = False) -> None:
        """Delete region clients from cache.

        :param region_name: The name of the region.
        :type region_name: str
        :param clear_token: Whether to clear the token cache. Defaults to False.
        :type clear_token: bool
        """
        LOG.warn(f"delete_region_clients={region_name}, clear_token={clear_token}")
        try:
            del cls.os_clients_dict[region_name]
        except KeyError:
            pass

        if clear_token:
            cls._identity_tokens[region_name] = None

    @classmethod
    @lockutils.synchronized(LOCK_NAME)
    def delete_region_clients_for_thread(
        cls, region_name: str, thread_name: str
    ) -> None:
        """Delete region clients for a specific thread from cache.

        :param region_name: The name of the region.
        :type region_name: str
        :param thread_name: The name of the thread.
        :type thread_name: str
        """
        LOG.debug(f"delete_region_clients={region_name}, thread_name={thread_name}")
        try:
            del cls.os_clients_dict[region_name][thread_name]
        except KeyError:
            pass

    @staticmethod
    def _reset_cached_clients_and_token(region_name: str) -> None:
        OptimizedOpenStackDriver.os_clients_dict[region_name] = collections.defaultdict(
            dict
        )
        OptimizedOpenStackDriver._identity_tokens[region_name] = None

    def _is_token_valid(self, region_name: str) -> bool:
        """Check if the cached token is valid.

        :param region_name: The name of the region.
        :type region_name: str
        """
        cached_os_clients = OptimizedOpenStackDriver.os_clients_dict

        # If the token is not cached, validate the session token and cache it
        try:
            keystone = cached_os_clients[region_name]["keystone"].keystone_client
            cached_tokens = OptimizedOpenStackDriver._identity_tokens
            if not cached_tokens.get(region_name):
                cached_tokens[region_name] = keystone.tokens.validate(
                    keystone.session.get_token(), include_catalog=False
                )

                LOG.info(
                    f"Token for subcloud {region_name} expires_at="
                    f"{cached_tokens[region_name]['expires_at']}"
                )
        except Exception as exception:
            LOG.info(
                f"_is_token_valid handle: region: {region_name} "
                f"error: {str(exception)}"
            )
            self._reset_cached_clients_and_token(region_name)
            return False

        # If token is expiring soon, reset cached data and return False.
        if is_token_expiring_soon(token=cached_tokens[region_name]):
            LOG.info(
                f"The cached keystone token for subcloud {region_name} will "
                f"expire soon {cached_tokens[region_name]['expires_at']}"
            )
            # Reset the cached dictionary
            self._reset_cached_clients_and_token(region_name)
            return False

        return True
