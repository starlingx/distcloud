# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Peer Site OpenStack Driver
"""
import collections
import threading

from keystoneauth1 import loading
from keystoneauth1 import session
from keystoneclient.v3 import client as ks_client
from oslo_concurrency import lockutils
from oslo_log import log

from dccommon import consts
from dccommon.drivers import base
from dccommon import exceptions
from dccommon.utils import is_token_expiring_soon

LOG = log.getLogger(__name__)

LOCK_NAME = "dc-openstackdriver-peer"
KEYSTONE_CLIENT_NAME = "keystone"
AUTH_PLUGIN_PASSWORD = "password"
HTTP_CONNECT_TIMEOUT = 10


class PeerSiteDriver(object):

    os_clients_dict = collections.defaultdict(dict)
    _identity_tokens = {}

    def __init__(
        self,
        site_uuid,
        auth_url,
        username,
        password,
        region_name=consts.CLOUD_0,
        endpoint_type=consts.KS_ENDPOINT_PUBLIC,
    ):
        if not (site_uuid and auth_url and username and password):
            raise exceptions.InvalidInputError

        self.site_uuid = site_uuid
        self.auth_url = auth_url
        self.username = username
        self.password = password

        self.region_name = region_name
        self.endpoint_type = endpoint_type

        # Check if objects are cached and try to use those
        self.keystone_client = self.get_cached_keystone_client(site_uuid)

        if self.keystone_client is None:
            LOG.debug(
                "No cached keystone client found. Creating new keystone "
                "client for peer site %s",
                site_uuid,
            )
            try:
                # Create the keystone client for this site with the provided
                # username and password and auth_url.
                self.keystone_client = PeerKeystoneClient(
                    auth_url,
                    username,
                    password,
                    region_name=region_name,
                    auth_type=endpoint_type,
                )
            except Exception as exception:
                LOG.error(
                    "peer site %s keystone_client error: %s"
                    % (site_uuid, str(exception))
                )
                raise exception

            # Cache the client object
            PeerSiteDriver.update_site_clients(
                site_uuid, KEYSTONE_CLIENT_NAME, self.keystone_client
            )

    @lockutils.synchronized(LOCK_NAME)
    def get_cached_keystone_client(self, site_uuid):
        if (site_uuid in PeerSiteDriver.os_clients_dict) and self._is_token_valid(
            site_uuid
        ):
            return PeerSiteDriver.os_clients_dict[site_uuid][KEYSTONE_CLIENT_NAME]

    @classmethod
    @lockutils.synchronized(LOCK_NAME)
    def update_site_clients(cls, site_uuid, client_name, client_object):
        cls.os_clients_dict[site_uuid][client_name] = client_object

    @classmethod
    @lockutils.synchronized(LOCK_NAME)
    def delete_site_clients(cls, site_uuid, clear_token=False):
        LOG.warn("delete_site_clients=%s, clear_token=%s" % (site_uuid, clear_token))
        if site_uuid in cls.os_clients_dict:
            del cls.os_clients_dict[site_uuid]
        if clear_token:
            cls._identity_tokens[site_uuid] = None

    def _is_token_valid(self, site_uuid):
        try:
            keystone = PeerSiteDriver.os_clients_dict[site_uuid][
                KEYSTONE_CLIENT_NAME
            ].keystone_client
            if (
                not PeerSiteDriver._identity_tokens
                or site_uuid not in PeerSiteDriver._identity_tokens
                or not PeerSiteDriver._identity_tokens[site_uuid]
            ):
                PeerSiteDriver._identity_tokens[site_uuid] = keystone.tokens.validate(
                    keystone.session.get_token(), include_catalog=False
                )
                LOG.info(
                    "Token for peer site %s expires_at=%s"
                    % (
                        site_uuid,
                        PeerSiteDriver._identity_tokens[site_uuid]["expires_at"],
                    )
                )
        except Exception as exception:
            LOG.warn(
                "_is_token_valid handle: site: %s error: %s"
                % (site_uuid, str(exception))
            )
            # Reset the cached dictionary
            PeerSiteDriver.os_clients_dict[site_uuid] = collections.defaultdict(dict)
            PeerSiteDriver._identity_tokens[site_uuid] = None
            return False

        token_expiring_soon = is_token_expiring_soon(
            token=self._identity_tokens[site_uuid]
        )

        # If token is expiring soon, reset cached dictionaries and return False.
        # Else return true.
        if token_expiring_soon:
            LOG.info(
                "The cached keystone token for peer site %s will expire soon %s"
                % (site_uuid, PeerSiteDriver._identity_tokens[site_uuid]["expires_at"])
            )
            # Reset the cached dictionary
            PeerSiteDriver.os_clients_dict[site_uuid] = collections.defaultdict(dict)
            PeerSiteDriver._identity_tokens[site_uuid] = None
            return False
        else:
            return True


class PeerKeystoneClient(base.DriverBase):
    """Peer Site Keystone V3 driver."""

    plugin_loader = None
    plugin_lock = threading.Lock()

    def __init__(
        self,
        auth_url,
        username,
        password,
        region_name=consts.CLOUD_0,
        project_name=consts.KS_ENDPOINT_PROJECT_DEFAULT,
        project_domain_name=consts.KS_ENDPOINT_PROJECT_DOMAIN_DEFAULT,
        user_domain_name=consts.KS_ENDPOINT_USER_DOMAIN_DEFAULT,
        auth_type=consts.KS_ENDPOINT_PUBLIC,
    ):
        if not (auth_url and username and password):
            raise exceptions.InvalidInputError
        self.auth_url = auth_url
        self.username = username
        self.password = password

        self.auth_type = auth_type
        self.region_name = region_name
        self.project_name = project_name
        self.project_domain_name = project_domain_name
        self.user_domain_name = user_domain_name

        self.session = PeerKeystoneClient.get_admin_session(
            self.auth_url,
            self.username,
            self.user_domain_name,
            self.password,
            self.project_name,
            self.project_domain_name,
        )
        self.keystone_client = self._create_keystone_client()

    @classmethod
    def get_admin_session(
        cls,
        auth_url,
        user_name,
        user_domain_name,
        user_password,
        user_project,
        user_project_domain,
        timeout=None,
    ):
        with PeerKeystoneClient.plugin_lock:
            if PeerKeystoneClient.plugin_loader is None:
                PeerKeystoneClient.plugin_loader = loading.get_plugin_loader(
                    AUTH_PLUGIN_PASSWORD
                )

        user_auth = PeerKeystoneClient.plugin_loader.load_from_options(
            auth_url=auth_url,
            username=user_name,
            user_domain_name=user_domain_name,
            password=user_password,
            project_name=user_project,
            project_domain_name=user_project_domain,
        )
        timeout = HTTP_CONNECT_TIMEOUT if timeout is None else timeout
        return session.Session(
            auth=user_auth, additional_headers=consts.USER_HEADER, timeout=timeout
        )

    def _create_keystone_client(self):
        client_kwargs = {
            "session": self.session,
            "region_name": self.region_name,
            "interface": self.auth_type,
        }
        return ks_client.Client(**client_kwargs)
