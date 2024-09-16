#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import threading
from types import SimpleNamespace

from keystoneauth1.identity import v3
from keystoneauth1 import session
from keystoneclient.v3 import client as ks_client
from oslo_config import cfg
from oslo_log import log as logging
from tsconfig import tsconfig as tsc

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.fm import FmClient
from dccommon.drivers.openstack.software_v1 import SoftwareClient
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon.utils import is_token_expiring_soon
from dcorch.common import consts as dcorch_consts
from dcorch.engine.sync_services.sysinv import SysinvSyncThread


CONF = cfg.CONF
LOG = logging.getLogger(__name__)


# TODO(vgluzrom): Implement lru_cache from functools to handle described case
def cache_wrapper(cls):
    """Decorator to cache the results of the methods in the class.

    Note: This decorator only caches the results based on the function name.
    It cannot handle the case where the same function is called with different
    arguments and the result is different.
    """

    def wrap_method(method):
        def wrapper(self, *args, **kwargs):
            # Return the cached result if available
            use_cache = getattr(self, "use_cache", False)
            if use_cache and method.__name__ in self.__class__._results:
                response = self.__class__._results[method.__name__]
                LOG.debug(
                    f"Returning cached response for {method.__name__} "
                    f"from {self.__class__.__name__}. Response: {response}"
                )
                return response

            result = method(self, *args, **kwargs)
            # Cache the results in the '_result' class variable
            LOG.debug(
                f"Saving new response for {method.__name__} "
                f"in {self.__class__.__name__}. Response: {result}"
            )
            with self.__class__._lock:
                self.__class__._results[method.__name__] = result
            return result

        return wrapper

    # Apply the wrapper to all non private functions in the class
    for attr_name in dir(cls):
        if not attr_name.startswith("_"):
            attr = getattr(cls, attr_name)
            if callable(attr):
                setattr(cls, attr_name, wrap_method(attr))
    return cls


@cache_wrapper
class CachedSysinvClient(SysinvClient):
    _results = {}
    _lock = threading.Lock()


@cache_wrapper
class CachedFmClient(FmClient):
    _results = {}
    _lock = threading.Lock()


@cache_wrapper
class CachedSoftwareClient(SoftwareClient):
    _results = {}
    _lock = threading.Lock()


class KeystoneCache(object):
    """Simple cache to store the subcloud keystone token and client/session."""

    subcloud_keystone_client: ks_client = None
    subcloud_token = {}

    def __init__(self, restart_cache: bool = False):
        if (
            not KeystoneCache.subcloud_keystone_client
            or restart_cache
            or is_token_expiring_soon(KeystoneCache.subcloud_token)
        ):
            self.clear_subcloud_keystone_data()
            self.initialize_keystone_client()

    @staticmethod
    def get_admin_session(
        auth_url: str,
        user_name: str,
        user_domain_name: str,
        user_password: str,
        user_project: str,
        user_project_domain: str,
        timeout: float = None,
    ) -> session.Session:
        """Get the admin session.

        :param auth_url: The authentication URL.
        :type auth_url: str
        :param user_name: The user name.
        :type user_name: str
        :param user_domain_name: The user domain name.
        :type user_domain_name: str
        :param user_password: The user password.
        :type user_password: str
        :param user_project: The user project.
        :type user_project: str
        :param user_project_domain: The user project domain.
        :type user_project_domain: str
        :param timeout: The timeout.
        :type timeout: int
        :return: The admin session.
        :rtype: session.Session
        """

        user_auth = v3.Password(
            auth_url=auth_url,
            username=user_name,
            user_domain_name=user_domain_name,
            password=user_password,
            project_name=user_project,
            project_domain_name=user_project_domain,
            include_catalog=True,
        )
        timeout = (
            CONF.endpoint_cache.http_connect_timeout if timeout is None else timeout
        )
        return session.Session(
            auth=user_auth,
            additional_headers=dccommon_consts.USER_HEADER,
            timeout=timeout,
        )

    @staticmethod
    def get_keystone_client(keystone_session: session.Session) -> ks_client:
        """Get the keystone client.

        :param keystone_session: subcloud keystone session
        :type keystone_session: session.Session
        :return: subcloud keystone client
        :rtype: ks_client
        """
        return ks_client.Client(session=keystone_session)

    @staticmethod
    def get_subcloud_token(subcloud_keystone_client: ks_client = None):
        """Get the subcloud token.

        :param subcloud_keystone_client: The subcloud keystone client.
        :type subcloud_keystone_client: ks_client
        :return: The subcloud token.
        """
        subcloud_keystone_client = (
            subcloud_keystone_client
            if subcloud_keystone_client
            else KeystoneCache.subcloud_keystone_client
        )
        return subcloud_keystone_client.tokens.validate(
            subcloud_keystone_client.session.get_token(),
            include_catalog=False,
        )

    @classmethod
    def initialize_keystone_client(cls):
        """Initialize the keystone client and token for the subcloud."""
        subcloud_keystone_client = cls.get_keystone_client(
            cls.get_admin_session(
                CONF.endpoint_cache.auth_uri,
                CONF.endpoint_cache.username,
                CONF.endpoint_cache.user_domain_name,
                CONF.endpoint_cache.password,
                CONF.endpoint_cache.project_name,
                CONF.endpoint_cache.project_domain_name,
                timeout=CONF.endpoint_cache.http_connect_timeout,
            )
        )
        subcloud_token = cls.get_subcloud_token(subcloud_keystone_client)
        cls.set_subcloud_keystone_data(subcloud_keystone_client, subcloud_token)

    @staticmethod
    def set_subcloud_keystone_data(keystone_client: ks_client, keystone_token: dict):
        KeystoneCache.subcloud_keystone_client = keystone_client
        KeystoneCache.subcloud_token = keystone_token

    @staticmethod
    def clear_subcloud_keystone_data():
        KeystoneCache.subcloud_keystone_client = None
        KeystoneCache.subcloud_token = {}


class BaseAuditManager(object):
    def __init__(self):
        self.keystone_client = None
        self.sysinv_client = None
        self.fm_client = None
        self.software_client = None

    def initialize_clients(
        self,
        use_cache: bool = True,
        restart_keystone_cache: bool = False,
        request_token: str = None,
    ):
        region_name = tsc.region_1_name
        self.keystone_client = KeystoneCache(
            restart_keystone_cache
        ).subcloud_keystone_client
        auth_session = self.keystone_client.session

        self.sysinv_client = CachedSysinvClient(
            region_name,
            auth_session,
            endpoint_type=dccommon_consts.KS_ENDPOINT_INTERNAL,
            token=request_token,
        )
        self.fm_client = CachedFmClient(
            region_name,
            auth_session,
            endpoint_type=dccommon_consts.KS_ENDPOINT_INTERNAL,
            token=request_token,
        )
        self.software_client = CachedSoftwareClient(
            auth_session,
            region=region_name,
            endpoint_type=dccommon_consts.KS_ENDPOINT_INTERNAL,
            token=request_token,
        )
        self.sysinv_client.use_cache = use_cache
        self.fm_client.use_cache = use_cache
        self.software_client.use_cache = use_cache
        return self.sysinv_client, self.fm_client, self.software_client


def format_platform_resource(resource):
    formatted_resource = {}
    # Process each resource type in the response
    for resource_type in resource:
        if resource_type == dcorch_consts.RESOURCE_TYPE_SYSINV_CERTIFICATE:
            # Creates a list of namespaces to maintain compatibility
            # with existing code that expects attributes instead of dict keys
            certificates_ns = [
                SimpleNamespace(**cert) for cert in resource.get(resource_type, [])
            ]
            formatted_resource[resource_type] = SysinvSyncThread.filter_cert_list(
                certificates_ns
            )
        elif resource_type == dcorch_consts.RESOURCE_TYPE_SYSINV_USER:
            # Return a list containing a single dictionary since the resource
            # needs to be iterable
            iuser = resource.get(resource_type, {})
            formatted_resource[resource_type] = [iuser]
        elif resource_type == dcorch_consts.RESOURCE_TYPE_SYSINV_FERNET_REPO:
            # Convert the list of dictionaries to a single
            # dictionary inside a list
            fernet_repo = [{d["id"]: d["key"] for d in resource.get(resource_type, [])}]
            formatted_resource[resource_type] = fernet_repo
    return formatted_resource
