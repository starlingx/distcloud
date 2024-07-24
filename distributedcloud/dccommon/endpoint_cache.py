# Copyright 2015 Huawei Technologies Co., Ltd.
# Copyright (c) 2018-2024 Wind River Systems, Inc.
# All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

import collections

from typing import Callable
from typing import List
from typing import Tuple
from typing import Union

from keystoneauth1.identity import v3
from keystoneauth1 import loading
from keystoneauth1 import session
import netaddr

from keystoneclient.v3 import client as ks_client

from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging

from dccommon import consts
from dccommon.utils import is_token_expiring_soon


CONF = cfg.CONF

LOG = logging.getLogger(__name__)

LOCK_NAME = "dc-keystone-endpoint-cache"

ENDPOINT_URLS = {
    "dcagent": "https://{}:8326",
    "fm": "https://{}:18003",
    "keystone": "https://{}:5001/v3",
    "patching": "https://{}:5492",
    "sysinv": "https://{}:6386/v1",
    "usm": "https://{}:5498",
    "vim": "https://{}:4546",
}


def build_subcloud_endpoint_map(ip: str) -> dict:
    """Builds a mapping of service endpoints for a given IP address.

    :param ip: The IP address for which service endpoints need to be mapped.
    :type ip: str
    :return: A dictionary containing service names as keys and formatted
             endpoint URLs as values.
    :rtype: dict
    """
    endpoint_map = {}
    for service, endpoint in ENDPOINT_URLS.items():
        formatted_ip = f"[{ip}]" if netaddr.IPAddress(ip).version == 6 else ip
        endpoint_map[service] = endpoint.format(formatted_ip)
    return endpoint_map


def build_subcloud_endpoints(subcloud_mgmt_ips: dict) -> dict:
    """Builds a dictionary of service endpoints for multiple subcloud management IPs.

    :param subcloud_mgmt_ips: A dictionary containing subcloud regions as keys
                              and the corresponding management IP as value.
    :type subcloud_mgmt_ips: dict
    :return: A dictionary with subcloud regions as keys and their respective
        service endpoints as values.
    :rtype: dict
    """
    subcloud_endpoints = {}
    for region, ip in subcloud_mgmt_ips.items():
        subcloud_endpoints[region] = build_subcloud_endpoint_map(ip)
    return subcloud_endpoints


def build_subcloud_endpoint(ip: str, service: str) -> str:
    """Builds a service endpoint for a given IP address.

    :param ip: The IP address for constructing the service endpoint.
    :type ip: str
    :param service: The service of the endpoint
    :type service: str
    :return: The service endpoint URL.
    :type: str
    """
    endpoint = ENDPOINT_URLS.get(service, None)
    if endpoint:
        formatted_ip = f"[{ip}]" if netaddr.IPAddress(ip).version == 6 else ip
        endpoint = endpoint.format(formatted_ip)
    return endpoint


class EndpointCache(object):
    """Cache for storing endpoint information.

    :param region_name: The name of the region.
    :type region_name: str
    :param auth_url: The authentication URL.
    :type auth_url: str
    :param fetch_subcloud_ips: A function to fetch subcloud IPs. It should
        accept the region_name as an optional argument. If it's called without
        the region_name, it should return a dictionary where the key is the
        region_name and the value is the subclouds management IP. If it's called
        with the region_name, it should return the management IP of the
        specified region.
    :type fetch_subcloud_ips: Callable[[str], Union[str, dict]]
    """

    master_keystone_client = None
    master_token = {}
    master_services_list = None
    master_service_endpoint_map = collections.defaultdict(dict)
    subcloud_endpoints: dict = None
    fetch_subcloud_ips: Callable[[str], Union[str, dict]] = None

    def __init__(
        self,
        region_name: str = None,
        auth_url: str = None,
        fetch_subcloud_ips: Callable[[str], Union[str, dict]] = None,
    ):
        # Region specific service endpoint map
        self.service_endpoint_map = collections.defaultdict(dict)
        self.admin_session = None
        self.keystone_client = None

        # Cache the fetch_subcloud_ips function
        if fetch_subcloud_ips:
            EndpointCache.fetch_subcloud_ips = fetch_subcloud_ips

        self._initialize_subcloud_endpoints()

        # if auth_url is provided use that otherwise use the one
        # defined in the config
        if auth_url:
            self.external_auth_url = auth_url
        else:
            self.external_auth_url = CONF.endpoint_cache.auth_uri

        self._initialize_keystone_client(region_name, auth_url)

    @lockutils.synchronized("subcloud_endpoints")
    def _initialize_subcloud_endpoints(self):
        # Initialize and cache the subcloud endpoints
        if (
            EndpointCache.subcloud_endpoints is None
            and EndpointCache.fetch_subcloud_ips
        ):
            LOG.info("Initializing and caching subcloud endpoints")
            # pylint: disable=not-callable
            EndpointCache.subcloud_endpoints = build_subcloud_endpoints(
                EndpointCache.fetch_subcloud_ips()
            )
            LOG.info("Finished initializing and caching subcloud endpoints")

    def _initialize_keystone_client(
        self, region_name: str = None, auth_url: str = None
    ) -> None:
        """Initialize the Keystone client.

        :param region_name: The name of the region.
        :type region_name: str
        :param auth_url: The authentication URL.
        :type auth_url: str
        """
        self.admin_session = EndpointCache.get_admin_session(
            self.external_auth_url,
            CONF.endpoint_cache.username,
            CONF.endpoint_cache.user_domain_name,
            CONF.endpoint_cache.password,
            CONF.endpoint_cache.project_name,
            CONF.endpoint_cache.project_domain_name,
        )

        self.keystone_client, self.service_endpoint_map = (
            self.get_cached_master_keystone_client_and_region_endpoint_map(region_name)
        )

        # If endpoint cache is intended for a subcloud then we need to
        # retrieve the subcloud token and session. Skip this if auth_url
        # was provided as its assumed that the auth_url would correspond
        # to a subcloud so session was set up above
        if (
            not auth_url
            and region_name
            and region_name not in [consts.CLOUD_0, consts.VIRTUAL_MASTER_CLOUD]
        ):
            try:
                sc_auth_url = self.service_endpoint_map["keystone"]
            except KeyError:
                # Should not be here...
                LOG.exception(
                    f"Endpoint not found for {region_name=}."
                    "Refreshing cached data..."
                )
                self.re_initialize_master_keystone_client()
                raise

            # We assume that the dcmanager user names and passwords are the
            # same on this subcloud since this is an audited resource
            self.admin_session = EndpointCache.get_admin_session(
                sc_auth_url,
                CONF.endpoint_cache.username,
                CONF.endpoint_cache.user_domain_name,
                CONF.endpoint_cache.password,
                CONF.endpoint_cache.project_name,
                CONF.endpoint_cache.project_domain_name,
            )

            try:
                self.keystone_client = ks_client.Client(
                    session=self.admin_session, region_name=region_name
                )
            except Exception:
                LOG.error(f"Retrying keystone client creation for {region_name}")
                self.keystone_client = ks_client.Client(
                    session=self.admin_session, region_name=region_name
                )
            self.external_auth_url = sc_auth_url

    @classmethod
    def get_admin_session(
        cls,
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
            auth=user_auth, additional_headers=consts.USER_HEADER, timeout=timeout
        )

    @staticmethod
    def _is_central_cloud(region_name: str) -> bool:
        """Check if the region is a central cloud.

        :param region_id: The region ID.
        :type region_id: str
        :return: True if the region is a central cloud, False otherwise.
        :rtype: bool
        """
        central_cloud_regions = [consts.CLOUD_0, consts.VIRTUAL_MASTER_CLOUD]
        return region_name in central_cloud_regions

    @staticmethod
    def _get_master_endpoint_map() -> dict:
        service_id_name_map = {}

        # pylint: disable-next=not-an-iterable
        for service in EndpointCache.master_services_list:
            service_id_name_map[service.id] = service.name

        service_endpoint_map = collections.defaultdict(dict)
        for endpoint in EndpointCache.master_keystone_client.endpoints.list():
            # Within central cloud, use only internal endpoints
            if EndpointCache._is_central_cloud(endpoint.region):
                if endpoint.interface != consts.KS_ENDPOINT_INTERNAL:
                    continue

            # For other regions store only admin endpoints
            elif endpoint.interface != consts.KS_ENDPOINT_ADMIN:
                continue

            # Add the endpoint url to the service endpoint map
            service_name = service_id_name_map[endpoint.service_id]
            service_endpoint_map[endpoint.region][service_name] = endpoint.url

        return service_endpoint_map

    @staticmethod
    def _generate_master_service_endpoint_map() -> dict:
        LOG.info("Generating service endpoint map")
        # Get the master endpoint map using keystone
        service_endpoint_map = EndpointCache._get_master_endpoint_map()

        # Insert the subcloud endpoints into the service_endpoint_map
        if EndpointCache.subcloud_endpoints:
            LOG.debug("Inserting subcloud endpoints into service_endpoint_map")
            service_endpoint_map.update(EndpointCache.subcloud_endpoints)

        return service_endpoint_map

    def get_endpoint(self, service: str) -> Union[str, None]:
        """Get the endpoint for the specified service.

        :param service: The service name.
        :type service: str
        return: service url or None
        """
        try:
            endpoint = self.service_endpoint_map[service]
        except KeyError:
            LOG.error(f"Unknown service: {service}")
            endpoint = None

        return endpoint

    @lockutils.synchronized(LOCK_NAME)
    def get_all_regions(self) -> List[str]:
        """Get region list.

        return: List of regions
        """
        return list(EndpointCache.master_service_endpoint_map.keys())

    def get_session_from_token(self, token: str, project_id: str) -> session.Session:
        """Get session based on token to communicate with openstack services.

        :param token: token with which the request is triggered.
        :type token: str
        :param project_id: UUID of the project.
        :type project_id: str

        :return: session object.
        """
        loader = loading.get_plugin_loader("token")
        auth = loader.load_from_options(
            auth_url=self.external_auth_url, token=token, project_id=project_id
        )
        return session.Session(auth=auth)

    @classmethod
    @lockutils.synchronized(LOCK_NAME)
    def update_master_service_endpoint_region(
        cls, region_name: str, endpoint_values: dict
    ) -> None:
        """Update the master endpoint map for a specific region.

        :param region_name: The name of the region.
        :type region_name: str
        :param endpoint_values: The endpoint values.
        :type endpoint_values: dict
        """
        LOG.info(
            "Updating service endpoint map for region: "
            f"{region_name} with endpoints: {endpoint_values}"
        )
        # Update the current endpoint map
        if EndpointCache.master_service_endpoint_map:
            EndpointCache.master_service_endpoint_map[region_name] = endpoint_values

        # Update the cached subcloud endpoit map
        if EndpointCache.subcloud_endpoints and not cls._is_central_cloud(region_name):
            LOG.debug(
                "Updating subcloud_endpoints for region: "
                f"{region_name} with endpoints: {endpoint_values}"
            )
            # pylint: disable-next=unsupported-assignment-operation
            EndpointCache.subcloud_endpoints[region_name] = endpoint_values

    def refresh_subcloud_endpoints(self, region_name: str) -> None:
        """Refresh the subcloud endpoints.

        :param region_name: The name of the region.
        :type region_name: str
        """
        LOG.info(f"Refreshing subcloud endpoinds of region_name: {region_name}")
        if not EndpointCache.fetch_subcloud_ips:
            raise Exception(
                f"Unable to fetch endpoints for region {region_name}: "
                "missing fetch_subcloud_ips"
            )
        # pylint: disable-next=not-callable
        subcloud_ip = EndpointCache.fetch_subcloud_ips(region_name)
        endpoint_map = build_subcloud_endpoint_map(subcloud_ip)
        # pylint: disable-next=unsupported-assignment-operation
        EndpointCache.subcloud_endpoints[region_name] = endpoint_map

    @lockutils.synchronized(LOCK_NAME)
    def get_cached_master_keystone_client_and_region_endpoint_map(
        self, region_name: str
    ) -> Tuple[ks_client.Client, dict]:
        """Get the cached master Keystone client and region endpoint map.

        :param region_name: The name of the region.
        :type region_name: str
        :return: The master Keystone client and region endpoint map.
        :rtype: tuple
        """
        # Initialize a new master keystone client if it doesn't exist or the
        # token is expiring soon
        token_expiring_soon = False
        if EndpointCache.master_keystone_client is None or (
            token_expiring_soon := is_token_expiring_soon(
                token=EndpointCache.master_token
            )
        ):
            if token_expiring_soon:
                msg = (
                    "Generating Master keystone client and master token as "
                    "they are expiring soon: "
                    f"{EndpointCache.master_token['expires_at']}"
                )
            else:
                msg = (
                    "Generating Master keystone client and master token the "
                    "very first time"
                )
            LOG.info(msg)
            self._create_master_cached_data()

        # Check if the cached master service endpoint map needs to be refreshed
        elif region_name not in self.master_service_endpoint_map:
            previous_size = len(EndpointCache.master_service_endpoint_map)

            if not self._is_central_cloud(region_name):
                self.refresh_subcloud_endpoints(region_name)

            EndpointCache.master_service_endpoint_map = (
                self._generate_master_service_endpoint_map()
            )
            current_size = len(EndpointCache.master_service_endpoint_map)
            LOG.info(
                f"Master endpoints list refreshed to include region {region_name}: "
                f"prev_size={previous_size}, current_size={current_size}"
            )

        if region_name is not None:
            region_service_endpoint_map = EndpointCache.master_service_endpoint_map[
                region_name
            ]
        else:
            region_service_endpoint_map = collections.defaultdict(dict)

        return (
            EndpointCache.master_keystone_client,
            region_service_endpoint_map,
        )

    @lockutils.synchronized(LOCK_NAME)
    def re_initialize_master_keystone_client(self) -> None:
        """Reinitialize the master Keystone client."""
        self._create_master_cached_data()
        LOG.info("Generated Master keystone client and master token upon exception")

    def _create_master_cached_data(self) -> None:
        EndpointCache.master_keystone_client = ks_client.Client(
            session=self.admin_session, region_name=consts.CLOUD_0
        )
        EndpointCache.master_token = (
            EndpointCache.master_keystone_client.tokens.validate(
                EndpointCache.master_keystone_client.session.get_token(),
                include_catalog=False,
            )
        )
        if EndpointCache.master_services_list is None:
            EndpointCache.master_services_list = (
                EndpointCache.master_keystone_client.services.list()
            )
        EndpointCache.master_service_endpoint_map = (
            self._generate_master_service_endpoint_map()
        )
