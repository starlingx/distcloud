# Copyright 2015 Huawei Technologies Co., Ltd.
# Copyright (c) 2018-2023 Wind River Systems, Inc.
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
import threading

from keystoneauth1 import loading
from keystoneauth1 import session

from keystoneclient.v3 import client as ks_client

from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging

from dccommon import consts
from dccommon.utils import is_token_expiring_soon

CONF = cfg.CONF

LOG = logging.getLogger(__name__)

LOCK_NAME = 'dc-keystone-endpoint-cache'


class EndpointCache(object):

    plugin_loader = None
    plugin_lock = threading.Lock()
    master_keystone_client = None
    master_token = {}
    master_services_list = None
    master_service_endpoint_map = collections.defaultdict(dict)

    def __init__(self, region_name=None, auth_url=None):
        # Region specific service endpoint map
        self.service_endpoint_map = collections.defaultdict(dict)
        self.admin_session = None
        self.keystone_client = None

        # if auth_url is provided use that otherwise use the one
        # defined in the config
        if auth_url:
            self.external_auth_url = auth_url
        else:
            self.external_auth_url = CONF.endpoint_cache.auth_uri

        self._initialize_keystone_client(region_name, auth_url)

    def _initialize_keystone_client(self, region_name=None, auth_url=None):
        self.admin_session = EndpointCache.get_admin_session(
            self.external_auth_url,
            CONF.endpoint_cache.username,
            CONF.endpoint_cache.user_domain_name,
            CONF.endpoint_cache.password,
            CONF.endpoint_cache.project_name,
            CONF.endpoint_cache.project_domain_name)

        self.keystone_client, self.service_endpoint_map = \
            self.get_cached_master_keystone_client_and_region_endpoint_map(region_name)

        # if Endpoint cache is intended for a subcloud then
        # we need to retrieve the subcloud token and session.
        # Skip this if auth_url was provided as its assumed that the
        # auth_url would correspond to a subcloud so session was
        # set up above
        if (not auth_url and region_name and
                region_name not in
                [consts.CLOUD_0, consts.VIRTUAL_MASTER_CLOUD]):
            try:
                sc_auth_url = self.service_endpoint_map['keystone']
            except KeyError:
                # Should not be here...
                LOG.exception("Endpoint not found for region_name = %s. "
                              "Refreshing cached data..." % region_name)
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
                CONF.endpoint_cache.project_domain_name)

            try:
                self.keystone_client = ks_client.Client(
                    session=self.admin_session,
                    region_name=region_name)
            except Exception:
                LOG.error("Retrying keystone client creation for %s" % region_name)
                self.keystone_client = ks_client.Client(
                    session=self.admin_session,
                    region_name=region_name)
            self.external_auth_url = sc_auth_url

    @classmethod
    def get_admin_session(cls, auth_url, user_name, user_domain_name,
                          user_password, user_project, user_project_domain,
                          timeout=None):
        with EndpointCache.plugin_lock:
            if EndpointCache.plugin_loader is None:
                EndpointCache.plugin_loader = loading.get_plugin_loader(
                    CONF.endpoint_cache.auth_plugin)

        user_auth = EndpointCache.plugin_loader.load_from_options(
            auth_url=auth_url,
            username=user_name,
            user_domain_name=user_domain_name,
            password=user_password,
            project_name=user_project,
            project_domain_name=user_project_domain,
        )
        timeout = (CONF.endpoint_cache.http_connect_timeout if timeout is None
                   else timeout)
        return session.Session(
            auth=user_auth, additional_headers=consts.USER_HEADER,
            timeout=timeout)

    @classmethod
    def get_master_services_list(cls):
        return EndpointCache.master_services_list

    @staticmethod
    def _is_central_cloud(region_id):
        central_cloud_regions = [consts.CLOUD_0, consts.VIRTUAL_MASTER_CLOUD]
        return region_id in central_cloud_regions

    @staticmethod
    def _generate_master_service_endpoint_map(self):

        master_endpoints_list = EndpointCache.master_keystone_client.endpoints.list()
        service_id_name_map = {}
        for service in EndpointCache.master_services_list:  # pylint: disable=not-an-iterable
            service_dict = service.to_dict()
            service_id_name_map[service_dict['id']] = service_dict['name']

        service_endpoint_map = {}
        for endpoint in master_endpoints_list:
            endpoint_dict = endpoint.to_dict()
            region_id = endpoint_dict['region']
            # within central cloud, use internal endpoints
            if EndpointCache._is_central_cloud(region_id):
                if endpoint_dict['interface'] != consts.KS_ENDPOINT_INTERNAL:
                    continue
            # Otherwise should always use admin endpoints
            elif endpoint_dict['interface'] != consts.KS_ENDPOINT_ADMIN:
                continue

            service_id = endpoint_dict['service_id']
            url = endpoint_dict['url']
            service_name = service_id_name_map[service_id]
            if region_id not in service_endpoint_map:
                service_endpoint_map[region_id] = {}
            service_endpoint_map[region_id][service_name] = url

        return service_endpoint_map

    def get_endpoint(self, service):
        """Get the endpoint for the specified service.

        return: service url or None
        """
        try:
            endpoint = self.service_endpoint_map[service]
        except KeyError:
            LOG.error("Unknown service: %s" % service)
            endpoint = None

        return endpoint

    @lockutils.synchronized(LOCK_NAME)
    def get_all_regions(self):
        """Get region list.

        return: List of regions
        """
        return list(EndpointCache.master_service_endpoint_map.keys())

    def get_session_from_token(self, token, project_id):
        """Get session based on token to communicate with openstack services.

        :param token: token with which the request is triggered.
        :param project_id: UUID of the project.

        :return: session object.
        """
        loader = loading.get_plugin_loader('token')
        auth = loader.load_from_options(auth_url=self.external_auth_url,
                                        token=token, project_id=project_id)
        sess = session.Session(auth=auth)
        return sess

    @lockutils.synchronized(LOCK_NAME)
    def update_master_service_endpoint_region(self, region_name, endpoint_values):
        EndpointCache.master_service_endpoint_map[region_name] = endpoint_values

    @lockutils.synchronized(LOCK_NAME)
    def get_cached_master_keystone_client_and_region_endpoint_map(self, region_name):
        if (EndpointCache.master_keystone_client is None):
            self._create_master_cached_data()
            LOG.info("Generated Master keystone client and master token the "
                     "very first time")
        else:
            token_expiring_soon = is_token_expiring_soon(token=EndpointCache.master_token)

            # If token is expiring soon, initialize a new master keystone
            # client
            if token_expiring_soon:
                LOG.info("The cached keystone token for %s "
                         "will expire soon %s" %
                         (consts.CLOUD_0, EndpointCache.master_token['expires_at']))
                self._create_master_cached_data()
                LOG.info("Generated Master keystone client and master token as they are expiring soon")
            else:
                # Check if the cached master service endpoint map needs to be refreshed
                if region_name not in self.master_service_endpoint_map:
                    previous_size = len(EndpointCache.master_service_endpoint_map)
                    EndpointCache.master_service_endpoint_map = self._generate_master_service_endpoint_map(self)
                    current_size = len(EndpointCache.master_service_endpoint_map)
                    LOG.info("Master endpoints list refreshed to include region %s: "
                             "prev_size=%d, current_size=%d" % (region_name, previous_size, current_size))

        # TODO(clientsession)
        if region_name is not None:
            region_service_endpoint_map = EndpointCache.master_service_endpoint_map[region_name]
        else:
            region_service_endpoint_map = collections.defaultdict(dict)

        return (EndpointCache.master_keystone_client, region_service_endpoint_map)

    @lockutils.synchronized(LOCK_NAME)
    def re_initialize_master_keystone_client(self):
        self._create_master_cached_data()
        LOG.info("Generated Master keystone client and master token upon exception")

    def _create_master_cached_data(self):
        EndpointCache.master_keystone_client = ks_client.Client(
            session=self.admin_session,
            region_name=consts.CLOUD_0)
        EndpointCache.master_token = EndpointCache.master_keystone_client.tokens.validate(
            EndpointCache.master_keystone_client.session.get_token(),
            include_catalog=False)
        if EndpointCache.master_services_list is None:
            EndpointCache.master_services_list = EndpointCache.master_keystone_client.services.list()
        EndpointCache.master_service_endpoint_map = self._generate_master_service_endpoint_map(self)
