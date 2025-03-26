# Copyright 2012-2013 OpenStack Foundation
# Copyright (c) 2017-2021, 2024-2025 Wind River Systems, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#

from keystoneauth1 import exceptions as keystone_exceptions
from keystoneclient.v3.contrib import endpoint_filter
from oslo_utils import importutils

from dccommon.drivers import base
from dccommon.endpoint_cache import EndpointCache
from dccommon import exceptions
from dccommon import utils

# Ensure keystonemiddleware options are imported
importutils.import_module("keystonemiddleware.auth_token")


class KeystoneClient(base.DriverBase):
    """Keystone V3 Driver.

    :param region_name: The name of the region.
    :type region_name: str
    :param auth_url: The authentication URL.
    :type auth_url: str
    :param fetch_subcloud_ips: A function to fetch subcloud IPs.
    :type fetch_subcloud_ips: Callable
    """

    def __init__(self, region_name=None, auth_url=None, fetch_subcloud_ips=None):
        self.endpoint_cache = EndpointCache(region_name, auth_url, fetch_subcloud_ips)
        self.session = self.endpoint_cache.admin_session
        self.keystone_client = self.endpoint_cache.keystone_client
        self.region_name = region_name
        if region_name in utils.get_system_controller_region_names():
            self.services_list = EndpointCache.master_services_list
        else:
            self.services_list = self.keystone_client.services.list()

    def get_enabled_projects(self, id_only=True):
        project_list = self.keystone_client.projects.list()
        if id_only:
            return [
                current_project.id
                for current_project in project_list
                if current_project.enabled
            ]
        else:
            return [
                current_project
                for current_project in project_list
                if current_project.enabled
            ]

    def get_project_by_id(self, projectid):
        if not projectid:
            return None
        return self.keystone_client.projects.get(projectid)

    def get_project_by_name(self, projectname):
        if not projectname:
            return None
        project_list = self.get_enabled_projects(id_only=False)
        for project in project_list:
            if project.name == projectname:
                return project

    def get_enabled_users(self, id_only=True):
        user_list = self.keystone_client.users.list()
        if id_only:
            return [
                current_user.id for current_user in user_list if current_user.enabled
            ]
        else:
            return [current_user for current_user in user_list if current_user.enabled]

    def get_user_by_id(self, userid):
        if not userid:
            return None
        return self.keystone_client.users.get(userid)

    def get_user_by_name(self, username):
        if not username:
            return None
        user_list = self.get_enabled_users(id_only=False)
        for user in user_list:
            if user.name == username:
                return user

    def is_service_enabled(self, service):
        for current_service in self.services_list:
            if service in current_service.type:
                return True
        return False

    # Returns list of regions if endpoint filter is applied for the project
    def get_filtered_region(self, project_id):
        try:
            region_list = []
            endpoint_manager = endpoint_filter.EndpointFilterManager(
                self.keystone_client
            )
            endpoint_lists = endpoint_manager.list_endpoints_for_project(project_id)
            for endpoint in endpoint_lists:
                region_list.append(endpoint.region)
            return region_list
        except keystone_exceptions.NotFound:
            raise exceptions.ProjectNotFound(project_id=project_id)

    def delete_endpoints(self, region_name):
        endpoints = self.keystone_client.endpoints.list(region=region_name)
        for endpoint in endpoints:
            self.keystone_client.endpoints.delete(endpoint)

    def delete_region(self, region_name):
        try:
            self.keystone_client.regions.delete(region_name)
        except keystone_exceptions.NotFound:
            pass
