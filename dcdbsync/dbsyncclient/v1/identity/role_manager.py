# Copyright (c) 2017 Ericsson AB.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dcdbsync.dbsyncclient import base
from dcdbsync.dbsyncclient.base import get_json
from dcdbsync.dbsyncclient import exceptions


class Role(base.Resource):
    resource_name = 'role'

    def __init__(self, manager, id, domain_id, name, description, extra={}):
        self.manager = manager
        self.id = id
        self.domain_id = domain_id
        self.name = name
        self.extra = extra
        self.description = description

    def info(self):
        resource_info = dict()
        resource_info.update({self.resource_name:
                             {'name': self.name,
                              'id': self.id,
                              'domain_id': self.domain_id}})
        return resource_info


class role_manager(base.ResourceManager):
    resource_class = Role

    def role_create(self, url, data):
        resp = self.http_client.post(url, data)

        # Unauthorized
        if resp.status_code == 401:
            raise exceptions.Unauthorized('Unauthorized request')
        if resp.status_code != 201:
            self._raise_api_exception(resp)

        # Converted into python dict
        json_object = get_json(resp)
        return json_object

    def roles_list(self, url):
        resp = self.http_client.get(url)

        # Unauthorized
        if resp.status_code == 401:
            raise exceptions.Unauthorized('Unauthorized request')
        if resp.status_code != 200:
            self._raise_api_exception(resp)

        # Converted into python dict
        json_objects = get_json(resp)

        roles = []
        for json_object in json_objects:
            json_object = json_object.get('role')
            role = Role(
                self,
                id=json_object['id'],
                domain_id=json_object['domain_id'],
                name=json_object['name'],
                description=json_object['description'],
                extra=json_object['extra'])

            roles.append(role)

        return roles

    def _role_detail(self, url):
        resp = self.http_client.get(url)

        # Unauthorized
        if resp.status_code == 401:
            raise exceptions.Unauthorized('Unauthorized request')
        if resp.status_code != 200:
            self._raise_api_exception(resp)

        # Return role details in original json format,
        # ie, without convert it into python dict
        return resp.content

    def _role_update(self, url, data):
        resp = self.http_client.put(url, data)

        # Unauthorized
        if resp.status_code == 401:
            raise exceptions.Unauthorized('Unauthorized request')
        if resp.status_code != 200:
            self._raise_api_exception(resp)

        # Converted into python dict
        json_object = get_json(resp)
        return json_object

    def add_role(self, data):
        url = '/identity/roles/'
        return self.role_create(url, data)

    def list_roles(self):
        url = '/identity/roles/'
        return self.roles_list(url)

    def role_detail(self, role_ref):
        url = '/identity/roles/%s' % role_ref
        return self._role_detail(url)

    def update_role(self, role_ref, data):
        url = '/identity/roles/%s' % role_ref
        return self._role_update(url, data)
