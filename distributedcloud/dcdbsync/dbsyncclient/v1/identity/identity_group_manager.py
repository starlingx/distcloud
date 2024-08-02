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
# Copyright (c) 2019-2021, 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


from dcdbsync.dbsyncclient import base
from dcdbsync.dbsyncclient.base import get_json
from dcdbsync.dbsyncclient import exceptions


class Group(base.Resource):
    resource_name = "group"

    def __init__(
        self, manager, id, domain_id, name, description, local_user_ids, extra={}
    ):
        self.manager = manager
        self.id = id
        self.domain_id = domain_id
        self.name = name
        self.description = description
        self.local_user_ids = local_user_ids
        self.extra = extra

    def to_dict(self):
        return {
            "id": self.id,
            "domain_id": self.domain_id,
            "name": self.name,
            "extra": self.extra,
            "local_user_ids": self.local_user_ids,
            "description": self.description,
        }

    def info(self):
        resource_info = dict()
        resource_info.update(
            {
                self.resource_name: {
                    "name": self.name,
                    "id": self.id,
                    "domain_id": self.domain_id,
                }
            }
        )

        return resource_info


class identity_group_manager(base.ResourceManager):
    resource_class = Group

    def group_create(self, url, data):
        resp = self.http_client.post(url, data)

        # Unauthorized request
        if resp.status_code == 401:
            raise exceptions.Unauthorized("Unauthorized request.")
        if resp.status_code != 201:
            self._raise_api_exception(resp)

        # Converted into python dict
        json_object = get_json(resp)
        return json_object

    def group_list(self, url):
        resp = self.http_client.get(url)

        # Unauthorized
        if resp.status_code == 401:
            raise exceptions.Unauthorized("Unauthorized request")
        if resp.status_code != 200:
            self._raise_api_exception(resp)

        # Converted into python dict
        json_objects = get_json(resp)

        groups = []
        for json_object in json_objects:
            group = Group(
                self,
                id=json_object["group"]["id"],
                domain_id=json_object["group"]["domain_id"],
                name=json_object["group"]["name"],
                extra=json_object["group"]["extra"],
                description=json_object["group"]["description"],
                local_user_ids=json_object["local_user_ids"],
            )

            groups.append(group)

        return groups

    def _group_detail(self, url):
        resp = self.http_client.get(url)

        # Unauthorized request
        if resp.status_code == 401:
            raise exceptions.Unauthorized("Unauthorized request.")
        if resp.status_code != 200:
            self._raise_api_exception(resp)

        # Return group details in original json format,
        # ie, without convert it into python dict
        return resp.content

    def _group_update(self, url, data):
        resp = self.http_client.put(url, data)

        # Unauthorized request
        if resp.status_code == 401:
            raise exceptions.Unauthorized("Unauthorized request.")
        if resp.status_code != 200:
            self._raise_api_exception(resp)

        # Converted into python dict
        json_object = get_json(resp)
        return json_object

    def add_group(self, data):
        url = "/identity/groups/"
        return self.group_create(url, data)

    def list_groups(self):
        url = "/identity/groups/"
        return self.group_list(url)

    def group_detail(self, group_ref):
        url = "/identity/groups/%s" % group_ref
        return self._group_detail(url)

    def update_group(self, group_ref, data):
        url = "/identity/groups/%s" % group_ref
        return self._group_update(url, data)
