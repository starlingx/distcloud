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
# Copyright (c) 2019, 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


from dcdbsync.dbsyncclient import base
from dcdbsync.dbsyncclient.base import get_json
from dcdbsync.dbsyncclient import exceptions


class Project(base.Resource):
    resource_name = "project"

    def __init__(
        self,
        manager,
        id,
        domain_id,
        name,
        enabled,
        parent_id,
        is_domain,
        extra={},
        description="",
    ):
        self.manager = manager
        self.id = id
        self.domain_id = domain_id
        self.name = name
        self.extra = extra
        self.description = description
        self.enabled = enabled
        self.parent_id = parent_id
        self.is_domain = is_domain

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


class project_manager(base.ResourceManager):
    resource_class = Project

    def project_create(self, url, data):
        resp = self.http_client.post(url, data)

        # Unauthorized
        if resp.status_code == 401:
            raise exceptions.Unauthorized("Unauthorized request")
        if resp.status_code != 201:
            self._raise_api_exception(resp)

        # Converted into python dict
        json_object = get_json(resp)
        return json_object

    def projects_list(self, url):
        resp = self.http_client.get(url)

        # Unauthorized
        if resp.status_code == 401:
            raise exceptions.Unauthorized("Unauthorized request")
        if resp.status_code != 200:
            self._raise_api_exception(resp)

        # Converted into python dict
        json_objects = get_json(resp)

        projects = []
        for json_object in json_objects:
            json_object = json_object["project"]
            project = Project(
                self,
                id=json_object["id"],
                domain_id=json_object["domain_id"],
                name=json_object["name"],
                extra=json_object["extra"],
                description=json_object["description"],
                enabled=json_object["enabled"],
                parent_id=json_object["parent_id"],
                is_domain=json_object["is_domain"],
            )

            projects.append(project)

        return projects

    def _project_detail(self, url):
        resp = self.http_client.get(url)

        # Unauthorized
        if resp.status_code == 401:
            raise exceptions.Unauthorized("Unauthorized request")
        if resp.status_code != 200:
            self._raise_api_exception(resp)

        # Return project details in original json format,
        # ie, without convert it into python dict
        return resp.content

    def _project_update(self, url, data):
        resp = self.http_client.put(url, data)

        # Unauthorized
        if resp.status_code == 401:
            raise exceptions.Unauthorized("Unauthorized request")
        if resp.status_code != 200:
            self._raise_api_exception(resp)

        # Converted into python dict
        json_object = get_json(resp)
        return json_object

    def add_project(self, data):
        url = "/identity/projects/"
        return self.project_create(url, data)

    def list_projects(self):
        url = "/identity/projects/"
        return self.projects_list(url)

    def project_detail(self, project_ref):
        url = "/identity/projects/%s" % project_ref
        return self._project_detail(url)

    def update_project(self, project_ref, data):
        url = "/identity/projects/%s" % project_ref
        return self._project_update(url, data)
