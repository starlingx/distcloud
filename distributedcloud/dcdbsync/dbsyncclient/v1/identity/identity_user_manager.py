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


class Password(base.Resource):
    resource_name = "password"

    def __init__(
        self,
        manager,
        id,
        local_user_id,
        self_service,
        password_hash,
        created_at,
        created_at_int,
        expires_at,
        expires_at_int,
    ):
        self.manager = manager
        self.id = id
        # Foreign key to local_user.id
        self.local_user_id = local_user_id
        self.self_service = self_service
        self.password_hash = password_hash
        self.created_at = created_at
        self.created_at_int = created_at_int
        self.expires_at = expires_at
        self.expires_at_int = expires_at_int


class LocalUser(base.Resource):
    resource_name = "localUser"

    def __init__(
        self,
        manager,
        id,
        domain_id,
        name,
        user_id,
        failed_auth_count,
        failed_auth_at,
        passwords=[],
    ):
        self.manager = manager
        self.id = id
        self.domain_id = domain_id
        self.name = name
        self.user_id = user_id
        self.failed_auth_count = failed_auth_count
        self.failed_auth_at = failed_auth_at
        self.passwords = passwords


class User(base.Resource):
    resource_name = "user"

    def __init__(
        self,
        manager,
        id,
        domain_id,
        default_project_id,
        enabled,
        created_at,
        last_active_at,
        local_user,
        extra={},
    ):
        self.manager = manager
        self.id = id
        self.domain_id = domain_id
        self.default_project_id = default_project_id
        self.enabled = enabled
        self.created_at = created_at
        self.last_active_at = last_active_at
        self.extra = extra
        self.local_user = local_user

    def info(self):
        resource_info = dict()
        resource_info.update(
            {
                self.resource_name: {
                    "name": self.local_user.name,
                    "id": self.id,
                    "domain_id": self.domain_id,
                }
            }
        )

        return resource_info


class identity_user_manager(base.ResourceManager):
    resource_class = User

    def user_create(self, url, data):
        resp = self.http_client.post(url, data)

        # Unauthorized request
        if resp.status_code == 401:
            raise exceptions.Unauthorized("Unauthorized request.")
        if resp.status_code != 201:
            self._raise_api_exception(resp)

        # Converted into python dict
        json_object = get_json(resp)
        return json_object

    def users_list(self, url):
        resp = self.http_client.get(url)

        # Unauthorized request
        if resp.status_code == 401:
            raise exceptions.Unauthorized("Unauthorized request.")
        if resp.status_code != 200:
            self._raise_api_exception(resp)

        # Converted into python dict
        json_objects = get_json(resp)

        users = []
        for json_object in json_objects:
            passwords = []
            for object in json_object["password"]:
                # skip empty password
                if not object:
                    continue
                password = Password(
                    self,
                    id=object["id"],
                    local_user_id=object["local_user_id"],
                    self_service=object["self_service"],
                    password_hash=object["password_hash"],
                    created_at=object["created_at"],
                    created_at_int=object["created_at_int"],
                    expires_at=object["expires_at"],
                    expires_at_int=object["expires_at_int"],
                )
                passwords.append(password)

            local_user = LocalUser(
                self,
                id=json_object["local_user"]["id"],
                domain_id=json_object["local_user"]["domain_id"],
                name=json_object["local_user"]["name"],
                user_id=json_object["local_user"]["user_id"],
                failed_auth_count=json_object["local_user"]["failed_auth_count"],
                failed_auth_at=json_object["local_user"]["failed_auth_at"],
                passwords=passwords,
            )

            user = User(
                self,
                id=json_object["user"]["id"],
                domain_id=json_object["user"]["domain_id"],
                default_project_id=json_object["user"]["default_project_id"],
                enabled=json_object["user"]["enabled"],
                created_at=json_object["user"]["created_at"],
                last_active_at=json_object["user"]["last_active_at"],
                extra=json_object["user"]["extra"],
                local_user=local_user,
            )

            users.append(user)

        return users

    def _user_detail(self, url):
        resp = self.http_client.get(url)

        # Unauthorized request
        if resp.status_code == 401:
            raise exceptions.Unauthorized("Unauthorized request.")
        if resp.status_code != 200:
            self._raise_api_exception(resp)

        # Return user details in original json format,
        # ie, without convert it into python dict
        return resp.content

    def _user_update(self, url, data):
        resp = self.http_client.put(url, data)

        # Unauthorized request
        if resp.status_code == 401:
            raise exceptions.Unauthorized("Unauthorized request.")
        if resp.status_code != 200:
            self._raise_api_exception(resp)

        # Converted into python dict
        json_object = get_json(resp)
        return json_object

    def add_user(self, data):
        url = "/identity/users/"
        return self.user_create(url, data)

    def list_users(self):
        url = "/identity/users/"
        return self.users_list(url)

    def user_detail(self, user_ref):
        url = "/identity/users/%s" % user_ref
        return self._user_detail(url)

    def update_user(self, user_ref, data):
        url = "/identity/users/%s" % user_ref
        return self._user_update(url, data)
