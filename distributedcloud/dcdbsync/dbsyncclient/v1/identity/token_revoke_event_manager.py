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


class RevokeEvent(base.Resource):
    resource_name = "token_revoke_event"

    def __init__(
        self,
        manager,
        id,
        domain_id,
        project_id,
        user_id,
        role_id,
        trust_id,
        consumer_id,
        access_token_id,
        issued_before,
        expires_at,
        revoked_at,
        audit_id,
        audit_chain_id,
    ):
        self.manager = manager
        self.id = id
        self.domain_id = domain_id
        self.project_id = project_id
        self.user_id = user_id
        self.role_id = role_id
        self.trust_id = trust_id
        self.consumer_id = consumer_id
        self.access_token_id = access_token_id
        self.issued_before = issued_before
        self.expires_at = expires_at
        self.revoked_at = revoked_at
        self.audit_id = audit_id
        self.audit_chain_id = audit_chain_id

    def info(self):
        resource_info = dict()
        resource_info.update(
            {
                self.resource_name: {
                    "id": self.id,
                    "project_id": self.project_id,
                    "user_id": self.user_id,
                    "role_id": self.role_id,
                    "audit_id": self.audit_id,
                    "issued_before": self.issued_before,
                }
            }
        )
        return resource_info


class revoke_event_manager(base.ResourceManager):
    resource_class = RevokeEvent

    def revoke_event_create(self, url, data):
        resp = self.http_client.post(url, data)

        # Unauthorized
        if resp.status_code == 401:
            raise exceptions.Unauthorized("Unauthorized request")
        if resp.status_code != 201:
            self._raise_api_exception(resp)

        # Converted into python dict
        json_object = get_json(resp)
        return json_object

    def revoke_events_list(self, url):
        resp = self.http_client.get(url)

        # Unauthorized
        if resp.status_code == 401:
            raise exceptions.Unauthorized("Unauthorized request")
        if resp.status_code != 200:
            self._raise_api_exception(resp)

        # Converted into python dict
        json_objects = get_json(resp)

        revoke_events = []
        for json_object in json_objects:
            json_object = json_object.get("revocation_event")
            revoke_event = RevokeEvent(
                self,
                id=json_object["id"],
                domain_id=json_object["domain_id"],
                project_id=json_object["project_id"],
                user_id=json_object["user_id"],
                role_id=json_object["role_id"],
                trust_id=json_object["trust_id"],
                consumer_id=json_object["consumer_id"],
                access_token_id=json_object["access_token_id"],
                issued_before=json_object["issued_before"],
                expires_at=json_object["expires_at"],
                revoked_at=json_object["revoked_at"],
                audit_id=json_object["audit_id"],
                audit_chain_id=json_object["audit_chain_id"],
            )

            revoke_events.append(revoke_event)

        return revoke_events

    def _revoke_event_detail(self, url):
        resp = self.http_client.get(url)

        # Unauthorized
        if resp.status_code == 401:
            raise exceptions.Unauthorized("Unauthorized request")
        if resp.status_code != 200:
            self._raise_api_exception(resp)

        # Return revoke_event details in original json format,
        # ie, without convert it into python dict
        return resp.content

    def _revoke_event_delete(self, url):
        resp = self.http_client.delete(url)

        # Unauthorized
        if resp.status_code == 401:
            raise exceptions.Unauthorized("Unauthorized request")
        # NotFound
        if resp.status_code == 404:
            raise exceptions.NotFound("Requested item not found")
        if resp.status_code != 204:
            self._raise_api_exception(resp)

    def add_revoke_event(self, data):
        url = "/identity/token-revocation-events/"
        return self.revoke_event_create(url, data)

    def list_revoke_events(self):
        url = "/identity/token-revocation-events/"
        return self.revoke_events_list(url)

    def revoke_event_detail(self, user_id=None, audit_id=None):
        if user_id:
            url = "/identity/token-revocation-events/users/%s" % user_id
        elif audit_id:
            url = "/identity/token-revocation-events/audits/%s" % audit_id
        else:
            raise exceptions.IllegalArgumentException(
                "Token revocation event user ID or audit ID required."
            )

        return self._revoke_event_detail(url)

    def delete_revoke_event(self, user_id=None, audit_id=None):
        if user_id:
            url = "/identity/token-revocation-events/users/%s" % user_id
        elif audit_id:
            url = "/identity/token-revocation-events/audits/%s" % audit_id
        else:
            raise exceptions.IllegalArgumentException(
                "Token revocation event ID or audit ID required."
            )

        return self._revoke_event_delete(url)
