# Copyright 2014 - Mirantis, Inc.
# Copyright 2015 - StackStorm, Inc.
# Copyright 2016 - Ericsson AB.
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

import keystoneauth1.identity.generic as auth_plugin
from keystoneauth1 import session as ks_session

from dcdbsync.dbsyncclient import httpclient
from dcdbsync.dbsyncclient.v1.identity import identity_manager as im
from dcdbsync.dbsyncclient.v1.identity import project_manager as pm
from dcdbsync.dbsyncclient.v1.identity import role_manager as rm
from dcdbsync.dbsyncclient.v1.identity \
    import token_revoke_event_manager as trem

from oslo_utils import importutils
osprofiler_profiler = importutils.try_import("osprofiler.profiler")

import six


_DEFAULT_DBSYNC_AGENT_URL = "http://localhost:8219/v1.0"


class Client(object):
    """Class where the communication from KB to Keystone happens."""

    def __init__(self, dbsync_agent_url=None, username=None, api_key=None,
                 project_name=None, auth_url=None, project_id=None,
                 endpoint_type='publicURL', service_type='dcorch-dbsync',
                 auth_token=None, user_id=None, cacert=None, insecure=False,
                 profile=None, auth_type='keystone', client_id=None,
                 client_secret=None, session=None, **kwargs):
        """Communicates with Keystone to fetch necessary values."""
        if dbsync_agent_url and not isinstance(dbsync_agent_url,
                                               six.string_types):
            raise RuntimeError('DC DBsync agent url should be a string.')

        if auth_url or session:
            if auth_type == 'keystone':
                (dbsync_agent_url, auth_token, project_id, user_id) = (
                    authenticate(
                        dbsync_agent_url,
                        username,
                        api_key,
                        project_name,
                        auth_url,
                        project_id,
                        endpoint_type,
                        service_type,
                        auth_token,
                        user_id,
                        session,
                        cacert,
                        insecure,
                        **kwargs
                    )
                )
            else:
                raise RuntimeError(
                    'Invalid authentication type [value=%s, valid_values=%s]'
                    % (auth_type, 'keystone')
                )

        if not dbsync_agent_url:
            dbsync_agent_url = _DEFAULT_DBSYNC_AGENT_URL

        if osprofiler_profiler and profile:
            osprofiler_profiler.init(profile)

        self.http_client = httpclient.HTTPClient(
            dbsync_agent_url,
            auth_token,
            project_id,
            user_id,
            cacert=cacert,
            insecure=insecure
        )

        # Create all managers
        self.identity_manager = im.identity_manager(self.http_client)
        self.project_manager = pm.project_manager(self.http_client)
        self.role_manager = rm.role_manager(self.http_client)
        self.revoke_event_manager = trem.revoke_event_manager(self.http_client)

    # update to get a new token
    def update(self, session=None):
        if session:
            (dbsync_agent_url, auth_token, project_id, user_id) = (
                authenticate(
                    auth_url=session.auth.auth_url,
                    username=session.auth._username,
                    api_key=session.auth._password,
                    project_name=session.auth._project_name,
                    user_domain_name=session.auth._user_domain_name,
                    project_domain_name=session.auth._project_domain_name,
                )
            )

            self.http_client.token = auth_token


def authenticate(dbsync_agent_url=None, username=None,
                 api_key=None, project_name=None, auth_url=None,
                 project_id=None, endpoint_type='publicURL',
                 service_type='dcorch-dbsync', auth_token=None, user_id=None,
                 session=None, cacert=None, insecure=False, **kwargs):
    """Get token, project_id, user_id and Endpoint."""
    if project_name and project_id:
        raise RuntimeError(
            'Only project name or project id should be set'
        )

    if username and user_id:
        raise RuntimeError(
            'Only user name or user id should be set'
        )
    user_domain_name = kwargs.get('user_domain_name')
    user_domain_id = kwargs.get('user_domain_id')
    project_domain_name = kwargs.get('project_domain_name')
    project_domain_id = kwargs.get('project_domain_id')

    if session is None:
        if auth_token:
            auth = auth_plugin.Token(
                auth_url=auth_url,
                token=auth_token,
                project_id=project_id,
                project_name=project_name,
                project_domain_name=project_domain_name,
                project_domain_id=project_domain_id,
                )

        elif api_key and (username or user_id):
            auth = auth_plugin.Password(
                auth_url=auth_url,
                username=username,
                user_id=user_id,
                password=api_key,
                project_id=project_id,
                project_name=project_name,
                user_domain_name=user_domain_name,
                user_domain_id=user_domain_id,
                project_domain_name=project_domain_name,
                project_domain_id=project_domain_id)

        else:
            raise RuntimeError('You must either provide a valid token or'
                               'a password (api_key) and a user.')
        if auth:
            session = ks_session.Session(auth=auth)

    if session:
        token = session.get_token()
        project_id = session.get_project_id()
        user_id = session.get_user_id()
        if not dbsync_agent_url:
            dbsync_agent_url = session.get_endpoint(
                service_type=service_type,
                interface=endpoint_type)

    return dbsync_agent_url, token, project_id, user_id
