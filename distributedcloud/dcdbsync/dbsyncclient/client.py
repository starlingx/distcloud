# Copyright 2016 - Ericsson AB
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

import six

from dcdbsync.dbsyncclient.v1 import client as client_v1


def Client(dbsync_agent_url=None, username=None, api_key=None,
           project_name=None, auth_url=None, project_id=None,
           endpoint_type='publicURL', service_type='dcorch-dbsync',
           auth_token=None, user_id=None, cacert=None, insecure=False,
           profile=None, auth_type='keystone', client_id=None,
           client_secret=None, session=None, **kwargs):
    if dbsync_agent_url and not isinstance(dbsync_agent_url, six.string_types):
        raise RuntimeError('DC DBsync agent url should be a string.')

    return client_v1.Client(
        dbsync_agent_url=dbsync_agent_url,
        username=username,
        api_key=api_key,
        project_name=project_name,
        auth_url=auth_url,
        project_id=project_id,
        endpoint_type=endpoint_type,
        service_type=service_type,
        auth_token=auth_token,
        user_id=user_id,
        cacert=cacert,
        insecure=insecure,
        profile=profile,
        auth_type=auth_type,
        client_id=client_id,
        client_secret=client_secret,
        session=session,
        **kwargs
    )


def determine_client_version(dbsync_version):
    if dbsync_version.find("v1.0") != -1:
        return 1

    raise RuntimeError("Cannot determine DC DBsync agent API version")
