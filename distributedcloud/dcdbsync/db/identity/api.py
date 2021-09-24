# Copyright (c) 2015 Ericsson AB.
# All Rights Reserved.
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
# Copyright (c) 2019-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Interface for database access.

SQLAlchemy is currently the only supported backend.
"""

from oslo_config import cfg
from oslo_db import api


CONF = cfg.CONF

_BACKEND_MAPPING = {'sqlalchemy': 'dcdbsync.db.identity.sqlalchemy.api'}

IMPL = api.DBAPI.from_config(CONF, backend_mapping=_BACKEND_MAPPING)


def get_engine():
    return IMPL.get_engine()


def get_session():
    return IMPL.get_session()


###################

# user db methods

###################

def user_get_all(context):
    """Retrieve all users."""
    return IMPL.user_get_all(context)


def user_get(context, user_id):
    """Retrieve details of a user."""
    return IMPL.user_get(context, user_id)


def user_create(context, payload):
    """Create a user."""
    return IMPL.user_create(context, payload)


def user_update(context, user_ref, payload):
    """Update a user"""
    return IMPL.user_update(context, user_ref, payload)


###################

# group db methods

###################

def group_get_all(context):
    """Retrieve all groups."""
    return IMPL.group_get_all(context)


def group_get(context, group_id):
    """Retrieve details of a group."""
    return IMPL.group_get(context, group_id)


def group_create(context, payload):
    """Create a group."""
    return IMPL.group_create(context, payload)


def group_update(context, group_ref, payload):
    """Update a group"""
    return IMPL.group_update(context, group_ref, payload)


###################

# project db methods

###################

def project_get_all(context):
    """Retrieve all projects."""
    return IMPL.project_get_all(context)


def project_get(context, project_id):
    """Retrieve details of a project."""
    return IMPL.project_get(context, project_id)


def project_create(context, payload):
    """Create a project."""
    return IMPL.project_create(context, payload)


def project_update(context, project_ref, payload):
    """Update a project"""
    return IMPL.project_update(context, project_ref, payload)


###################

# role db methods

###################

def role_get_all(context):
    """Retrieve all roles."""
    return IMPL.role_get_all(context)


def role_get(context, role_id):
    """Retrieve details of a role."""
    return IMPL.role_get(context, role_id)


def role_create(context, payload):
    """Create a role."""
    return IMPL.role_create(context, payload)


def role_update(context, role_ref, payload):
    """Update a role"""
    return IMPL.role_update(context, role_ref, payload)


###################

# revoke_event db methods

###################

def revoke_event_get_all(context):
    """Retrieve all token revocation events."""
    return IMPL.revoke_event_get_all(context)


def revoke_event_get_by_audit(context, audit_id):
    """Retrieve details of a token revocation event."""
    return IMPL.revoke_event_get_by_audit(context, audit_id)


def revoke_event_get_by_user(context, user_id, issued_before):
    """Retrieve details of a token revocation event."""
    return IMPL.revoke_event_get_by_user(context, user_id, issued_before)


def revoke_event_create(context, payload):
    """Create a token revocation event."""
    return IMPL.revoke_event_create(context, payload)


def revoke_event_delete_by_audit(context, audit_id):
    """Delete a token revocation event."""
    return IMPL.revoke_event_delete_by_audit(context, audit_id)


def revoke_event_delete_by_user(context, user_id, issued_before):
    """Delete a token revocation event."""
    return IMPL.revoke_event_delete_by_user(context, user_id, issued_before)
