# Copyright (c) 2015 Ericsson AB.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# Copyright (c) 2019-2022, 2024-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Implementation of SQLAlchemy backend.
"""

import sys

from oslo_db.sqlalchemy import enginefacade
from oslo_log import log as logging
from sqlalchemy import Table, MetaData
from sqlalchemy.sql import select

from dcdbsync.common import exceptions as exception
from dcdbsync.common.i18n import _

LOG = logging.getLogger(__name__)

_main_context_manager = None


def _get_main_context_manager():
    global _main_context_manager

    if not _main_context_manager:
        _main_context_manager = enginefacade.transaction_context()

    return _main_context_manager


_CONTEXT = None


def _get_context():
    global _CONTEXT
    if _CONTEXT is None:
        import threading

        _CONTEXT = threading.local()
    return _CONTEXT


class TableRegistry(object):
    def __init__(self):
        self.metadata = MetaData()

    def get(self, connection, tablename):
        try:
            table = self.metadata.tables[tablename]
        except KeyError:
            table = Table(tablename, self.metadata, autoload_with=connection)
        return table


registry = TableRegistry()


def get_read_connection():
    reader = _get_main_context_manager().reader
    return reader.connection.using(_get_context())


def get_write_connection():
    writer = _get_main_context_manager().writer
    return writer.connection.using(_get_context())


def row2dict(table, row):
    d = {}
    for c in table.columns:
        c_value = row[c.name]
        d[c.name] = c_value

    return d


def index2column(r_table, index_name):
    column = None
    for c in r_table.columns:
        if c.name == index_name:
            column = c
            break

    return column


def query(connection, table, index_name=None, index_value=None):
    r_table = registry.get(connection, table)

    if index_name and index_value:
        c = index2column(r_table, index_name)
        stmt = select([r_table]).where(c == index_value)
    else:
        stmt = select([r_table])

    records = []
    result = connection.execute(stmt)
    for row in result:
        # convert the row into a dictionary
        d = row2dict(r_table, row)
        records.append(d)

    return records


def insert(connection, table, data):
    r_table = registry.get(connection, table)
    stmt = r_table.insert()

    connection.execute(stmt, data)


def delete(connection, table, index_name, index_value):
    r_table = registry.get(connection, table)

    c = index2column(r_table, index_name)
    stmt = r_table.delete().where(c == index_value)
    connection.execute(stmt)


def update(connection, table, index_name, index_value, data):
    r_table = registry.get(connection, table)

    c = index2column(r_table, index_name)
    stmt = r_table.update().where(c == index_value).values(data)
    connection.execute(stmt)


def get_backend():
    """The backend is this module itself."""
    return sys.modules[__name__]


def is_admin_context(context):
    """Indicate if the request context is an administrator."""
    if not context:
        LOG.warning(_("Use of empty request context is deprecated"), DeprecationWarning)
        raise Exception("die")
    return context.is_admin


def is_user_context(context):
    """Indicate if the request context is a normal user."""
    if not context:
        return False
    if context.is_admin:
        return False
    if not context.user or not context.project:
        return False
    return True


def require_admin_context(f):
    """Decorator to require admin request context.

    The first argument to the wrapped function must be the context.
    """

    def wrapper(*args, **kwargs):
        if not is_admin_context(args[0]):
            raise exception.AdminRequired()
        return f(*args, **kwargs)

    return wrapper


def require_context(f):
    """Decorator to require *any* user or admin context.

    This does no authorization for user or project access matching, see
    :py:func:`authorize_project_context` and
    :py:func:`authorize_user_context`.
    The first argument to the wrapped function must be the context.

    """

    def wrapper(*args, **kwargs):
        if not is_admin_context(args[0]) and not is_user_context(args[0]):
            raise exception.NotAuthorized()
        return f(*args, **kwargs)

    return wrapper


###################

# identity users

###################


@require_context
def user_get_all(context):
    result = []

    with get_read_connection() as conn:
        # user table
        users = query(conn, "user")
        # local_user table
        local_users = query(conn, "local_user")
        # password table
        passwords = query(conn, "password")

    for local_user in local_users:
        user = {"user": user for user in users if user["id"] == local_user["user_id"]}
        user_passwords = {
            "password": [
                password
                for password in passwords
                if password["local_user_id"] == local_user["id"]
            ]
        }
        user_consolidated = dict(
            list({"local_user": local_user}.items())
            + list(user.items())
            + list(user_passwords.items())
        )
        result.append(user_consolidated)

    return result


@require_context
def user_get(context, user_id):
    result = {}

    with get_read_connection() as conn:
        # user table
        users = query(conn, "user", "id", user_id)
        if not users:
            raise exception.UserNotFound(user_id=user_id)
        result["user"] = users[0]
        # local_user table
        local_users = query(conn, "local_user", "user_id", user_id)
        if not local_users:
            raise exception.UserNotFound(user_id=user_id)
        result["local_user"] = local_users[0]
        # password table
        result["password"] = []
        if result["local_user"]:
            result["password"] = query(
                conn, "password", "local_user_id", result["local_user"].get("id")
            )

    return result


@require_admin_context
def user_create(context, payload):
    users = [payload["user"]]
    local_users = [payload["local_user"]]
    passwords = payload["password"]

    with get_write_connection() as conn:
        insert(conn, "user", users)

        # ignore auto generated id
        for local_user in local_users:
            local_user.pop("id", None)
        insert(conn, "local_user", local_users)

        inserted_local_users = query(
            conn, "local_user", "user_id", payload["local_user"]["user_id"]
        )

        if not inserted_local_users:
            raise exception.UserNotFound(user_id=payload["local_user"]["user_id"])

        for password in passwords:
            # ignore auto generated id
            password.pop("id", None)
            password["local_user_id"] = inserted_local_users[0]["id"]

        insert(conn, "password", passwords)

    return user_get(context, payload["user"]["id"])


@require_admin_context
def user_update(context, user_id, payload):
    with get_write_connection() as conn:
        # user table
        table = "user"
        new_user_id = user_id
        if table in payload:
            user_options = []
            user = payload[table]
            new_user_id = user.get("id")
            if user_id != new_user_id:
                # Delete the user_option record referencing to the old user_id
                # to avoid the foreign key constraint violation when we update
                # the user table in the next step.
                user_options = query(conn, "user_option", "user_id", user_id)
                delete(conn, "user_option", "user_id", user_id)
            else:
                user.pop("id", None)
            update(conn, table, "id", user_id, user)
            if user_options:
                for user_option in user_options:
                    user_option["user_id"] = new_user_id
                insert(conn, "user_option", user_option)
        # local_user table
        table = "local_user"
        if table in payload:
            local_user = payload[table]
            # ignore auto generated id
            local_user.pop("id", None)
            update(conn, table, "user_id", user_id, local_user)
            updated_local_users = query(conn, table, "user_id", new_user_id)

            if not updated_local_users:
                raise exception.UserNotFound(user_id=payload[table]["user_id"])
            # password table
            table = "password"
            if table in payload:
                delete(conn, table, "local_user_id", updated_local_users[0]["id"])
                passwords = payload[table]
                for password in passwords:
                    # ignore auto generated ids
                    password.pop("id", None)
                    password["local_user_id"] = updated_local_users[0]["id"]
                    insert(conn, table, password)
        # Need to update the actor_id in assignment and system_assignment
        # along with the user_id in user_group_membership tables if the
        # user id is updated
        if user_id != new_user_id:
            assignment = {"actor_id": new_user_id}
            user_group_membership = {"user_id": new_user_id}
            update(conn, "assignment", "actor_id", user_id, assignment)
            update(conn, "system_assignment", "actor_id", user_id, assignment)
            update(
                conn, "user_group_membership", "user_id", user_id, user_group_membership
            )

    return user_get(context, new_user_id)


###################

# identity groups

###################


@require_context
def group_get_all(context):
    result = []

    with get_read_connection() as conn:
        # groups table
        groups = query(conn, "group")
        # user_group_membership table
        user_group_memberships = query(conn, "user_group_membership")

    for group in groups:
        local_user_id_list = [
            membership["user_id"]
            for membership in user_group_memberships
            if membership["group_id"] == group["id"]
        ]
        local_user_id_list.sort()
        local_user_ids = {"local_user_ids": local_user_id_list}
        group_consolidated = dict(
            list({"group": group}.items()) + list(local_user_ids.items())
        )
        result.append(group_consolidated)

    return result


@require_context
def group_get(context, group_id):
    result = {}

    with get_read_connection() as conn:
        local_user_id_list = []

        # group table
        group = query(conn, "group", "id", group_id)
        if not group:
            raise exception.GroupNotFound(group_id=group_id)
        result["group"] = group[0]

        # user_group_membership table
        user_group_memberships = query(
            conn, "user_group_membership", "group_id", group_id
        )

        for user_group_membership in user_group_memberships:
            local_user = query(
                conn, "local_user", "user_id", user_group_membership.get("user_id")
            )
            if not local_user:
                raise exception.UserNotFound(
                    user_id=user_group_membership.get("user_id")
                )
            local_user_id_list.append(local_user[0]["user_id"])

        result["local_user_ids"] = local_user_id_list

    return result


@require_admin_context
def group_create(context, payload):
    group = payload["group"]
    local_user_ids = payload["local_user_ids"]
    with get_write_connection() as conn:

        insert(conn, "group", group)

        for local_user_id in local_user_ids:
            user_group_membership = {"user_id": local_user_id, "group_id": group["id"]}
            insert(conn, "user_group_membership", user_group_membership)

    return group_get(context, payload["group"]["id"])


@require_admin_context
def group_update(context, group_id, payload):
    with get_write_connection() as conn:
        new_group_id = group_id
        if "group" in payload and "local_user_ids" in payload:
            group = payload["group"]
            new_group_id = group.get("id")
            # local_user_id_list is a sorted list of user IDs that
            # belong to this group
            local_user_id_list = payload["local_user_ids"]
            user_group_memberships = query(
                conn, "user_group_membership", "group_id", group_id
            )
            existing_user_list = [
                user_group_membership["user_id"]
                for user_group_membership in user_group_memberships
            ]
            existing_user_list.sort()
            deleted = False
            # Foreign key constraint exists on 'group_id' of user_group_membership
            # table and 'id' of group table. So delete user group membership records
            # before updating group if groups IDs are different.
            # Alternatively, if there is a discrepency in the user group memberships,
            # delete and re-create them
            if (group_id != new_group_id) or (local_user_id_list != existing_user_list):
                delete(conn, "user_group_membership", "group_id", group_id)
                deleted = True
            # Update group table
            update(conn, "group", "id", group_id, group)

            if deleted:
                for local_user_id in local_user_id_list:
                    item = {"user_id": local_user_id, "group_id": new_group_id}
                    insert(conn, "user_group_membership", item)

        # Need to update the actor_id in assignment and system_assignment
        # tables if the group id is updated
        if group_id != new_group_id:
            assignment = {"actor_id": new_group_id}
            update(conn, "assignment", "actor_id", group_id, assignment)
            update(conn, "system_assignment", "actor_id", group_id, assignment)

    return group_get(context, new_group_id)


###################

# identity projects

###################


@require_context
def project_get_all(context):
    result = []

    with get_read_connection() as conn:
        # project table
        projects = query(conn, "project")

    for project in projects:
        project_consolidated = {"project": project}
        result.append(project_consolidated)

    return result


@require_context
def project_get(context, project_id):
    result = {}

    with get_read_connection() as conn:
        # project table
        projects = query(conn, "project", "id", project_id)
        if not projects:
            raise exception.ProjectNotFound(project_id=project_id)
        result["project"] = projects[0]

    return result


@require_admin_context
def project_create(context, payload):
    projects = [payload["project"]]

    with get_write_connection() as conn:
        insert(conn, "project", projects)

    return project_get(context, payload["project"]["id"])


@require_admin_context
def project_update(context, project_id, payload):
    with get_write_connection() as conn:
        # project table
        table = "project"
        new_project_id = project_id
        if table in payload:
            domain_ref_projects = []
            parent_ref_projects = []
            domain_ref_users = []
            domain_ref_local_users = []
            project = payload[table]
            new_project_id = project.get("id")
            if project_id != new_project_id:
                domain_ref_projects = query(conn, "project", "domain_id", project_id)
                delete(conn, "project", "domain_id", project_id)
                parent_ref_projects = query(conn, "project", "parent_id", project_id)
                delete(conn, "project", "parent_id", project_id)
                # For user table: CONSTRAINT `user_ibfk_1`
                # FOREIGN KEY(`domain_id`) REFERENCES `project`(`id`)
                domain_ref_users = query(conn, "user", "domain_id", project_id)
                domain_ref_local_users = query(
                    conn, "local_user", "domain_id", project_id
                )
                delete(conn, "user", "domain_id", project_id)

            # Update project table
            update(conn, table, "id", project_id, project)

            # Update saved records from project table and insert them back
            if domain_ref_projects:
                for domain_ref_project in domain_ref_projects:
                    domain_ref_project["domain_id"] = new_project_id
                    if domain_ref_project["parent_id"] == project_id:
                        domain_ref_project["parent_id"] = new_project_id
                insert(conn, "project", domain_ref_projects)
            if parent_ref_projects:
                for parent_ref_project in parent_ref_projects:
                    parent_ref_project["parent_id"] = new_project_id
                    if parent_ref_project["domain_id"] == project_id:
                        parent_ref_project["domain_id"] = new_project_id
                insert(conn, "project", parent_ref_projects)
            if domain_ref_users:
                for domain_ref_user in domain_ref_users:
                    domain_ref_user["domain_id"] = new_project_id
                insert(conn, "user", domain_ref_users)
            if domain_ref_local_users:
                for domain_ref_local_user in domain_ref_local_users:
                    domain_ref_local_user["domain_id"] = new_project_id
                insert(conn, "local_user", domain_ref_local_users)

        # Need to update the target_id in assignment table
        # if the project id is updated
        if project_id != new_project_id:
            table = "assignment"
            assignment = {"target_id": new_project_id}
            update(conn, table, "target_id", project_id, assignment)

    return project_get(context, new_project_id)


###################

# identity roles

###################


@require_context
def role_get_all(context):
    result = []

    with get_read_connection() as conn:
        # role table
        roles = query(conn, "role")

    for role in roles:
        role_consolidated = {"role": role}
        result.append(role_consolidated)

    return result


@require_context
def role_get(context, role_id):
    result = {}

    with get_read_connection() as conn:
        # role table
        roles = query(conn, "role", "id", role_id)
        if not roles:
            raise exception.RoleNotFound(role_id=role_id)
        result["role"] = roles[0]

    return result


@require_admin_context
def role_create(context, payload):
    roles = [payload["role"]]

    with get_write_connection() as conn:
        insert(conn, "role", roles)

    return role_get(context, payload["role"]["id"])


@require_admin_context
def role_update(context, role_id, payload):
    with get_write_connection() as conn:
        # role table
        table = "role"
        new_role_id = role_id
        if table in payload:
            prior_roles = []
            implied_roles = []
            role_options = []
            role = payload[table]
            new_role_id = role.get("id")
            if role_id != new_role_id:
                # implied_role table has foreign key references to role table.
                # The foreign key references are on DELETE CASCADE only. To
                # avoid foreign key constraints violation, save these records
                # from implied_role table, delete them, update role table,
                # update and insert them back after role table is updated.
                prior_roles = query(conn, "implied_role", "prior_role_id", role_id)
                delete(conn, "implied_role", "prior_role_id", role_id)
                implied_roles = query(conn, "implied_role", "implied_role_id", role_id)
                delete(conn, "implied_role", "implied_role_id", role_id)
                # Delete the role_option record referencing to the old role_id
                # to avoid the foreign key constraint violation when we update
                # the role table in the next step.
                role_options = query(conn, "role_option", "role_id", role_id)
                delete(conn, "role_option", "role_id", role_id)
            else:
                role.pop("id", None)
            # Update role table
            update(conn, table, "id", role_id, role)
            # Update saved records from implied_role table and insert them back
            if prior_roles:
                for prior_role in prior_roles:
                    prior_role["prior_role_id"] = new_role_id
                insert(conn, "implied_role", prior_roles)
            if implied_roles:
                for implied_role in implied_roles:
                    implied_role["implied_role_id"] = new_role_id
                insert(conn, "implied_role", implied_roles)
            if role_options:
                for role_option in role_options:
                    role_option["role_id"] = new_role_id
                insert(conn, "role_option", role_option)

        # Need to update the role_id in assignment and system_assignment tables
        # if the role id is updated
        if role_id != new_role_id:
            assignment = {"role_id": new_role_id}
            update(conn, "assignment", "role_id", role_id, assignment)
            update(conn, "system_assignment", "role_id", role_id, assignment)

    return role_get(context, new_role_id)


##################################

# identity token revocation events

##################################


@require_context
def revoke_event_get_all(context):
    result = []

    with get_read_connection() as conn:
        # revocation_event table
        revoke_events = query(conn, "revocation_event")

    for revoke_event in revoke_events:
        revoke_event_consolidated = {"revocation_event": revoke_event}
        result.append(revoke_event_consolidated)

    return result


@require_context
def revoke_event_get_by_audit(context, audit_id):
    result = {}

    with get_read_connection() as conn:
        # revocation_event table
        revoke_events = query(conn, "revocation_event", "audit_id", audit_id)
        if not revoke_events:
            raise exception.RevokeEventNotFound()
        result["revocation_event"] = revoke_events[0]

    return result


@require_context
def revoke_event_get_by_user(context, user_id, issued_before):
    result = {}

    with get_read_connection() as conn:
        # revocation_event table
        events = query(conn, "revocation_event", "user_id", user_id)
    revoke_events = [
        event for event in events if str(event["issued_before"]) == issued_before
    ]
    if not revoke_events:
        raise exception.RevokeEventNotFound()
    result["revocation_event"] = revoke_events[0]

    return result


@require_admin_context
def revoke_event_create(context, payload):
    revoke_event = payload["revocation_event"]
    # ignore auto generated id
    revoke_event.pop("id", None)

    revoke_events = [revoke_event]

    with get_write_connection() as conn:
        insert(conn, "revocation_event", revoke_events)

    result = {}
    if revoke_event.get("audit_id") is not None:
        result = revoke_event_get_by_audit(context, revoke_event.get("audit_id"))
    elif (revoke_event.get("user_id") is not None) and (
        revoke_event.get("issued_before") is not None
    ):
        result = revoke_event_get_by_user(
            context, revoke_event.get("user_id"), revoke_event.get("issued_before")
        )
    return result


@require_admin_context
def revoke_event_delete_by_audit(context, audit_id):
    with get_write_connection() as conn:
        delete(conn, "revocation_event", "audit_id", audit_id)


@require_admin_context
def revoke_event_delete_by_user(context, user_id, issued_before):
    result = revoke_event_get_by_user(context, user_id, issued_before)
    event_id = result["revocation_event"]["id"]
    with get_write_connection() as conn:
        delete(conn, "revocation_event", "id", event_id)
