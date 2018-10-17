# Copyright 2018 Wind River
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import keyring

from collections import namedtuple
from keystoneauth1 import exceptions as keystone_exceptions
from keystoneclient import client as keystoneclient

from oslo_log import log as logging
from oslo_serialization import jsonutils

from dcorch.common import consts
from dcorch.common import exceptions
from dcorch.engine.sync_thread import SyncThread

LOG = logging.getLogger(__name__)


class IdentitySyncThread(SyncThread):
    """Manages tasks related to resource management for keystone."""

    def __init__(self, subcloud_engine):
        super(IdentitySyncThread, self).__init__(subcloud_engine)
        self.endpoint_type = consts.ENDPOINT_TYPE_IDENTITY
        self.sync_handler_map = {
            consts.RESOURCE_TYPE_IDENTITY_USERS:
                self.sync_identity_resource,
            consts.RESOURCE_TYPE_IDENTITY_USERS_PASSWORD:
                self.sync_identity_resource,
            consts.RESOURCE_TYPE_IDENTITY_ROLES:
                self.sync_identity_resource,
            consts.RESOURCE_TYPE_IDENTITY_PROJECTS:
                self.sync_identity_resource,
            consts.RESOURCE_TYPE_IDENTITY_PROJECT_ROLE_ASSIGNMENTS:
                self.sync_identity_resource,
        }
        # Since services may use unscoped tokens, it is essential to ensure
        # that users are replicated prior to assignment data (roles/projects)
        self.audit_resources = [
            consts.RESOURCE_TYPE_IDENTITY_USERS,
            consts.RESOURCE_TYPE_IDENTITY_ROLES,
            consts.RESOURCE_TYPE_IDENTITY_PROJECTS,
            consts.RESOURCE_TYPE_IDENTITY_PROJECT_ROLE_ASSIGNMENTS
        ]

        # For all the resource types, we need to filter out certain
        # resources
        self.filtered_audit_resources = {
            consts.RESOURCE_TYPE_IDENTITY_USERS:
                ['admin', 'mtce', 'heat_admin',
                 'cinder' + self.subcloud_engine.subcloud.region_name],
            consts.RESOURCE_TYPE_IDENTITY_ROLES:
                ['heat_stack_owner', 'heat_stack_user', 'ResellerAdmin'],
            consts.RESOURCE_TYPE_IDENTITY_PROJECTS:
                ['admin', 'services']
        }

        self.log_extra = {"instance": "{}/{}: ".format(
            self.subcloud_engine.subcloud.region_name, self.endpoint_type)}
        self.sc_ks_client = None
        self.initialize()
        LOG.info("IdentitySyncThread initialized", extra=self.log_extra)

    def initialize_sc_clients(self):
        super(IdentitySyncThread, self).initialize_sc_clients()
        if (not self.sc_ks_client and self.sc_admin_session):
            self.sc_ks_client = keystoneclient.Client(
                session=self.sc_admin_session,
                endpoint_type=consts.KS_ENDPOINT_INTERNAL,
                region_name=self.subcloud_engine.subcloud.region_name)

    def initialize(self):
        # Subcloud may be enabled a while after being added.
        # Keystone endpoints for the subcloud could be added in
        # between these 2 steps. Reinitialize the session to
        # get the most up-to-date service catalog.
        super(IdentitySyncThread, self).initialize()

        # We initialize a master version of the keystone client, and a
        # subcloud specific version
        self.m_ks_client = self.ks_client

        LOG.info("Identity session and clients initialized",
                 extra=self.log_extra)

    def sync_identity_resource(self, request, rsrc):
        self.initialize_sc_clients()
        # Invoke function with name format "operationtype_resourcetype"
        # For example: post_users()
        try:
            # If this sync is triggered by an audit, then the default
            # audit action is a CREATE instead of a POST Operation Type.
            # We therefore recognize those triggers and convert them to
            # POST operations
            operation_type = request.orch_job.operation_type
            rtype_role_assignments = \
                consts.RESOURCE_TYPE_IDENTITY_PROJECT_ROLE_ASSIGNMENTS
            if operation_type == consts.OPERATION_TYPE_CREATE:
                if (rsrc.resource_type == rtype_role_assignments):
                    operation_type = consts.OPERATION_TYPE_PUT
                else:
                    operation_type = consts.OPERATION_TYPE_POST

            func_name = operation_type + \
                "_" + rsrc.resource_type
            getattr(self, func_name)(request, rsrc)
        except AttributeError:
            LOG.error("{} not implemented for {}"
                      .format(operation_type,
                              rsrc.resource_type))
            raise exceptions.SyncRequestFailed
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.error("sync_identity_resource: {} is not reachable [{}]"
                      .format(self.subcloud_engine.subcloud.region_name,
                              str(e)), extra=self.log_extra)
            raise exceptions.SyncRequestTimeout
        except exceptions.SyncRequestFailed:
            raise
        except Exception as e:
            LOG.exception(e)
            raise exceptions.SyncRequestFailedRetry

    def post_users(self, request, rsrc):
        # Create this user on this subcloud
        user_dict = jsonutils.loads(request.orch_job.resource_info)
        if 'user' in user_dict.keys():
            user_dict = user_dict['user']

        # (NOTE: knasim-wrs): If the user create request contains
        # "default_project_id" or "domain_id" then we need to remove
        # both these fields, since it is highly unlikely that these
        # IDs would exist on the subcloud, i.e. the ID for the "services"
        # project on subcloud-X will be different to the ID for the
        # project on Central Region.
        # These fields are optional anyways since a subsequent role
        # assignment will give the same scoping
        #
        # If these do need to be synced in the future then
        # procure the project / domain list for this subcloud first
        # and use IDs from that.
        user_dict.pop('default_project_id', None)
        user_dict.pop('domain_id', None)
        username = user_dict.pop('name', None)  # compulsory
        if not username:
            LOG.error("Received user create request without required "
                      "'name' field", extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        password = user_dict.pop('password', None)  # compulsory
        if not password:
            # this user creation request may have been generated
            # from the Identity Audit, in which case this password
            # would not be present in the resource info. We will
            # attempt to retrieve it from Keyring, failing which
            # we cannot proceed.

            # TODO(knasim-wrs): Set Service as constant
            password = keyring.get_password('CGCS', username)
            if not password:
                LOG.error("Received user create request without required "
                          "'password' field and cannot retrieve from "
                          "Keyring either", extra=self.log_extra)
                raise exceptions.SyncRequestFailed

        # Create the user in the subcloud
        user_ref = self.sc_ks_client.users.create(
            name=username,
            domain=user_dict.pop('domain', None),
            password=password,
            email=user_dict.pop('email', None),
            description=user_dict.pop('description', None),
            enabled=user_dict.pop('enabled', True),
            project=user_dict.pop('project', None),
            default_project=user_dict.pop('default_project', None))

        user_ref_id = user_ref.id

        # Persist the subcloud resource.
        subcloud_rsrc_id = self.persist_db_subcloud_resource(rsrc.id,
                                                             user_ref_id)
        LOG.info("Created Keystone user {}:{} [{}]"
                 .format(rsrc.id, subcloud_rsrc_id, username),
                 extra=self.log_extra)

    def post_users_password(self, request, rsrc):
        # Update this user's password on this subcloud
        user_dict = jsonutils.loads(request.orch_job.resource_info)
        oldpw = user_dict.pop('original_password', None)
        newpw = user_dict.pop('password', None)
        if (not oldpw or not newpw):
            LOG.error("Received users password change request without "
                      "required original password or new password field",
                      extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        # NOTE (knasim-wrs): We can only update the password of the ADMIN
        # user, that is the one used to establish this subcloud session,
        # since the default behavior within the keystone client is to
        # take the user_id from within the client context (client.user_id)

        # user_id for this resource was passed in via URL and extracted
        # into the resource_id
        if (self.sc_ks_client.user_id == rsrc.id):
            self.sc_ks_client.users.update_password(oldpw, newpw)
            LOG.info("Updated password for user {}".format(rsrc.id),
                     extra=self.log_extra)

        else:
            LOG.error("User {} requested a modification to its password. "
                      "Can only self-modify for user {}. Consider updating "
                      "the password for {} using the Admin user"
                      .format(rsrc.id, self.sc_ks_client.user_id, rsrc.id))
            raise exceptions.SyncRequestFailed

    def patch_users(self, request, rsrc):
        # Update user reference on this subcloud
        user_update_dict = jsonutils.loads(request.orch_job.resource_info)
        if not user_update_dict.keys():
            LOG.error("Received user update request "
                      "without any update fields", extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        user_update_dict = user_update_dict['user']
        user_subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if not user_subcloud_rsrc:
            LOG.error("Unable to update user reference {}:{}, "
                      "cannot find equivalent Keystone user in subcloud."
                      .format(rsrc, user_update_dict),
                      extra=self.log_extra)
            return

        # instead of stowing the entire user reference or
        # retrieving it, we build an opaque wrapper for the
        # v3 User Manager, containing the ID field which is
        # needed to update this user reference
        UserReferenceWrapper = namedtuple('UserReferenceWrapper',
                                          'id')
        user_id = user_subcloud_rsrc.subcloud_resource_id
        original_user_ref = UserReferenceWrapper(id=user_id)

        # Update the user in the subcloud
        user_ref = self.sc_ks_client.users.update(
            original_user_ref,
            name=user_update_dict.pop('name', None),
            domain=user_update_dict.pop('domain', None),
            project=user_update_dict.pop('project', None),
            password=user_update_dict.pop('password', None),
            email=user_update_dict.pop('email', None),
            description=user_update_dict.pop('description', None),
            enabled=user_update_dict.pop('enabled', None),
            default_project=user_update_dict.pop('default_project', None))

        if (user_ref.id == user_id):
            LOG.info("Updated Keystone user: {}:{}"
                     .format(rsrc.id, user_ref.id), extra=self.log_extra)
        else:
            LOG.error("Unable to update Keystone user {}:{} for subcloud"
                      .format(rsrc.id, user_id), extra=self.log_extra)

    def delete_users(self, request, rsrc):
        # Delete user reference on this subcloud
        user_subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if not user_subcloud_rsrc:
            LOG.error("Unable to delete user reference {}, "
                      "cannot find equivalent Keystone user in subcloud."
                      .format(rsrc), extra=self.log_extra)
            return

        # instead of stowing the entire user reference or
        # retrieving it, we build an opaque wrapper for the
        # v3 User Manager, containing the ID field which is
        # needed to delete this user reference
        UserReferenceWrapper = namedtuple('UserReferenceWrapper',
                                          'id')
        user_id = user_subcloud_rsrc.subcloud_resource_id
        original_user_ref = UserReferenceWrapper(id=user_id)

        # Delete the user in the subcloud
        self.sc_ks_client.users.delete(original_user_ref)
        # Master Resource can be deleted only when all subcloud resources
        # are deleted along with corresponding orch_job and orch_requests.
        LOG.info("Keystone user {}:{} [{}] deleted"
                 .format(rsrc.id, user_subcloud_rsrc.id,
                         user_subcloud_rsrc.subcloud_resource_id),
                 extra=self.log_extra)
        user_subcloud_rsrc.delete()

    def post_projects(self, request, rsrc):
        # Create this project on this subcloud
        project_dict = jsonutils.loads(request.orch_job.resource_info)
        if 'project' in project_dict.keys():
            project_dict = project_dict['project']

        projectname = project_dict.pop('name', None)  # compulsory
        projectdomain = project_dict.pop('domain_id', 'default')  # compulsory
        if not projectname:
            LOG.error("Received project create request without required "
                      "'name' field", extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        # Create the project in the subcloud
        project_ref = self.sc_ks_client.projects.create(
            name=projectname,
            domain=projectdomain,
            description=project_dict.pop('description', None),
            enabled=project_dict.pop('enabled', True),
            parent=project_dict.pop('parent_id', None))

        project_ref_id = project_ref.id

        # Persist the subcloud resource.
        subcloud_rsrc_id = self.persist_db_subcloud_resource(rsrc.id,
                                                             project_ref_id)
        LOG.info("Created Keystone project {}:{} [{}]"
                 .format(rsrc.id, subcloud_rsrc_id, projectname),
                 extra=self.log_extra)

    def patch_projects(self, request, rsrc):
        # Update project on this subcloud
        project_update_dict = jsonutils.loads(request.orch_job.resource_info)
        if not project_update_dict.keys():
            LOG.error("Received project update request "
                      "without any update fields", extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        project_update_dict = project_update_dict['project']
        project_subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if not project_subcloud_rsrc:
            LOG.error("Unable to update project reference {}:{}, "
                      "cannot find equivalent Keystone project in subcloud."
                      .format(rsrc, project_update_dict),
                      extra=self.log_extra)
            return

        # instead of stowing the entire project reference or
        # retrieving it, we build an opaque wrapper for the
        # v3 ProjectManager, containing the ID field which is
        # needed to update this user reference
        ProjectReferenceWrapper = namedtuple('ProjectReferenceWrapper', 'id')
        proj_id = project_subcloud_rsrc.subcloud_resource_id
        original_proj_ref = ProjectReferenceWrapper(id=proj_id)

        # Update the project in the subcloud
        project_ref = self.sc_ks_client.projects.update(
            original_proj_ref,
            name=project_update_dict.pop('name', None),
            domain=project_update_dict.pop('domain_id', None),
            description=project_update_dict.pop('description', None),
            enabled=project_update_dict.pop('enabled', None))

        if (project_ref.id == proj_id):
            LOG.info("Updated Keystone project: {}:{}"
                     .format(rsrc.id, project_ref.id), extra=self.log_extra)
        else:
            LOG.error("Unable to update Keystone project {}:{} for subcloud"
                      .format(rsrc.id, proj_id), extra=self.log_extra)

    def delete_projects(self, request, rsrc):
        # Delete this project on this subcloud

        project_subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if not project_subcloud_rsrc:
            LOG.error("Unable to delete project reference {}, "
                      "cannot find equivalent Keystone project in subcloud."
                      .format(rsrc), extra=self.log_extra)
            return

        # instead of stowing the entire project reference or
        # retrieving it, we build an opaque wrapper for the
        # v3 ProjectManager, containing the ID field which is
        # needed to delete this project reference
        ProjectReferenceWrapper = namedtuple('ProjectReferenceWrapper', 'id')
        proj_id = project_subcloud_rsrc.subcloud_resource_id
        original_proj_ref = ProjectReferenceWrapper(id=proj_id)

        # Delete the project in the subcloud
        self.sc_ks_client.projects.delete(original_proj_ref)
        # Master Resource can be deleted only when all subcloud resources
        # are deleted along with corresponding orch_job and orch_requests.
        LOG.info("Keystone project {}:{} [{}] deleted"
                 .format(rsrc.id, project_subcloud_rsrc.id,
                         project_subcloud_rsrc.subcloud_resource_id),
                 extra=self.log_extra)
        project_subcloud_rsrc.delete()

    def post_roles(self, request, rsrc):
        # Create this role on this subcloud
        role_dict = jsonutils.loads(request.orch_job.resource_info)
        if 'role' in role_dict.keys():
            role_dict = role_dict['role']

        rolename = role_dict.pop('name', None)  # compulsory
        if not rolename:
            LOG.error("Received role create request without required "
                      "'name' field", extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        # Create the role in the subcloud
        role_ref = self.sc_ks_client.roles.create(
            name=rolename,
            domain=role_dict.pop('domain_id', None))

        role_ref_id = role_ref.id

        # Persist the subcloud resource.
        subcloud_rsrc_id = self.persist_db_subcloud_resource(rsrc.id,
                                                             role_ref_id)
        LOG.info("Created Keystone role {}:{} [{}]"
                 .format(rsrc.id, subcloud_rsrc_id, rolename),
                 extra=self.log_extra)

    def patch_roles(self, request, rsrc):
        # Update this role on this subcloud
        role_update_dict = jsonutils.loads(request.orch_job.resource_info)
        if not role_update_dict.keys():
            LOG.error("Received role update request "
                      "without any update fields", extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        role_update_dict = role_update_dict['role']
        role_subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if not role_subcloud_rsrc:
            LOG.error("Unable to update role reference {}:{}, "
                      "cannot find equivalent Keystone role in subcloud."
                      .format(rsrc, role_update_dict),
                      extra=self.log_extra)
            return

        # instead of stowing the entire role reference or
        # retrieving it, we build an opaque wrapper for the
        # v3 RoleManager, containing the ID field which is
        # needed to update this user reference
        RoleReferenceWrapper = namedtuple('RoleReferenceWrapper', 'id')
        role_id = role_subcloud_rsrc.subcloud_resource_id
        original_role_ref = RoleReferenceWrapper(id=role_id)

        # Update the role in the subcloud
        role_ref = self.sc_ks_client.roles.update(
            original_role_ref,
            name=role_update_dict.pop('name', None))

        if (role_ref.id == role_id):
            LOG.info("Updated Keystone role: {}:{}"
                     .format(rsrc.id, role_ref.id), extra=self.log_extra)
        else:
            LOG.error("Unable to update Keystone role {}:{} for subcloud"
                      .format(rsrc.id, role_id), extra=self.log_extra)

    def delete_roles(self, request, rsrc):
        # Delete this role on this subcloud

        role_subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if not role_subcloud_rsrc:
            LOG.error("Unable to delete role reference {}, "
                      "cannot find equivalent Keystone role in subcloud."
                      .format(rsrc), extra=self.log_extra)
            return

        # instead of stowing the entire role reference or
        # retrieving it, we build an opaque wrapper for the
        # v3 RoleManager, containing the ID field which is
        # needed to delete this role reference
        RoleReferenceWrapper = namedtuple('RoleReferenceWrapper', 'id')
        role_id = role_subcloud_rsrc.subcloud_resource_id
        original_role_ref = RoleReferenceWrapper(id=role_id)

        # Delete the role in the subcloud
        self.sc_ks_client.roles.delete(original_role_ref)
        # Master Resource can be deleted only when all subcloud resources
        # are deleted along with corresponding orch_job and orch_requests.
        LOG.info("Keystone role {}:{} [{}] deleted"
                 .format(rsrc.id, role_subcloud_rsrc.id,
                         role_subcloud_rsrc.subcloud_resource_id),
                 extra=self.log_extra)
        role_subcloud_rsrc.delete()

    def put_project_role_assignments(self, request, rsrc):
        # Assign this role to user on project on this subcloud
        resource_tags = rsrc.master_id.split('_')
        if len(resource_tags) < 3:
            LOG.error("Malformed resource tag {} expected to be in "
                      "format: ProjectID_UserID_RoleID."
                      .format(rsrc.id), extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        project_id = resource_tags[0]
        user_id = resource_tags[1]
        role_id = resource_tags[2]

        project_name = self.m_ks_client.projects.get(project_id).name
        user_name = self.m_ks_client.users.get(user_id).name
        role_name = self.m_ks_client.roles.get(role_id).name

        # Ensure that we have already synced the project, user and role
        # prior to syncing the assignment
        sc_role = None
        sc_role_list = self.sc_ks_client.roles.list()
        for role in sc_role_list:
            if role.name == role_name:
                sc_role = role
                break
        if not sc_role:
            LOG.error("Unable to assign role to user on project reference {}:"
                      "{}, cannot find equivalent Keystone Role in subcloud."
                      .format(rsrc, role_name),
                      extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        sc_proj = None
        sc_proj_list = self.sc_ks_client.projects.list()
        for proj in sc_proj_list:
            if proj.name == project_name:
                sc_proj = proj
                break
        if not sc_proj:
            LOG.error("Unable to assign role to user on project reference {}:"
                      "{}, cannot find equivalent Keystone Project in subcloud"
                      .format(rsrc, project_name),
                      extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        sc_user = None
        sc_user_list = self.sc_ks_client.users.list()
        for user in sc_user_list:
            if user.name == user_name:
                sc_user = user
                break
        if not sc_user:
            LOG.error("Unable to assign role to user on project reference {}:"
                      "{}, cannot find equivalent Keystone User in subcloud."
                      .format(rsrc, user_name),
                      extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        # Create role assignment
        self.sc_ks_client.roles.grant(
            sc_role,
            user=sc_user,
            project=sc_proj)
        role_ref = self.sc_ks_client.role_assignments.list(
            user=sc_user,
            project=sc_proj,
            role=sc_role)

        if role_ref:
            LOG.info("Added Keystone role assignment: {}:{}"
                     .format(rsrc.id, role_ref), extra=self.log_extra)
            # Persist the subcloud resource.
            sc_rid = sc_proj.id + '_' + sc_user.id + '_' + sc_role.id
            subcloud_rsrc_id = self.persist_db_subcloud_resource(rsrc.id,
                                                                 sc_rid)
            LOG.info("Created Keystone role assignment {}:{} [{}]"
                     .format(rsrc.id, subcloud_rsrc_id, sc_rid),
                     extra=self.log_extra)
        else:
            LOG.error("Unable to update Keystone role assignment {}:{} "
                      .format(rsrc.id, sc_role), extra=self.log_extra)

    def delete_project_role_assignments(self, request, rsrc):
        # Revoke this role for user on project on this subcloud

        # Ensure that we have already synced the project, user and role
        # prior to syncing the assignment
        assignment_subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if not assignment_subcloud_rsrc:
            LOG.error("Unable to delete assignment {}, "
                      "cannot find Keystone Role Assignment in subcloud."
                      .format(rsrc), extra=self.log_extra)
            return

        # resource_id is in format:
        # projectId_userId_roleId
        subcloud_rid = assignment_subcloud_rsrc.subcloud_resource_id
        resource_tags = subcloud_rid.split('_')
        if len(resource_tags) < 3:
            LOG.error("Malformed subcloud resource tag {} expected to be in "
                      "format: ProjectID_UserID_RoleID."
                      .format(assignment_subcloud_rsrc), extra=self.log_extra)
            assignment_subcloud_rsrc.delete()
            return

        project_id = resource_tags[0]
        user_id = resource_tags[1]
        role_id = resource_tags[2]

        # Revoke role assignment
        self.sc_ks_client.roles.revoke(
            role_id,
            user=user_id,
            project=project_id)

        role_ref = self.sc_ks_client.role_assignments.list(
            user=user_id,
            project=project_id,
            role=role_id)

        if (not role_ref):
            LOG.info("Deleted Keystone role assignment: {}:{}"
                     .format(rsrc.id, assignment_subcloud_rsrc),
                     extra=self.log_extra)
        else:
            LOG.error("Unable to delete Keystone role assignment {}:{} "
                      .format(rsrc.id, role_id), extra=self.log_extra)
        assignment_subcloud_rsrc.delete()

    # ---- Override common audit functions ----

    def _get_resource_audit_handler(self, resource_type, client):
        if resource_type == consts.RESOURCE_TYPE_IDENTITY_USERS:
            return self._get_users_resource(client)
        elif resource_type == consts.RESOURCE_TYPE_IDENTITY_ROLES:
            return self._get_roles_resource(client)
        elif resource_type == consts.RESOURCE_TYPE_IDENTITY_PROJECTS:
            return self._get_projects_resource(client)
        elif (resource_type ==
                consts.RESOURCE_TYPE_IDENTITY_PROJECT_ROLE_ASSIGNMENTS):
            return self._get_assignments_resource(client)
        else:
            LOG.error("Wrong resource type {}".format(resource_type),
                      extra=self.log_extra)
            return None

    def _get_users_resource(self, client):
        try:
            users = client.users.list()
            # NOTE (knasim-wrs): We need to filter out services users,
            # as some of these users may be for optional services
            # (such as Magnum, Murano etc) which will be picked up by
            # the Sync Audit and created on subclouds, later when these
            # optional services are enabled on the subcloud
            services = client.services.list()
            filtered_list = self.filtered_audit_resources[
                consts.RESOURCE_TYPE_IDENTITY_USERS]

            filtered_users = [user for user in users if
                              (all(user.name != service.name for
                                   service in services) and
                               all(user.name != filtered for
                                   filtered in filtered_list))]
            return filtered_users
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.info("User Audit: subcloud {} is not reachable [{}]"
                     .format(self.subcloud_engine.subcloud.region_name,
                             str(e)), extra=self.log_extra)
            # None will force skip of audit
            return None
        except Exception as e:
            LOG.exception(e)
            return None

    def _get_roles_resource(self, client):
        try:
            roles = client.roles.list()
            # Filter out system roles
            filtered_list = self.filtered_audit_resources[
                consts.RESOURCE_TYPE_IDENTITY_ROLES]

            filtered_roles = [role for role in roles if
                              (all(role.name != filtered for
                                   filtered in filtered_list))]
            return filtered_roles
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.info("Role Audit: subcloud {} is not reachable [{}]"
                     .format(self.subcloud_engine.subcloud.region_name,
                             str(e)), extra=self.log_extra)
            # None will force skip of audit
            return None
        except Exception as e:
            LOG.exception(e)
            return None

    def _get_projects_resource(self, client):
        try:
            projects = client.projects.list()
            # Filter out admin or services projects
            filtered_list = self.filtered_audit_resources[
                consts.RESOURCE_TYPE_IDENTITY_PROJECTS]

            filtered_projects = [project for project in projects if
                                 all(project.name != filtered for
                                     filtered in filtered_list)]
            return filtered_projects
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.info("Project Audit: subcloud {} is not reachable [{}]"
                     .format(self.subcloud_engine.subcloud.region_name,
                             str(e)), extra=self.log_extra)
            # None will force skip of audit
            return None
        except Exception as e:
            LOG.exception(e)
            return None

    def _get_assignments_resource(self, client):
        try:
            refactored_assignments = []
            # An assignment will only contain scope information,
            # i.e. the IDs for the Role, the User and the Project.
            # We need to furnish additional information such a
            # role, project and user names
            assignments = client.role_assignments.list()
            roles = self._get_roles_resource(client)
            projects = self._get_projects_resource(client)
            users = self._get_users_resource(client)
            for assignment in assignments:
                if 'project' not in assignment.scope:
                    # this is a domain scoped role, we don't care
                    # about syncing or auditing them for now
                    continue
                role_id = assignment.role['id']
                user_id = assignment.user['id']
                project_id = assignment.scope['project']['id']
                assignment_dict = {}

                for user in users:
                    if user.id == user_id:
                        assignment_dict['user'] = user
                        break
                else:
                    continue

                for role in roles:
                    if role.id == role_id:
                        assignment_dict['role'] = role
                        break
                else:
                    continue

                for project in projects:
                    if project.id == project_id:
                        assignment_dict['project'] = project
                        break
                else:
                    continue

                # The id of a Role Assigment is:
                # projectID_userID_roleID
                assignment_dict['id'] = "{}_{}_{}".format(
                    project_id, user_id, role_id)

                # Build an opaque object wrapper for this RoleAssignment
                refactored_assignment = namedtuple(
                    'RoleAssignmentWrapper',
                    assignment_dict.keys())(*assignment_dict.values())
                refactored_assignments.append(refactored_assignment)

            return refactored_assignments
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.info("Assignment Audit: subcloud {} is not reachable [{}]"
                     .format(self.subcloud_engine.subcloud.region_name,
                             str(e)), extra=self.log_extra)
            # None will force skip of audit
            return None
        except Exception as e:
            LOG.exception(e)
            return None

    def _same_identity_resource(self, m, sc):
        LOG.debug("master={}, subcloud={}".format(m, sc),
                  extra=self.log_extra)
        # Any Keystone resource can be system wide or domain scoped,
        # If the domains are different then these resources
        # are instantly unique since the same resource name can be
        # mapped in different domains
        return (m.name == sc.name and
                m.domain_id == sc.domain_id)

    def _same_assignment_resource(self, m, sc):
        LOG.debug("same_assignment master={}, subcloud={}".format(m, sc),
                  extra=self.log_extra)
        # For an assignment to be the same, all 3 of its role, project and
        # user information must match up
        is_same = (self._same_identity_resource(m.user, sc.user) and
                   self._same_identity_resource(m.role, sc.role) and
                   self._same_identity_resource(m.project, sc.project))
        return is_same

    def get_master_resources(self, resource_type):
        return self._get_resource_audit_handler(resource_type,
                                                self.m_ks_client)

    def get_subcloud_resources(self, resource_type):
        self.initialize_sc_clients()
        return self._get_resource_audit_handler(resource_type,
                                                self.sc_ks_client)

    def same_resource(self, resource_type, m_resource, sc_resource):
        if (resource_type ==
                consts.RESOURCE_TYPE_IDENTITY_PROJECT_ROLE_ASSIGNMENTS):
            return self._same_assignment_resource(m_resource, sc_resource)
        else:
            return self._same_identity_resource(m_resource, sc_resource)

    def get_resource_id(self, resource_type, resource):
        if hasattr(resource, 'master_id'):
            # If resource from DB, return master resource id
            # from master cloud
            return resource.master_id

        # Else, it is OpenStack resource retrieved from master cloud
        return resource.id

    def get_resource_info(self, resource_type,
                          resource, operation_type=None):
        rtype = consts.RESOURCE_TYPE_IDENTITY_PROJECT_ROLE_ASSIGNMENTS
        if (operation_type == consts.OPERATION_TYPE_CREATE and
                resource_type != rtype):
            # With the exception of role assignments, for all create
            # requests the resource_info needs to be extracted
            # from the master resource
            return jsonutils.dumps(resource._info)
        else:
            super(IdentitySyncThread, self).get_resource_info(
                resource_type, resource, operation_type)

    def audit_discrepancy(self, resource_type, m_resource, sc_resources):
        # It could be that the details are different
        # between master cloud and subcloud now.
        # Thus, delete the resource before creating it again.
        self.schedule_work(self.endpoint_type, resource_type,
                           self.get_resource_id(resource_type, m_resource),
                           consts.OPERATION_TYPE_DELETE)
        # Return true to try creating the resource again
        return True

    def map_subcloud_resource(self, resource_type, m_r, m_rsrc_db,
                              sc_resources):
        # Map an existing subcloud resource to an existing master resource.
        # If a mapping is created the function should return True.

        # Need to do this for all Identity resources (users, roles, projects)
        # as common resources would be created by application of the Puppet
        # manifest on the Subclouds and the Central Region should not try
        # to create these on the subclouds
        for sc_r in sc_resources:
            if self.same_resource(resource_type, m_r, sc_r):
                LOG.info(
                    "Mapping resource {} to existing subcloud resource {}"
                    .format(m_r, sc_r), extra=self.log_extra)
                self.persist_db_subcloud_resource(m_rsrc_db.id,
                                                  self.get_resource_id(
                                                      resource_type,
                                                      sc_r))
                return True
        return False
