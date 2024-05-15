# Copyright (c) 2018-2022, 2024 Wind River Systems, Inc.
# All Rights Reserved.
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

import base64
from collections import namedtuple

from keystoneauth1 import exceptions as keystone_exceptions
from oslo_log import log as logging
from oslo_serialization import jsonutils

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack import sdk_platform as sdk
from dcdbsync.dbsyncclient import exceptions as dbsync_exceptions
from dcorch.common import consts
from dcorch.common import exceptions
from dcorch.engine.sync_thread import SyncThread
from dcorch.objects import resource

LOG = logging.getLogger(__name__)


class IdentitySyncThread(SyncThread):
    """Manages tasks related to resource management for keystone."""

    def __init__(self, subcloud_name, endpoint_type=None, engine_id=None):
        super(IdentitySyncThread, self).__init__(subcloud_name,
                                                 endpoint_type=endpoint_type,
                                                 engine_id=engine_id)
        self.region_name = subcloud_name
        if not self.endpoint_type:
            self.endpoint_type = dccommon_consts.ENDPOINT_TYPE_IDENTITY
        self.sync_handler_map = {
            consts.RESOURCE_TYPE_IDENTITY_USERS:
                self.sync_identity_resource,
            consts.RESOURCE_TYPE_IDENTITY_GROUPS:
                self.sync_identity_resource,
            consts.RESOURCE_TYPE_IDENTITY_USERS_PASSWORD:
                self.sync_identity_resource,
            consts.RESOURCE_TYPE_IDENTITY_ROLES:
                self.sync_identity_resource,
            consts.RESOURCE_TYPE_IDENTITY_PROJECTS:
                self.sync_identity_resource,
            consts.RESOURCE_TYPE_IDENTITY_PROJECT_ROLE_ASSIGNMENTS:
                self.sync_identity_resource,
            consts.RESOURCE_TYPE_IDENTITY_TOKEN_REVOKE_EVENTS:
                self.sync_identity_resource,
            consts.RESOURCE_TYPE_IDENTITY_TOKEN_REVOKE_EVENTS_FOR_USER:
                self.sync_identity_resource,
        }

        self.audit_resources = [
            consts.RESOURCE_TYPE_IDENTITY_USERS,
            consts.RESOURCE_TYPE_IDENTITY_GROUPS,
            consts.RESOURCE_TYPE_IDENTITY_PROJECTS,
            consts.RESOURCE_TYPE_IDENTITY_ROLES,
            consts.RESOURCE_TYPE_IDENTITY_PROJECT_ROLE_ASSIGNMENTS,
            consts.RESOURCE_TYPE_IDENTITY_TOKEN_REVOKE_EVENTS,
            consts.RESOURCE_TYPE_IDENTITY_TOKEN_REVOKE_EVENTS_FOR_USER
        ]

        # For all the resource types, we need to filter out certain
        # resources
        self.filtered_audit_resources = {
            consts.RESOURCE_TYPE_IDENTITY_USERS:
                ['dcdbsync', 'dcorch', 'heat_admin', 'smapi',
                 'fm', 'cinder' + self.region_name],
            consts.RESOURCE_TYPE_IDENTITY_ROLES:
                ['heat_stack_owner', 'heat_stack_user', 'ResellerAdmin'],
            consts.RESOURCE_TYPE_IDENTITY_PROJECTS:
                [],
            consts.RESOURCE_TYPE_IDENTITY_GROUPS:
                []
        }

        self.log_extra = {"instance": "{}/{}: ".format(
            self.region_name, self.endpoint_type)}
        LOG.info("IdentitySyncThread initialized", extra=self.log_extra)

    @staticmethod
    def get_os_client(region):
        try:
            os_client = sdk.OpenStackDriver(
                region_name=region,
                region_clients=['dbsync'])
        except Exception as e:
            LOG.error("Failed to get os_client for region {} {}."
                      .format(region, str(e)))
            raise e
        return os_client

    def get_ks_client(self, region):
        return self.get_os_client(region).keystone_client.keystone_client

    def get_dbs_client(self, region):
        return self.get_os_client(region).dbsync_client

    def _initial_sync_users(self, m_users, sc_users):
        # Particularly sync users with same name but different ID.  admin,
        # sysinv, and dcmanager users are special cases as the id's will match
        # (as this is forced during the subcloud deploy) but the details will
        # not so we still need to sync them here.
        m_client = self.get_dbs_client(self.master_region_name).identity_user_manager
        sc_client = self.get_dbs_client(self.region_name).identity_user_manager

        for m_user in m_users:
            for sc_user in sc_users:
                if (m_user.local_user.name == sc_user.local_user.name and
                        m_user.domain_id == sc_user.domain_id and
                        (m_user.id != sc_user.id or
                         sc_user.local_user.name in
                         [dccommon_consts.ADMIN_USER_NAME,
                          dccommon_consts.SYSINV_USER_NAME,
                          dccommon_consts.DCMANAGER_USER_NAME])):
                    user_records = m_client.user_detail(m_user.id)
                    if not user_records:
                        LOG.error("No data retrieved from master cloud for"
                                  " user {} to update its equivalent in"
                                  " subcloud.".format(m_user.id))
                        raise exceptions.SyncRequestFailed
                    # update the user by pushing down the DB records to
                    # subcloud
                    try:
                        user_ref = sc_client.update_user(sc_user.id,
                                                         user_records)
                    # Retry once if unauthorized
                    except dbsync_exceptions.Unauthorized as e:
                        LOG.info("Update user {} request failed for {}: {}."
                                 .format(sc_user.id,
                                         self.region_name, str(e)))
                        # Clear the cache so that the old token will not be validated
                        sdk.OpenStackDriver.delete_region_clients(self.region_name)
                        # Retry with a new token
                        sc_client = self.get_dbs_client(
                            self.region_name).identity_user_manager
                        user_ref = sc_client.update_user(sc_user.id,
                                                         user_records)
                    if not user_ref:
                        LOG.error("No user data returned when updating user {}"
                                  " in subcloud.".format(sc_user.id))
                        raise exceptions.SyncRequestFailed

    def _initial_sync_groups(self, m_groups, sc_groups):
        # Particularly sync groups with same name but different ID.
        m_client = self.get_dbs_client(
            self.master_region_name).identity_group_manager
        sc_client = self.get_dbs_client(self.region_name).identity_group_manager

        for m_group in m_groups:
            for sc_group in sc_groups:
                if (m_group.name == sc_group.name and
                        m_group.domain_id == sc_group.domain_id and
                        m_group.id != sc_group.id):
                    group_records = m_client.group_detail(m_group.id)
                    if not group_records:
                        LOG.error("No data retrieved from master cloud for"
                                  " group {} to update its equivalent in"
                                  " subcloud.".format(m_group.id))
                        raise exceptions.SyncRequestFailed
                    # update the group by pushing down the DB records to
                    # subcloud
                    try:
                        group_ref = sc_client.update_group(sc_group.id,
                                                           group_records)
                    # Retry once if unauthorized
                    except dbsync_exceptions.Unauthorized as e:
                        LOG.info("Update group {} request failed for {}: {}."
                                 .format(sc_group.id,
                                         self.region_name, str(e)))
                        # Clear the cache so that the old token will not be validated
                        sdk.OpenStackDriver.delete_region_clients(self.region_name)
                        sc_client = self.get_dbs_client(
                            self.region_name).identity_group_manager
                        group_ref = sc_client.update_group(sc_group.id,
                                                           group_records)

                    if not group_ref:
                        LOG.error("No group data returned when updating"
                                  " group {} in subcloud.".
                                  format(sc_group.id))
                        raise exceptions.SyncRequestFailed

    def _initial_sync_projects(self, m_projects, sc_projects):
        # Particularly sync projects with same name but different ID.
        m_client = self.get_dbs_client(self.master_region_name).project_manager
        sc_client = self.get_dbs_client(self.region_name).project_manager

        for m_project in m_projects:
            for sc_project in sc_projects:
                if (m_project.name == sc_project.name and
                        m_project.domain_id == sc_project.domain_id and
                        m_project.id != sc_project.id):
                    project_records = m_client.project_detail(m_project.id)
                    if not project_records:
                        LOG.error("No data retrieved from master cloud for"
                                  " project {} to update its equivalent in"
                                  " subcloud.".format(m_project.id))
                        raise exceptions.SyncRequestFailed
                    # update the project by pushing down the DB records to
                    # subcloud
                    try:
                        project_ref = sc_client.update_project(sc_project.id,
                                                               project_records)
                    # Retry once if unauthorized
                    except dbsync_exceptions.Unauthorized as e:
                        LOG.info("Update project {} request failed for {}: {}."
                                 .format(sc_project.id,
                                         self.region_name, str(e)))
                        # Clear the cache so that the old token will not be validated
                        sdk.OpenStackDriver.delete_region_clients(self.region_name)
                        sc_client = self.get_dbs_client(
                            self.region_name).project_manager
                        project_ref = sc_client.update_project(sc_project.id,
                                                               project_records)

                    if not project_ref:
                        LOG.error("No project data returned when updating"
                                  " project {} in subcloud.".
                                  format(sc_project.id))
                        raise exceptions.SyncRequestFailed

    def _initial_sync_roles(self, m_roles, sc_roles):
        # Particularly sync roles with same name but different ID
        m_client = self.get_dbs_client(self.master_region_name).role_manager
        sc_client = self.get_dbs_client(self.region_name).role_manager

        for m_role in m_roles:
            for sc_role in sc_roles:
                if (m_role.name == sc_role.name and
                        m_role.domain_id == sc_role.domain_id and
                        m_role.id != sc_role.id):
                    role_record = m_client.role_detail(m_role.id)
                    if not role_record:
                        LOG.error("No data retrieved from master cloud for"
                                  " role {} to update its equivalent in"
                                  " subcloud.".format(m_role.id))
                        raise exceptions.SyncRequestFailed
                    # update the role by pushing down the DB records to
                    # subcloud
                    try:
                        role_ref = sc_client.update_role(sc_role.id,
                                                         role_record)
                    # Retry once if unauthorized
                    except dbsync_exceptions.Unauthorized as e:
                        LOG.info("Update role {} request failed for {}: {}."
                                 .format(sc_role.id,
                                         self.region_name, str(e)))
                        # Clear the cache so that the old token will not be validated
                        sdk.OpenStackDriver.delete_region_clients(self.region_name)
                        sc_client = self.get_dbs_client(
                            self.region_name).role_manager
                        role_ref = sc_client.update_role(sc_role.id,
                                                         role_record)

                    if not role_ref:
                        LOG.error("No role data returned when updating role {}"
                                  " in subcloud {}."
                                  .format(sc_role.id, self.region_name))
                        raise exceptions.SyncRequestFailed

    def initial_sync(self):
        # Service users and projects are created at deployment time. They exist
        # before dcorch starts to audit resources. Later on when dcorch audits
        # and sync them over(including their IDs) to the subcloud, running
        # services at the subcloud with tokens issued before their ID are
        # changed will get user/group/project not found error since their IDs are
        # changed. This will continue until their tokens expire in up to
        # 1 hour. Before that these services basically stop working.
        # By an initial synchronization on existing users/groups/projects,
        # synchronously followed by a fernet keys synchronization, existing
        # tokens at subcloud are revoked and services are forced to
        # re-authenticate to get new tokens. This significantly decreases
        # service recovery time at subcloud.

        # get users from master cloud
        m_users = self.get_cached_master_resources(
            consts.RESOURCE_TYPE_IDENTITY_USERS)

        if not m_users:
            LOG.error("No users returned from {}".
                      format(dccommon_consts.VIRTUAL_MASTER_CLOUD))
            raise exceptions.SyncRequestFailed

        # get users from the subcloud
        sc_users = self.get_subcloud_resources(
            consts.RESOURCE_TYPE_IDENTITY_USERS)

        if not sc_users:
            LOG.error("No users returned from subcloud {}".
                      format(self.region_name))
            raise exceptions.SyncRequestFailed

        self._initial_sync_users(m_users, sc_users)

        # get groups from master cloud
        m_groups = self.get_cached_master_resources(
            consts.RESOURCE_TYPE_IDENTITY_GROUPS)

        if not m_groups:
            LOG.info("No groups returned from {}".
                     format(dccommon_consts.VIRTUAL_MASTER_CLOUD))

        # get groups from the subcloud
        sc_groups = self.get_subcloud_resources(
            consts.RESOURCE_TYPE_IDENTITY_GROUPS)

        if not sc_groups:
            LOG.info("No groups returned from subcloud {}".
                     format(self.region_name))

        if m_groups and sc_groups:
            self._initial_sync_groups(m_groups, sc_groups)

        # get projects from master cloud
        m_projects = self.get_cached_master_resources(
            consts.RESOURCE_TYPE_IDENTITY_PROJECTS)

        if not m_projects:
            LOG.error("No projects returned from {}".
                      format(dccommon_consts.VIRTUAL_MASTER_CLOUD))
            raise exceptions.SyncRequestFailed

        # get projects from the subcloud
        sc_projects = self.get_subcloud_resources(
            consts.RESOURCE_TYPE_IDENTITY_PROJECTS)

        if not sc_projects:
            LOG.error("No projects returned from subcloud {}".
                      format(self.region_name))
            raise exceptions.SyncRequestFailed

        self._initial_sync_projects(m_projects, sc_projects)

        # get roles from master cloud
        m_roles = self.get_cached_master_resources(
            consts.RESOURCE_TYPE_IDENTITY_ROLES)

        if not m_roles:
            LOG.error("No roles returned from {}".
                      format(dccommon_consts.VIRTUAL_MASTER_CLOUD))
            raise exceptions.SyncRequestFailed

        # get roles from the subcloud
        sc_roles = self.get_subcloud_resources(
            consts.RESOURCE_TYPE_IDENTITY_ROLES)

        if not sc_roles:
            LOG.error("No roles returned from subcloud {}".
                      format(self.region_name))
            raise exceptions.SyncRequestFailed

        self._initial_sync_roles(m_roles, sc_roles)

        # Return True if no exceptions
        return True

    def sync_identity_resource(self, request, rsrc):
        # Invoke function with name format "operationtype_resourcetype"
        # For example: post_users()
        try:
            # If this sync is triggered by an audit, then the default
            # audit action is a CREATE instead of a POST Operation Type.
            # We therefore recognize those triggers and convert them to
            # POST operations
            operation_type = request.orch_job.operation_type
            if operation_type == consts.OPERATION_TYPE_CREATE:
                operation_type = consts.OPERATION_TYPE_POST

            func_name = operation_type + "_" + rsrc.resource_type
            getattr(self, func_name)(request, rsrc)
        except AttributeError:
            LOG.error("{} not implemented for {}"
                      .format(request.orch_job.operation_type,
                              rsrc.resource_type))
            raise exceptions.SyncRequestFailed
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure,
                dbsync_exceptions.ConnectTimeout,
                dbsync_exceptions.ConnectFailure) as e:
            LOG.error("sync_identity_resource: {} is not reachable [{}]"
                      .format(self.region_name,
                              str(e)), extra=self.log_extra)
            raise exceptions.SyncRequestTimeout
        except (dbsync_exceptions.Unauthorized,
                keystone_exceptions.Unauthorized) as e:
            LOG.info("Request [{} {}] failed for {}: {}"
                     .format(request.orch_job.operation_type,
                             rsrc.resource_type,
                             self.region_name,
                             str(e)), extra=self.log_extra)
            raise exceptions.SyncRequestFailedRetry
        except dbsync_exceptions.UnauthorizedMaster as e:
            LOG.info("Request [{} {}] failed for {}: {}"
                     .format(request.orch_job.operation_type,
                             rsrc.resource_type,
                             self.region_name,
                             str(e)), extra=self.log_extra)
            raise exceptions.SyncRequestFailedRetry
        except exceptions.SyncRequestFailed:
            raise
        except Exception as e:
            LOG.exception(e)
            raise exceptions.SyncRequestFailedRetry

    def post_users(self, request, rsrc):
        # Create this user on this subcloud
        # The DB level resource creation process is, retrieve the resource
        # records from master cloud by its ID, send the records in its original
        # JSON format by REST call to the DB synchronization service on this
        # subcloud, which then inserts the resource records into DB tables.
        user_id = request.orch_job.source_resource_id
        if not user_id:
            LOG.error("Received user create request without required "
                      "'source_resource_id' field", extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        # Retrieve DB records of the user just created. The records is in JSON
        # format
        try:
            user_records = self.get_dbs_client(self.master_region_name).\
                identity_user_manager.user_detail(user_id)
        except dbsync_exceptions.Unauthorized:
            raise dbsync_exceptions.UnauthorizedMaster
        if not user_records:
            LOG.error("No data retrieved from master cloud for user {} to"
                      " create its equivalent in subcloud.".format(user_id),
                      extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        # Create the user on subcloud by pushing the DB records to subcloud
        user_ref = self.get_dbs_client(
            self.region_name).identity_user_manager.add_user(
            user_records)
        if not user_ref:
            LOG.error("No user data returned when creating user {} in"
                      " subcloud.".format(user_id), extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        # Persist the subcloud resource.
        user_ref_id = user_ref.get('user').get('id')
        subcloud_rsrc_id = self.persist_db_subcloud_resource(rsrc.id,
                                                             user_ref_id)
        username = user_ref.get('local_user').get('name')
        LOG.info("Created Keystone user {}:{} [{}]"
                 .format(rsrc.id, subcloud_rsrc_id, username),
                 extra=self.log_extra)

    def put_users(self, request, rsrc):
        # Update this user on this subcloud
        # The DB level resource update process is, retrieve the resource
        # records from master cloud by its ID, send the records in its original
        # JSON format by REST call to the DB synchronization service on this
        # subcloud, which then updates the resource records in its DB tables.
        user_id = request.orch_job.source_resource_id
        if not user_id:
            LOG.error("Received user update request without required "
                      "source resource id", extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        user_dict = jsonutils.loads(request.orch_job.resource_info)
        if 'user' in user_dict:
            user_dict = user_dict['user']

        sc_user_id = user_dict.pop('id', None)
        if not sc_user_id:
            LOG.error("Received user update request without required "
                      "subcloud resource id", extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        # Retrieve DB records of the user. The records is in JSON
        # format
        try:
            user_records = self.get_dbs_client(self.master_region_name).\
                identity_user_manager.user_detail(user_id)
        except dbsync_exceptions.Unauthorized:
            raise dbsync_exceptions.UnauthorizedMaster
        if not user_records:
            LOG.error("No data retrieved from master cloud for user {} to"
                      " update its equivalent in subcloud.".format(user_id),
                      extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        # Update the corresponding user on subcloud by pushing the DB records
        # to subcloud
        user_ref = self.get_dbs_client(self.region_name).identity_user_manager.\
            update_user(sc_user_id, user_records)
        if not user_ref:
            LOG.error("No user data returned when updating user {} in"
                      " subcloud.".format(sc_user_id), extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        # Persist the subcloud resource.
        user_ref_id = user_ref.get('user').get('id')
        subcloud_rsrc_id = self.persist_db_subcloud_resource(rsrc.id,
                                                             user_ref_id)
        username = user_ref.get('local_user').get('name')
        LOG.info("Updated Keystone user {}:{} [{}]"
                 .format(rsrc.id, subcloud_rsrc_id, username),
                 extra=self.log_extra)

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

        sc_ks_client = self.get_ks_client(self.region_name)
        # Update the user in the subcloud
        user_ref = sc_ks_client.users.update(
            original_user_ref,
            name=user_update_dict.pop('name', None),
            domain=user_update_dict.pop('domain', None),
            project=user_update_dict.pop('project', None),
            password=user_update_dict.pop('password', None),
            email=user_update_dict.pop('email', None),
            description=user_update_dict.pop('description', None),
            enabled=user_update_dict.pop('enabled', None),
            default_project=user_update_dict.pop('default_project', None))

        if user_ref.id == user_id:
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
        try:
            sc_ks_client = self.get_ks_client(self.region_name)
            sc_ks_client.users.delete(original_user_ref)
        except keystone_exceptions.NotFound:
            LOG.info("Delete user: user {} not found in {}, "
                     "considered as deleted.".
                     format(original_user_ref.id,
                            self.region_name),
                     extra=self.log_extra)

        # Master Resource can be deleted only when all subcloud resources
        # are deleted along with corresponding orch_job and orch_requests.
        LOG.info("Keystone user {}:{} [{}] deleted"
                 .format(rsrc.id, user_subcloud_rsrc.id,
                         user_subcloud_rsrc.subcloud_resource_id),
                 extra=self.log_extra)
        user_subcloud_rsrc.delete()

    def post_groups(self, request, rsrc):
        # Create this group on this subcloud
        # The DB level resource creation process is, retrieve the resource
        # records from master cloud by its ID, send the records in its original
        # JSON format by REST call to the DB synchronization service on this
        # subcloud, which then inserts the resource records into DB tables.
        group_id = request.orch_job.source_resource_id
        if not group_id:
            LOG.error("Received group create request without required "
                      "'source_resource_id' field", extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        # Retrieve DB records of the group just created. The records is in JSON
        # format
        try:
            group_records = self.get_dbs_client(self.master_region_name).\
                identity_group_manager.group_detail(group_id)
        except dbsync_exceptions.Unauthorized:
            raise dbsync_exceptions.UnauthorizedMaster
        if not group_records:
            LOG.error("No data retrieved from master cloud for group {} to"
                      " create its equivalent in subcloud.".format(group_id),
                      extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        # Create the group on subcloud by pushing the DB records to subcloud
        group_ref = self.get_dbs_client(
            self.region_name).identity_group_manager.add_group(
            group_records)
        if not group_ref:
            LOG.error("No group data returned when creating group {} in"
                      " subcloud.".format(group_id), extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        # Persist the subcloud resource.
        group_ref_id = group_ref.get('group').get('id')
        subcloud_rsrc_id = self.persist_db_subcloud_resource(rsrc.id,
                                                             group_ref_id)
        groupname = group_ref.get('group').get('name')
        LOG.info("Created Keystone group {}:{} [{}]"
                 .format(rsrc.id, subcloud_rsrc_id, groupname),
                 extra=self.log_extra)

    def put_groups(self, request, rsrc):
        # Update this group on this subcloud
        # The DB level resource update process is, retrieve the resource
        # records from master cloud by its ID, send the records in its original
        # JSON format by REST call to the DB synchronization service on this
        # subcloud, which then updates the resource records in its DB tables.
        group_id = request.orch_job.source_resource_id
        if not group_id:
            LOG.error("Received group update request without required "
                      "source resource id", extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        group_dict = jsonutils.loads(request.orch_job.resource_info)
        if 'group' in group_dict:
            group_dict = group_dict['group']

        sc_group_id = group_dict.pop('id', None)
        if not sc_group_id:
            LOG.error("Received group update request without required "
                      "subcloud resource id", extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        # Retrieve DB records of the group. The records is in JSON
        # format
        try:
            group_records = self.get_dbs_client(self.master_region_name).\
                identity_group_manager.group_detail(group_id)
        except dbsync_exceptions.Unauthorized:
            raise dbsync_exceptions.UnauthorizedMaster
        if not group_records:
            LOG.error("No data retrieved from master cloud for group {} to"
                      " update its equivalent in subcloud.".format(group_id),
                      extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        # Update the corresponding group on subcloud by pushing the DB records
        # to subcloud
        group_ref = self.get_dbs_client(self.region_name).identity_group_manager.\
            update_group(sc_group_id, group_records)
        if not group_ref:
            LOG.error("No group data returned when updating group {} in"
                      " subcloud.".format(sc_group_id), extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        # Persist the subcloud resource.
        group_ref_id = group_ref.get('group').get('id')
        subcloud_rsrc_id = self.persist_db_subcloud_resource(rsrc.id,
                                                             group_ref_id)
        groupname = group_ref.get('group').get('name')
        LOG.info("Updated Keystone group {}:{} [{}]"
                 .format(rsrc.id, subcloud_rsrc_id, groupname),
                 extra=self.log_extra)

    def patch_groups(self, request, rsrc):
        # Update group reference on this subcloud
        group_update_dict = jsonutils.loads(request.orch_job.resource_info)
        if not group_update_dict.keys():
            LOG.error("Received group update request "
                      "without any update fields", extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        group_update_dict = group_update_dict['group']
        group_subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if not group_subcloud_rsrc:
            LOG.error("Unable to update group reference {}:{}, "
                      "cannot find equivalent Keystone group in subcloud."
                      .format(rsrc, group_update_dict),
                      extra=self.log_extra)
            return

        # instead of stowing the entire group reference or
        # retrieving it, we build an opaque wrapper for the
        # v3 Group Manager, containing the ID field which is
        # needed to update this group reference
        GroupReferenceWrapper = namedtuple('GroupReferenceWrapper',
                                           'id')
        group_id = group_subcloud_rsrc.subcloud_resource_id
        original_group_ref = GroupReferenceWrapper(id=group_id)

        sc_ks_client = self.get_ks_client(self.region_name)
        # Update the group in the subcloud
        group_ref = sc_ks_client.groups.update(
            original_group_ref,
            name=group_update_dict.pop('name', None),
            domain=group_update_dict.pop('domain', None),
            description=group_update_dict.pop('description', None))

        if group_ref.id == group_id:
            LOG.info("Updated Keystone group: {}:{}"
                     .format(rsrc.id, group_ref.id), extra=self.log_extra)
        else:
            LOG.error("Unable to update Keystone group {}:{} for subcloud"
                      .format(rsrc.id, group_id), extra=self.log_extra)

    def delete_groups(self, request, rsrc):
        # Delete group reference on this subcloud
        group_subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if not group_subcloud_rsrc:
            LOG.error("Unable to delete group reference {}, "
                      "cannot find equivalent Keystone group in subcloud."
                      .format(rsrc), extra=self.log_extra)
            return

        # instead of stowing the entire group reference or
        # retrieving it, we build an opaque wrapper for the
        # v3 User Manager, containing the ID field which is
        # needed to delete this group reference
        GroupReferenceWrapper = namedtuple('GroupReferenceWrapper',
                                           'id')
        group_id = group_subcloud_rsrc.subcloud_resource_id
        original_group_ref = GroupReferenceWrapper(id=group_id)

        # Delete the group in the subcloud
        try:
            sc_ks_client = self.get_ks_client(self.region_name)
            sc_ks_client.groups.delete(original_group_ref)
        except keystone_exceptions.NotFound:
            LOG.info("Delete group: group {} not found in {}, "
                     "considered as deleted.".
                     format(original_group_ref.id,
                            self.region_name),
                     extra=self.log_extra)

        # Master Resource can be deleted only when all subcloud resources
        # are deleted along with corresponding orch_job and orch_requests.
        LOG.info("Keystone group {}:{} [{}] deleted"
                 .format(rsrc.id, group_subcloud_rsrc.id,
                         group_subcloud_rsrc.subcloud_resource_id),
                 extra=self.log_extra)
        group_subcloud_rsrc.delete()

    def post_projects(self, request, rsrc):
        # Create this project on this subcloud
        # The DB level resource creation process is, retrieve the resource
        # records from master cloud by its ID, send the records in its original
        # JSON format by REST call to the DB synchronization service on this
        # subcloud, which then inserts the resource records into DB tables.
        project_id = request.orch_job.source_resource_id
        if not project_id:
            LOG.error("Received project create request without required "
                      "'source_resource_id' field", extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        # Retrieve DB records of the project just created.
        # The records is in JSON format.
        try:
            m_dbs_client = self.get_dbs_client(self.master_region_name)
            project_records = m_dbs_client.project_manager.\
                project_detail(project_id)
        except dbsync_exceptions.Unauthorized:
            raise dbsync_exceptions.UnauthorizedMaster
        if not project_records:
            LOG.error("No data retrieved from master cloud for project {} to"
                      " create its equivalent in subcloud.".format(project_id),
                      extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        # Create the project on subcloud by pushing the DB records to subcloud
        sc_dbs_client = self.get_dbs_client(self.region_name)
        project_ref = sc_dbs_client.project_manager.\
            add_project(project_records)
        if not project_ref:
            LOG.error("No project data returned when creating project {} in"
                      " subcloud.".format(project_id), extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        # Persist the subcloud resource.
        project_ref_id = project_ref.get('project').get('id')
        subcloud_rsrc_id = self.persist_db_subcloud_resource(rsrc.id,
                                                             project_ref_id)
        projectname = project_ref.get('project').get('name')
        LOG.info("Created Keystone project {}:{} [{}]"
                 .format(rsrc.id, subcloud_rsrc_id, projectname),
                 extra=self.log_extra)

    def put_projects(self, request, rsrc):
        # Update this project on this subcloud
        # The DB level resource update process is, retrieve the resource
        # records from master cloud by its ID, send the records in its original
        # JSON format by REST call to the DB synchronization service on this
        # subcloud, which then updates the resource records in its DB tables.
        project_id = request.orch_job.source_resource_id
        if not project_id:
            LOG.error("Received project update request without required "
                      "source resource id", extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        project_dict = jsonutils.loads(request.orch_job.resource_info)
        if 'project' in list(project_dict.keys()):
            project_dict = project_dict['project']

        sc_project_id = project_dict.pop('id', None)
        if not sc_project_id:
            LOG.error("Received project update request without required "
                      "subcloud resource id", extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        # Retrieve DB records of the project. The records is in JSON
        # format
        try:
            m_dbs_client = self.get_dbs_client(self.master_region_name)
            project_records = m_dbs_client.project_manager.\
                project_detail(project_id)
        except dbsync_exceptions.Unauthorized:
            raise dbsync_exceptions.UnauthorizedMaster
        if not project_records:
            LOG.error("No data retrieved from master cloud for project {} to"
                      " update its equivalent in subcloud.".format(project_id),
                      extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        # Update the corresponding project on subcloud by pushing the DB
        # records to subcloud
        sc_dbs_client = self.get_dbs_client(self.region_name)
        project_ref = sc_dbs_client.project_manager.\
            update_project(sc_project_id, project_records)
        if not project_ref:
            LOG.error("No project data returned when updating project {} in"
                      " subcloud.".format(sc_project_id), extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        # Persist the subcloud resource.
        project_ref_id = project_ref.get('project').get('id')
        subcloud_rsrc_id = self.persist_db_subcloud_resource(rsrc.id,
                                                             project_ref_id)
        projectname = project_ref.get('project').get('name')
        LOG.info("Updated Keystone project {}:{} [{}]"
                 .format(rsrc.id, subcloud_rsrc_id, projectname),
                 extra=self.log_extra)

    def patch_projects(self, request, rsrc):
        # Update project on this subcloud
        project_update_dict = jsonutils.loads(request.orch_job.resource_info)
        if not list(project_update_dict.keys()):
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
        # needed to update this project reference
        ProjectReferenceWrapper = namedtuple('ProjectReferenceWrapper', 'id')
        proj_id = project_subcloud_rsrc.subcloud_resource_id
        original_proj_ref = ProjectReferenceWrapper(id=proj_id)

        # Update the project in the subcloud
        sc_ks_client = self.get_ks_client(self.region_name)
        project_ref = sc_ks_client.projects.update(
            original_proj_ref,
            name=project_update_dict.pop('name', None),
            domain=project_update_dict.pop('domain_id', None),
            description=project_update_dict.pop('description', None),
            enabled=project_update_dict.pop('enabled', None))

        if project_ref.id == proj_id:
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
        try:
            sc_ks_client = self.get_ks_client(self.region_name)
            sc_ks_client.projects.delete(original_proj_ref)
        except keystone_exceptions.NotFound:
            LOG.info("Delete project: project {} not found in {}, "
                     "considered as deleted.".
                     format(original_proj_ref.id,
                            self.region_name),
                     extra=self.log_extra)

        # Master Resource can be deleted only when all subcloud resources
        # are deleted along with corresponding orch_job and orch_requests.
        LOG.info("Keystone project {}:{} [{}] deleted"
                 .format(rsrc.id, project_subcloud_rsrc.id,
                         project_subcloud_rsrc.subcloud_resource_id),
                 extra=self.log_extra)
        project_subcloud_rsrc.delete()

    def post_roles(self, request, rsrc):
        # Create this role on this subcloud
        # The DB level resource creation process is, retrieve the resource
        # records from master cloud by its ID, send the records in its original
        # JSON format by REST call to the DB synchronization service on this
        # subcloud, which then inserts the resource records into DB tables.
        role_id = request.orch_job.source_resource_id
        if not role_id:
            LOG.error("Received role create request without required "
                      "'source_resource_id' field", extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        # Retrieve DB records of the role just created. The records is in JSON
        # format.
        try:
            m_dbs_client = self.get_dbs_client(self.master_region_name)
            role_records = m_dbs_client.role_manager.\
                role_detail(role_id)
        except dbsync_exceptions.Unauthorized:
            raise dbsync_exceptions.UnauthorizedMaster
        if not role_records:
            LOG.error("No data retrieved from master cloud for role {} to"
                      " create its equivalent in subcloud.".format(role_id),
                      extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        # Create the role on subcloud by pushing the DB records to subcloud
        sc_dbs_client = self.get_dbs_client(self.region_name)
        role_ref = sc_dbs_client.role_manager.add_role(role_records)
        if not role_ref:
            LOG.error("No role data returned when creating role {} in"
                      " subcloud.".format(role_id), extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        # Persist the subcloud resource.
        role_ref_id = role_ref.get('role').get('id')
        subcloud_rsrc_id = self.persist_db_subcloud_resource(rsrc.id,
                                                             role_ref_id)
        rolename = role_ref.get('role').get('name')
        LOG.info("Created Keystone role {}:{} [{}]"
                 .format(rsrc.id, subcloud_rsrc_id, rolename),
                 extra=self.log_extra)

    def put_roles(self, request, rsrc):
        # Update this role on this subcloud
        # The DB level resource update process is, retrieve the resource
        # records from master cloud by its ID, send the records in its original
        # JSON format by REST call to the DB synchronization service on this
        # subcloud, which then updates the resource records in its DB tables.
        role_id = request.orch_job.source_resource_id
        if not role_id:
            LOG.error("Received role update request without required "
                      "source resource id", extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        role_dict = jsonutils.loads(request.orch_job.resource_info)
        if 'role' in list(role_dict.keys()):
            role_dict = role_dict['role']

        sc_role_id = role_dict.pop('id', None)
        if not sc_role_id:
            LOG.error("Received role update request without required "
                      "subcloud resource id", extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        # Retrieve DB records of the role. The records is in JSON
        # format
        try:
            m_dbs_client = self.get_dbs_client(self.master_region_name)
            role_records = m_dbs_client.role_manager.role_detail(role_id)
        except dbsync_exceptions.Unauthorized:
            raise dbsync_exceptions.UnauthorizedMaster
        if not role_records:
            LOG.error("No data retrieved from master cloud for role {} to"
                      " update its equivalent in subcloud.".format(role_id),
                      extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        # Update the corresponding role on subcloud by pushing the DB records
        # to subcloud
        sc_dbs_client = self.get_dbs_client(self.region_name)
        role_ref = sc_dbs_client.role_manager.\
            update_role(sc_role_id, role_records)
        if not role_ref:
            LOG.error("No role data returned when updating role {} in"
                      " subcloud.".format(sc_role_id), extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        # Persist the subcloud resource.
        role_ref_id = role_ref.get('role').get('id')
        subcloud_rsrc_id = self.persist_db_subcloud_resource(rsrc.id,
                                                             role_ref_id)
        rolename = role_ref.get('role').get('name')
        LOG.info("Updated Keystone role {}:{} [{}]"
                 .format(rsrc.id, subcloud_rsrc_id, rolename),
                 extra=self.log_extra)

    def patch_roles(self, request, rsrc):
        # Update this role on this subcloud
        role_update_dict = jsonutils.loads(request.orch_job.resource_info)
        if not list(role_update_dict.keys()):
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
        sc_ks_client = self.get_ks_client(self.region_name)
        role_ref = sc_ks_client.roles.update(
            original_role_ref,
            name=role_update_dict.pop('name', None))

        if role_ref.id == role_id:
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
        try:
            sc_ks_client = self.get_ks_client(self.region_name)
            sc_ks_client.roles.delete(original_role_ref)
        except keystone_exceptions.NotFound:
            LOG.info("Delete role: role {} not found in {}, "
                     "considered as deleted.".
                     format(original_role_ref.id,
                            self.region_name),
                     extra=self.log_extra)

        # Master Resource can be deleted only when all subcloud resources
        # are deleted along with corresponding orch_job and orch_requests.
        LOG.info("Keystone role {}:{} [{}] deleted"
                 .format(rsrc.id, role_subcloud_rsrc.id,
                         role_subcloud_rsrc.subcloud_resource_id),
                 extra=self.log_extra)
        role_subcloud_rsrc.delete()

    def post_project_role_assignments(self, request, rsrc):
        # Assign this role to user/group on project on this subcloud
        # Project role assignments creation is still using keystone APIs since
        # the APIs can be used to sync them.
        resource_tags = rsrc.master_id.split('_')
        if len(resource_tags) < 3:
            LOG.error("Malformed resource tag {} expected to be in "
                      "format: ProjectID_UserID_RoleID."
                      .format(rsrc.id), extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        project_id = resource_tags[0]
        # actor_id can be either user_id or group_id
        actor_id = resource_tags[1]
        role_id = resource_tags[2]

        # Ensure that we have already synced the project, user and role
        # prior to syncing the assignment
        sc_role = None
        sc_ks_client = self.get_ks_client(self.region_name)
        sc_role_list = sc_ks_client.roles.list()
        for role in sc_role_list:
            if role.id == role_id:
                sc_role = role
                break
        if not sc_role:
            LOG.error("Unable to assign role to user on project reference {}:"
                      "{}, cannot find equivalent Keystone Role in subcloud."
                      .format(rsrc, role_id),
                      extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        sc_proj = None
        # refresh client in case the token expires in between API calls
        sc_proj_list = sc_ks_client.projects.list()
        for proj in sc_proj_list:
            if proj.id == project_id:
                sc_proj = proj
                break
        if not sc_proj:
            LOG.error("Unable to assign role to user on project reference {}:"
                      "{}, cannot find equivalent Keystone Project in subcloud"
                      .format(rsrc, project_id),
                      extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        sc_user = None
        sc_user_list = self._get_all_users(sc_ks_client)
        for user in sc_user_list:
            if user.id == actor_id:
                sc_user = user
                break
        sc_group = None
        sc_group_list = self._get_all_groups(sc_ks_client)
        for group in sc_group_list:
            if group.id == actor_id:
                sc_group = group
                break
        if not sc_user and not sc_group:
            LOG.error("Unable to assign role to user/group on project reference {}:"
                      "{}, cannot find equivalent Keystone User/Group in subcloud."
                      .format(rsrc, actor_id),
                      extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        # Create role assignment
        if sc_user:
            sc_ks_client.roles.grant(
                sc_role,
                user=sc_user,
                project=sc_proj)
            role_ref = sc_ks_client.role_assignments.list(
                user=sc_user,
                project=sc_proj,
                role=sc_role)
        elif sc_group:
            sc_ks_client.roles.grant(
                sc_role,
                group=sc_group,
                project=sc_proj)
            role_ref = sc_ks_client.role_assignments.list(
                group=sc_group,
                project=sc_proj,
                role=sc_role)

        if role_ref:
            LOG.info("Added Keystone role assignment: {}:{}"
                     .format(rsrc.id, role_ref), extra=self.log_extra)
            # Persist the subcloud resource.
            if sc_user:
                sc_rid = sc_proj.id + '_' + sc_user.id + '_' + sc_role.id
            elif sc_group:
                sc_rid = sc_proj.id + '_' + sc_group.id + '_' + sc_role.id
            subcloud_rsrc_id = self.persist_db_subcloud_resource(rsrc.id,
                                                                 sc_rid)
            LOG.info("Created Keystone role assignment {}:{} [{}]"
                     .format(rsrc.id, subcloud_rsrc_id, sc_rid),
                     extra=self.log_extra)
        else:
            LOG.error("Unable to update Keystone role assignment {}:{} "
                      .format(rsrc.id, sc_role), extra=self.log_extra)
            raise exceptions.SyncRequestFailed

    def put_project_role_assignments(self, request, rsrc):
        # update the project role assignment on this subcloud
        # For project role assignment, there is nothing to update.
        return

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
            LOG.error("Malformed subcloud resource tag {}, expected to be in "
                      "format: ProjectID_UserID_RoleID or ProjectID_GroupID_RoleID."
                      .format(assignment_subcloud_rsrc), extra=self.log_extra)
            assignment_subcloud_rsrc.delete()
            return

        project_id = resource_tags[0]
        actor_id = resource_tags[1]
        role_id = resource_tags[2]

        # Revoke role assignment
        actor = None
        try:
            sc_ks_client = self.get_ks_client(self.region_name)
            sc_ks_client.roles.revoke(
                role_id,
                user=actor_id,
                project=project_id)
            actor = 'user'
        except keystone_exceptions.NotFound:
            LOG.info("Revoke role assignment: (role {}, user {}, project {})"
                     " not found in {}, considered as deleted.".
                     format(role_id, actor_id, project_id,
                            self.region_name),
                     extra=self.log_extra)
            try:
                sc_ks_client = self.get_ks_client(self.region_name)
                sc_ks_client.roles.revoke(
                    role_id,
                    group=actor_id,
                    project=project_id)
                actor = 'group'
            except keystone_exceptions.NotFound:
                LOG.info("Revoke role assignment: (role {}, group {}, project {})"
                         " not found in {}, considered as deleted.".
                         format(role_id, actor_id, project_id,
                                self.region_name),
                         extra=self.log_extra)

        role_ref = None
        if actor == 'user':
            role_ref = sc_ks_client.role_assignments.list(
                user=actor_id,
                project=project_id,
                role=role_id)
        elif actor == 'group':
            role_ref = sc_ks_client.role_assignments.list(
                group=actor_id,
                project=project_id,
                role=role_id)

        if not role_ref:
            LOG.info("Deleted Keystone role assignment: {}:{}"
                     .format(rsrc.id, assignment_subcloud_rsrc),
                     extra=self.log_extra)
        else:
            LOG.error("Unable to delete Keystone role assignment {}:{} "
                      .format(rsrc.id, role_id), extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        assignment_subcloud_rsrc.delete()

    def post_revoke_events(self, request, rsrc):
        # Create token revoke event on this subcloud
        # The DB level resource creation process is, retrieve the resource
        # records from master cloud by its ID, send the records in its original
        # JSON format by REST call to the DB synchronization service on this
        # subcloud, which then inserts the resource records into DB tables.
        revoke_event_dict = jsonutils.loads(request.orch_job.resource_info)
        if 'token_revoke_event' in list(revoke_event_dict.keys()):
            revoke_event_dict = revoke_event_dict['token_revoke_event']

        audit_id = revoke_event_dict.pop('audit_id', None)
        if not audit_id:
            LOG.error("Received token revocation event create request without "
                      "required subcloud resource id", extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        # Retrieve DB records of the revoke event just created. The records
        # is in JSON format.
        try:
            m_dbs_client = self.get_dbs_client(self.master_region_name)
            revoke_event_records = m_dbs_client.revoke_event_manager.\
                revoke_event_detail(audit_id=audit_id)
        except dbsync_exceptions.Unauthorized:
            raise dbsync_exceptions.UnauthorizedMaster
        if not revoke_event_records:
            LOG.error("No data retrieved from master cloud for token"
                      " revocation event with audit_id {} to create its"
                      " equivalent in subcloud.".format(audit_id),
                      extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        # Create the revoke event on subcloud by pushing the DB records to
        # subcloud
        sc_dbs_client = self.get_dbs_client(self.region_name)
        revoke_event_ref = sc_dbs_client.revoke_event_manager.\
            add_revoke_event(revoke_event_records)
        if not revoke_event_ref:
            LOG.error("No token revocation event data returned when creating"
                      " token revocation event with audit_id {} in subcloud."
                      .format(audit_id), extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        revoke_event_ref_id = revoke_event_ref.\
            get('revocation_event').get('audit_id')
        subcloud_rsrc_id = self.\
            persist_db_subcloud_resource(rsrc.id, revoke_event_ref_id)
        LOG.info("Created Keystone token revocation event {}:{}"
                 .format(rsrc.id, subcloud_rsrc_id),
                 extra=self.log_extra)

    def delete_revoke_events(self, request, rsrc):
        # Delete token revocation event reference on this subcloud
        revoke_event_subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if not revoke_event_subcloud_rsrc:
            LOG.error("Unable to delete token revocation event reference {}, "
                      "cannot find equivalent Keystone token revocation event "
                      "in subcloud.".format(rsrc), extra=self.log_extra)
            return

        # subcloud resource id is the audit_id
        subcloud_resource_id = revoke_event_subcloud_rsrc.subcloud_resource_id
        try:
            sc_dbs_client = self.get_dbs_client(self.region_name)
            sc_dbs_client.revoke_event_manager.delete_revoke_event(
                audit_id=subcloud_resource_id)
        except dbsync_exceptions.NotFound:
            LOG.info("Delete token revocation event: event {} not found in {},"
                     " considered as deleted.".
                     format(revoke_event_subcloud_rsrc.subcloud_resource_id,
                            self.region_name),
                     extra=self.log_extra)

        # Master Resource can be deleted only when all subcloud resources
        # are deleted along with corresponding orch_job and orch_requests.
        # pylint: disable=E1101
        LOG.info("Keystone token revocation event {}:{} [{}] deleted"
                 .format(rsrc.id, revoke_event_subcloud_rsrc.id,
                         revoke_event_subcloud_rsrc.subcloud_resource_id),
                 extra=self.log_extra)
        revoke_event_subcloud_rsrc.delete()

    def post_revoke_events_for_user(self, request, rsrc):
        # Create token revoke event on this subcloud
        # The DB level resource creation process is, retrieve the resource
        # records from master cloud by its ID, send the records in its original
        # JSON format by REST call to the DB synchronization service on this
        # subcloud, which then inserts the resource records into DB tables.
        event_id = request.orch_job.source_resource_id
        if not event_id:
            LOG.error("Received token revocation event create request without "
                      "required subcloud resource id", extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        # Retrieve DB records of the revoke event just created. The records
        # is in JSON format.
        try:
            m_dbs_client = self.get_dbs_client(self.master_region_name)
            revoke_event_records = m_dbs_client.revoke_event_manager.\
                revoke_event_detail(user_id=event_id)
        except dbsync_exceptions.Unauthorized:
            raise dbsync_exceptions.UnauthorizedMaster
        if not revoke_event_records:
            LOG.error("No data retrieved from master cloud for token"
                      " revocation event with event_id {} to create its"
                      " equivalent in subcloud.".format(event_id),
                      extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        # Create the revoke event on subcloud by pushing the DB records to
        # subcloud
        sc_dbs_client = self.get_dbs_client(self.region_name)
        revoke_event_ref = sc_dbs_client.revoke_event_manager.\
            add_revoke_event(revoke_event_records)
        if not revoke_event_ref:
            LOG.error("No token revocation event data returned when creating"
                      " token revocation event with event_id {} in subcloud."
                      .format(event_id), extra=self.log_extra)
            raise exceptions.SyncRequestFailed

        subcloud_rsrc_id = self.persist_db_subcloud_resource(rsrc.id,
                                                             event_id)
        LOG.info("Created Keystone token revocation event {}:{}"
                 .format(rsrc.id, subcloud_rsrc_id),
                 extra=self.log_extra)

    def delete_revoke_events_for_user(self, request, rsrc):
        # Delete token revocation event reference on this subcloud
        revoke_event_subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if not revoke_event_subcloud_rsrc:
            LOG.error("Unable to delete token revocation event reference {}, "
                      "cannot find equivalent Keystone token revocation event "
                      "in subcloud.".format(rsrc), extra=self.log_extra)
            return

        # subcloud resource id is <user_id>_<issued_before> encoded in base64
        subcloud_resource_id = revoke_event_subcloud_rsrc.subcloud_resource_id
        try:
            sc_dbs_client = self.get_dbs_client(self.region_name)
            sc_dbs_client.revoke_event_manager.delete_revoke_event(
                user_id=subcloud_resource_id)
        except dbsync_exceptions.NotFound:
            LOG.info("Delete token revocation event: event {} not found in {},"
                     " considered as deleted.".
                     format(revoke_event_subcloud_rsrc.subcloud_resource_id,
                            self.region_name),
                     extra=self.log_extra)

        # Master Resource can be deleted only when all subcloud resources
        # are deleted along with corresponding orch_job and orch_requests.
        # pylint: disable=E1101
        LOG.info("Keystone token revocation event {}:{} [{}] deleted"
                 .format(rsrc.id, revoke_event_subcloud_rsrc.id,
                         revoke_event_subcloud_rsrc.subcloud_resource_id),
                 extra=self.log_extra)
        revoke_event_subcloud_rsrc.delete()

    # ---- Override common audit functions ----
    def _get_resource_audit_handler(self, resource_type, client):
        if resource_type == consts.RESOURCE_TYPE_IDENTITY_USERS:
            return self._get_users_resource(client.identity_user_manager)
        if resource_type == consts.RESOURCE_TYPE_IDENTITY_GROUPS:
            return self._get_groups_resource(client.identity_group_manager)
        elif resource_type == consts.RESOURCE_TYPE_IDENTITY_ROLES:
            return self._get_roles_resource(client.role_manager)
        elif resource_type == consts.RESOURCE_TYPE_IDENTITY_PROJECTS:
            return self._get_projects_resource(client.project_manager)
        elif (resource_type ==
                consts.RESOURCE_TYPE_IDENTITY_PROJECT_ROLE_ASSIGNMENTS):
            return self._get_assignments_resource(client)
        elif (resource_type ==
                consts.RESOURCE_TYPE_IDENTITY_TOKEN_REVOKE_EVENTS):
            return self._get_revoke_events_resource(client.
                                                    revoke_event_manager)
        elif (resource_type ==
                consts.RESOURCE_TYPE_IDENTITY_TOKEN_REVOKE_EVENTS_FOR_USER):
            return self._get_revoke_events_for_user_resource(
                client.revoke_event_manager)
        else:
            LOG.error("Wrong resource type {}".format(resource_type),
                      extra=self.log_extra)
            return None

    def _get_all_users(self, client):
        domains = client.domains.list()
        users = []
        for domain in domains:
            domain_users = client.users.list(domain=domain)
            users = users + domain_users
        return users

    def _get_all_groups(self, client):
        domains = client.domains.list()
        groups = []
        for domain in domains:
            domain_groups = client.groups.list(domain=domain)
            groups = groups + domain_groups
        return groups

    def _get_users_resource(self, client):
        try:
            services = []

            filtered_list = self.filtered_audit_resources[
                consts.RESOURCE_TYPE_IDENTITY_USERS]

            # Filter out services users and some predefined users. These users
            # are not to be synced to the subcloud.
            filtered_users = []
            # get users from DB API
            if hasattr(client, 'list_users'):
                users = client.list_users()
                for user in users:
                    user_name = user.local_user.name
                    if all(user_name != service.name for service in services)\
                            and all(user_name != filtered for filtered in
                                    filtered_list):
                        filtered_users.append(user)
            # get users from keystone API
            else:
                users = self._get_all_users(client)
                for user in users:
                    user_name = user.name
                    if all(user_name != service.name for service in services)\
                            and all(user_name != filtered for filtered in
                                    filtered_list):
                        filtered_users.append(user)

            return filtered_users
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure,
                dbsync_exceptions.ConnectTimeout,
                dbsync_exceptions.ConnectFailure) as e:
            LOG.info("User Audit: subcloud {} is not reachable [{}]"
                     .format(self.region_name,
                             str(e)), extra=self.log_extra)
            # None will force skip of audit
            return None

    def _get_groups_resource(self, client):
        try:
            # get groups from DB API
            if hasattr(client, 'list_groups'):
                groups = client.list_groups()
            # get groups from keystone API
            else:
                groups = client.groups.list()

            # Filter out admin or services projects
            filtered_list = self.filtered_audit_resources[
                consts.RESOURCE_TYPE_IDENTITY_GROUPS]

            filtered_groups = [group for group in groups if
                               all(group.name != filtered for
                                   filtered in filtered_list)]
            return filtered_groups
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure,
                dbsync_exceptions.ConnectTimeout,
                dbsync_exceptions.ConnectFailure) as e:
            LOG.info("Group Audit: subcloud {} is not reachable [{}]"
                     .format(self.region_name,
                             str(e)), extra=self.log_extra)
            # None will force skip of audit
            return None

    def _get_roles_resource(self, client):
        try:
            # get roles from DB API
            if hasattr(client, 'list_roles'):
                roles = client.list_roles()
            # get roles from keystone API
            else:
                roles = client.roles.list()

            # Filter out system roles
            filtered_list = self.filtered_audit_resources[
                consts.RESOURCE_TYPE_IDENTITY_ROLES]

            filtered_roles = [role for role in roles if
                              (all(role.name != filtered for
                                   filtered in filtered_list))]
            return filtered_roles
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure,
                dbsync_exceptions.ConnectTimeout,
                dbsync_exceptions.ConnectFailure) as e:
            LOG.info("Role Audit: subcloud {} is not reachable [{}]"
                     .format(self.region_name,
                             str(e)), extra=self.log_extra)
            # None will force skip of audit
            return None

    def _get_projects_resource(self, client):
        try:
            # get projects from DB API
            if hasattr(client, 'list_projects'):
                projects = client.list_projects()
            # get roles from keystone API
            else:
                projects = client.projects.list()

            # Filter out admin or services projects
            filtered_list = self.filtered_audit_resources[
                consts.RESOURCE_TYPE_IDENTITY_PROJECTS]

            filtered_projects = [project for project in projects if
                                 all(project.name != filtered for
                                     filtered in filtered_list)]
            return filtered_projects
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure,
                dbsync_exceptions.ConnectTimeout,
                dbsync_exceptions.ConnectFailure) as e:
            LOG.info("Project Audit: subcloud {} is not reachable [{}]"
                     .format(self.region_name,
                             str(e)), extra=self.log_extra)
            # None will force skip of audit
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
            groups = self._get_groups_resource(client)
            for assignment in assignments:
                if 'project' not in assignment.scope:
                    # this is a domain scoped role, we don't care
                    # about syncing or auditing them for now
                    continue
                role_id = assignment.role['id']
                actor_id = assignment.user['id'] if hasattr(
                    assignment, 'user') else assignment.group['id']
                project_id = assignment.scope['project']['id']
                assignment_dict = {}

                for user in users:
                    if user.id == actor_id:
                        assignment_dict['actor'] = user
                        break
                else:
                    for group in groups:
                        if group.id == actor_id:
                            assignment_dict['actor'] = group
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
                    project_id, actor_id, role_id)

                # Build an opaque object wrapper for this RoleAssignment
                refactored_assignment = namedtuple(
                    'RoleAssignmentWrapper',
                    list(assignment_dict.keys()))(*list(assignment_dict.values()))
                refactored_assignments.append(refactored_assignment)

            return refactored_assignments
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure,
                dbsync_exceptions.ConnectTimeout,
                dbsync_exceptions.ConnectFailure) as e:
            LOG.info("Assignment Audit: subcloud {} is not reachable [{}]"
                     .format(self.region_name,
                             str(e)), extra=self.log_extra)
            # None will force skip of audit
            return None

    def _get_revoke_events_resource(self, client):
        try:
            # get token revoke events from DB API
            revoke_events = client.list_revoke_events()
            # Events with audit_id are generated by openstack token
            # revocation command. audit_id will be the unique id of
            # the resource.
            filtered_revoke_events = [event for event in revoke_events if
                                      event.audit_id is not None]
            return filtered_revoke_events

        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure,
                dbsync_exceptions.ConnectTimeout,
                dbsync_exceptions.ConnectFailure) as e:
            LOG.info("Token revoke events Audit: subcloud {} is not reachable"
                     " [{}]".format(self.region_name,
                                    str(e)), extra=self.log_extra)
            # None will force skip of audit
            return None

    def _get_revoke_events_for_user_resource(self, client):
        try:
            # get token revoke events from DB API
            revoke_events = client.list_revoke_events()
            # Events with user_id are generated when user password is changed.
            # <user_id>_<issued_before> will be the unique id of
            # the resource.
            filtered_revoke_events = [event for event in revoke_events if
                                      event.user_id is not None]
            return filtered_revoke_events

        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure,
                dbsync_exceptions.ConnectTimeout,
                dbsync_exceptions.ConnectFailure) as e:
            LOG.info("Token revoke events Audit: subcloud {} is not reachable"
                     " [{}]".format(self.region_name,
                                    str(e)), extra=self.log_extra)
            # None will force skip of audit
            return None

    def _same_identity_user_resource(self, m, sc):
        LOG.debug("master={}, subcloud={}".format(m, sc),
                  extra=self.log_extra)
        # For user the comparison is DB records by DB records.
        # The user DB records are from multiple tables, including user,
        # local_user, and password tables. If any of them are not matched,
        # it is considered as a different identity resource.
        # Note that the user id is compared, since user id has to be synced
        # to the subcloud too.
        same_user = (m.id == sc.id and
                     m.domain_id == sc.domain_id and
                     m.default_project_id == sc.default_project_id and
                     m.enabled == sc.enabled and
                     m.created_at == sc.created_at and
                     m.last_active_at == sc.last_active_at and
                     m.extra == sc.extra)
        if not same_user:
            return False

        same_local_user = (m.local_user.domain_id ==
                           sc.local_user.domain_id and
                           m.local_user.name == sc.local_user.name and
                           m.local_user.user_id == sc.local_user.user_id)
        if not same_local_user:
            return False

        result = False
        if len(m.local_user.passwords) == len(sc.local_user.passwords):
            for m_password in m.local_user.passwords:
                for sc_password in sc.local_user.passwords:
                    if m_password.password_hash == sc_password.password_hash:
                        break
                # m_password is not found in sc_passwords
                else:
                    break
            # All are found
            else:
                result = True
        return result

    def _same_identity_group_resource(self, m, sc):
        LOG.debug("master={}, subcloud={}".format(m, sc),
                  extra=self.log_extra)
        # For group the comparison is DB records by DB records.
        # The group DB records are from two tables - group and
        # user_group_membership tables. If any of them are not matched,
        # it is considered as different identity resource.
        # Note that the group id is compared, since group id has to be synced
        # to the subcloud too.
        same_group = (m.id == sc.id and
                      m.domain_id == sc.domain_id and
                      m.description == sc.description and
                      m.name == sc.name and
                      m.extra == sc.extra)
        if not same_group:
            return False

        same_local_user_ids = (m.local_user_ids ==
                               sc.local_user_ids)
        if not same_local_user_ids:
            return False

        return True

    def _has_same_identity_user_ids(self, m, sc):
        # If (user name + domain name) or use id is the same,
        # the resources are considered to be the same resource.
        # Any difference in other attributes will trigger an update (PUT)
        # to that resource in subcloud.
        return ((m.local_user.name == sc.local_user.name and
                 m.domain_id == sc.domain_id) or m.id == sc.id)

    def _has_same_identity_group_ids(self, m, sc):
        # If (group name + domain name) or group id is the same,
        # then the resources are considered to be the same.
        # Any difference in other attributes will trigger an update (PUT)
        # to that resource in subcloud.
        return ((m.name == sc.name and m.domain_id == sc.domain_id)
                or m.id == sc.id)

    def _same_project_resource(self, m, sc):
        LOG.debug("master={}, subcloud={}".format(m, sc),
                  extra=self.log_extra)
        # For project the comparison is DB records by DB records.
        # The project DB records are from project tables. If any of
        # them are not matched, it is considered not the same.
        # Note that the project id is compared, since project id is to
        # be synced to subcloud too.
        return (m.id == sc.id and
                m.domain_id == sc.domain_id and
                m.name == sc.name and
                m.extra == sc.extra and
                m.description == sc.description and
                m.enabled == sc.enabled and
                m.parent_id == sc.parent_id and
                m.is_domain == sc.is_domain)

    def _has_same_project_ids(self, m, sc):
        # If (project name + domain name) or project id is the same,
        # the resources are considered to be the same resource.
        # Any difference in other attributes will trigger an update (PUT)
        # to that resource in subcloud.
        return ((m.name == sc.name and m.domain_id == sc.domain_id)
                or m.id == sc.id)

    def _same_role_resource(self, m, sc):
        LOG.debug("master={}, subcloud={}".format(m, sc),
                  extra=self.log_extra)
        # For role the comparison is DB records by DB records.
        # The role DB records are from role tables. If any of
        # them are not matched, it is considered not the same.
        # Note that the role id is compared, since role id is to
        # be synced to subcloud too.
        return (m.id == sc.id and
                m.domain_id == sc.domain_id and
                m.name == sc.name and
                m.description == sc.description and
                m.extra == sc.extra)

    def _has_same_role_ids(self, m, sc):
        # If (role name + domain name) or role id is the same,
        # the resources are considered to be the same resource.
        # Any difference in other attributes will trigger an update (PUT)
        # to that resource in subcloud.
        return ((m.name == sc.name and m.domain_id == sc.domain_id)
                or m.id == sc.id)

    def _same_assignment_resource(self, m, sc):
        LOG.debug("same_assignment master={}, subcloud={}".format(m, sc),
                  extra=self.log_extra)
        # For an assignment to be the same, all 3 of its role, project and
        # actor (user/group) information must match up.
        # Compare by names here is fine, since this comparison gets called
        # only if the mapped subcloud assignment is found by id in subcloud
        # resources just retrieved. In another word, the ids are guaranteed
        # to be the same by the time same_resource() is called in
        # audit_find_missing(). same_resource() in audit_find_missing() is
        # actually redundant for assignment but it's the generic algorithm
        # for all types of resources.
        return ((m.actor.name == sc.actor.name and
                 m.actor.domain_id == sc.actor.domain_id) and
                (m.role.name == sc.role.name and
                 m.role.domain_id == sc.role.domain_id) and
                (m.project.name == sc.project.name and
                 m.project.domain_id == sc.project.domain_id))

    def _has_same_assignment_ids(self, m, sc):
        # For assignment the unique id is projectID_userID_roleID.
        # The two resources have same id only when all of the three IDs are
        # identical.
        return m.id == sc.id

    def _same_revoke_event_resource(self, m, sc):
        LOG.debug("same_revoke_event master={}, subcloud={}".format(m, sc),
                  extra=self.log_extra)
        # For token revocation event the comparison is DB records by
        # DB records. The DB records are from revocation_event tables.
        # Token revocation events are considered the same when all columns
        # match up.
        return (m.domain_id == sc.domain_id and
                m.project_id == sc.project_id and
                m.user_id == sc.user_id and
                m.role_id == sc.role_id and
                m.trust_id == sc.trust_id and
                m.consumer_id == sc.consumer_id and
                m.access_token_id == sc.access_token_id and
                m.issued_before == sc.issued_before and
                m.expires_at == sc.expires_at and
                m.revoked_at == sc.revoked_at and
                m.audit_id == sc.audit_id and
                m.audit_chain_id == sc.audit_chain_id)

    def _has_same_revoke_event_ids(self, m, sc):
        # For token revoke events to have same ids, all columns must be
        # match up.
        return self._same_revoke_event_resource(m, sc)

    def get_master_resources(self, resource_type):
        # Retrieve master resources from DB or through Keystone.
        # users, groups, projects, roles, and token revocation events use
        # dbsync client, other resources use keystone client.
        if self.is_resource_handled_by_dbs_client(resource_type):
            try:
                return self._get_resource_audit_handler(
                    resource_type,
                    self.get_dbs_client(self.master_region_name))
            except dbsync_exceptions.Unauthorized as e:
                LOG.info("Get master resource [{}] request failed for {}: {}."
                         .format(resource_type,
                                 dccommon_consts.VIRTUAL_MASTER_CLOUD,
                                 str(e)), extra=self.log_extra)
                # Clear the cache so that the old token will not be validated
                sdk.OpenStackDriver.delete_region_clients(self.master_region_name)
                # Retry will get a new token
                return self._get_resource_audit_handler(
                    resource_type,
                    self.get_dbs_client(self.master_region_name))
            except Exception as e:
                LOG.exception(e)
                return None
        else:
            try:
                return self._get_resource_audit_handler(
                    resource_type,
                    self.get_ks_client(self.master_region_name))
            except keystone_exceptions.Unauthorized as e:
                LOG.info("Get master resource [{}] request failed for {}: {}."
                         .format(resource_type,
                                 dccommon_consts.VIRTUAL_MASTER_CLOUD,
                                 str(e)), extra=self.log_extra)
                # Clear the cache so that the old token will not be validated
                sdk.OpenStackDriver.delete_region_clients(self.master_region_name)
                # Retry with get a new token
                return self._get_resource_audit_handler(
                    resource_type,
                    self.get_ks_client(self.master_region_name))
            except Exception as e:
                LOG.exception(e)
                return None

    def get_subcloud_resources(self, resource_type):
        # Retrieve subcloud resources from DB or through keystone.
        # users, projects, roles, and token revocation events use
        # dbsync client, other resources use keystone client.

        if self.is_resource_handled_by_dbs_client(resource_type):
            try:
                return self._get_resource_audit_handler(
                    resource_type, self.get_dbs_client(self.region_name))
            except dbsync_exceptions.Unauthorized as e:
                LOG.info("Get subcloud resource [{}] request failed for {}: {}."
                         .format(resource_type,
                                 self.region_name,
                                 str(e)), extra=self.log_extra)
                # Clear the cache so that the old token will not be validated
                sdk.OpenStackDriver.delete_region_clients(self.region_name)
                # Retry with re-authenticated dbsync client
                return self._get_resource_audit_handler(
                    resource_type, self.get_dbs_client(self.region_name))
            except Exception as e:
                LOG.exception(e)
                return None
        else:
            try:
                return self._get_resource_audit_handler(
                    resource_type, self.get_ks_client(self.region_name))
            except keystone_exceptions.Unauthorized as e:
                LOG.info("Get subcloud resource [{}] request failed for {}: {}."
                         .format(resource_type,
                                 self.region_name,
                                 str(e)), extra=self.log_extra)
                # Clear the cache so that the old token will not be validated
                sdk.OpenStackDriver.delete_region_clients(self.region_name)
                # Retry with re-authenticated ks client
                return self._get_resource_audit_handler(
                    resource_type, self.get_ks_client(self.region_name))
            except Exception as e:
                LOG.exception(e)
                return None

    def same_resource(self, resource_type, m_resource, sc_resource):
        if (resource_type ==
                consts.RESOURCE_TYPE_IDENTITY_USERS):
            return self._same_identity_user_resource(m_resource, sc_resource)
        elif (resource_type ==
                consts.RESOURCE_TYPE_IDENTITY_GROUPS):
            return self._same_identity_group_resource(m_resource, sc_resource)
        elif (resource_type ==
                consts.RESOURCE_TYPE_IDENTITY_PROJECTS):
            return self._same_project_resource(m_resource, sc_resource)
        elif (resource_type ==
                consts.RESOURCE_TYPE_IDENTITY_ROLES):
            return self._same_role_resource(m_resource, sc_resource)
        elif (resource_type ==
                consts.RESOURCE_TYPE_IDENTITY_PROJECT_ROLE_ASSIGNMENTS):
            return self._same_assignment_resource(m_resource, sc_resource)
        elif (resource_type ==
                consts.RESOURCE_TYPE_IDENTITY_TOKEN_REVOKE_EVENTS):
            return self._same_revoke_event_resource(m_resource, sc_resource)
        elif (resource_type ==
                consts.RESOURCE_TYPE_IDENTITY_TOKEN_REVOKE_EVENTS_FOR_USER):
            return self._same_revoke_event_resource(m_resource, sc_resource)

    def has_same_ids(self, resource_type, m_resource, sc_resource):
        if (resource_type ==
                consts.RESOURCE_TYPE_IDENTITY_USERS):
            return self._has_same_identity_user_ids(m_resource, sc_resource)
        elif (resource_type ==
                consts.RESOURCE_TYPE_IDENTITY_GROUPS):
            return self._has_same_identity_group_ids(m_resource, sc_resource)
        elif (resource_type ==
                consts.RESOURCE_TYPE_IDENTITY_PROJECTS):
            return self._has_same_project_ids(m_resource, sc_resource)
        elif (resource_type ==
                consts.RESOURCE_TYPE_IDENTITY_ROLES):
            return self._has_same_role_ids(m_resource, sc_resource)
        elif (resource_type ==
                consts.RESOURCE_TYPE_IDENTITY_PROJECT_ROLE_ASSIGNMENTS):
            return self._has_same_assignment_ids(m_resource, sc_resource)
        elif (resource_type ==
                consts.RESOURCE_TYPE_IDENTITY_TOKEN_REVOKE_EVENTS):
            return self._has_same_revoke_event_ids(m_resource, sc_resource)
        elif (resource_type ==
                consts.RESOURCE_TYPE_IDENTITY_TOKEN_REVOKE_EVENTS_FOR_USER):
            return self._has_same_revoke_event_ids(m_resource, sc_resource)

    def get_resource_id(self, resource_type, resource):
        if hasattr(resource, 'master_id'):
            # If resource from DB, return master resource id
            # from master cloud
            return resource.master_id
        # For token revocation event, use audit_id if it presents.
        if (resource_type ==
                consts.RESOURCE_TYPE_IDENTITY_TOKEN_REVOKE_EVENTS)\
                and resource.audit_id:
            return resource.audit_id
        # For user token revocation event, the id is
        # <user_id>_<issued_before> then base64 encoded
        elif (resource_type ==
                consts.RESOURCE_TYPE_IDENTITY_TOKEN_REVOKE_EVENTS_FOR_USER)\
                and resource.user_id and resource.issued_before:
            event_id = "{}_{}".format(resource.user_id, resource.issued_before)
            return base64.urlsafe_b64encode(
                event_id.encode('utf-8')).decode('utf-8')
        # Default id field retrieved from master cloud
        return resource.id

    def get_resource_info(self, resource_type,
                          resource, operation_type=None):
        rtype = consts.RESOURCE_TYPE_IDENTITY_PROJECT_ROLE_ASSIGNMENTS
        if ((operation_type == consts.OPERATION_TYPE_CREATE or
             operation_type == consts.OPERATION_TYPE_POST or
             operation_type == consts.OPERATION_TYPE_PUT)
           and resource_type != rtype):
            # With the exception of role assignments, for all create
            # requests the resource_info needs to be extracted
            # from the master resource
            resource_info = resource.info()
            return jsonutils.dumps(resource_info)
        else:
            super(IdentitySyncThread, self).get_resource_info(
                resource_type, resource, operation_type)

    def audit_discrepancy(self, resource_type, m_resource, sc_resources):
        # Check if the resource is indeed missing or its details are mismatched
        # from master cloud. If missing, return True to create the resource.
        # If mismatched, queue work to update this resource and return False.
        mismatched_resource = False
        for sc_r in sc_resources:
            if self.has_same_ids(resource_type, m_resource, sc_r):
                mismatched_resource = True
                break

        if mismatched_resource:
            LOG.info("Subcloud res {}:{} is found but diverse in details,"
                     " will update".format(resource_type, sc_r.id),
                     extra=self.log_extra)
            self.schedule_work(self.endpoint_type, resource_type,
                               self.get_resource_id(resource_type, m_resource),
                               consts.OPERATION_TYPE_PUT,
                               self.get_resource_info(
                                   resource_type, sc_r,
                                   consts.OPERATION_TYPE_PUT))
            return False

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
            if self.has_same_ids(resource_type, m_r, sc_r):
                LOG.info("Mapping resource {} to existing subcloud resource {}"
                         .format(m_r, sc_r), extra=self.log_extra)
                # If the resource is not even in master cloud resource DB,
                # create it first.
                rsrc = m_rsrc_db
                if not rsrc:
                    master_id = self.get_resource_id(resource_type, m_r)
                    rsrc = resource.Resource(
                        self.ctxt, resource_type=resource_type,
                        master_id=master_id)
                    rsrc.create()
                    LOG.info("Resource created in DB {}/{}/{}".format(
                        rsrc.id,  # pylint: disable=E1101
                        resource_type, master_id))

                self.persist_db_subcloud_resource(rsrc.id,
                                                  self.get_resource_id(
                                                      resource_type,
                                                      sc_r))
                return True
        return False

    # check if the subcloud resource (from dcorch subcloud_resource table)
    # exists in subcloud resources.
    def resource_exists_in_subcloud(self, subcloud_rsrc, sc_resources):
        exist = False
        for sc_r in sc_resources:
            if subcloud_rsrc.subcloud_resource_id == sc_r.id:
                LOG.debug("Resource {} exists in subcloud {}"
                          .format(subcloud_rsrc.subcloud_resource_id,
                                  self.region_name),
                          extra=self.log_extra)
                exist = True
                break
        return exist

    @staticmethod
    def is_resource_handled_by_dbs_client(resource_type):
        if resource_type in [
                consts.RESOURCE_TYPE_IDENTITY_USERS,
                consts.RESOURCE_TYPE_IDENTITY_GROUPS,
                consts.RESOURCE_TYPE_IDENTITY_PROJECTS,
                consts.RESOURCE_TYPE_IDENTITY_ROLES,
                consts.RESOURCE_TYPE_IDENTITY_TOKEN_REVOKE_EVENTS,
                consts.RESOURCE_TYPE_IDENTITY_TOKEN_REVOKE_EVENTS_FOR_USER]:
            return True
        return False
