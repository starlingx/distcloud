# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from keystoneauth1 import exceptions as keystone_exceptions
from keystoneclient import client as keystone_client
from oslo_serialization import jsonutils

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.keystone_v3 import EndpointCache
from dccommon.drivers.openstack import sdk_platform
from dccommon import endpoint_cache
from dcdbsync.dbsyncclient import exceptions as dbsync_exceptions
from dcmanager.rpc import client as dcmanager_rpc_client
import dcorch.common.exceptions as exceptions
import dcorch.db.api as db_api
import dcorch.engine.sync_services.identity as identity_service
from dcorch.engine.sync_thread import dbsyncclient
import dcorch.objects.subcloud_resource as subcloud_resource
from dcorch.tests.base import OrchestratorTestCase
import dcorch.tests.unit.engine.sync_services.mixins as mixins

SOURCE_RESOURCE_ID = 2
RESOURCE_ID = 3
MASTER_ID = 4


class BaseTestIdentitySyncThread(OrchestratorTestCase, mixins.BaseMixin):
    """Base test class for IdentitySyncThread"""

    def setUp(self):
        super().setUp()

        self._mock_object(sdk_platform, "OpenStackDriver")
        self._mock_object(keystone_client, "Client")
        self._mock_object(EndpointCache, "get_admin_session")
        self._mock_object(endpoint_cache.EndpointCache, "get_admin_session")
        self._mock_object(dbsyncclient, "Client")
        self._mock_object(identity_service, "Client")
        self._mock_object(dcmanager_rpc_client, "SubcloudStateClient")
        self._mock_object(dcmanager_rpc_client, "ManagerClient")
        self.mock_log = self._mock_object(identity_service, "LOG")

        self._create_request_and_resource_mocks()
        self._create_subcloud_and_subcloud_resource()

        self.identity_sync_thread = identity_service.IdentitySyncThread(
            self.subcloud.region_name,
            management_ip=self.subcloud.management_ip,
            subcloud_id=self.subcloud.id,
        )

        self.method = lambda *args: None
        self.resource_name = ""
        self.resource_ref = None
        self.resource_ref_name = None
        self.resource_add = lambda: None
        self.resource_detail = lambda: None
        self.resource_update = lambda: None
        self.resource_keystone_update = lambda: None
        self.resource_keystone_delete = lambda: None

    def _create_request_and_resource_mocks(self):
        self.request = mock.MagicMock()
        self.request.orch_job.resource_info = f'{{"id": {RESOURCE_ID}}}'
        self.request.orch_job.source_resource_id = SOURCE_RESOURCE_ID

        self.rsrc = mock.MagicMock
        self.rsrc.id = RESOURCE_ID
        self.rsrc.master_id = MASTER_ID

        self.cached_m_rsrc = mock.MagicMock()
        self.cached_m_rsrc.id = SOURCE_RESOURCE_ID

    def _create_subcloud_and_subcloud_resource(self):
        values = {
            "software_version": "10.04",
            "management_state": dccommon_consts.MANAGEMENT_MANAGED,
            "availability_status": dccommon_consts.AVAILABILITY_ONLINE,
            "initial_sync_state": "",
            "capabilities": {},
            "management_ip": "192.168.0.1",
        }
        self.subcloud = db_api.subcloud_create(self.ctx, "subcloud", values)
        self.subcloud_resource = subcloud_resource.SubcloudResource(
            self.ctx,
            subcloud_resource_id=self.rsrc.master_id,
            resource_id=self.rsrc.id,
            subcloud_id=self.subcloud.id,
        )
        self.subcloud_resource.create()

    def _get_request(self):
        return self.request

    def _get_rsrc(self):
        return self.rsrc

    def _get_log(self):
        return self.mock_log

    def _get_subcloud(self):
        return self.subcloud

    def _get_subcloud_resource(self):
        return self.subcloud_resource

    def _get_resource_name(self):
        return self.resource_name

    def _get_resource_ref(self):
        return self.resource_ref

    def _get_resource_ref_name(self):
        return self.resource_ref_name

    def _resource_add(self):
        return self.resource_add

    def _resource_detail(self):
        return self.resource_detail

    def _resource_update(self):
        return self.resource_update

    def _resource_keystone_update(self):
        return self.resource_keystone_update

    def _resource_keystone_delete(self):
        return self.resource_keystone_delete

    def _execute(self):
        self.method(self.request, self.rsrc)

    def _execute_and_assert_exception(self, exception):
        self.assertRaises(exception, self.method, self.request, self.rsrc)

    def _assert_log(self, level, message, extra=mock.ANY):
        if level == "info":
            self.mock_log.info.assert_called_with(message, extra=extra)
        elif level == "error":
            self.mock_log.error.assert_called_with(message, extra=extra)
        elif level == "debug":
            self.mock_log.debug.assert_called_with(message, extra=extra)


class BaseTestIdentitySyncThreadUsers(BaseTestIdentitySyncThread):
    """Base test class for users' requests"""

    def setUp(self):
        super().setUp()

        self.resource_name = "user"
        self.resource_ref = {
            self.resource_name: {"id": RESOURCE_ID},
            "local_user": {"name": "fake value"},
        }
        self.resource_ref_name = self.resource_ref.get("local_user").get("name")

        self.cached_m_rsrc.resource_name = self.resource_name
        self.cached_m_rsrc.to_dict = mock.MagicMock(return_value=self.resource_ref)
        self.identity_sync_thread.get_cached_master_resources = mock.MagicMock(
            return_value=[self.cached_m_rsrc]
        )


class TestIdentitySyncThreadUsersPost(
    BaseTestIdentitySyncThreadUsers, mixins.PostResourceMixin
):
    """Test class for users' post method"""

    def setUp(self):
        super().setUp()

        self.method = self.identity_sync_thread.post_users
        self.sc_dbs_client = self.identity_sync_thread.get_sc_dbs_client()
        self.resource_add = self.sc_dbs_client.identity_user_manager.add_user


class TestIdentitySyncThreadUsersPut(
    BaseTestIdentitySyncThreadUsers, mixins.PutResourceMixin
):
    """Test class for users' put method"""

    def setUp(self):
        super().setUp()

        self.method = self.identity_sync_thread.put_users
        self.sc_dbs_client = self.identity_sync_thread.get_sc_dbs_client()
        self.resource_update = self.sc_dbs_client.identity_user_manager.update_user


class TestIdentitySyncThreadUsersPatch(
    BaseTestIdentitySyncThreadUsers, mixins.PatchResourceMixin
):
    """Test class for users' patch method"""

    def setUp(self):
        super().setUp()

        self.method = self.identity_sync_thread.patch_users
        self.request.orch_job.resource_info = f'{{"{self.resource_name}": {{}}}}'
        self.resource_keystone_update = (
            self.identity_sync_thread.get_sc_ks_client().users.update
        )


class TestIdentitySyncThreadUsersDelete(
    BaseTestIdentitySyncThreadUsers, mixins.DeleteResourceMixin
):
    """Test class for users' delete method"""

    def setUp(self):
        super().setUp()

        self.method = self.identity_sync_thread.delete_users
        self.resource_keystone_delete = (
            self.identity_sync_thread.get_sc_ks_client().users.delete
        )


class BaseTestIdentitySyncThreadGroups(BaseTestIdentitySyncThread):
    """Base test class for groups' methods"""

    def setUp(self):
        super().setUp()

        self.resource_name = "group"
        self.resource_ref = {
            self.resource_name: {"id": RESOURCE_ID, "name": "fake value"}
        }
        self.resource_ref_name = self.resource_ref.get(self.resource_name).get("name")

        self.cached_m_rsrc.resource_name = self.resource_name
        self.cached_m_rsrc.to_dict = mock.MagicMock(return_value=self.resource_ref)
        self.identity_sync_thread.get_cached_master_resources = mock.MagicMock(
            return_value=[self.cached_m_rsrc]
        )


class TestIdentitySyncThreadGroupsPost(
    BaseTestIdentitySyncThreadGroups, mixins.PostResourceMixin
):
    """Test class for groups' post method"""

    def setUp(self):
        super().setUp()

        self.method = self.identity_sync_thread.post_groups
        self.sc_dbs_client = self.identity_sync_thread.get_sc_dbs_client()
        self.resource_add = self.sc_dbs_client.identity_group_manager.add_group


class TestIdentitySyncThreadGroupsPut(
    BaseTestIdentitySyncThreadGroups, mixins.PutResourceMixin
):
    """Test class for groups' put method"""

    def setUp(self):
        super().setUp()

        self.method = self.identity_sync_thread.put_groups
        self.sc_dbs_client = self.identity_sync_thread.get_sc_dbs_client()
        self.resource_update = self.sc_dbs_client.identity_group_manager.update_group


class TestIdentitySyncThreadGroupsPatch(
    BaseTestIdentitySyncThreadGroups, mixins.PatchResourceMixin
):
    """Test class for groups' patch method"""

    def setUp(self):
        super().setUp()

        self.method = self.identity_sync_thread.patch_groups
        self.request.orch_job.resource_info = f'{{"{self.resource_name}": {{}}}}'
        self.resource_keystone_update = (
            self.identity_sync_thread.get_sc_ks_client().groups.update
        )


class TestIdentitySyncThreadGroupsDelete(
    BaseTestIdentitySyncThreadGroups, mixins.DeleteResourceMixin
):
    """Test class for groups' delete method"""

    def setUp(self):
        super().setUp()

        self.method = self.identity_sync_thread.delete_groups
        self.resource_keystone_delete = (
            self.identity_sync_thread.get_sc_ks_client().groups.delete
        )


class BaseTestIdentitySyncThreadProjects(BaseTestIdentitySyncThread):
    """Base test class for projects' methods"""

    def setUp(self):
        super().setUp()

        self.resource_name = "project"
        self.resource_ref = {
            self.resource_name: {"id": RESOURCE_ID, "name": "fake value"}
        }
        self.resource_ref_name = self.resource_ref.get(self.resource_name).get("name")

        self.cached_m_rsrc.resource_name = self.resource_name
        self.cached_m_rsrc.to_dict = mock.MagicMock(return_value=self.resource_ref)
        self.identity_sync_thread.get_cached_master_resources = mock.MagicMock(
            return_value=[self.cached_m_rsrc]
        )


class TestIdentitySyncThreadProjectsPost(
    BaseTestIdentitySyncThreadProjects, mixins.PostResourceMixin
):
    """Test class for projects' post method"""

    def setUp(self):
        super().setUp()

        self.method = self.identity_sync_thread.post_projects
        self.resource_add = (
            self.identity_sync_thread.get_sc_dbs_client().project_manager.add_project
        )


class TestIdentitySyncThreadProjectsPut(
    BaseTestIdentitySyncThreadProjects, mixins.PutResourceMixin
):
    """Test class for projects' put method"""

    def setUp(self):
        super().setUp()

        self.method = self.identity_sync_thread.put_projects
        self.resource_update = (
            self.identity_sync_thread.get_sc_dbs_client().project_manager.update_project
        )


class TestIdentitySyncThreadProjectsPatch(
    BaseTestIdentitySyncThreadProjects, mixins.PatchResourceMixin
):
    """Test class for projects' patch method"""

    def setUp(self):
        super().setUp()

        self.method = self.identity_sync_thread.patch_projects
        self.request.orch_job.resource_info = f'{{"{self.resource_name}": {{}}}}'
        self.resource_keystone_update = (
            self.identity_sync_thread.get_sc_ks_client().projects.update
        )


class TestIdentitySyncThreadProjectsDelete(
    BaseTestIdentitySyncThreadProjects, mixins.DeleteResourceMixin
):
    """Test class for projects' delete method"""

    def setUp(self):
        super().setUp()

        self.method = self.identity_sync_thread.delete_projects
        self.resource_keystone_delete = (
            self.identity_sync_thread.get_sc_ks_client().projects.delete
        )


class BaseTestIdentitySyncThreadRoles(BaseTestIdentitySyncThread):
    """Base test class for roles' methods"""

    def setUp(self):
        super().setUp()

        self.resource_name = "role"
        self.resource_ref = {
            self.resource_name: {"id": RESOURCE_ID, "name": "fake value"}
        }
        self.resource_ref_name = self.resource_ref.get(self.resource_name).get("name")
        self.cached_m_rsrc.resource_name = self.resource_name
        self.cached_m_rsrc.to_dict = mock.MagicMock(return_value=self.resource_ref)
        self.identity_sync_thread.get_cached_master_resources = mock.MagicMock(
            return_value=[self.cached_m_rsrc]
        )


class TestIdentitySyncThreadRolesPost(
    BaseTestIdentitySyncThreadRoles, mixins.PostResourceMixin
):
    """Test class for roles' post method"""

    def setUp(self):
        super().setUp()

        self.method = self.identity_sync_thread.post_roles
        self.resource_add = (
            self.identity_sync_thread.get_sc_dbs_client().role_manager.add_role
        )


class TestIdentitySyncThreadRolesPut(
    BaseTestIdentitySyncThreadRoles, mixins.PutResourceMixin
):
    """Test class for roles' put method"""

    def setUp(self):
        super().setUp()

        self.method = self.identity_sync_thread.put_roles
        self.resource_update = (
            self.identity_sync_thread.get_sc_dbs_client().role_manager.update_role
        )


class TestIdentitySyncThreadRolesPatch(
    BaseTestIdentitySyncThreadRoles, mixins.PatchResourceMixin
):
    """Test class for roles' patch method"""

    def setUp(self):
        super().setUp()

        self.method = self.identity_sync_thread.patch_roles
        self.request.orch_job.resource_info = f'{{"{self.resource_name}": {{}}}}'
        self.resource_keystone_update = (
            self.identity_sync_thread.get_sc_ks_client().roles.update
        )


class TestIdentitySyncThreadRolesDelete(
    BaseTestIdentitySyncThreadRoles, mixins.DeleteResourceMixin
):
    """Test class for roles' delete method"""

    def setUp(self):
        super().setUp()

        self.method = self.identity_sync_thread.delete_roles
        self.resource_keystone_delete = (
            self.identity_sync_thread.get_sc_ks_client().roles.delete
        )


class BaseTestIdentitySyncThreadProjectRoleAssignments(BaseTestIdentitySyncThread):
    """Base test class for project role assignments' methods"""

    def setUp(self):
        super().setUp()

        self.project_id = 10
        self.actor_id = 11
        self.role_id = 12
        self.domain = 13

        self.resource_tags = f"{self.project_id}_{self.actor_id}_{self.role_id}"


class TestIdentitySyncThreadProjectRoleAssignmentsPost(
    BaseTestIdentitySyncThreadProjectRoleAssignments
):
    """Test class for project role assignments' post method"""

    def setUp(self):
        super().setUp()

        self.method = self.identity_sync_thread.post_project_role_assignments
        self.rsrc.master_id = self.resource_tags

        self.mock_sc_role = self._create_mock_object(self.role_id)
        self.sc_ks_client = self.identity_sync_thread.get_sc_ks_client()
        self.sc_ks_client.roles.list.return_value = [self.mock_sc_role]
        self.sc_ks_client.projects.list.return_value = [
            self._create_mock_object(self.project_id)
        ]
        self.sc_ks_client.domains.list.return_value = [
            self._create_mock_object(self.project_id)
        ]
        self.sc_ks_client.users.list.return_value = [
            self._create_mock_object(self.actor_id)
        ]

    def _create_mock_object(self, id):
        mock_object = mock.MagicMock()
        mock_object.id = str(id)

        return mock_object

    def test_post_succeeds_with_sc_user(self):
        """Test post succeeds with sc user"""

        self._execute()
        self._assert_log(
            "info",
            f"Created Keystone role assignment {self.rsrc.id}:"
            f"{self.rsrc.master_id} [{self.rsrc.master_id}]",
        )

    def test_post_succeeds_with_sc_group(self):
        """Test post succeeds with sc group"""

        self.sc_ks_client.users.list.return_value = []
        self.sc_ks_client.groups.list.return_value = [
            self._create_mock_object(self.actor_id)
        ]

        self._execute()
        self._assert_log(
            "info",
            f"Created Keystone role assignment {self.rsrc.id}:"
            f"{self.rsrc.master_id} [{self.rsrc.master_id}]",
        )

    def test_post_fails_with_invalid_resource_tags(self):
        """Test post fails with invalid resource tags"""

        self.rsrc.master_id = f"{self.project_id}_{self.actor_id}"

        self._execute_and_assert_exception(exceptions.SyncRequestFailed)
        self._assert_log(
            "error",
            f"Malformed resource tag {self.rsrc.id} expected to be in "
            "format: ProjectID_UserID_RoleID.",
        )

    def test_post_fails_without_sc_role(self):
        """Test post fails without sc role"""

        self.sc_ks_client.roles.list.return_value = []

        self._execute_and_assert_exception(exceptions.SyncRequestFailed)
        self._assert_log(
            "error",
            "Unable to assign role to user on project reference "
            f"{self.rsrc}:{self.role_id}, cannot "
            "find equivalent Keystone Role in subcloud.",
        )

    def test_post_fails_without_sc_proj(self):
        """Test post fails without sc proj"""

        self.sc_ks_client.projects.list.return_value = []

        self._execute_and_assert_exception(exceptions.SyncRequestFailed)
        self._assert_log(
            "error",
            "Unable to assign role to user on project reference "
            f"{self.rsrc}:{self.project_id}, cannot "
            "find equivalent Keystone Project in subcloud",
        )

    def test_post_fails_wihtout_sc_user_and_sc_group(self):
        """Test post fails without sc user and sc group"""

        self.sc_ks_client.users.list.return_value = []

        self._execute_and_assert_exception(exceptions.SyncRequestFailed)
        self._assert_log(
            "error",
            "Unable to assign role to user/group on project "
            f"reference {self.rsrc}:{self.actor_id}, cannot find "
            "equivalent Keystone User/Group in subcloud.",
        )

    def test_post_fails_without_role_ref(self):
        """Test post fails without role ref"""

        self.sc_ks_client.role_assignments.list.return_value = []

        self._execute_and_assert_exception(exceptions.SyncRequestFailed)
        self._assert_log(
            "error",
            "Unable to update Keystone role assignment "
            f"{self.rsrc.id}:{self.mock_sc_role}",
        )


class TestIdentitySyncThreadProjectRoleAssignmentsPut(
    BaseTestIdentitySyncThreadProjectRoleAssignments
):
    """Test class for project role assignments' put method"""

    def setUp(self):
        super().setUp()

        self.method = self.identity_sync_thread.put_project_role_assignments
        self.subcloud_resource.subcloud_resource_id = self.resource_tags

    def test_put_succeeds(self):
        """Test put succeeds

        Currently, there isn't an implementation for the put method. Because of
        that, it only returns an empty response.
        """

        self._execute()

        self._assert_log("debug", "IdentitySyncThread initialized")
        self.mock_log.error.assert_not_called()


class TestIdentitySyncThreadProjectRoleAssignmentsDelete(
    BaseTestIdentitySyncThreadProjectRoleAssignments
):
    """Test class for project role assignments' delete method"""

    def setUp(self):
        super().setUp()

        self.method = self.identity_sync_thread.delete_project_role_assignments

        self.sc_ks_client = self.identity_sync_thread.get_sc_ks_client()
        self.subcloud_resource.subcloud_resource_id = self.resource_tags
        self.subcloud_resource.save()

    def test_delete_succeeds(self):
        """Test delete succeeds"""

        self.sc_ks_client.role_assignments.list.return_value = []

        self._execute()

        self._assert_log(
            "info",
            "Deleted Keystone role assignment: "
            f"{self.rsrc.id}:{self.subcloud_resource}",
        )

    def test_delete_succeeds_without_assignment_subcloud_rsrc(self):
        """Test delete succeeds without assignment subcloud rsrc"""

        self.rsrc.id = 999

        self._execute()

        self._assert_log(
            "error",
            f"Unable to delete assignment {self.rsrc}, "
            "cannot find Keystone Role Assignment in subcloud.",
        )

    def test_delete_succeeds_with_invalid_resource_tags(self):
        """Test delete succeeds with invalid resource tags"""

        self.subcloud_resource.subcloud_resource_id = MASTER_ID
        self.subcloud_resource.save()

        self._execute()

        self._assert_log(
            "error",
            f"Malformed subcloud resource tag {self.subcloud_resource}, "
            "expected to be in format: ProjectID_UserID_RoleID or "
            "ProjectID_GroupID_RoleID.",
        )

    def test_delete_for_user_succeeds_with_keystone_not_found_exception(self):
        """Test delete fails for user with keystone not found exception"""

        self.sc_ks_client.roles.revoke.side_effect = [
            keystone_exceptions.NotFound,
            None,
        ]
        self.sc_ks_client.role_assignments.list.return_value = []

        self._execute()

        self.mock_log.assert_has_calls(
            [
                mock.call.info(
                    f"Revoke role assignment: (role {self.role_id}, "
                    f"user {self.actor_id}, project {self.project_id}) "
                    f"not found in {self.subcloud.region_name}, "
                    "considered as deleted.",
                    extra=mock.ANY,
                ),
                mock.call.info(
                    f"Deleted Keystone role assignment: {self.rsrc.id}:"
                    f"{self.subcloud_resource}",
                    extra=mock.ANY,
                ),
            ],
            any_order=False,
        )

    def test_delete_for_group_succeeds_with_keystone_not_found_exception(self):
        """Test delete fails for group with keystone not found exception"""

        self.sc_ks_client.roles.revoke.side_effect = keystone_exceptions.NotFound

        self._execute()

        self.mock_log.assert_has_calls(
            [
                mock.call.info(
                    f"Revoke role assignment: (role {self.role_id}, "
                    f"group {self.actor_id}, project {self.project_id}) "
                    f"not found in {self.subcloud.region_name}, "
                    "considered as deleted.",
                    extra=mock.ANY,
                ),
                mock.call.info(
                    f"Deleted Keystone role assignment: {self.rsrc.id}:"
                    f"{self.subcloud_resource}",
                    extra=mock.ANY,
                ),
            ],
            any_order=False,
        )

    def test_delete_fails_without_role_ref(self):
        """Test delete fails without role ref"""

        self._execute_and_assert_exception(exceptions.SyncRequestFailed)

        self._assert_log(
            "error",
            "Unable to delete Keystone role assignment "
            f"{self.rsrc.id}:{self.role_id} ",
        )


class BaseTestIdentitySyncThreadRevokeEvents(BaseTestIdentitySyncThread):
    """Base test class for revoke events' methods"""

    def setUp(self):
        super().setUp()

        self.resource_name = "token revocation event"
        self.resource_ref = {
            "revocation_event": {"audit_id": RESOURCE_ID, "name": "fake value"}
        }
        self.resource_ref_name = self.resource_ref.get("revocation_event").get("name")

        self.cached_m_rsrc.resource_name = self.resource_name
        self.cached_m_rsrc.to_dict = mock.MagicMock(return_value=self.resource_ref)
        self.cached_m_rsrc.audit_id = RESOURCE_ID

        self.identity_sync_thread.get_cached_master_resources = mock.MagicMock(
            return_value=[self.cached_m_rsrc]
        )


class BaseTestIdentitySyncThreadRevokeEventsPost(
    BaseTestIdentitySyncThreadRevokeEvents, mixins.PostResourceMixin
):
    """Test class for revoke events' post method"""

    def setUp(self):
        super().setUp()

        self.resource_info = {"token_revoke_event": {"audit_id": RESOURCE_ID}}
        self.request.orch_job.resource_info = jsonutils.dumps(self.resource_info)
        self.method = self.identity_sync_thread.post_revoke_events
        self.sc_dbs_client = self.identity_sync_thread.get_sc_dbs_client()
        self.resource_add = self.sc_dbs_client.revoke_event_manager.add_revoke_event

    def test_post_succeeds(self):
        """Test post succeeds"""

        self._resource_add().return_value = self._get_resource_ref()

        self._execute()

        self._resource_add().assert_called_once()

        self._assert_log(
            "info",
            f"Created Keystone {self._get_resource_name()} "
            f"{self._get_rsrc().id}:"
            f"{self.resource_info.get('token_revoke_event').get('audit_id')}",
        )

    def test_post_fails_without_source_resource_id(self):
        """Test post fails without source resource id"""

        self._get_request().orch_job.resource_info = "{}"

        self._execute_and_assert_exception(exceptions.SyncRequestFailed)
        self._assert_log(
            "error",
            f"Received {self._get_resource_name()} create request "
            "without required subcloud resource id",
        )

    def test_post_fails_with_empty_resource_ref(self):
        """Test post fails with empty resource ref"""

        self._resource_add().return_value = None

        self._execute_and_assert_exception(exceptions.SyncRequestFailed)
        self._assert_log(
            "error",
            f"No {self._get_resource_name()} data returned when creating "
            f"{self._get_resource_name()} with audit_id "
            f"{self.resource_info.get('token_revoke_event').get('audit_id')} "
            "in subcloud.",
        )

    def test_post_fails_without_resource_records(self):
        """Test post fails without resource records"""

        self._resource_detail().return_value = None
        self.identity_sync_thread.get_cached_master_resources = mock.MagicMock(
            return_value=None
        )

        self._execute_and_assert_exception(exceptions.SyncRequestFailed)
        self._assert_log(
            "error",
            "No data retrieved from master cloud for "
            f"{self._get_resource_name()} with audit_id "
            f"{self.resource_info.get('token_revoke_event').get('audit_id')} "
            "to create its equivalent in subcloud.",
        )


class BaseTestIdentitySyncThreadRevokeEventsDelete(
    BaseTestIdentitySyncThreadRevokeEvents, mixins.DeleteResourceMixin
):
    """Test class for revoke events' delete method"""

    def setUp(self):
        super().setUp()

        self.method = self.identity_sync_thread.delete_revoke_events
        self.sc_dbs_client = self.identity_sync_thread.get_sc_dbs_client()
        self.resource_keystone_delete = (
            self.sc_dbs_client.revoke_event_manager.delete_revoke_event
        )

    def test_delete_succeeds_with_keystone_not_found_exception(self):
        """Test delete succeeds with keystone's not found exception

        The revoke events doesn't use the keystone client
        """

    def test_delete_succeeds_with_dbsync_not_found_exception(self):
        """Test delete succeeds with dbsync's not found exception"""

        self._resource_keystone_delete().side_effect = dbsync_exceptions.NotFound()

        self._execute()

        self._resource_keystone_delete().assert_called_once()
        self._get_log().assert_has_calls(
            [
                mock.call.info(
                    f"Delete {self._get_resource_name()}: event "
                    f"{self._get_subcloud_resource().subcloud_resource_id} "
                    f"not found in {self._get_subcloud().region_name}, "
                    "considered as deleted.",
                    extra=mock.ANY,
                ),
                mock.call.info(
                    f"Keystone {self._get_resource_name()} {self._get_rsrc().id}:"
                    f"{self._get_subcloud().id} "
                    f"[{self._get_subcloud_resource().subcloud_resource_id}] deleted",
                    extra=mock.ANY,
                ),
            ],
            any_order=False,
        )


class BaseTestIdentitySyncThreadRevokeEventsForUser(BaseTestIdentitySyncThread):
    """Base test class for revoke events for user' methods"""

    def setUp(self):
        super().setUp()

        self.resource_name = "token revocation event"
        self.resource_ref = {
            "revocation_event": {"audit_id": RESOURCE_ID, "name": "fake value"}
        }
        self.resource_ref_name = self.resource_ref.get("revocation_event").get("name")
        self.dbs_client = self.identity_sync_thread.get_master_dbs_client()
        self.resource_detail = self.dbs_client.revoke_event_manager.revoke_event_detail


class TestIdentitySyncThreadRevokeEventsForUserPost(
    BaseTestIdentitySyncThreadRevokeEventsForUser, mixins.PostResourceMixin
):
    """Test class for revoke events for user' post method"""

    def setUp(self):
        super().setUp()

        self.method = self.identity_sync_thread.post_revoke_events_for_user
        self.sc_dbs_client = self.identity_sync_thread.get_sc_dbs_client()
        self.resource_add = self.sc_dbs_client.revoke_event_manager.add_revoke_event

    def test_post_succeeds(self):
        """Test post succeeds"""

        self._resource_add().return_value = self._get_resource_ref()

        self._execute()

        self._resource_detail().assert_called_once()
        self._resource_add().assert_called_once()

        self._assert_log(
            "info",
            f"Created Keystone {self._get_resource_name()} "
            f"{self._get_rsrc().id}:"
            f"{self._get_request().orch_job.source_resource_id}",
        )

    def test_post_fails_without_source_resource_id(self):
        """Test post fails without source resource id"""

        self._get_request().orch_job.source_resource_id = None

        self._execute_and_assert_exception(exceptions.SyncRequestFailed)
        self._assert_log(
            "error",
            f"Received {self._get_resource_name()} create request "
            "without required subcloud resource id",
        )

    def test_post_fails_with_empty_resource_ref(self):
        """Test post fails with empty resource ref"""

        self._resource_add().return_value = None

        self._execute_and_assert_exception(exceptions.SyncRequestFailed)
        self._assert_log(
            "error",
            f"No {self._get_resource_name()} data returned when creating "
            f"{self._get_resource_name()} with event_id "
            f"{self._get_request().orch_job.source_resource_id} in subcloud.",
        )

    def test_post_fails_without_resource_records(self):
        """Test post fails without resource records"""

        self._resource_detail().return_value = None

        self._execute_and_assert_exception(exceptions.SyncRequestFailed)
        self._assert_log(
            "error",
            "No data retrieved from master cloud for "
            f"{self._get_resource_name()} with event_id "
            f"{self._get_request().orch_job.source_resource_id} to create its "
            "equivalent in subcloud.",
        )


class TestIdentitySyncThreadRevokeEventsForUserDelete(
    BaseTestIdentitySyncThreadRevokeEventsForUser, mixins.DeleteResourceMixin
):
    """Test class for revoke events for user' delete method"""

    def setUp(self):
        super().setUp()

        self.method = self.identity_sync_thread.delete_revoke_events_for_user
        self.sc_dbs_client = self.identity_sync_thread.get_sc_dbs_client()
        self.resource_keystone_delete = (
            self.sc_dbs_client.revoke_event_manager.delete_revoke_event
        )

    def test_delete_succeeds_with_keystone_not_found_exception(self):
        """Test delete succeeds with keystone's not found exception

        The revoke events for users doesn't use the keystone client
        """

    def test_delete_succeeds_with_dbsync_not_found_exception(self):
        """Test delete succeeds with dbsync's not found exception"""

        self._resource_keystone_delete().side_effect = dbsync_exceptions.NotFound()

        self._execute()

        self._resource_keystone_delete().assert_called_once()
        self._get_log().assert_has_calls(
            [
                mock.call.info(
                    f"Delete {self._get_resource_name()}: event "
                    f"{self._get_subcloud_resource().subcloud_resource_id} "
                    f"not found in {self._get_subcloud().region_name}, "
                    "considered as deleted.",
                    extra=mock.ANY,
                ),
                mock.call.info(
                    f"Keystone {self._get_resource_name()} {self._get_rsrc().id}:"
                    f"{self._get_subcloud().id} "
                    f"[{self._get_subcloud_resource().subcloud_resource_id}] deleted",
                    extra=mock.ANY,
                ),
            ],
            any_order=False,
        )
