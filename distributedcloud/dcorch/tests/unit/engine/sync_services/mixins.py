# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from keystoneauth1 import exceptions as keystone_exceptions

from oslo_serialization import jsonutils

import dcorch.common.exceptions as exceptions

from dcdbsync.dbsyncclient import exceptions as dbsync_exceptions


class BaseMixin(object):
    """Base mixin class to declare common methods for generic resource requests"""

    def _get_request(self):
        """Returns the request object"""

        raise NotImplementedError

    def _get_rsrc(self):
        """Returns the rsrc object"""

        raise NotImplementedError

    def _get_log(self):
        """Returns the log object"""

        raise NotImplementedError

    def _get_subcloud(self):
        """Returns the subcloud object"""

        raise NotImplementedError

    def _get_subcloud_resource(self):
        """Returns the subcloud resouce object"""

        raise NotImplementedError

    def _get_resource_name(self):
        """Returns the resource name"""

        raise NotImplementedError

    def _get_resource_ref(self):
        """Returns the resource ref mock"""

        raise NotImplementedError

    def _get_resource_ref_name(self):
        """Returns the resource ref name path"""

        raise NotImplementedError

    def _resource_add(self):
        """Returns the resource's add method"""

        raise NotImplementedError

    def _resource_detail(self):
        """Returns the resource's detail method"""

        raise NotImplementedError

    def _resource_update(self):
        """Returns the resource's update method"""

        raise NotImplementedError

    def _resource_keystone_update(self):
        """Returns the resource's update method from Keystone"""

        raise NotImplementedError

    def _resource_keystone_delete(self):
        """Returns the resource's delete method from Keystone"""

        raise NotImplementedError

    def _execute(self):
        """Executes the method"""

        raise NotImplementedError

    def _execute_and_assert_exception(self, exception):
        """Executes the method"""

        raise NotImplementedError

    def _assert_log(self, level, message, extra=mock.ANY):
        """Asserts the log's call"""

        raise NotImplementedError


class PostResourceMixin(BaseMixin):
    """Base mixin class for post requests to a resource"""

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
            f"{self._get_resource_ref().get(self._get_resource_name()).get('id')} "
            f"[{self._get_resource_ref_name()}]",
        )

    def test_post_fails_without_source_resource_id(self):
        """Test post fails without source resource id"""

        self._get_request().orch_job.source_resource_id = None

        self._execute_and_assert_exception(exceptions.SyncRequestFailed)
        self._assert_log(
            "error",
            f"Received {self._get_resource_name()} create request "
            "without required 'source_resource_id' field",
        )

    def test_post_fails_with_dbsync_unauthorized_exception(self):
        """Test post fails with dbsync unauthorized exception"""

        self._resource_detail().side_effect = dbsync_exceptions.Unauthorized()

        self._execute_and_assert_exception(dbsync_exceptions.UnauthorizedMaster)

        self._resource_detail().assert_called_once()
        self._resource_add().assert_not_called()

    def test_post_fails_with_empty_resource_ref(self):
        """Test post fails with empty resource ref"""

        self._resource_add().return_value = None

        self._execute_and_assert_exception(exceptions.SyncRequestFailed)
        self._assert_log(
            "error",
            f"No {self._get_resource_name()} data returned when creating "
            f"{self._get_resource_name()} "
            f"{self._get_request().orch_job.source_resource_id} in subcloud.",
        )

    def test_post_fails_without_resource_records(self):
        """Test post fails without resource records"""

        self._resource_detail().return_value = None

        self._execute_and_assert_exception(exceptions.SyncRequestFailed)
        self._assert_log(
            "error",
            "No data retrieved from master cloud for "
            f"{self._get_resource_name()} "
            f"{self._get_request().orch_job.source_resource_id} to create its "
            "equivalent in subcloud.",
        )


class PutResourceMixin(BaseMixin):
    """Base mixin class for put requests to a resource"""

    def test_put_succeeds(self):
        """Test put succeeds"""

        self._resource_update().return_value = self._get_resource_ref()

        self._execute()

        self._resource_detail().assert_called_once()
        self._resource_update().assert_called_once()
        self._assert_log(
            "info",
            f"Updated Keystone {self._get_resource_name()} {self.rsrc.id}:"
            f"{self._get_resource_ref().get(self._get_resource_name()).get('id')} "
            f"[{self._get_resource_ref_name()}]",
        )

    def test_put_fails_without_source_resource_id(self):
        """Test put fails without source resource id"""

        self._get_request().orch_job.source_resource_id = None

        self._execute_and_assert_exception(exceptions.SyncRequestFailed)
        self._assert_log(
            "error",
            f"Received {self._get_resource_name()} update request "
            "without required source resource id",
        )

    def test_put_fails_without_id_in_resource_info(self):
        """Test put fails without id in resource info"""

        print(f"{{{self._get_resource_name()}: {{}}}}")
        self._get_request().orch_job.resource_info = (
            f'{{"{self._get_resource_name()}": {{}}}}'
        )

        self._execute_and_assert_exception(exceptions.SyncRequestFailed)
        self._assert_log(
            "error",
            f"Received {self._get_resource_name()} update request "
            "without required subcloud resource id",
        )

    def test_put_fails_with_dbsync_unauthorized_exception(self):
        """Test put fails with dbsync unauthorized exception"""

        self._resource_detail().side_effect = dbsync_exceptions.Unauthorized

        self._execute_and_assert_exception(dbsync_exceptions.UnauthorizedMaster)

        self._resource_detail().assert_called_once()
        self._resource_update().assert_not_called()

    def test_put_fails_without_resource_records(self):
        """Test put fails without resource records"""

        self._resource_detail().return_value = None

        self._execute_and_assert_exception(exceptions.SyncRequestFailed)
        self._assert_log(
            "error",
            "No data retrieved from master cloud for "
            f"{self._get_resource_name()} "
            f"{self._get_request().orch_job.source_resource_id} "
            "to update its equivalent in subcloud.",
        )

    def test_put_fails_without_resource_ref(self):
        """Test put fails without resource ref"""

        self._resource_update().return_value = None

        self._execute_and_assert_exception(exceptions.SyncRequestFailed)
        self._assert_log(
            "error",
            f"No {self._get_resource_name()} data returned when updating "
            f"{self._get_resource_name()} "
            f"{self._get_resource_ref().get(self._get_resource_name()).get('id')} "
            "in subcloud.",
        )


class PatchResourceMixin(BaseMixin):
    """Base mixin class for patch requests to a resource"""

    def test_patch_succeeds(self):
        """Test patch succeeds"""

        mock_update = mock.Mock()
        mock_update.id = self._get_subcloud_resource().subcloud_resource_id
        self._resource_keystone_update().return_value = mock_update

        self._execute()

        self._resource_keystone_update().assert_called_once()
        self._assert_log(
            "info",
            f"Updated Keystone {self._get_resource_name()}: "
            f"{self._get_rsrc().id}:{mock_update.id}",
        )

    def test_patch_fails_with_empty_resource_update_dict(self):
        """Test patch fails with empty resource update dict"""

        self._get_request().orch_job.resource_info = "{}"

        self._execute_and_assert_exception(exceptions.SyncRequestFailed)
        self._assert_log(
            "error",
            f"Received {self._get_resource_name()} update request "
            "without any update fields",
        )

    def test_patch_fails_without_resource_subcloud_rsrc(self):
        """Test patch fails with empty resource update dict

        When the resource id and subcloud id does not match to a subcloud resource,
        the resource subcloud rsrc is not found
        """

        loaded_resource_info = jsonutils.loads(
            self._get_request().orch_job.resource_info
        )

        self._get_rsrc().id = 9999

        self._execute()

        self._assert_log(
            "error",
            f"Unable to update {self._get_resource_name()} reference "
            f"{self.rsrc}:{loaded_resource_info[self._get_resource_name()]}, cannot "
            f"find equivalent Keystone {self._get_resource_name()} in subcloud.",
        )

    def test_patch_fails_with_resource_ref_id_not_equal_resource_id(self):
        """Test patch fails with resource ref id not equal resource id"""

        mock_update = mock.Mock()
        mock_update.id = 9999
        self._resource_keystone_update().return_value = mock_update

        self._execute()

        self._assert_log(
            "error",
            f"Unable to update Keystone {self._get_resource_name()} "
            f"{self._get_rsrc().id}:"
            f"{self._get_subcloud_resource().subcloud_resource_id} for subcloud",
        )


class DeleteResourceMixin(BaseMixin):
    """Base mixin class for delete requests to a resource"""

    def test_delete_succeeds(self):
        """Test delete succeeds"""

        self._execute()

        self._resource_keystone_delete().assert_called_once()
        self._assert_log(
            "info",
            f"Keystone {self._get_resource_name()} {self._get_rsrc().id}:"
            f"{self._get_subcloud_resource().id} "
            f"[{self._get_subcloud_resource().subcloud_resource_id}] deleted",
        )

    def test_delete_succeeds_with_keystone_not_found_exception(self):
        """Test delete succeeds with keystone's not found exception"""

        self._resource_keystone_delete().side_effect = keystone_exceptions.NotFound()

        self._execute()

        self._resource_keystone_delete().assert_called_once()
        self._get_log().assert_has_calls(
            [
                mock.call.info(
                    f"Delete {self._get_resource_name()}: {self._get_resource_name()} "
                    f"{self._get_subcloud_resource().subcloud_resource_id} "
                    f"not found in {self._get_subcloud().region_name}, "
                    "considered as deleted.",
                    extra=mock.ANY,
                ),
                mock.call.info(
                    f"Keystone {self._get_resource_name()} {self._get_rsrc().id}:"
                    f"{self._get_subcloud_resource().id} "
                    f"[{self._get_subcloud_resource().subcloud_resource_id}] deleted",
                    extra=mock.ANY,
                ),
            ],
            any_order=False,
        )

    def test_delete_fails_without_resource_subcloud_rsrc(self):
        """Test delete fails without resource subcloud rsrc

        When the resource id and subcloud id does not match to a subcloud resource,
        the user subcloud rsrc is not found
        """

        self._get_rsrc().id = 9999

        self._execute()

        self._assert_log(
            "error",
            f"Unable to delete {self._get_resource_name()} reference "
            f"{self._get_rsrc()}, cannot find equivalent Keystone "
            f"{self._get_resource_name()} in subcloud.",
        )
