#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import http.client
import json
import uuid

import mock
from oslo_messaging import RemoteError

from dcmanager.api.controllers.v1 import peer_group_association
from dcmanager.common import consts
from dcmanager.common import phased_subcloud_deploy as psd_common
from dcmanager.db.sqlalchemy import api as db_api
from dcmanager.tests.unit.api.test_root_controller import DCManagerApiTest
from dcmanager.tests.unit.api.v1.controllers.mixins import APIMixin
from dcmanager.tests.unit.api.v1.controllers.mixins import GetMixin

# SAMPLE SYSTEM PEER DATA
SAMPLE_SYSTEM_PEER_UUID = str(uuid.uuid4())
SAMPLE_SYSTEM_PEER_NAME = 'SystemPeer1'
SAMPLE_MANAGER_ENDPOINT = 'http://127.0.0.1:5000'
SAMPLE_MANAGER_USERNAME = 'admin'
SAMPLE_MANAGER_PASSWORD = 'password'
SAMPLE_PEER_CONTROLLER_GATEWAY_IP = '128.128.128.1'
SAMPLE_ADMINISTRATIVE_STATE = 'enabled'
SAMPLE_HEARTBEAT_INTERVAL = 10
SAMPLE_HEARTBEAT_FAILURE_THRESHOLD = 3
SAMPLE_HEARTBEAT_FAILURES_POLICY = 'alarm'
SAMPLE_HEARTBEAT_MAINTENANCE_TIMEOUT = 600
SAMPLE_AVAILABILITY_STATE_AVAILABLE = 'available'

# SAMPLE SUBCLOUD PEER GROUP DATA
SAMPLE_SUBCLOUD_PEER_GROUP_NAME = 'GroupX'
SAMPLE_SUBCLOUD_PEER_GROUP_SYSTEM_LEADER_ID = str(uuid.uuid4())
SAMPLE_SUBCLOUD_PEER_GROUP_SYSTEM_LEADER_NAME = 'dc-local'
SAMPLE_SUBCLOUD_PEER_GROUP_MAX_SUBCLOUDS_REHOMING = 50
SAMPLE_SUBCLOUD_PEER_GROUP_PRIORITY = 0
SAMPLE_SUBCLOUD_PEER_GROUP_STATE = 'enabled'

# SAMPLE PEER GROUP ASSOCIATION DATA
SAMPLE_SUBCLOUD_PEER_GROUP_ID = 1
SAMPLE_SYSTEM_PEER_ID = 1
SAMPLE_PEER_GROUP_PRIORITY = 1
SAMPLE_PEER_GROUP_PRIORITY_UPDATED = 99
SAMPLE_SYNC_STATUS = 'synced'
SAMPLE_SYNC_MESSAGE = 'None'
SAMPLE_ASSOCIATION_TYPE = 'primary'


class PeerGroupAssociationAPIMixin(APIMixin):
    API_PREFIX = '/v1.0/peer-group-associations'
    RESULT_KEY = 'peer_group_associations'
    EXPECTED_FIELDS = [
        'id', 'peer-group-id', 'system-peer-id', 'peer-group-priority',
        'created-at', 'updated-at'
    ]

    def setUp(self):
        super().setUp()

    def _get_test_system_peer_dict(self, **kw):
        # id should not be part of the structure
        system_peer = {
            'peer_uuid': kw.get('peer_uuid', SAMPLE_SYSTEM_PEER_UUID),
            'peer_name': kw.get('peer_name', SAMPLE_SYSTEM_PEER_NAME),
            'endpoint': kw.get('manager_endpoint', SAMPLE_MANAGER_ENDPOINT),
            'username': kw.get('manager_username', SAMPLE_MANAGER_USERNAME),
            'password': kw.get('manager_password', SAMPLE_MANAGER_PASSWORD),
            'gateway_ip': kw.get(
                'peer_controller_gateway_ip', SAMPLE_PEER_CONTROLLER_GATEWAY_IP
            ),
            'administrative_state': kw.get(
                'administrative_state', SAMPLE_ADMINISTRATIVE_STATE
            ),
            'heartbeat_interval': kw.get(
                'heartbeat_interval', SAMPLE_HEARTBEAT_INTERVAL
            ),
            'heartbeat_failure_threshold': kw.get(
                'heartbeat_failure_threshold', SAMPLE_HEARTBEAT_FAILURE_THRESHOLD
            ),
            'heartbeat_failure_policy': kw.get(
                'heartbeat_failure_policy', SAMPLE_HEARTBEAT_FAILURES_POLICY
            ),
            'heartbeat_maintenance_timeout': kw.get(
                'heartbeat_maintenance_timeout', SAMPLE_HEARTBEAT_MAINTENANCE_TIMEOUT
            )
        }
        return system_peer

    def _get_test_subcloud_peer_group_dict(self, **kw):
        # id should not be part of the structure
        group = {
            'peer_group_name': kw.get(
                'peer_group_name', SAMPLE_SUBCLOUD_PEER_GROUP_NAME
            ),
            'system_leader_id': kw.get(
                'system_leader_id', SAMPLE_SUBCLOUD_PEER_GROUP_SYSTEM_LEADER_ID
            ),
            'system_leader_name': kw.get(
                'system_leader_name', SAMPLE_SUBCLOUD_PEER_GROUP_SYSTEM_LEADER_NAME
            ),
            'group_priority': kw.get(
                'group_priority', SAMPLE_SUBCLOUD_PEER_GROUP_PRIORITY
            ),
            'group_state': kw.get(
                'group_state', SAMPLE_SUBCLOUD_PEER_GROUP_STATE
            ),
            'max_subcloud_rehoming': kw.get(
                'max_subcloud_rehoming',
                SAMPLE_SUBCLOUD_PEER_GROUP_MAX_SUBCLOUDS_REHOMING
            ),
            'migration_status': None
        }
        return group

    def _get_test_peer_group_association_dict(self, **kw):
        # id should not be part of the structure
        association = {
            'peer_group_id': kw.get(
                'peer_group_id', SAMPLE_SUBCLOUD_PEER_GROUP_ID
            ),
            'system_peer_id': kw.get('system_peer_id', SAMPLE_SYSTEM_PEER_ID),
            'peer_group_priority': kw.get(
                'peer_group_priority', SAMPLE_PEER_GROUP_PRIORITY
            ),
            'sync_status': kw.get('sync_status', SAMPLE_SYNC_STATUS),
            'sync_message': kw.get('sync_message', SAMPLE_SYNC_MESSAGE),
            'association_type': kw.get('association_type', SAMPLE_ASSOCIATION_TYPE)
        }
        return association

    # The following methods are required for subclasses of APIMixin
    def get_api_prefix(self):
        return self.API_PREFIX

    def get_result_key(self):
        return self.RESULT_KEY

    def get_expected_api_fields(self):
        return self.EXPECTED_FIELDS

    def get_omitted_api_fields(self):
        return []

    def _create_db_related_objects(self, context):
        system_peer_fields = self._get_test_system_peer_dict()
        peer = db_api.system_peer_create(context, **system_peer_fields)

        peer_group_fields = self._get_test_subcloud_peer_group_dict()
        peer_group = db_api.subcloud_peer_group_create(context, **peer_group_fields)

        return peer.id, peer_group.id

    def _create_db_object(self, context, **kw):
        peer_id, peer_group_id = self._create_db_related_objects(context)

        return self._create_peer_group_association(
            context, peer_id, peer_group_id, **kw
        )

    def _create_peer_group_association(self, context, peer_id, peer_group_id, **kw):
        kw['peer_group_id'] = peer_group_id if kw.get('peer_group_id') is None \
            else kw.get('peer_group_id')
        kw['system_peer_id'] = peer_id if kw.get('system_peer_id') is None \
            else kw.get('system_peer_id')
        creation_fields = self._get_test_peer_group_association_dict(**kw)

        return db_api.peer_group_association_create(context, **creation_fields)

    def get_post_object(self):
        return self._get_test_peer_group_association_dict()

    def get_update_object(self):
        update_object = {
            'peer_group_priority': SAMPLE_PEER_GROUP_PRIORITY_UPDATED
        }
        return update_object


class BaseTestPeerGroupAssociationController(
    DCManagerApiTest, PeerGroupAssociationAPIMixin
):
    """Base class for testing PeerGroupAssociationController"""

    def setUp(self):
        super().setUp()

        self.url = self.API_PREFIX

        self._mock_rpc_client()

        self.single_obj = None
        self.peer_id, self.peer_group_id = self._create_db_related_objects(self.ctx)

    def _create_non_primary_association_type(self):
        db_api.peer_group_association_destroy(self.ctx, self.single_obj.id)
        self.single_obj = self._create_peer_group_association(
            self.ctx, self.peer_id, self.peer_group_id,
            association_type=consts.ASSOCIATION_TYPE_NON_PRIMARY
        )


class TestPeerGroupAssociationController(BaseTestPeerGroupAssociationController):
    """"Test class for PeerGroupAssociationController"""

    def setUp(self):
        super().setUp()

    def test_unmapped_method(self):
        """Test requesting an unmapped method results in success with null content"""

        self.method = self.app.put

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(response.text, 'null')


class TestPeerGroupAssociationPost(BaseTestPeerGroupAssociationController):
    """"Test class for post requests"""

    def setUp(self):
        super().setUp()

        self.method = self.app.post_json
        self.params = self.get_post_object()

        db_api.system_peer_update(
            self.ctx, peer_id=self.peer_id,
            availability_state=SAMPLE_AVAILABILITY_STATE_AVAILABLE
        )

    def _validate_peer_group_association(self):
        self.assertEqual(len(db_api.peer_group_association_get_all(self.ctx)), 1)

    def test_post_succeeds(self):
        """Test post succeeds"""

        self.mock_rpc_client().sync_subcloud_peer_group.return_value = \
            self._get_test_peer_group_association_dict()

        response = self._send_request()

        self._assert_response(response)
        self._validate_peer_group_association()
        self.mock_rpc_client().sync_subcloud_peer_group.assert_called_once()
        self.mock_rpc_client().peer_monitor_notify.assert_not_called()

    def test_post_succeeds_with_non_primary_subcloud_peer_group(self):
        """Test post succeeds with non primary subcloud peer group"""

        db_api.subcloud_peer_group_update(
            self.ctx, self.peer_group_id,
            group_priority=peer_group_association.MIN_PEER_GROUP_ASSOCIATION_PRIORITY
        )
        self.params['peer_group_priority'] = None

        response = self._send_request()

        self._assert_response(response)
        self._validate_peer_group_association()
        self.mock_rpc_client().sync_subcloud_peer_group.assert_not_called()
        self.mock_rpc_client().peer_monitor_notify.assert_called_once()

    def test_post_fails_with_invalid_system_peer_id(self):
        """Test post fails with invalid system peer id"""

        bad_values = ['', 'test-system-peer-id']
        for index, bad_value in enumerate(bad_values, start=1):
            self.params['system_peer_id'] = bad_value

            response = self._send_request()

            self._assert_pecan_and_response(
                response, http.client.BAD_REQUEST,
                'Invalid system_peer_id', call_count=index
            )

    @mock.patch.object(db_api, 'system_peer_get')
    def test_post_fails_with_generic_exception_while_validating_system_peer_id(
        self, mock_system_peer_get
    ):
        """Test post fails with  generic exception while validating system_peer_id"""

        mock_system_peer_get.side_effect = Exception()

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, 'Invalid system_peer_id'
        )

    def test_post_fails_with_textual_peer_group_id(self):
        """Test post fails with textual peer group id"""

        # A string peer group priority is not permitted.
        self.params['peer_group_id'] = 'peer-group-id'

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, 'Invalid peer_group_id'
        )

    @mock.patch.object(db_api, 'subcloud_peer_group_get')
    def test_post_fails_with_generic_exception_while_validating_peer_group_id(
        self, mock_subcloud_peer_group_get
    ):
        """Test post fails with generic exception while validating peer_group_id"""

        mock_subcloud_peer_group_get.side_effect = Exception()

        response = self._send_request()

        # TODO(rlima): the correct behavior should be raising an Internal Server
        # Error exception instead of a Bad Request. This also applies to all of the
        # others validations when a generic exception occurs.
        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, 'Invalid peer_group_id'
        )

    def test_post_fails_with_invalid_peer_group_priority(self):
        """Test post fails with invalid peer group priority"""

        # peer_group_priority must be an integer between 1 and 65536
        # All the entries in bad_values should be considered invalid
        # TODO(rlima): a floting point value should also raise an invalid
        # peer_group_priority, but, currently, it doesn't since the validation
        # updates the value to an integer
        bad_values = [65537, -2, 'abc', 0]
        for index, bad_value in enumerate(bad_values, start=1):
            self.params['peer_group_priority'] = bad_value

            response = self._send_request()

            self._assert_pecan_and_response(
                response, http.client.BAD_REQUEST,
                'Invalid peer_group_priority', call_count=index
            )

    def test_post_fails_with_primary_group_priority(self):
        """Test post fails with primary group priority

        When the existing peer group has a primary group priority and the sent
        payload doesn't have one, a bad request should occur
        """

        self.params['peer_group_priority'] = None

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST,
            "Peer Group Association create is not allowed when the subcloud "
            "peer group priority is greater than 0 and it is required when "
            "the subcloud peer group priority is 0."
        )

    @mock.patch.object(json, 'loads')
    def test_post_fails_with_malformed_payload(self, mock_json_loads):
        """Test post fails when the payload is malformed"""

        mock_json_loads.side_effect = Exception()

        self.params = None

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Request body is malformed."
        )
        mock_json_loads.assert_called_once()

    def test_post_fails_with_invalid_payload(self):
        """Test post fails when the payload is invalid"""

        self.params = 'invalid payload'

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Invalid request body format"
        )

    def test_post_fails_without_payload(self):
        """Test post fails when the payload is empty"""

        self.params = {}

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Body required"
        )

    @mock.patch.object(
        db_api, 'peer_group_association_get_by_peer_group_and_system_peer_id'
    )
    def test_post_fails_with_get_by_peer_group_and_system_peer_id_exception(
        self, mock_peer_group_association_get
    ):
        """Test post fails with a generic exception

        When peer_group_association_get_by_peer_group_and_system_peer_id raises a
        generic exception, the execution should stop with an internal server error
        """

        mock_peer_group_association_get.side_effect = Exception()

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.INTERNAL_SERVER_ERROR,
            "peer_group_association_get_by_peer_group_and_system_peer_id failed: "
        )

    def test_post_fails_with_existing_association(self):
        """Test post fails when an association exists"""

        self._create_peer_group_association(
            self.ctx, self.peer_id, self.peer_group_id
        )

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "A Peer group association with same "
            "peer_group_id, system_peer_id already exists"
        )

    def test_post_fails_with_remote_error_for_rpc_client(self):
        """Test post fails with a remote error for rpc_client"""

        self.mock_rpc_client().sync_subcloud_peer_group.side_effect = \
            RemoteError('msg', 'value')

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.UNPROCESSABLE_ENTITY, 'value'
        )

    def test_post_fails_with_generic_exception_for_rpc_client(self):
        """Test post fails with a generic exception for rpc_client"""

        self.mock_rpc_client().sync_subcloud_peer_group.side_effect = Exception()

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.INTERNAL_SERVER_ERROR,
            'Unable to create peer group association'
        )


class TestPeerGroupAssociationGet(BaseTestPeerGroupAssociationController, GetMixin):
    """"Test class for get requests"""

    def setUp(self):
        super().setUp()

        self.method = self.app.get

        db_api.system_peer_destroy(self.ctx, self.peer_id)
        db_api.subcloud_peer_group_destroy(self.ctx, self.peer_group_id)

    def test_get_fails_with_association_id_not_being_digit(self):
        """Test get fails when the association id is not a digit"""

        self.url = f'{self.url}/fake'

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST,
            "Peer Group Association ID must be an integer"
        )


class BaseTestPeerGroupAssociationPatch(BaseTestPeerGroupAssociationController):
    """"Base test class for patch requests"""

    def setUp(self):
        super().setUp()

        self.single_obj = self._create_peer_group_association(
            self.ctx, self.peer_id, self.peer_group_id
        )

        self.url = f'{self.url}/{self.single_obj.id}'
        self.method = self.app.patch_json
        self.params = self.get_update_object()

        self._mock_openstack_driver(psd_common)
        self._mock_sysinv_client(peer_group_association)

        mock_get_system = mock.MagicMock()
        mock_get_system.uuid = SAMPLE_SUBCLOUD_PEER_GROUP_SYSTEM_LEADER_ID

        self.mock_sysinv_client().get_system.return_value = mock_get_system


class TestPeerGroupAssociationPatch(BaseTestPeerGroupAssociationPatch):
    """"Test class for patch requests"""

    def setUp(self):
        super().setUp()

    def _validate_peer_group_association(self):
        peer_group_association = db_api.peer_group_association_get(
            self.ctx, self.peer_group_id
        )

        for key, value in self.params.items():
            self.assertEqual(peer_group_association[key], value)

    def test_patch_succeeds(self):
        """Test patch succeeds"""

        self.mock_rpc_client().sync_subcloud_peer_group_only.return_value = \
            self._get_test_peer_group_association_dict()

        response = self._send_request()

        self._assert_response(response)
        self._validate_peer_group_association()

    def test_patch_succeeds_for_sync_status_when_non_primary(self):
        """Test patch succeeds for sync status when non primary"""

        self._create_non_primary_association_type()

        self.params.pop('peer_group_priority')
        self.params['sync_status'] = consts.ASSOCIATION_SYNC_STATUS_IN_SYNC

        response = self._send_request()

        self._assert_response(response)
        self._validate_peer_group_association()
        self.mock_rpc_client().peer_monitor_notify.assert_called_once()
        self.mock_rpc_client().update_subcloud_peer_group.assert_not_called()

    def test_patch_fails_with_empty_payload(self):
        """Test patch fails with an empty payload"""

        self.params = {}

        response = self._send_request()

        # Failures will return text rather than json
        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, 'Body required'
        )

    def test_patch_fails_without_valid_association_id(self):
        """Test patch fails without a valid association_id"""

        self.url = f'{self.API_PREFIX}/fake'

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST,
            "Peer Group Association ID must be an integer"
        )

    def test_patch_fails_with_peer_group_association_not_found(self):
        """Test patch fails with peer group association not found"""

        self.url = f'{self.API_PREFIX}/999'

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.NOT_FOUND,
            "Peer Group Association not found"
        )

    def test_patch_fails_with_nothing_to_update(self):
        """Test patch fails with nothing to update"""

        self.params = {'fake key': 'fake value'}

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "nothing to update"
        )

    def test_patch_fails_with_invalid_peer_group_priority_in_payload(self):
        """Test patch fails with invalid peer group priority in payload"""

        # peer_group_priority must be an integer between 1 and 65536
        # All the entries in bad_values should be considered invalid
        bad_values = [65537, -2, 'abc', 0]
        for index, bad_value in enumerate(bad_values, start=1):
            self.params['peer_group_priority'] = bad_value

            response = self._send_request()

            self._assert_pecan_and_response(
                response, http.client.BAD_REQUEST,
                'Invalid peer_group_priority', call_count=index
            )

    def test_patch_fails_with_peer_group_priority_and_sync_status(self):
        """Test patch fails with peer group priority and sync status"""

        self.params['sync_status'] = consts.ASSOCIATION_SYNC_STATUS_SYNCING

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST,
            "peer_group_priority and sync_status cannot be updated at the same time."
        )

    def test_patch_fails_for_peer_group_priority_when_non_primary(self):
        """Test patch fails for peer group priority when non primary"""

        self._create_non_primary_association_type()

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST,
            "Peer Group Association peer_group_priority is not allowed to update "
            "when the association type is non-primary."
        )
        self.mock_rpc_client().peer_monitor_notify.assert_called_once()

    def test_patch_fails_for_invalid_sync_status(self):
        """Test patch fails for invalid sync status"""

        self.params.pop('peer_group_priority')
        self.params['sync_status'] = 'fake value'

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Invalid sync_status"
        )

    def test_patch_fails_for_sync_status_when_primary(self):
        """Test patch fails for sync status when association type is primary"""

        self.params.pop('peer_group_priority')
        self.params['sync_status'] = consts.ASSOCIATION_SYNC_STATUS_IN_SYNC

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST,
            "Peer Group Association sync_status is not allowed "
            "to update when the association type is primary."
        )
        self.mock_rpc_client().peer_monitor_notify.assert_called_once()

    def test_patch_fails_with_remote_error_for_rpc_client_update(self):
        """Test patch fails with a remote error for rpc_client"""

        self.mock_rpc_client().sync_subcloud_peer_group_only.side_effect = \
            RemoteError('msg', 'value')

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.UNPROCESSABLE_ENTITY, 'value'
        )

    def test_patch_fails_with_generic_exception_for_rpc_client_update(self):
        """Test patch fails with a generic exception for rpc_client"""

        self.mock_rpc_client().sync_subcloud_peer_group_only.side_effect = \
            Exception()

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.INTERNAL_SERVER_ERROR,
            "Unable to update peer group association"
        )


class TestPeerGroupAssociationPatchSync(BaseTestPeerGroupAssociationPatch):
    """"Test class for patch requests with sync verb"""

    def setUp(self):
        super().setUp()

        self.url = f"{self.url}/sync"

    def test_patch_sync_succeeds(self):
        """Test patch sync succeeds"""

        response = self._send_request()

        self._assert_response(response)
        self.mock_rpc_client().sync_subcloud_peer_group.assert_called_once()

    def test_patch_sync_fails_without_valid_peer_group_leader_id(self):
        """Test patch sync fails without a valid peer group leader id"""

        db_api.subcloud_peer_group_update(
            self.ctx, SAMPLE_SUBCLOUD_PEER_GROUP_ID,
            system_leader_id=str(uuid.uuid4())
        )

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST,
            "Peer Group Association sync is not allowed when the subcloud "
            "peer group system_leader_id is not the current system controller UUID."
        )

    def test_patch_sync_fails_with_non_primary_association_type(self):
        """Test patch sync fails with non primary association type"""

        self._create_non_primary_association_type()

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST,
            "Peer Group Association sync is not allowed when the association type "
            "is non-primary. But the peer monitor notify was triggered."
        )
        self.mock_rpc_client().peer_monitor_notify.assert_called_once()

    def test_patch_sync_fails_with_remote_error_for_rpc_client_sync(self):
        """Test patch sync fails with remote error for rpc_client"""

        self.mock_rpc_client().sync_subcloud_peer_group.side_effect = \
            RemoteError('msg', 'value')

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.UNPROCESSABLE_ENTITY, 'value'
        )

    def test_patch_sync_fails_with_generic_exception_for_rpc_client_sync(self):
        """Test patch sync fails with a generic exception for rpc_client"""

        self.mock_rpc_client().sync_subcloud_peer_group.side_effect = Exception()

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.INTERNAL_SERVER_ERROR,
            "Unable to sync peer group association"
        )


class TestPeerGroupAssociationDelete(BaseTestPeerGroupAssociationController):
    """"Test class for delete requests"""

    def setUp(self):
        super().setUp()

        self.single_obj = self._create_peer_group_association(
            self.ctx, self.peer_id, self.peer_group_id
        )

        self.url = f'{self.url}/{self.single_obj.id}'
        self.method = self.app.delete
        self.params = {}

        self.mock_rpc_client().delete_peer_group_association.return_value = \
            self._get_test_peer_group_association_dict()

    def test_delete_succeeds(self):
        """Test delete succeeds"""

        response = self._send_request()

        self._assert_response(response)
        self.mock_rpc_client().delete_peer_group_association.assert_called_once()

    def test_delete_succeeds_with_non_primary_association_type(self):
        """Test delete succeeds with non primary association type"""

        self._create_non_primary_association_type()

        response = self._send_request()

        self._assert_response(response)
        self.mock_rpc_client().peer_monitor_notify.assert_called_once()
        self.mock_rpc_client().delete_peer_group_association.assert_not_called()
        self.assertEqual(len(db_api.peer_group_association_get_all(self.ctx)), 0)

    def test_delete_fails_when_called_twice_for_the_same_object(self):
        """Test delete fails when called twice for the same object"""

        response = self._send_request()

        self.mock_rpc_client().delete_peer_group_association.assert_called_once()
        self._assert_response(response)

        db_api.peer_group_association_destroy(self.ctx, self.single_obj.id)

        # delete the same object a second time. this should fail (NOT_FOUND)
        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.NOT_FOUND, 'Peer Group Association not found'
        )

    def test_delete_fails_without_valid_association_id(self):
        """Test delete fails without a valid association_id"""

        self.url = f'{self.API_PREFIX}/fake'

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST,
            "Peer Group Association ID must be an integer"
        )

    def test_delete_fails_with_remote_error_on_delete(self):
        """Test delete fails with remote error for rpc_client"""

        self.mock_rpc_client().delete_peer_group_association.side_effect = \
            RemoteError('msg', 'value')

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.UNPROCESSABLE_ENTITY, 'value'
        )

    def test_delete_fails_with_generic_exception_on_delete(self):
        """Test delete fails with generic exception for rpc_client"""

        self.mock_rpc_client().delete_peer_group_association.side_effect = \
            Exception()

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.INTERNAL_SERVER_ERROR,
            "Unable to delete peer group association"
        )
