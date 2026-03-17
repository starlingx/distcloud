# Copyright (c) 2023-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import http.client as httpclient
import json
import uuid

import ipaddress
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging
from oslo_messaging import RemoteError
import pecan
from pecan import expose
from pecan import request

from dcmanager.api.controllers import restcomm
from dcmanager.api.policies import system_peers as system_peer_policy
from dcmanager.api import policy
from dcmanager.common import consts
from dcmanager.common.i18n import _
from dcmanager.common import utils
from dcmanager.db import api as db_api
from dcmanager.rpc import client as rpc_client

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

# validation constants for System Peer
MAX_SYSTEM_PEER_MANAGER_ENDPOINT_LEN = 255
MAX_SYSTEM_PEER_MANAGER_USERNAME_LEN = 255
MAX_SYSTEM_PEER_MANAGER_PASSWORD_LEN = 255
MAX_SYSTEM_PEER_STRING_DEFAULT_LEN = 255
# validation constants for System Peer Administrative State
# Set to disabled this function will be disabled
#
# We will not support this function in the first release
SYSTEM_PEER_ADMINISTRATIVE_STATE_LIST = ["enabled", "disabled"]
MIN_SYSTEM_PEER_HEARTBEAT_INTERVAL = 10
MAX_SYSTEM_PEER_HEARTBEAT_INTERVAL = 600
MIN_SYSTEM_PEER_HEARTBEAT_FAILURE_THRESHOLD = 1
MAX_SYSTEM_PEER_HEARTBEAT_FAILURE_THRESHOLD = 30
# validation constants for System Peer Heartbeat Failure Policy
# Set to alarm this function will be triggered alarm when the
# heartbeat failure threshold is reached
# Set to rehome this function will be automatically rehome the
# subcloud when the heartbeat failure threshold is reached
# Set to delegate this function will be delegate the system when
# the heartbeat failure threshold is reached
#
# We will only support alarm in the first release
SYSTEM_PEER_HEARTBEAT_FAILURE_POLICY_LIST = ["alarm", "rehome", "delegate"]
MIN_SYSTEM_PEER_HEARTBEAT_MAINTENACE_TIMEOUT = 300
MAX_SYSTEM_PEER_HEARTBEAT_MAINTENACE_TIMEOUT = 36000


class SystemPeersController(restcomm.GenericPathController):

    def __init__(self):
        super(SystemPeersController, self).__init__()

        self.dcmanager_rpc_client = rpc_client.ManagerClient()

    @expose(generic=True, template="json")
    def index(self):
        # Route the request to specific methods with parameters
        pass

    @staticmethod
    def _get_payload(request):
        try:
            payload = json.loads(request.body)
        except Exception:
            error_msg = "Request body is malformed."
            LOG.exception(error_msg)
            pecan.abort(400, _(error_msg))

        if not isinstance(payload, dict):
            pecan.abort(400, _("Invalid request body format"))
        return payload

    def _get_peer_group_list_for_system_peer(self, context, peer_id):
        peer_groups = db_api.peer_group_get_for_system_peer(context, peer_id)
        return utils.subcloud_peer_group_db_list_to_dict(peer_groups)

    def _get_system_peer_list(self, context):
        peers = db_api.system_peer_get_all(context)

        system_peer_list = list()
        for peer in peers:
            peer_dict = db_api.system_peer_db_model_to_dict(peer)
            system_peer_list.append(peer_dict)

        result = dict()
        result["system_peers"] = system_peer_list
        return result

    @index.when(method="GET", template="json")
    def get(self, peer_ref=None, subcloud_peer_groups=False):
        """Retrieve information about a system peer.

        This function allows you to retrieve details about a specific
        system peer or obtain a list of subcloud peer groups associated with
        a specific system peer.

        :param peer_ref: ID or UUID or Name of system peer
        :param subcloud_peer_groups: If this request should return subcloud
                                     peer groups
        ---
        get:
          summary: Get system peers
          description: Retrieve list of all system peers or details of a specific peer
          operationId: getSystemPeers
          tags:
          - system-peers
          parameters:
          - name: peer_ref
            in: query
            description: ID or name of system peer
            required: false
            schema:
              type: string
          - name: subcloud_peer_groups
            in: query
            description: Include subcloud peer groups
            required: false
            schema:
              type: boolean
          responses:
            200:
              description: System peers retrieved successfully
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      system_peers:
                        $ref: '#/components/schemas/system_peers'
                  example:
                    system_peers:
                    - id: 1
                      peer-uuid: 22e8ce03-2691-4d6d-8960-59b7c7fc731e
                      peer-name: DC1-2
                      manager-endpoint: https://[2620:10a:a001:d41::1208]:5000
                      manager-username: admin
                      peer-controller-gateway-address: fd00:8:58::1
                      administrative-state: enabled
                      heartbeat-interval: 60
                      heartbeat-failure-threshold: 3
                      heartbeat-failure-policy: alarm
                      heartbeat-maintenance-timeout: 600
                      availability-state: available
                      created-at: '2026-03-12 19:17:12.027885'
                      updated-at: '2026-03-12 19:21:20.423925'
            404:
              description: System peer not found
            500:
              description: Internal server error
        """
        policy.authorize(
            system_peer_policy.POLICY_ROOT % "get",
            {},
            restcomm.extract_credentials_for_policy(),
        )
        context = restcomm.extract_context_from_environ()

        if peer_ref is None:
            # List of system peers requested
            return self._get_system_peer_list(context)

        peer = utils.system_peer_get_by_ref(context, peer_ref)
        if peer is None:
            pecan.abort(httpclient.NOT_FOUND, _("System Peer not found"))
        if subcloud_peer_groups:
            return self._get_peer_group_list_for_system_peer(context, peer.id)
        system_peer_dict = db_api.system_peer_db_model_to_dict(peer)
        return system_peer_dict

    def _validate_uuid(self, _uuid):
        try:
            uuid.UUID(str(_uuid))
            return True
        except ValueError:
            LOG.exception("Invalid UUID: %s" % _uuid)
            return False

    def _validate_manager_endpoint(self, endpoint):
        if (
            not endpoint
            or len(endpoint) >= MAX_SYSTEM_PEER_MANAGER_ENDPOINT_LEN
            or not endpoint.startswith(("http", "https"))
        ):
            LOG.debug("Invalid manager_endpoint: %s" % endpoint)
            return False
        return True

    def _validate_manager_username(self, username):
        if not username or len(username) >= MAX_SYSTEM_PEER_MANAGER_USERNAME_LEN:
            LOG.debug("Invalid manager_username: %s" % username)
            return False
        return True

    def _validate_manager_password(self, password):
        if not password or len(password) >= MAX_SYSTEM_PEER_MANAGER_PASSWORD_LEN:
            LOG.debug("Invalid manager_password: %s" % password)
            return False
        return True

    def _validate_peer_controller_gateway_ip(self, ip):
        if not ip or len(ip) >= MAX_SYSTEM_PEER_STRING_DEFAULT_LEN:
            LOG.debug("Invalid peer_manager_gateway_address: %s" % ip)
            return False
        try:
            ipaddress.ip_address(ip)
            return True
        except Exception:
            LOG.warning("Invalid IP address: %s" % ip)
            return False

    def _validate_administrative_state(self, administrative_state):
        if administrative_state not in SYSTEM_PEER_ADMINISTRATIVE_STATE_LIST:
            LOG.debug("Invalid administrative_state: %s" % administrative_state)
            return False
        return True

    def _validate_heartbeat_interval(self, heartbeat_interval):
        try:
            # Check the value is an integer
            val = int(heartbeat_interval)
        except ValueError:
            LOG.warning("Invalid heartbeat_interval: %s" % heartbeat_interval)
            return False

        # We do not support less than min or greater than max
        if (
            val < MIN_SYSTEM_PEER_HEARTBEAT_INTERVAL
            or val > MAX_SYSTEM_PEER_HEARTBEAT_INTERVAL
        ):
            LOG.debug("Invalid heartbeat_interval: %s" % heartbeat_interval)
            return False
        return True

    def _validate_heartbeat_failure_threshold(self, heartbeat_failure_threshold):
        try:
            # Check the value is an integer
            val = int(heartbeat_failure_threshold)
        except ValueError:
            LOG.warning(
                "Invalid heartbeat_failure_threshold: %s" % heartbeat_failure_threshold
            )
            return False

        # We do not support less than min or greater than max
        if (
            val < MIN_SYSTEM_PEER_HEARTBEAT_FAILURE_THRESHOLD
            or val > MAX_SYSTEM_PEER_HEARTBEAT_FAILURE_THRESHOLD
        ):
            LOG.debug(
                "Invalid heartbeat_failure_threshold: %s" % heartbeat_failure_threshold
            )
            return False
        return True

    def _validate_heartbeat_failure_policy(self, heartbeat_failure_policy):
        if heartbeat_failure_policy not in SYSTEM_PEER_HEARTBEAT_FAILURE_POLICY_LIST:
            LOG.debug("Invalid heartbeat_failure_policy: %s" % heartbeat_failure_policy)
            return False
        return True

    def _validate_heartbeat_maintenance_timeout(self, heartbeat_maintenance_timeout):
        try:
            # Check the value is an integer
            val = int(heartbeat_maintenance_timeout)
        except ValueError:
            LOG.warning(
                "Invalid heartbeat_maintenance_timeout: %s"
                % heartbeat_maintenance_timeout
            )
            return False

        # We do not support less than min or greater than max
        if (
            val < MIN_SYSTEM_PEER_HEARTBEAT_MAINTENACE_TIMEOUT
            or val > MAX_SYSTEM_PEER_HEARTBEAT_MAINTENACE_TIMEOUT
        ):
            LOG.debug(
                "Invalid heartbeat_maintenance_timeout: %s"
                % heartbeat_maintenance_timeout
            )
            return False
        return True

    @index.when(method="POST", template="json")
    def post(self):
        """Create a new system peer.

        ---
        post:
          summary: Create a new system peer
          description: Create a new system peer connection
          operationId: createSystemPeer
          tags:
          - system-peers
          requestBody:
            required: true
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    peer_name:
                      $ref: '#/components/schemas/peer_name'
                    peer_uuid:
                      $ref: '#/components/schemas/peer_uuid'
                    manager_endpoint:
                      $ref: '#/components/schemas/manager_endpoint'
                    manager_username:
                      $ref: '#/components/schemas/manager_username'
                    manager_password:
                      $ref: '#/components/schemas/manager_password'
                    peer_controller_gateway_address:
                      $ref: '#/components/schemas/peer_controller_gateway_address'
                    administrative_state:
                      $ref: '#/components/schemas/administrative_state'
                    heartbeat_interval:
                      $ref: '#/components/schemas/heartbeat_interval'
                    heartbeat_failure_threshold:
                      $ref: '#/components/schemas/heartbeat_failure_threshold'
                    heartbeat_failure_policy:
                      $ref: '#/components/schemas/heartbeat_failure_policy'
                    heartbeat_maintenance_timeout:
                      $ref: '#/components/schemas/heartbeat_maintenance_timeout'
                example:
                  peer_name: DC1-2-2nd
                  peer_uuid: 22e8ce03-2691-4d6d-8960-59b7c7fc731e
                  manager_endpoint: https://[2620:10a:a001:d41::1208]:5000
                  manager_username: admin
                  manager_password: password
                  peer_controller_gateway_address: fd00:8:58::1
                  administrative_state: enabled
                  heartbeat_interval: 60
                  heartbeat_failure_threshold: 3
                  heartbeat_failure_policy: alarm
                  heartbeat_maintenance_timeout: 600
          responses:
            200:
              description: System peer created successfully
              content:
                application/json:
                  schema:
                    type: object
                  example:
                    id: 3
                    peer-uuid: 22e8ce03-2691-4d6d-8960-59b7c7fc731e
                    peer-name: DC1-2-2nd
                    manager-endpoint: https://[2620:10a:a001:d41::1208]:5000
                    manager-username: admin
                    peer-controller-gateway-address: fd00:8:58::1
                    administrative-state: enabled
                    heartbeat-interval: 60
                    heartbeat-failure-threshold: 3
                    heartbeat-failure-policy: alarm
                    heartbeat-maintenance-timeout: 600
                    availability-state: created
                    created-at: '2026-03-12 20:41:06.142761'
                    updated-at: null
            400:
              description: Bad request - invalid parameters
            409:
              description: Conflict - system peer UUID already exists
            422:
              description: Unprocessable entity
            500:
              description: Internal server error
        """

        context = restcomm.extract_context_from_environ()
        context.is_admin = policy.authorize(
            system_peer_policy.POLICY_ROOT % "create",
            {},
            restcomm.extract_credentials_for_policy(),
        )
        LOG.info("Creating a new system peer: %s" % context)

        payload = self._get_payload(request)
        if not payload:
            pecan.abort(httpclient.BAD_REQUEST, _("Body required"))

        # Validate payload
        peer_uuid = payload.get("peer_uuid")
        if not self._validate_uuid(peer_uuid):
            pecan.abort(httpclient.BAD_REQUEST, _("Invalid peer uuid"))

        peer_name = payload.get("peer_name")
        if not utils.validate_name(peer_name):
            pecan.abort(httpclient.BAD_REQUEST, _("Invalid peer name"))

        endpoint = payload.get("manager_endpoint")
        if not self._validate_manager_endpoint(endpoint):
            pecan.abort(httpclient.BAD_REQUEST, _("Invalid peer manager_endpoint"))

        username = payload.get("manager_username")
        if not self._validate_manager_username(username):
            pecan.abort(httpclient.BAD_REQUEST, _("Invalid peer manager_username"))

        password = payload.get("manager_password")
        if not self._validate_manager_password(password):
            pecan.abort(httpclient.BAD_REQUEST, _("Invalid peer manager_password"))

        gateway_ip = payload.get("peer_controller_gateway_address")
        if not self._validate_peer_controller_gateway_ip(gateway_ip):
            pecan.abort(
                httpclient.BAD_REQUEST,
                _("Invalid peer peer_controller_gateway_address"),
            )

        # Optional request parameters
        kwargs = {}
        administrative_state = payload.get("administrative_state")
        if administrative_state:
            if not self._validate_administrative_state(administrative_state):
                pecan.abort(
                    httpclient.BAD_REQUEST, _("Invalid peer administrative_state")
                )
            kwargs["administrative_state"] = administrative_state

        heartbeat_interval = payload.get("heartbeat_interval")
        if heartbeat_interval is not None:
            if not self._validate_heartbeat_interval(heartbeat_interval):
                pecan.abort(
                    httpclient.BAD_REQUEST, _("Invalid peer heartbeat_interval")
                )
            kwargs["heartbeat_interval"] = heartbeat_interval

        heartbeat_failure_threshold = payload.get("heartbeat_failure_threshold")
        if heartbeat_failure_threshold is not None:
            if not self._validate_heartbeat_failure_threshold(
                heartbeat_failure_threshold
            ):
                pecan.abort(
                    httpclient.BAD_REQUEST,
                    _("Invalid peer heartbeat_failure_threshold"),
                )
            kwargs["heartbeat_failure_threshold"] = heartbeat_failure_threshold

        heartbeat_failure_policy = payload.get("heartbeat_failure_policy")
        if heartbeat_failure_policy:
            if not self._validate_heartbeat_failure_policy(heartbeat_failure_policy):
                pecan.abort(
                    httpclient.BAD_REQUEST, _("Invalid peer heartbeat_failure_policy")
                )
            kwargs["heartbeat_failure_policy"] = heartbeat_failure_policy

        heartbeat_maintenance_timeout = payload.get("heartbeat_maintenance_timeout")
        if heartbeat_maintenance_timeout is not None:
            if not self._validate_heartbeat_maintenance_timeout(
                heartbeat_maintenance_timeout
            ):
                pecan.abort(
                    httpclient.BAD_REQUEST,
                    _("Invalid peer heartbeat_maintenance_timeout"),
                )
            kwargs["heartbeat_maintenance_timeout"] = heartbeat_maintenance_timeout

        try:
            peer_ref = db_api.system_peer_create(
                context,
                peer_uuid,
                peer_name,
                endpoint,
                username,
                password,
                gateway_ip,
                **kwargs
            )
            return db_api.system_peer_db_model_to_dict(peer_ref)
        except db_exc.DBDuplicateEntry:
            LOG.info("Peer create failed. Peer UUID %s already exists" % peer_uuid)
            pecan.abort(
                httpclient.CONFLICT, _("A system peer with this UUID already exists")
            )
        except RemoteError as e:
            pecan.abort(httpclient.UNPROCESSABLE_ENTITY, e.value)
        except Exception as e:
            LOG.exception(e)
            pecan.abort(
                httpclient.INTERNAL_SERVER_ERROR, _("Unable to create system peer")
            )

    @index.when(method="PATCH", template="json")
    def patch(self, peer_ref):
        """Update a system peer.

        :param peer_ref: ID or UUID of system peer to update
        ---
        patch:
          summary: Update a system peer
          description: Update system peer configuration
          operationId: updateSystemPeer
          tags:
          - system-peers
          parameters:
          - name: peer_ref
            in: query
            description: ID or name of system peer
            required: true
            schema:
              type: string
          requestBody:
            required: true
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    peer_name:
                      $ref: '#/components/schemas/peer_name'
                    manager_endpoint:
                      $ref: '#/components/schemas/manager_endpoint'
                    manager_username:
                      $ref: '#/components/schemas/manager_username'
                    manager_password:
                      $ref: '#/components/schemas/manager_password'
                    peer_controller_gateway_address:
                      $ref: '#/components/schemas/peer_controller_gateway_address'
                    administrative_state:
                      $ref: '#/components/schemas/administrative_state'
                    heartbeat_interval:
                      $ref: '#/components/schemas/heartbeat_interval'
                    heartbeat_failure_threshold:
                      $ref: '#/components/schemas/heartbeat_failure_threshold'
                    heartbeat_failure_policy:
                      $ref: '#/components/schemas/heartbeat_failure_policy'
                    heartbeat_maintenance_timeout:
                      $ref: '#/components/schemas/heartbeat_maintenance_timeout'
                example:
                  heartbeat_interval: 61
          responses:
            200:
              description: System peer updated successfully
              content:
                application/json:
                  schema:
                    type: object
                  example:
                    id: 3
                    peer-uuid: 22e8ce03-2691-4d6d-8960-59b7c7fc731e
                    peer-name: DC1-2-2nd
                    manager-endpoint: https://[2620:10a:a001:d41::1208]:5000
                    manager-username: admin
                    peer-controller-gateway-address: fd00:8:58::1
                    administrative-state: enabled
                    heartbeat-interval: 61
                    heartbeat-failure-threshold: 3
                    heartbeat-failure-policy: alarm
                    heartbeat-maintenance-timeout: 600
                    availability-state: created
                    created-at: '2026-03-12 20:41:06.142761'
                    updated-at: '2026-03-12 20:47:38.087695'
            400:
              description: Bad request - invalid parameters
            404:
              description: System peer not found
            422:
              description: Unprocessable entity
            500:
              description: Internal server error
        """

        context = restcomm.extract_context_from_environ()
        context.is_admin = policy.authorize(
            system_peer_policy.POLICY_ROOT % "modify",
            {},
            restcomm.extract_credentials_for_policy(),
        )
        LOG.info("Updating system peer: %s" % context)

        if peer_ref is None:
            pecan.abort(httpclient.BAD_REQUEST, _("System Peer UUID or ID required"))

        payload = self._get_payload(request)
        if not payload:
            pecan.abort(httpclient.BAD_REQUEST, _("Body required"))

        peer = utils.system_peer_get_by_ref(context, peer_ref)
        if peer is None:
            pecan.abort(httpclient.NOT_FOUND, _("System Peer not found"))

        (
            peer_uuid,
            peer_name,
            endpoint,
            username,
            password,
            gateway_ip,
            administrative_state,
            heartbeat_interval,
            heartbeat_failure_threshold,
            heartbeat_failure_policy,
            heartbeat_maintenance_timeout,
        ) = (
            payload.get("peer_uuid"),
            payload.get("peer_name"),
            payload.get("manager_endpoint"),
            payload.get("manager_username"),
            payload.get("manager_password"),
            payload.get("peer_controller_gateway_address"),
            payload.get("administrative_state"),
            payload.get("heartbeat_interval"),
            payload.get("heartbeat_failure_threshold"),
            payload.get("heartbeat_failure_policy"),
            payload.get("heartbeat_maintenance_timeout"),
        )

        if not (
            peer_uuid
            or peer_name
            or endpoint
            or username
            or password
            or administrative_state
            or heartbeat_interval
            or heartbeat_failure_threshold
            or heartbeat_failure_policy
            or heartbeat_maintenance_timeout
            or gateway_ip
        ):
            pecan.abort(httpclient.BAD_REQUEST, _("nothing to update"))

        # Check value is not None or empty before calling validate
        if peer_uuid:
            if not self._validate_uuid(peer_uuid):
                pecan.abort(httpclient.BAD_REQUEST, _("Invalid peer uuid"))

        if peer_name:
            if not utils.validate_name(peer_name):
                pecan.abort(httpclient.BAD_REQUEST, _("Invalid peer name"))

        if endpoint:
            if not self._validate_manager_endpoint(endpoint):
                pecan.abort(httpclient.BAD_REQUEST, _("Invalid peer manager_endpoint"))

        if username:
            if not self._validate_manager_username(username):
                pecan.abort(httpclient.BAD_REQUEST, _("Invalid peer manager_username"))

        if password:
            if not self._validate_manager_password(password):
                pecan.abort(httpclient.BAD_REQUEST, _("Invalid peer manager_password"))

        if gateway_ip:
            if not self._validate_peer_controller_gateway_ip(gateway_ip):
                pecan.abort(
                    httpclient.BAD_REQUEST,
                    _("Invalid peer peer_controller_gateway_address"),
                )

        if administrative_state:
            if not self._validate_administrative_state(administrative_state):
                pecan.abort(
                    httpclient.BAD_REQUEST, _("Invalid peer administrative_state")
                )

        if heartbeat_interval:
            if not self._validate_heartbeat_interval(heartbeat_interval):
                pecan.abort(
                    httpclient.BAD_REQUEST, _("Invalid peer heartbeat_interval")
                )

        if heartbeat_failure_threshold:
            if not self._validate_heartbeat_failure_threshold(
                heartbeat_failure_threshold
            ):
                pecan.abort(
                    httpclient.BAD_REQUEST,
                    _("Invalid peer heartbeat_failure_threshold"),
                )

        if heartbeat_failure_policy:
            if not self._validate_heartbeat_failure_policy(heartbeat_failure_policy):
                pecan.abort(
                    httpclient.BAD_REQUEST, _("Invalid peer heartbeat_failure_policy")
                )

        if heartbeat_maintenance_timeout:
            if not self._validate_heartbeat_maintenance_timeout(
                heartbeat_maintenance_timeout
            ):
                pecan.abort(
                    httpclient.BAD_REQUEST,
                    _("Invalid peer heartbeat_maintenance_timeout"),
                )

        try:
            updated_peer = db_api.system_peer_update(
                context,
                peer.id,
                peer_uuid,
                peer_name,
                endpoint,
                username,
                password,
                gateway_ip,
                administrative_state,
                heartbeat_interval,
                heartbeat_failure_threshold,
                heartbeat_failure_policy,
                heartbeat_maintenance_timeout,
            )

            updated_peer_dict = db_api.system_peer_db_model_to_dict(updated_peer)

            # Set the sync status to out-of-sync if the peer_controller_gateway_ip
            # was updated
            if gateway_ip is not None and gateway_ip != peer.peer_controller_gateway_ip:
                associations = db_api.peer_group_association_get_by_system_peer_id(
                    context, peer.id
                )
                association_ids = set()
                for association in associations:
                    # Update the sync status on both sites
                    association_ids.update(
                        self.dcmanager_rpc_client.update_association_sync_status(
                            context,
                            association.peer_group_id,
                            consts.ASSOCIATION_SYNC_STATUS_OUT_OF_SYNC,
                        )
                    )
                # Generate an informative message to remind the operator
                # that the sync command(s) should be executed.
                info_message = utils.generate_sync_info_message(association_ids)
                if info_message:
                    updated_peer_dict["info_message"] = info_message

            return updated_peer_dict
        except RemoteError as e:
            pecan.abort(httpclient.UNPROCESSABLE_ENTITY, e.value)
        except Exception as e:
            # additional exceptions.
            LOG.exception(e)
            pecan.abort(
                httpclient.INTERNAL_SERVER_ERROR, _("Unable to update system peer")
            )

    @index.when(method="delete", template="json")
    def delete(self, peer_ref):
        """Delete the system peer.

        ---
        delete:
          summary: Delete a system peer
          description: Delete a system peer connection
          operationId: deleteSystemPeer
          tags:
          - system-peers
          parameters:
          - name: peer_ref
            in: query
            description: ID or name of system peer
            required: true
            schema:
              type: string
          responses:
            200:
              description: System peer deleted successfully
              content:
                application/json:
                  schema:
                    type: object
            400:
              description: Bad request - cannot delete peer
            404:
              description: System peer not found
            422:
              description: Unprocessable entity
            500:
              description: Internal server error
        """

        context = restcomm.extract_context_from_environ()
        context.is_admin = policy.authorize(
            system_peer_policy.POLICY_ROOT % "delete",
            {},
            restcomm.extract_credentials_for_policy(),
        )
        LOG.info("Deleting system peer: %s" % context)

        if peer_ref is None:
            pecan.abort(httpclient.BAD_REQUEST, _("System Peer UUID or ID required"))
        peer = utils.system_peer_get_by_ref(context, peer_ref)
        if peer is None:
            pecan.abort(httpclient.NOT_FOUND, _("System Peer not found"))

        # A system peer cannot be deleted if it is used by any associations
        association = db_api.peer_group_association_get_by_system_peer_id(
            context, str(peer.id)
        )
        if len(association) > 0:
            pecan.abort(
                httpclient.BAD_REQUEST,
                _("Cannot delete a system peer which is associated with peer group."),
            )

        try:
            db_api.system_peer_destroy(context, peer.id)
        except RemoteError as e:
            pecan.abort(httpclient.UNPROCESSABLE_ENTITY, e.value)
        except Exception as e:
            LOG.exception(e)
            pecan.abort(
                httpclient.INTERNAL_SERVER_ERROR, _("Unable to delete system peer")
            )
