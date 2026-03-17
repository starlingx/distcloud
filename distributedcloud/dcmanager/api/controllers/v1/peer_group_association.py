#
# Copyright (c) 2023-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import http.client as httpclient
import json

from oslo_config import cfg
from oslo_log import log as logging
from oslo_messaging import RemoteError
import pecan
from pecan import expose
from pecan import request

from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon.endpoint_cache import EndpointCache
from dccommon import utils
from dcmanager.api.controllers import restcomm
from dcmanager.api.policies import (
    peer_group_association as peer_group_association_policy,
)
from dcmanager.api import policy
from dcmanager.common import consts
from dcmanager.common import exceptions as exception
from dcmanager.common.i18n import _
from dcmanager.db import api as db_api
from dcmanager.rpc import client as rpc_client

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

MIN_PEER_GROUP_ASSOCIATION_PRIORITY = 1
MAX_PEER_GROUP_ASSOCIATION_PRIORITY = 65536
ASSOCIATION_SYNC_STATUS_LIST = [
    consts.ASSOCIATION_SYNC_STATUS_SYNCING,
    consts.ASSOCIATION_SYNC_STATUS_IN_SYNC,
    consts.ASSOCIATION_SYNC_STATUS_OUT_OF_SYNC,
    consts.ASSOCIATION_SYNC_STATUS_FAILED,
    consts.ASSOCIATION_SYNC_STATUS_UNKNOWN,
]


class PeerGroupAssociationsController(restcomm.GenericPathController):

    def __init__(self):
        super(PeerGroupAssociationsController, self).__init__()
        self.rpc_client = rpc_client.ManagerClient()

    @expose(generic=True, template="json")
    def index(self):
        # Route the request to specific methods with parameters
        pass

    def _get_peer_group_association_list(self, context):
        associations = db_api.peer_group_association_get_all(context)
        association_list = []

        for association in associations:
            association_dict = db_api.peer_group_association_db_model_to_dict(
                association
            )
            # Remove the sync_message from the list response
            association_dict.pop("sync-message", None)
            association_list.append(association_dict)

        result = {"peer_group_associations": association_list}
        return result

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

    def _validate_peer_group_leader_id(self, system_leader_id):
        admin_session = EndpointCache.get_admin_session()
        sysinv_client = SysinvClient(
            utils.get_region_one_name(),
            admin_session,
        )
        system = sysinv_client.get_system()
        return True if system.uuid == system_leader_id else False

    @index.when(method="GET", template="json")
    def get(self, association_id=None):
        """Get details about peer group association.

        :param association_id: ID of peer group association
        ---
        get:
          summary: Get peer group associations
          description: >-
            Retrieve list of all peer group associations
            or details of a specific association
          operationId: getPeerGroupAssociations
          tags:
          - peer-group-associations
          parameters:
          - name: association_id
            in: query
            description: ID of peer group association
            required: false
            schema:
              type: integer
          responses:
            200:
              description: Associations retrieved successfully
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      peer_group_associations:
                        $ref: '#/components/schemas/peer_group_associations'
                  example:
                    peer_group_associations:
                    - id: 1
                      peer-group-id: 1
                      system-peer-id: 1
                      peer-group-priority: 1
                      association-type: primary
                      sync-status: in-sync
                      created-at: '2026-03-12 19:21:18.992598'
                      updated-at: '2026-03-12 19:21:20.406960'
            400:
              description: Bad request - invalid association ID
            404:
              description: Association not found
            500:
              description: Internal server error
        """
        policy.authorize(
            peer_group_association_policy.POLICY_ROOT % "get",
            {},
            restcomm.extract_credentials_for_policy(),
        )
        context = restcomm.extract_context_from_environ()

        if association_id is None:
            # List of peer group association requested
            return self._get_peer_group_association_list(context)
        elif not association_id.isdigit():
            pecan.abort(
                httpclient.BAD_REQUEST,
                _("Peer Group Association ID must be an integer"),
            )

        try:
            association = db_api.peer_group_association_get(context, association_id)
        except exception.PeerGroupAssociationNotFound:
            pecan.abort(httpclient.NOT_FOUND, _("Peer Group Association not found"))

        return db_api.peer_group_association_db_model_to_dict(association)

    def _validate_peer_group_id(self, context, peer_group_id):
        try:
            db_api.subcloud_peer_group_get(context, peer_group_id)
        except exception.SubcloudPeerGroupNotFound:
            LOG.debug(
                "Subcloud Peer Group Not Found, peer group id: %s" % peer_group_id
            )
            return False
        except Exception as e:
            LOG.warning(
                "Get Subcloud Peer Group failed: %s; peer_group_id: %s"
                % (e, peer_group_id)
            )
            return False
        return True

    def _validate_system_peer_id(self, context, system_peer_id):
        try:
            db_api.system_peer_get(context, system_peer_id)
        except exception.SystemPeerNotFound:
            LOG.debug("System Peer Not Found, system peer id: %s" % system_peer_id)
            return False
        except Exception as e:
            LOG.warning(
                "Get System Peer failed: %s; system_peer_id: %s" % (e, system_peer_id)
            )
            return False
        return True

    def _validate_peer_group_priority(self, peer_group_priority):
        try:
            # Check the value is an integer
            val = int(peer_group_priority)
        except ValueError:
            LOG.debug("Peer Group Priority is not Integer: %s" % peer_group_priority)
            return False
        # Less than min or greater than max priority is not supported.
        if (
            val < MIN_PEER_GROUP_ASSOCIATION_PRIORITY
            or val > MAX_PEER_GROUP_ASSOCIATION_PRIORITY
        ):
            LOG.debug(
                "Invalid Peer Group Priority out of support range: %s"
                % peer_group_priority
            )
            return False
        return True

    def _validate_sync_status(self, sync_status):
        if sync_status not in ASSOCIATION_SYNC_STATUS_LIST:
            LOG.debug("Invalid sync_status: %s" % sync_status)
            return False
        return True

    @index.when(method="POST", template="json")
    def post(self):
        """Create a new peer group association.

        ---
        post:
          summary: Create a new peer group association
          description: Create a new association between peer groups
          operationId: createPeerGroupAssociation
          tags:
          - peer-group-associations
          requestBody:
            required: true
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    system_peer_id:
                      $ref: '#/components/schemas/system_peer_id'
                    peer_group_id:
                      $ref: '#/components/schemas/association_peer_group_id'
                    peer_group_priority:
                      $ref: '#/components/schemas/association_peer_group_priority'
                example:
                  system_peer_id: 3
                  peer_group_id: '1'
                  peer_group_priority: '1'
          responses:
            200:
              description: Association created successfully
              content:
                application/json:
                  schema:
                    type: object
                  example:
                    id: 2
                    peer-group-id: '1'
                    system-peer-id: 3
                    peer-group-priority: '1'
                    association-type: primary
                    sync-status: syncing
                    sync-message: null
                    created-at: '2026-03-12 21:00:21.338674'
                    updated-at: null
            400:
              description: Bad request - invalid parameters
            422:
              description: Unprocessable entity
            500:
              description: Internal server error
        """

        context = restcomm.extract_context_from_environ()
        context.is_admin = policy.authorize(
            peer_group_association_policy.POLICY_ROOT % "create",
            {},
            restcomm.extract_credentials_for_policy(),
        )

        payload = self._get_payload(request)
        if not payload:
            pecan.abort(httpclient.BAD_REQUEST, _("Body required"))

        # Validate payload
        peer_group_id = payload.get("peer_group_id")
        if not self._validate_peer_group_id(context, peer_group_id):
            pecan.abort(httpclient.BAD_REQUEST, _("Invalid peer_group_id"))

        system_peer_id = payload.get("system_peer_id")
        if not self._validate_system_peer_id(context, system_peer_id):
            pecan.abort(httpclient.BAD_REQUEST, _("Invalid system_peer_id"))

        peer_group_priority = payload.get("peer_group_priority")
        peer_group = db_api.subcloud_peer_group_get(context, peer_group_id)

        if peer_group_priority is not None and not self._validate_peer_group_priority(
            peer_group_priority
        ):
            pecan.abort(httpclient.BAD_REQUEST, _("Invalid peer_group_priority"))

        if (
            peer_group.group_priority == consts.PEER_GROUP_PRIMARY_PRIORITY
            and peer_group_priority is None
        ) or (
            peer_group.group_priority > consts.PEER_GROUP_PRIMARY_PRIORITY
            and peer_group_priority is not None
        ):
            pecan.abort(
                httpclient.BAD_REQUEST,
                _(
                    "Peer Group Association create is not allowed when the subcloud "
                    "peer group priority is greater than 0 and it is required when "
                    "the subcloud peer group priority is 0."
                ),
            )

        is_primary = peer_group.group_priority == consts.PEER_GROUP_PRIMARY_PRIORITY

        # only one combination of peer_group_id + system_peer_id can exists
        association = None
        try:
            association = (
                db_api.peer_group_association_get_by_peer_group_and_system_peer_id(
                    context, peer_group_id, system_peer_id
                )
            )
        except exception.PeerGroupAssociationCombinationNotFound:
            # This is a normal scenario, no need to log or raise an error
            pass
        except Exception as e:
            LOG.warning(
                "Peer Group Association get failed: %s;"
                "peer_group_id: %s, system_peer_id: %s"
                % (e, peer_group_id, system_peer_id)
            )
            pecan.abort(
                httpclient.INTERNAL_SERVER_ERROR,
                _(
                    "peer_group_association_get_by_peer_group_and_"
                    "system_peer_id failed: %s" % e
                ),
            )
        if association:
            LOG.warning(
                "Failed to create Peer group association, association with "
                "peer_group_id:[%s],system_peer_id:[%s] already exists"
                % (peer_group_id, system_peer_id)
            )
            pecan.abort(
                httpclient.BAD_REQUEST,
                _(
                    "A Peer group association with same peer_group_id, "
                    "system_peer_id already exists"
                ),
            )

        # Create the peer group association
        try:
            association_type = (
                consts.ASSOCIATION_TYPE_PRIMARY
                if is_primary
                else consts.ASSOCIATION_TYPE_NON_PRIMARY
            )
            association = db_api.peer_group_association_create(
                context,
                peer_group_id,
                system_peer_id,
                peer_group_priority,
                association_type,
                consts.ASSOCIATION_SYNC_STATUS_SYNCING,
            )

            if is_primary:
                # Sync the subcloud peer group to peer site
                self.rpc_client.sync_subcloud_peer_group(context, association.id)
            else:
                self.rpc_client.peer_monitor_notify(context)
            return db_api.peer_group_association_db_model_to_dict(association)
        except RemoteError as e:
            pecan.abort(httpclient.UNPROCESSABLE_ENTITY, e.value)
        except Exception as e:
            LOG.exception(e)
            pecan.abort(
                httpclient.INTERNAL_SERVER_ERROR,
                _("Unable to create peer group association"),
            )

    def _sync_association(self, context, association, is_non_primary):
        if is_non_primary:
            self.rpc_client.peer_monitor_notify(context)
            pecan.abort(
                httpclient.BAD_REQUEST,
                _(
                    "Peer Group Association sync is not allowed when the association "
                    "type is non-primary. But the peer monitor notify was triggered."
                ),
            )
        else:
            peer_group = db_api.subcloud_peer_group_get(
                context, association.peer_group_id
            )
            if not self._validate_peer_group_leader_id(peer_group.system_leader_id):
                pecan.abort(
                    httpclient.BAD_REQUEST,
                    _(
                        "Peer Group Association sync is not allowed when "
                        "the subcloud peer group system_leader_id is not "
                        "the current system controller UUID."
                    ),
                )
            try:
                # Sync the subcloud peer group to peer site
                self.rpc_client.sync_subcloud_peer_group(context, association.id)
                association = db_api.peer_group_association_update(
                    context,
                    id=association.id,
                    sync_status=consts.ASSOCIATION_SYNC_STATUS_SYNCING,
                    sync_message="None",
                )
                return db_api.peer_group_association_db_model_to_dict(association)
            except RemoteError as e:
                pecan.abort(httpclient.UNPROCESSABLE_ENTITY, e.value)
            except Exception as e:
                # additional exceptions.
                LOG.exception(e)
                pecan.abort(
                    httpclient.INTERNAL_SERVER_ERROR,
                    _("Unable to sync peer group association"),
                )

    def _update_association(self, context, association, is_non_primary):
        payload = self._get_payload(request)
        if not payload:
            pecan.abort(httpclient.BAD_REQUEST, _("Body required"))

        peer_group_priority = payload.get("peer_group_priority")
        sync_status = payload.get("sync_status")
        # Check value is not None or empty before calling validate
        if not (peer_group_priority is not None or sync_status):
            pecan.abort(httpclient.BAD_REQUEST, _("nothing to update"))
        elif peer_group_priority is not None and sync_status:
            pecan.abort(
                httpclient.BAD_REQUEST,
                _(
                    "peer_group_priority and sync_status cannot be "
                    "updated at the same time."
                ),
            )
        if peer_group_priority is not None:
            if not self._validate_peer_group_priority(peer_group_priority):
                pecan.abort(httpclient.BAD_REQUEST, _("Invalid peer_group_priority"))
            if is_non_primary:
                self.rpc_client.peer_monitor_notify(context)
                pecan.abort(
                    httpclient.BAD_REQUEST,
                    _(
                        "Peer Group Association peer_group_priority is not allowed to "
                        "update when the association type is non-primary."
                    ),
                )
            else:
                db_api.peer_group_association_update(
                    context, id=association.id, peer_group_priority=peer_group_priority
                )
        if sync_status:
            if not self._validate_sync_status(sync_status):
                pecan.abort(httpclient.BAD_REQUEST, _("Invalid sync_status"))

            if not is_non_primary:
                self.rpc_client.peer_monitor_notify(context)
                pecan.abort(
                    httpclient.BAD_REQUEST,
                    _(
                        "Peer Group Association sync_status is not allowed to update "
                        "when the association type is primary."
                    ),
                )
            else:
                sync_message = (
                    "Primary association sync to current site failed."
                    if sync_status == consts.ASSOCIATION_SYNC_STATUS_FAILED
                    else "None"
                )
                association = db_api.peer_group_association_update(
                    context,
                    id=association.id,
                    sync_status=sync_status,
                    sync_message=sync_message,
                )
                self.rpc_client.peer_monitor_notify(context)
                return db_api.peer_group_association_db_model_to_dict(association)

        try:
            # Ask dcmanager-manager to update the subcloud peer group priority
            # to peer site. It will do the real work...
            return self.rpc_client.sync_subcloud_peer_group_only(
                context, association.id
            )
        except RemoteError as e:
            pecan.abort(httpclient.UNPROCESSABLE_ENTITY, e.value)
        except Exception as e:
            # additional exceptions.
            LOG.exception(e)
            pecan.abort(
                httpclient.INTERNAL_SERVER_ERROR,
                _("Unable to update peer group association"),
            )

    @index.when(method="PATCH", template="json")
    def patch(self, association_id, sync=False):
        """Update a peer group association.

        :param association_id: ID of peer group association to update
        :param sync: sync action that sync the peer group
        ---
        patch:
          summary: Update a peer group association
          description: Update peer group association configuration or sync status
          operationId: updatePeerGroupAssociation
          tags:
          - peer-group-associations
          parameters:
          - name: association_id
            in: query
            description: ID of peer group association
            required: true
            schema:
              type: integer
          - name: sync
            in: query
            description: Sync the association
            required: false
            schema:
              type: boolean
          requestBody:
            required: true
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    peer_group_priority:
                      $ref: '#/components/schemas/association_peer_group_priority'
                    sync_status:
                      $ref: '#/components/schemas/association_sync_status'
                example:
                  peer_group_priority: 3
          responses:
            200:
              description: Association updated successfully
              content:
                application/json:
                  schema:
                    type: object
                  example:
                    id: 1
                    peer-group-id: 1
                    system-peer-id: 1
                    peer-group-priority: 3
                    association-type: primary
                    sync-status: in-sync
                    sync-message: null
                    created-at: '2026-03-12T19:21:18.992598'
                    updated-at: '2026-03-12T20:24:31.801489'
            400:
              description: Bad request - invalid parameters
            404:
              description: Association not found
            422:
              description: Unprocessable entity
            500:
              description: Internal server error
        """

        context = restcomm.extract_context_from_environ()
        context.is_admin = policy.authorize(
            peer_group_association_policy.POLICY_ROOT % "modify",
            {},
            restcomm.extract_credentials_for_policy(),
        )

        if association_id is None:
            pecan.abort(httpclient.BAD_REQUEST, _("Peer Group Association ID required"))
        elif not association_id.isdigit():
            pecan.abort(
                httpclient.BAD_REQUEST,
                _("Peer Group Association ID must be an integer"),
            )

        try:
            association = db_api.peer_group_association_get(context, association_id)
        except exception.PeerGroupAssociationNotFound:
            pecan.abort(httpclient.NOT_FOUND, _("Peer Group Association not found"))

        is_non_primary = (
            association.association_type == consts.ASSOCIATION_TYPE_NON_PRIMARY
        )

        if sync:
            return self._sync_association(context, association, is_non_primary)
        else:
            return self._update_association(context, association, is_non_primary)

    @index.when(method="delete", template="json")
    def delete(self, association_id):
        """Delete the peer group association.

        :param association_id: ID of peer group association to delete
        ---
        delete:
          summary: Delete a peer group association
          description: Delete a peer group association
          operationId: deletePeerGroupAssociation
          tags:
          - peer-group-associations
          parameters:
          - name: association_id
            in: query
            description: ID of peer group association
            required: true
            schema:
              type: integer
          responses:
            200:
              description: Association deleted successfully
              content:
                application/json:
                  schema:
                    type: object
            400:
              description: Bad request - cannot delete association
            404:
              description: Association not found
            422:
              description: Unprocessable entity
            500:
              description: Internal server error
        """

        context = restcomm.extract_context_from_environ()
        context.is_admin = policy.authorize(
            peer_group_association_policy.POLICY_ROOT % "delete",
            {},
            restcomm.extract_credentials_for_policy(),
        )

        if association_id is None:
            pecan.abort(httpclient.BAD_REQUEST, _("Peer Group Association ID required"))
        # Validate the ID
        if not association_id.isdigit():
            pecan.abort(
                httpclient.BAD_REQUEST,
                _("Peer Group Association ID must be an integer"),
            )

        try:
            association = db_api.peer_group_association_get(context, association_id)
            is_non_primary = (
                association.association_type == consts.ASSOCIATION_TYPE_NON_PRIMARY
            )
            if is_non_primary:
                result = db_api.peer_group_association_destroy(context, association_id)
                self.rpc_client.peer_monitor_notify(context)
                return result
            else:
                # Ask system-peer-manager to delete the association.
                # It will do all the real work...
                return self.rpc_client.delete_peer_group_association(
                    context, association_id
                )
        except exception.PeerGroupAssociationNotFound:
            pecan.abort(httpclient.NOT_FOUND, _("Peer Group Association not found"))
        except RemoteError as e:
            pecan.abort(httpclient.UNPROCESSABLE_ENTITY, e.value)
        except Exception as e:
            LOG.exception(e)
            pecan.abort(
                httpclient.INTERNAL_SERVER_ERROR,
                _("Unable to delete peer group association"),
            )
