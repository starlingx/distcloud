# Copyright (c) 2023-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import json
import uuid

import http.client as httpclient

from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging
from oslo_messaging import RemoteError

import pecan
from pecan import expose
from pecan import request

from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon import endpoint_cache
from dccommon import utils as cutils
from dcmanager.api.controllers import restcomm
from dcmanager.api.policies import subcloud_peer_group as subcloud_peer_group_policy
from dcmanager.api import policy
from dcmanager.common import consts
from dcmanager.common.i18n import _
from dcmanager.common import utils
from dcmanager.db import api as db_api
from dcmanager.rpc import client as rpc_client


CONF = cfg.CONF
LOG = logging.getLogger(__name__)


# validation constants for Subcloud Peer Group
MAX_SUBCLOUD_PEER_GROUP_NAME_LEN = 255
MIN_SUBCLOUD_PEER_GROUP_SUBCLOUD_REHOMING = 1
MAX_SUBCLOUD_PEER_GROUP_SUBCLOUD_REHOMING = 250
MAX_SUBCLOUD_PEER_GROUP_PRIORITY = 65536
MIN_SUBCLOUD_PEER_GROUP_PRIORITY = 0
DEFAULT_SUBCLOUD_PEER_GROUP_PRIORITY = 0
DEFAULT_SUBCLOUD_PEER_GROUP_MAX_REHOMING = 10
SUPPORTED_GROUP_STATES = [consts.OPERATIONAL_ENABLED, consts.OPERATIONAL_DISABLED]


class SubcloudPeerGroupsController(restcomm.GenericPathController):

    def __init__(self):
        super(SubcloudPeerGroupsController, self).__init__()
        self.rpc_client = rpc_client.ManagerClient()

    @expose(generic=True, template="json")
    def index(self):
        # Route the request to specific methods with parameters
        pass

    def _get_subcloud_list_for_peer_group(self, context, group_id):
        subclouds = db_api.subcloud_get_for_peer_group(context, group_id)
        return utils.subcloud_db_list_to_dict(subclouds)

    def _get_subcloud_peer_group_list(self, context):
        groups = db_api.subcloud_peer_group_get_all(context)
        subcloud_peer_group_list = []

        for group in groups:
            group_dict = db_api.subcloud_peer_group_db_model_to_dict(group)
            subcloud_peer_group_list.append(group_dict)

        result = {"subcloud_peer_groups": subcloud_peer_group_list}
        return result

    def _get_local_system(self):
        try:
            sysinv_client = SysinvClient(
                region=cutils.get_region_one_name(),
                session=endpoint_cache.EndpointCache.get_admin_session(),
            )
            system = sysinv_client.get_system()
            return system
        except Exception:
            pecan.abort(httpclient.BAD_REQUEST, _("Failed to get local system info"))

    def _get_subcloud_status_for_peer_group(self, context, group):
        subclouds = db_api.subcloud_get_for_peer_group(context, group.id)
        pg_status = dict()
        pg_status["peer_group_id"] = group.id
        pg_status["peer_group_name"] = group.peer_group_name
        pg_status["total_subclouds"] = len(subclouds)
        pg_status["complete"] = 0
        pg_status["waiting_for_migrate"] = 0
        pg_status["rehoming"] = 0
        pg_status["rehome_failed"] = 0
        pg_status["managed"] = 0
        pg_status["unmanaged"] = 0
        for subcloud in subclouds:
            if subcloud.management_state == "managed":
                pg_status["managed"] += 1
            else:
                pg_status["unmanaged"] += 1

            if subcloud.deploy_status == "secondary":
                pg_status["waiting_for_migrate"] += 1
            elif subcloud.deploy_status == "rehome-failed":
                pg_status["rehome_failed"] += 1
            elif subcloud.deploy_status == "rehome-prep-failed":
                pg_status["rehome_failed"] += 1
            elif subcloud.deploy_status == "complete":
                pg_status["complete"] += 1
            elif subcloud.deploy_status == "rehoming":
                pg_status["rehoming"] += 1
        return pg_status

    @index.when(method="GET", template="json")
    def get(self, group_ref=None, verb=None):
        """Get details about subcloud peer group.

        :param verb: Specifies the get action to be taken
        to the subcloud-peer-group get operation
        :param group_ref: ID or name of subcloud peer group
        """
        policy.authorize(
            subcloud_peer_group_policy.POLICY_ROOT % "get",
            {},
            restcomm.extract_credentials_for_policy(),
        )
        context = restcomm.extract_context_from_environ()

        if group_ref is None:
            # List of subcloud peer groups requested
            return self._get_subcloud_peer_group_list(context)

        group = utils.subcloud_peer_group_get_by_ref(context, group_ref)
        if group is None:
            pecan.abort(httpclient.NOT_FOUND, _("Subcloud Peer Group not found"))
        if verb is None:
            subcloud_peer_group_dict = db_api.subcloud_peer_group_db_model_to_dict(
                group
            )
            return subcloud_peer_group_dict
        elif verb == "subclouds":
            # Return only the subclouds for this subcloud peer group
            return self._get_subcloud_list_for_peer_group(context, group.id)
        elif verb == "status":
            return self._get_subcloud_status_for_peer_group(context, group)
        else:
            pecan.abort(400, _("Invalid request"))

    @index.when(method="POST", template="json")
    def post(self):
        """Create a new subcloud peer group."""

        context = restcomm.extract_context_from_environ()
        context.is_admin = policy.authorize(
            subcloud_peer_group_policy.POLICY_ROOT % "create",
            {},
            restcomm.extract_credentials_for_policy(),
        )

        payload = json.loads(request.body)
        if not payload:
            pecan.abort(httpclient.BAD_REQUEST, _("Body required"))

        LOG.info("Handling create subcloud peer group request for: %s" % payload)
        peer_group_name = payload.get("peer-group-name")
        group_priority = payload.get("group-priority")
        group_state = payload.get("group-state")
        system_leader_id = payload.get("system-leader-id")
        system_leader_name = payload.get("system-leader-name")
        max_subcloud_rehoming = payload.get("max-subcloud-rehoming")

        local_system = None
        # Validate payload
        # peer_group_name is mandatory
        if not utils.validate_name(peer_group_name, prohibited_name_list=["none"]):
            pecan.abort(httpclient.BAD_REQUEST, _("Invalid peer-group-name"))
        if not system_leader_id:
            # 1.Operator does not need to (and should not) specify
            # system_leader_id for a local subcloud peer group which
            # is supposed to group local subclouds being managed by
            # local system, since the leader should be the local system
            # 2.system_leader_id should be specified via API when the
            # subcloud peer group is duplicated into peer system which
            # is not the leader of this subcloud peer group
            if not local_system:
                local_system = self._get_local_system()
            system_leader_id = local_system.uuid
        elif not self._validate_system_leader_id(system_leader_id):
            pecan.abort(
                httpclient.BAD_REQUEST,
                _("Invalid system-leader-id [%s]" % (system_leader_id)),
            )
        if not system_leader_name:
            # Get system_leader_name from local DC
            # if no system_leader_name provided
            if not local_system:
                local_system = self._get_local_system()
            system_leader_name = local_system.name
        elif not utils.validate_name(system_leader_name):
            pecan.abort(httpclient.BAD_REQUEST, _("Invalid system-leader-name"))
        if group_priority is None:
            group_priority = DEFAULT_SUBCLOUD_PEER_GROUP_PRIORITY
        elif not self._validate_group_priority(group_priority):
            pecan.abort(httpclient.BAD_REQUEST, _("Invalid group-priority"))
        if not group_state:
            group_state = consts.OPERATIONAL_ENABLED
        elif not self._validate_group_state(group_state):
            pecan.abort(httpclient.BAD_REQUEST, _("Invalid group-state"))
        if max_subcloud_rehoming is None:
            max_subcloud_rehoming = DEFAULT_SUBCLOUD_PEER_GROUP_MAX_REHOMING
        elif not self._validate_max_subcloud_rehoming(max_subcloud_rehoming):
            pecan.abort(httpclient.BAD_REQUEST, _("Invalid max-subcloud-rehoming"))

        try:
            group_ref = db_api.subcloud_peer_group_create(
                context,
                peer_group_name,
                group_priority,
                group_state,
                max_subcloud_rehoming,
                system_leader_id,
                system_leader_name,
            )
            return db_api.subcloud_peer_group_db_model_to_dict(group_ref)
        except db_exc.DBDuplicateEntry:
            pecan.abort(
                httpclient.CONFLICT,
                _("A subcloud peer group with this name already exists"),
            )
        except RemoteError as e:
            pecan.abort(httpclient.UNPROCESSABLE_ENTITY, e.value)
        except Exception as e:
            LOG.exception(e)
            pecan.abort(
                httpclient.INTERNAL_SERVER_ERROR,
                _("Unable to create subcloud peer group"),
            )

    @index.when(method="PATCH", template="json")
    def patch(self, group_ref, verb=None):
        """Update a subcloud peer group.

        :param verb: Specifies the get action to be taken
        to the subcloud-peer-group patch operation
        :param group_ref: ID or name of subcloud group to update
        """

        context = restcomm.extract_context_from_environ()
        context.is_admin = policy.authorize(
            subcloud_peer_group_policy.POLICY_ROOT % "modify",
            {},
            restcomm.extract_credentials_for_policy(),
        )

        if group_ref is None:
            pecan.abort(
                httpclient.BAD_REQUEST, _("Subcloud Peer Group Name or ID required")
            )

        group = utils.subcloud_peer_group_get_by_ref(context, group_ref)
        if group is None:
            pecan.abort(httpclient.NOT_FOUND, _("Subcloud Peer Group not found"))
        if verb is None:
            payload = json.loads(request.body)
            if not payload:
                pecan.abort(httpclient.BAD_REQUEST, _("Body required"))

            if group.group_priority > 0 and not utils.is_req_from_another_dc(request):
                pecan.abort(
                    httpclient.BAD_REQUEST,
                    _("Cannot update a peer group from a non-primary site."),
                )

            LOG.info("Handling update subcloud peer group request for: %s" % payload)
            peer_group_name = payload.get("peer-group-name")
            group_priority = payload.get("group-priority")
            group_state = payload.get("group-state")
            system_leader_id = payload.get("system-leader-id")
            system_leader_name = payload.get("system-leader-name")
            max_subcloud_rehoming = payload.get("max-subcloud-rehoming")
            if "migration_status" in payload:
                migration_status = payload.get("migration_status")
                if migration_status is None:
                    migration_status = consts.PEER_GROUP_MIGRATION_NONE
            else:
                migration_status = None

            if not (
                peer_group_name
                or group_priority is not None
                or group_state
                or system_leader_id
                or system_leader_name
                or max_subcloud_rehoming is not None
                or migration_status
            ):
                pecan.abort(httpclient.BAD_REQUEST, _("nothing to update"))

            # The flag to indicate if the update needs to be synced to
            # the peer site(s).
            sync_needed = (
                (peer_group_name and peer_group_name != group.peer_group_name)
                or (group_state and group_state != group.group_state)
                or (
                    max_subcloud_rehoming is not None
                    and max_subcloud_rehoming != group.max_subcloud_rehoming
                )
            )

            any_update = sync_needed or (
                (group_priority is not None and group_priority != group.group_priority)
                or (system_leader_id and system_leader_id != group.system_leader_id)
                or (
                    system_leader_name
                    and system_leader_name != group.system_leader_name
                )
                or (migration_status and migration_status != group.migration_status)
            )
            if not any_update:
                return db_api.subcloud_peer_group_db_model_to_dict(group)

            # Check value is not None or empty before calling validation function
            if peer_group_name is not None and not utils.validate_name(
                peer_group_name, prohibited_name_list=["none"]
            ):
                pecan.abort(httpclient.BAD_REQUEST, _("Invalid peer-group-name"))
            if group_priority is not None and not self._validate_group_priority(
                group_priority
            ):
                pecan.abort(httpclient.BAD_REQUEST, _("Invalid group-priority"))
            if group_state and not self._validate_group_state(group_state):
                pecan.abort(httpclient.BAD_REQUEST, _("Invalid group-state"))
            if (
                max_subcloud_rehoming is not None
                and not self._validate_max_subcloud_rehoming(max_subcloud_rehoming)
            ):
                pecan.abort(httpclient.BAD_REQUEST, _("Invalid max-subcloud-rehoming"))
            if system_leader_id and not self._validate_system_leader_id(
                system_leader_id
            ):
                pecan.abort(httpclient.BAD_REQUEST, _("Invalid system-leader-id"))
            if system_leader_name is not None and not utils.validate_name(
                system_leader_name
            ):
                pecan.abort(httpclient.BAD_REQUEST, _("Invalid system-leader-name"))
            if migration_status and migration_status.lower() not in [
                consts.PEER_GROUP_MIGRATING,
                consts.PEER_GROUP_MIGRATION_COMPLETE,
                consts.PEER_GROUP_MIGRATION_NONE,
            ]:
                pecan.abort(httpclient.BAD_REQUEST, _("Invalid migration_status"))

            # Update on peer site(s)
            if (not utils.is_req_from_another_dc(request)) and sync_needed:
                success_peer_ids, failed_peer_ids = (
                    self.rpc_client.update_subcloud_peer_group(
                        context,
                        group.id,
                        group_state,
                        max_subcloud_rehoming,
                        group.peer_group_name,
                        peer_group_name,
                    )
                )
                if failed_peer_ids:
                    if not success_peer_ids:
                        # Reject if all failed
                        pecan.abort(
                            httpclient.FORBIDDEN,
                            _("Unable to sync the update to the peer site(s)"),
                        )
                    # Local update will continue if it's only partial
                    # failure.
                    # TODO(gherzmann): update the association sync status to
                    # out-of-date on partial failures when support for multiple
                    # associations is added (geo-redundancy phase 2)
                    LOG.error(
                        f"Failed to sync the subcloud peer group {group.id} update on "
                        f"the peer site(s) {failed_peer_ids} with the values: "
                        f"{group_state=}, {max_subcloud_rehoming=}, {peer_group_name=}"
                    )

            try:
                updated_peer_group = db_api.subcloud_peer_group_update(
                    context,
                    group.id,
                    peer_group_name=peer_group_name,
                    group_priority=group_priority,
                    group_state=group_state,
                    max_subcloud_rehoming=max_subcloud_rehoming,
                    system_leader_id=system_leader_id,
                    system_leader_name=system_leader_name,
                    migration_status=migration_status,
                )
                return db_api.subcloud_peer_group_db_model_to_dict(updated_peer_group)
            except RemoteError as e:
                pecan.abort(httpclient.UNPROCESSABLE_ENTITY, e.value)
            except Exception as e:
                # additional exceptions.
                LOG.exception(e)
                pecan.abort(
                    httpclient.INTERNAL_SERVER_ERROR,
                    _("Unable to update subcloud peer group"),
                )
        elif verb == "migrate":
            payload = json.loads(request.body)
            LOG.info("Handling migrate subcloud peer group request for: %s" % group_ref)
            if not payload:
                pecan.abort(httpclient.BAD_REQUEST, _("Body required"))
            if "sysadmin_password" not in payload:
                msg = (
                    "Unable to migrate subcloud peer group: %s need sysadmin_password"
                    % group_ref
                )
                LOG.error(msg)
                pecan.abort(400, _(msg))
            payload["peer_group"] = group_ref
            # Validate subclouds
            subclouds = db_api.subcloud_get_for_peer_group(context, group.id)
            rehome_ready_subclouds = []
            err_msg_list = []
            for tmp_subcloud in subclouds:
                # Verify rehome data
                rehome_data_json_str = tmp_subcloud.rehome_data
                if not rehome_data_json_str:
                    msg = (
                        "Unable to migrate subcloud: %s "
                        "required rehoming data is missing" % tmp_subcloud.name
                    )
                    err_msg_list.append(msg)
                    continue
                tmp_rehome_data = json.loads(rehome_data_json_str)
                if "saved_payload" not in tmp_rehome_data:
                    msg = (
                        "Unable to migrate subcloud: %s saved_payload is missing in "
                        "rehoming data" % tmp_subcloud.name
                    )
                    err_msg_list.append(msg)
                    continue
                saved_payload = tmp_rehome_data["saved_payload"]

                # Validate saved_payload
                if not saved_payload:
                    msg = (
                        "Unable to migrate subcloud: %s saved_payload is empty"
                        % tmp_subcloud.name
                    )
                    err_msg_list.append(msg)
                    continue
                if "bootstrap-address" not in saved_payload:
                    msg = (
                        "Unable to migrate subcloud: %s, bootstrap-address is missing "
                        "in rehoming data" % tmp_subcloud.name
                    )
                    err_msg_list.append(msg)
                    continue

                # If any subcloud in the peer group is in 'rehoming'
                # or 'pre-rehome'state, we consider the peer group
                # is already in batch rehoming, then abort.
                rehome_states = [
                    consts.DEPLOY_STATE_PRE_REHOME,
                    consts.DEPLOY_STATE_REHOMING,
                ]
                if tmp_subcloud.deploy_status in rehome_states:
                    msg = (
                        "Unable to migrate subcloud peer group %s, "
                        "subcloud %s already in rehoming process"
                        % (group.peer_group_name, tmp_subcloud.name)
                    )
                    err_msg_list.append(msg)
                    continue
                # Filter for secondary/rehome-failed/rehome-prep-failed
                # subclouds, which is the correct state for rehoming
                if tmp_subcloud.deploy_status in [
                    consts.DEPLOY_STATE_SECONDARY,
                    consts.DEPLOY_STATE_REHOME_FAILED,
                    consts.DEPLOY_STATE_REHOME_PREP_FAILED,
                ]:
                    rehome_ready_subclouds.append(tmp_subcloud)
                else:
                    LOG.info(
                        "Excluding subcloud: %s from batch migration: "
                        "subcloud deploy_status is not secondary, "
                        "rehome-failed or rehome-prep-failed" % tmp_subcloud.name
                    )
            if err_msg_list:
                for m in err_msg_list:
                    LOG.error(m)
                pecan.abort(500, _("Batch migrate subclouds error: %s" % err_msg_list))

            if not rehome_ready_subclouds:
                pecan.abort(
                    400,
                    _(
                        "Nothing to migrate, no secondary, rehome-failed or "
                        "rehome-prep-failed subcloud in peer group %s"
                        % group.peer_group_name
                    ),
                )

            # Call batch migrate
            try:
                self.rpc_client.batch_migrate_subcloud(context, payload)
                return utils.subcloud_db_list_to_dict(rehome_ready_subclouds)
            except RemoteError as e:
                pecan.abort(422, e.value)
            except Exception:
                LOG.exception(
                    "Unable to batch migrate peer group %s" % group.peer_group_name
                )
                pecan.abort(
                    500,
                    _("Unable to batch migrate peer group %s" % group.peer_group_name),
                )
        elif verb == "audit":
            payload = json.loads(request.body)
            if "peer_uuid" not in payload:
                pecan.abort(
                    400,
                    _(
                        "Unable to audit peer group %s, missing peer_uuid"
                        % group.peer_group_name
                    ),
                )
            if "peer_group_name" not in payload:
                pecan.abort(
                    400,
                    _(
                        "Unable to audit peer group %s, missing peer_group_name"
                        % group.peer_group_name
                    ),
                )
            if "group_priority" not in payload:
                pecan.abort(
                    400,
                    _(
                        "Unable to audit peer group %s, missing group_priority"
                        % group.peer_group_name
                    ),
                )
            if "group_state" not in payload:
                pecan.abort(
                    400,
                    _(
                        "Unable to audit peer group %s, missing group_state"
                        % group.peer_group_name
                    ),
                )
            if "system_leader_id" not in payload:
                pecan.abort(
                    400,
                    _(
                        "Unable to audit peer group %s, missing system_leader_id"
                        % group.peer_group_name
                    ),
                )
            if "system_leader_name" not in payload:
                pecan.abort(
                    400,
                    _(
                        "Unable to audit peer group %s, missing system_leader_name"
                        % group.peer_group_name
                    ),
                )
            if "migration_status" not in payload:
                pecan.abort(
                    400,
                    _(
                        "Unable to audit peer group %s, missing migration_status"
                        % group.peer_group_name
                    ),
                )
            try:
                msg = self.rpc_client.peer_group_audit_notify(
                    context, group.peer_group_name, payload
                )
                return {"message": msg}
            except Exception:
                LOG.exception("Unable to audit peer group %s" % group.peer_group_name)
                pecan.abort(
                    500, _("Unable to audit peer group %s" % group.peer_group_name)
                )
        else:
            pecan.abort(400, _("Invalid request"))

    def _validate_group_priority(self, priority):
        try:
            # Check the value is an integer
            val = int(priority)
        except ValueError:
            return False
        # We do not support less than min or greater than max
        if val < MIN_SUBCLOUD_PEER_GROUP_PRIORITY:
            return False
        if val > MAX_SUBCLOUD_PEER_GROUP_PRIORITY:
            return False
        return True

    def _validate_group_state(self, state):
        if state not in SUPPORTED_GROUP_STATES:
            return False
        return True

    def _validate_max_subcloud_rehoming(self, max_parallel_str):
        try:
            # Check the value is an integer
            val = int(max_parallel_str)
        except ValueError:
            return False

        # We do not support less than min or greater than max
        if val < MIN_SUBCLOUD_PEER_GROUP_SUBCLOUD_REHOMING:
            return False
        if val > MAX_SUBCLOUD_PEER_GROUP_SUBCLOUD_REHOMING:
            return False
        return True

    def _validate_system_leader_id(self, uuid_str):
        try:
            uuid.UUID(str(uuid_str))
            return True
        except Exception:
            return False

    @index.when(method="delete", template="json")
    def delete(self, group_ref):
        """Delete the subcloud peer group."""

        context = restcomm.extract_context_from_environ()
        context.is_admin = policy.authorize(
            subcloud_peer_group_policy.POLICY_ROOT % "delete",
            {},
            restcomm.extract_credentials_for_policy(),
        )

        if group_ref is None:
            pecan.abort(
                httpclient.BAD_REQUEST, _("Subcloud Peer Group Name or ID required")
            )
        group = utils.subcloud_peer_group_get_by_ref(context, group_ref)
        if group is None:
            LOG.info("Subcloud Peer Group [%s] not found" % group_ref)
            pecan.abort(httpclient.NOT_FOUND, _("Subcloud Peer Group not found"))

        LOG.info("Handling delete subcloud peer group request for: %s" % group)
        # A peer group cannot be deleted if it is used by any associations
        association = db_api.peer_group_association_get_by_peer_group_id(
            context, group.id
        )
        if len(association) > 0:
            pecan.abort(
                httpclient.BAD_REQUEST,
                _("Cannot delete a peer group which is associated with a system peer."),
            )
        try:
            db_api.subcloud_peer_group_destroy(context, group.id)
            # Disassociate the subcloud.
            subclouds = db_api.subcloud_get_for_peer_group(context, group.id)
            for subcloud in subclouds:
                db_api.subcloud_update(context, subcloud.id, peer_group_id="none")
        except RemoteError as e:
            pecan.abort(httpclient.UNPROCESSABLE_ENTITY, e.value)
        except Exception as e:
            LOG.exception(e)
            pecan.abort(
                httpclient.INTERNAL_SERVER_ERROR,
                _("Unable to delete subcloud peer group"),
            )
