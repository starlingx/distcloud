# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging
from oslo_messaging import RemoteError

import http.client as httpclient
import json
import pecan
from pecan import expose
from pecan import request
import uuid

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.sdk_platform import OpenStackDriver
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
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
MAX_SYSTEM_LEADER_NAME_LEN = 255
MAX_SUBCLOUD_PEER_GROUP_PRIORITY = 65536
MIN_SUBCLOUD_PEER_GROUP_PRIORITY = 0
DEFAULT_SUBCLOUD_PEER_GROUP_PRIORITY = 0
DEFAULT_SUBCLOUD_PEER_GROUP_MAX_REHOMING = 10
SUPPORTED_GROUP_STATES = [
    consts.OPERATIONAL_ENABLED,
    consts.OPERATIONAL_DISABLED
]


class SubcloudPeerGroupsController(restcomm.GenericPathController):

    def __init__(self):
        super(SubcloudPeerGroupsController, self).__init__()
        self.rpc_client = rpc_client.ManagerClient()

    @expose(generic=True, template='json')
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

        result = {'subcloud_peer_groups': subcloud_peer_group_list}
        return result

    def _get_local_system(self):
        try:
            ks_client = OpenStackDriver(
                region_name=dccommon_consts.DEFAULT_REGION_NAME,
                region_clients=None
            )
            sysinv_client = SysinvClient(
                dccommon_consts.DEFAULT_REGION_NAME,
                ks_client.keystone_client.session,
                endpoint=ks_client.keystone_client.endpoint_cache.get_endpoint
                ("sysinv"),
            )
            system = sysinv_client.get_system()
            return system
        except Exception:
            pecan.abort(httpclient.BAD_REQUEST,
                        _("Failed to get local system info"))

    def _get_subcloud_status_for_peer_group(self, context, group):
        subclouds = db_api.subcloud_get_for_peer_group(context, group.id)
        pg_status = dict()
        pg_status['peer_group_id'] = group.id
        pg_status['peer_group_name'] = group.peer_group_name
        pg_status['total_subclouds'] = len(subclouds)
        pg_status['complete'] = 0
        pg_status['waiting_for_migrate'] = 0
        pg_status['rehoming'] = 0
        pg_status['rehome_failed'] = 0
        pg_status['managed'] = 0
        pg_status['unmanaged'] = 0
        for subcloud in subclouds:
            if subcloud.management_state == 'managed':
                pg_status['managed'] += 1
            else:
                pg_status['unmanaged'] += 1

            if subcloud.deploy_status == 'secondary':
                pg_status['waiting_for_migrate'] += 1
            elif subcloud.deploy_status == 'rehome-failed':
                pg_status['rehome_failed'] += 1
            elif subcloud.deploy_status == 'rehome-prep-failed':
                pg_status['rehome_failed'] += 1
            elif subcloud.deploy_status == 'complete':
                pg_status['complete'] += 1
            elif subcloud.deploy_status == 'rehoming':
                pg_status['rehoming'] += 1
        return pg_status

    @index.when(method='GET', template='json')
    def get(self, group_ref=None, verb=None):
        """Get details about subcloud peer group.

        :param verb: Specifies the get action to be taken
        to the subcloud-peer-group get operation
        :param group_ref: ID or name of subcloud peer group
        """
        policy.authorize(subcloud_peer_group_policy.POLICY_ROOT % "get", {},
                         restcomm.extract_credentials_for_policy())
        context = restcomm.extract_context_from_environ()

        if group_ref is None:
            # List of subcloud peer groups requested
            return self._get_subcloud_peer_group_list(context)

        group = utils.subcloud_peer_group_get_by_ref(context, group_ref)
        if group is None:
            pecan.abort(httpclient.NOT_FOUND, _("Subcloud Peer Group not found"))
        if verb is None:
            subcloud_peer_group_dict = db_api.subcloud_peer_group_db_model_to_dict(group)
            return subcloud_peer_group_dict
        elif verb == 'subclouds':
            # Return only the subclouds for this subcloud peer group
            return self._get_subcloud_list_for_peer_group(context, group.id)
        elif verb == 'status':
            return self._get_subcloud_status_for_peer_group(context, group)
        else:
            pecan.abort(400, _('Invalid request'))

    @index.when(method='POST', template='json')
    def post(self):
        """Create a new subcloud peer group."""
        policy.authorize(subcloud_peer_group_policy.POLICY_ROOT % "create", {},
                         restcomm.extract_credentials_for_policy())
        context = restcomm.extract_context_from_environ()

        payload = json.loads(request.body)
        if not payload:
            pecan.abort(httpclient.BAD_REQUEST, _('Body required'))

        LOG.info("Handling create subcloud peer group request for: %s" % payload)
        peer_group_name = payload.get('peer-group-name')
        group_priority = payload.get('group-priority')
        group_state = payload.get('group-state')
        system_leader_id = payload.get('system-leader-id')
        system_leader_name = payload.get('system-leader-name')
        max_subcloud_rehoming = payload.get('max-subcloud-rehoming')

        local_system = None
        # Validate payload
        # peer_group_name is mandatory
        if not self._validate_name(peer_group_name):
            pecan.abort(httpclient.BAD_REQUEST, _('Invalid peer-group-name'))
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
            pecan.abort(httpclient.BAD_REQUEST,
                        _('Invalid system-leader-id [%s]' % (system_leader_id)))
        if not system_leader_name:
            # Get system_leader_name from local DC
            # if no system_leader_name provided
            if not local_system:
                local_system = self._get_local_system()
            system_leader_name = local_system.name
        elif not self._validate_system_leader_name(system_leader_name):
            pecan.abort(httpclient.BAD_REQUEST,
                        _('Invalid system-leader-name'))
        if not group_priority:
            group_priority = DEFAULT_SUBCLOUD_PEER_GROUP_PRIORITY
        elif not self._validate_group_priority(group_priority):
            pecan.abort(httpclient.BAD_REQUEST, _('Invalid group-priority'))
        if not group_state:
            group_state = consts.OPERATIONAL_ENABLED
        elif not self._validate_group_state(group_state):
            pecan.abort(httpclient.BAD_REQUEST,
                        _('Invalid group-state'))
        if not max_subcloud_rehoming:
            max_subcloud_rehoming = DEFAULT_SUBCLOUD_PEER_GROUP_MAX_REHOMING
        elif not self._validate_max_subcloud_rehoming(max_subcloud_rehoming):
            pecan.abort(httpclient.BAD_REQUEST,
                        _('Invalid max-subcloud-rehoming'))

        try:
            group_ref = db_api.subcloud_peer_group_create(context,
                                                          peer_group_name,
                                                          group_priority,
                                                          group_state,
                                                          max_subcloud_rehoming,
                                                          system_leader_id,
                                                          system_leader_name)
            return db_api.subcloud_peer_group_db_model_to_dict(group_ref)
        except db_exc.DBDuplicateEntry:
            pecan.abort(httpclient.CONFLICT,
                        _('A subcloud peer group with this name already exists'))
        except RemoteError as e:
            pecan.abort(httpclient.UNPROCESSABLE_ENTITY, e.value)
        except Exception as e:
            LOG.exception(e)
            pecan.abort(httpclient.INTERNAL_SERVER_ERROR,
                        _('Unable to create subcloud peer group'))

    @index.when(method='PATCH', template='json')
    def patch(self, group_ref, verb=None):
        """Update a subcloud peer group.

        :param verb: Specifies the get action to be taken
        to the subcloud-peer-group patch operation
        :param group_ref: ID or name of subcloud group to update
        """

        policy.authorize(subcloud_peer_group_policy.POLICY_ROOT % "modify", {},
                         restcomm.extract_credentials_for_policy())
        context = restcomm.extract_context_from_environ()
        if group_ref is None:
            pecan.abort(httpclient.BAD_REQUEST,
                        _('Subcloud Peer Group Name or ID required'))

        group = utils.subcloud_peer_group_get_by_ref(context, group_ref)
        if group is None:
            pecan.abort(httpclient.NOT_FOUND, _('Subcloud Peer Group not found'))
        if verb is None:
            payload = json.loads(request.body)
            if not payload:
                pecan.abort(httpclient.BAD_REQUEST, _('Body required'))

            LOG.info("Handling update subcloud peer group request for: %s" % payload)
            peer_group_name = payload.get('peer-group-name')
            group_priority = payload.get('group-priority')
            group_state = payload.get('group-state')
            system_leader_id = payload.get('system-leader-id')
            system_leader_name = payload.get('system-leader-name')
            max_subcloud_rehoming = payload.get('max-subcloud-rehoming')

            if not (
                peer_group_name
                or group_priority
                or group_state
                or system_leader_id
                or system_leader_name
                or max_subcloud_rehoming
            ):
                pecan.abort(httpclient.BAD_REQUEST, _('nothing to update'))

            # Check value is not None or empty before calling validation function
            if peer_group_name and not self._validate_name(peer_group_name):
                    pecan.abort(httpclient.BAD_REQUEST, _('Invalid peer-group-name'))
            if group_priority and not self._validate_group_priority(group_priority):
                    pecan.abort(httpclient.BAD_REQUEST, _('Invalid group-priority'))
            if group_state and not self._validate_group_state(group_state):
                    pecan.abort(httpclient.BAD_REQUEST,
                                _('Invalid group-state'))
            if (max_subcloud_rehoming and
               not self._validate_max_subcloud_rehoming(max_subcloud_rehoming)):
                    pecan.abort(httpclient.BAD_REQUEST,
                                _('Invalid max-subcloud-rehoming'))
            if (system_leader_id and
               not self._validate_system_leader_id(system_leader_id)):
                    pecan.abort(httpclient.BAD_REQUEST,
                                _('Invalid system-leader-id'))
            if (system_leader_name and
               not self._validate_system_leader_name(system_leader_name)):
                    pecan.abort(httpclient.BAD_REQUEST,
                                _('Invalid system-leader-name'))

            try:
                updated_peer_group = db_api.subcloud_peer_group_update(
                    context,
                    group.id,
                    peer_group_name=peer_group_name,
                    group_priority=group_priority,
                    group_state=group_state,
                    max_subcloud_rehoming=max_subcloud_rehoming,
                    system_leader_id=system_leader_id,
                    system_leader_name=system_leader_name)
                return db_api.subcloud_peer_group_db_model_to_dict(updated_peer_group)
            except RemoteError as e:
                pecan.abort(httpclient.UNPROCESSABLE_ENTITY, e.value)
            except Exception as e:
                # additional exceptions.
                LOG.exception(e)
                pecan.abort(httpclient.INTERNAL_SERVER_ERROR,
                            _('Unable to update subcloud peer group'))
        elif verb == 'migrate':
            # TODO(tao): Subcloud Peer Group migrate implementation will
            # be submitted in the follow-up review.
            pass
        else:
            pecan.abort(400, _('Invalid request'))

    def _validate_name(self, name):
        # Reject post and update operations for name that:
        # - attempt to set to None
        # - attempt to set to a number
        # - exceed the max length
        if not name:
            return False
        if name.isdigit():
            LOG.warning("Invalid name [%s], can not be digit" % name)
            return False
        if len(name) > MAX_SUBCLOUD_PEER_GROUP_NAME_LEN:
            LOG.warning("Invalid name length")
            return False
        # none is not a valid name
        if name.lower() == 'none':
            LOG.warning("Invalid name, cannot use 'none' as name")
            return False
        return True

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

    def _validate_system_leader_name(self, name):
        if len(name) > MAX_SYSTEM_LEADER_NAME_LEN:
            return False
        return True

    def _validate_system_leader_id(self, uuid_str):
        try:
            uuid.UUID(str(uuid_str))
            return True
        except Exception:
            return False

    @index.when(method='delete', template='json')
    def delete(self, group_ref):
        """Delete the subcloud peer group."""
        policy.authorize(subcloud_peer_group_policy.POLICY_ROOT % "delete", {},
                         restcomm.extract_credentials_for_policy())
        context = restcomm.extract_context_from_environ()

        if group_ref is None:
            pecan.abort(httpclient.BAD_REQUEST,
                        _('Subcloud Peer Group Name or ID required'))
        group = utils.subcloud_peer_group_get_by_ref(context, group_ref)
        if group is None:
            LOG.info("Subcloud Peer Group [%s] not found" % group_ref)
            pecan.abort(httpclient.NOT_FOUND, _('Subcloud Peer Group not found'))

        LOG.info("Handling delete subcloud peer group request for: %s" % group)
        # TODO(Jon): uncomment in Association of System and Peer Group management commit
        '''
        # a peer group may not be deleted if it is used by any associations
        association = db_api.peer_group_association_get_by_peer_group_id(context,
                                                                         group.id)
        if len(association) > 0:
            pecan.abort(httpclient.BAD_REQUEST,
                        _("Cannot delete a peer group "
                          "which is associated with a system peer."))
        '''
        try:
            db_api.subcloud_peer_group_destroy(context, group.id)
            # Disassociate the subcloud.
            subclouds = db_api.subcloud_get_for_peer_group(context, group.id)
            for subcloud in subclouds:
                db_api.subcloud_update(context, subcloud.id,
                                       peer_group_id='none')
        except RemoteError as e:
            pecan.abort(httpclient.UNPROCESSABLE_ENTITY, e.value)
        except Exception as e:
            LOG.exception(e)
            pecan.abort(httpclient.INTERNAL_SERVER_ERROR,
                        _('Unable to delete subcloud peer group'))
