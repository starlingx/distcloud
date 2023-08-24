#
# Copyright (c) 2023 Wind River Systems, Inc.
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

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dcmanager.api.controllers import restcomm
from dcmanager.api.policies import peer_group_association as \
    peer_group_association_policy
from dcmanager.api import policy
from dcmanager.common import consts
from dcmanager.common import exceptions as exception
from dcmanager.common.i18n import _
from dcmanager.common import phased_subcloud_deploy as psd_common
from dcmanager.db import api as db_api
from dcmanager.rpc import client as rpc_client


CONF = cfg.CONF
LOG = logging.getLogger(__name__)

MIN_PEER_GROUP_ASSOCIATION_PRIORITY = 1
MAX_PEER_GROUP_ASSOCIATION_PRIORITY = 65536


class PeerGroupAssociationsController(restcomm.GenericPathController):

    def __init__(self):
        super(PeerGroupAssociationsController, self).__init__()
        self.rpc_client = rpc_client.ManagerClient()

    @expose(generic=True, template='json')
    def index(self):
        # Route the request to specific methods with parameters
        pass

    def _get_peer_group_association_list(self, context):
        associations = db_api.peer_group_association_get_all(context)
        association_list = []

        for association in associations:
            association_dict = db_api.peer_group_association_db_model_to_dict(
                association)
            # Remove the sync_message from the list response
            association_dict.pop('sync-message', None)
            association_list.append(association_dict)

        result = {'peer_group_associations': association_list}
        return result

    @staticmethod
    def _get_payload(request):
        try:
            payload = json.loads(request.body)
        except Exception:
            error_msg = 'Request body is malformed.'
            LOG.exception(error_msg)
            pecan.abort(400, _(error_msg))

        if not isinstance(payload, dict):
            pecan.abort(400, _('Invalid request body format'))
        return payload

    def _validate_peer_group_leader_id(self, system_leader_id):
        ks_client = psd_common.get_ks_client()
        sysinv_client = SysinvClient(
            dccommon_consts.DEFAULT_REGION_NAME,
            ks_client.session,
            endpoint=ks_client.endpoint_cache.get_endpoint('sysinv'))
        system = sysinv_client.get_system()
        return True if system.uuid == system_leader_id else False

    @index.when(method='GET', template='json')
    def get(self, association_id=None):
        """Get details about peer group association.

        :param association_id: ID of peer group association
        """
        policy.authorize(peer_group_association_policy.POLICY_ROOT % "get", {},
                         restcomm.extract_credentials_for_policy())
        context = restcomm.extract_context_from_environ()

        if association_id is None:
            # List of peer group association requested
            return self._get_peer_group_association_list(context)
        elif not association_id.isdigit():
            pecan.abort(httpclient.BAD_REQUEST,
                        _('Peer Group Association ID must be an integer'))

        try:
            association = db_api.peer_group_association_get(context,
                                                            association_id)
        except exception.PeerGroupAssociationNotFound:
            pecan.abort(httpclient.NOT_FOUND,
                        _('Peer Group Association not found'))

        return db_api.peer_group_association_db_model_to_dict(association)

    def _validate_peer_group_id(self, context, peer_group_id):
        try:
            db_api.subcloud_peer_group_get(context, peer_group_id)
        except exception.SubcloudPeerGroupNotFound:
            LOG.debug("Subcloud Peer Group Not Found, peer group id: %s"
                      % peer_group_id)
            return False
        except Exception as e:
            LOG.warning("Get Subcloud Peer Group failed: %s; peer_group_id: %s"
                        % (e, peer_group_id))
            return False
        return True

    def _validate_system_peer_id(self, context, system_peer_id):
        try:
            db_api.system_peer_get(context, system_peer_id)
        except exception.SystemPeerNotFound:
            LOG.debug("System Peer Not Found, system peer id: %s"
                      % system_peer_id)
            return False
        except Exception as e:
            LOG.warning("Get System Peer failed: %s; system_peer_id: %s"
                        % (e, system_peer_id))
            return False
        return True

    def _validate_peer_group_priority(self, peer_group_priority):
        try:
            # Check the value is an integer
            val = int(peer_group_priority)
        except ValueError:
            LOG.debug("Peer Group Priority is not Integer: %s"
                      % peer_group_priority)
            return False
        # Less than min or greater than max priority is not supported.
        if val < MIN_PEER_GROUP_ASSOCIATION_PRIORITY or \
            val > MAX_PEER_GROUP_ASSOCIATION_PRIORITY:
            LOG.debug("Invalid Peer Group Priority out of support range: %s"
                      % peer_group_priority)
            return False
        return True

    @index.when(method='POST', template='json')
    def post(self):
        """Create a new peer group association."""
        policy.authorize(peer_group_association_policy.POLICY_ROOT %
                         "create", {},
                         restcomm.extract_credentials_for_policy())
        context = restcomm.extract_context_from_environ()

        payload = self._get_payload(request)
        if not payload:
            pecan.abort(httpclient.BAD_REQUEST, _('Body required'))

        # Validate payload
        peer_group_id = payload.get('peer_group_id')
        if not self._validate_peer_group_id(context, peer_group_id):
            pecan.abort(httpclient.BAD_REQUEST, _('Invalid peer_group_id'))

        system_peer_id = payload.get('system_peer_id')
        if not self._validate_system_peer_id(context, system_peer_id):
            pecan.abort(httpclient.BAD_REQUEST, _('Invalid system_peer_id'))

        peer_group_priority = payload.get('peer_group_priority')
        peer_group = db_api.subcloud_peer_group_get(context, peer_group_id)

        if (peer_group.group_priority == 0 and not peer_group_priority) or \
            (peer_group.group_priority > 0 and peer_group_priority):
            pecan.abort(httpclient.BAD_REQUEST,
                        _('Peer Group Association create with peer_group_'
                          'priority is required when the subcloud peer group '
                          'priority is 0, and it is not allowed when the '
                          'subcloud peer group priority is greater than 0.'))

        if peer_group_priority and not self._validate_peer_group_priority(
            peer_group_priority):
            pecan.abort(httpclient.BAD_REQUEST,
                        _('Invalid peer_group_priority'))

        sync_enabled = peer_group.group_priority == 0

        # only one combination of peer_group_id + system_peer_id can exists
        association = None
        try:
            association = db_api.\
                peer_group_association_get_by_peer_group_and_system_peer_id(
                    context,
                    peer_group_id,
                    system_peer_id)
        except exception.PeerGroupAssociationCombinationNotFound:
            LOG.warning("Peer Group Association Combination Not Found, "
                        "peer_group_id: %s, system_peer_id: %s"
                        % (peer_group_id, system_peer_id))
        except Exception as e:
            LOG.warning("Peer Group Association get failed: %s;"
                        "peer_group_id: %s, system_peer_id: %s"
                        % (e, peer_group_id, system_peer_id))
            pecan.abort(httpclient.INTERNAL_SERVER_ERROR,
                        _('peer_group_association_get_by_peer_group_and_'
                          'system_peer_id failed: %s' % e))
        if association:
            LOG.info("Failed to create Peer group association, association \
                     with peer_group_id:[%s],system_peer_id:[%s] \
                     already exists" % (peer_group_id, system_peer_id))
            pecan.abort(httpclient.BAD_REQUEST,
                        _('A Peer group association with same peer_group_id, '
                          'system_peer_id already exists'))

        # Create the peer group association
        try:
            sync_status = consts.ASSOCIATION_SYNC_STATUS_SYNCING if \
                sync_enabled else consts.ASSOCIATION_SYNC_STATUS_DISABLED
            association = db_api.peer_group_association_create(
                context, peer_group_id, system_peer_id, peer_group_priority,
                sync_status)

            if sync_enabled:
                # Sync the subcloud peer group to peer site
                self.rpc_client.sync_subcloud_peer_group(context, association.id)
            return db_api.peer_group_association_db_model_to_dict(association)
        except RemoteError as e:
            pecan.abort(httpclient.UNPROCESSABLE_ENTITY, e.value)
        except Exception as e:
            LOG.exception(e)
            pecan.abort(httpclient.INTERNAL_SERVER_ERROR,
                        _('Unable to create peer group association'))

    @index.when(method='PATCH', template='json')
    def patch(self, association_id, sync=False):
        """Update a peer group association.

        :param association_id: ID of peer group association to update
        :param sync: sync action that sync the peer group
        """

        policy.authorize(peer_group_association_policy.POLICY_ROOT % "modify",
                         {}, restcomm.extract_credentials_for_policy())
        context = restcomm.extract_context_from_environ()
        if association_id is None:
            pecan.abort(httpclient.BAD_REQUEST,
                        _('Peer Group Association ID required'))
        elif not association_id.isdigit():
            pecan.abort(httpclient.BAD_REQUEST,
                        _('Peer Group Association ID must be an integer'))

        try:
            association = db_api.peer_group_association_get(context,
                                                            association_id)
        except exception.PeerGroupAssociationNotFound:
            pecan.abort(httpclient.NOT_FOUND,
                        _('Peer Group Association not found'))

        sync_disabled = association.sync_status == consts.\
            ASSOCIATION_SYNC_STATUS_DISABLED
        if sync_disabled:
            pecan.abort(httpclient.BAD_REQUEST,
                        _('Peer Group Association sync or update is not allowed'
                          ' when the sync_status is disabled.'))

        if sync:
            peer_group = db_api.subcloud_peer_group_get(
                context, association.peer_group_id)
            if not self._validate_peer_group_leader_id(peer_group.
                                                       system_leader_id):
                pecan.abort(httpclient.BAD_REQUEST,
                            _('Peer Group Association sync is not allowed when '
                              'the subcloud peer group system_leader_id is not '
                              'the current system controller UUID.'))
            try:
                # Sync the subcloud peer group to peer site
                self.rpc_client.sync_subcloud_peer_group(context,
                                                         association.id)
                association = db_api.peer_group_association_update(
                    context, id=association_id,
                    sync_status=consts.ASSOCIATION_SYNC_STATUS_SYNCING,
                    sync_message='None')
                return db_api.peer_group_association_db_model_to_dict(
                    association)
            except RemoteError as e:
                pecan.abort(httpclient.UNPROCESSABLE_ENTITY, e.value)
            except Exception as e:
                # additional exceptions.
                LOG.exception(e)
                pecan.abort(httpclient.INTERNAL_SERVER_ERROR,
                            _('Unable to sync peer group association'))

        payload = self._get_payload(request)
        if not payload:
            pecan.abort(httpclient.BAD_REQUEST, _('Body required'))

        peer_group_priority = payload.get('peer_group_priority')
        # Check value is not None or empty before calling validate
        if not peer_group_priority:
            pecan.abort(httpclient.BAD_REQUEST, _('nothing to update'))
        if not self._validate_peer_group_priority(peer_group_priority):
            pecan.abort(httpclient.BAD_REQUEST,
                        _('Invalid peer_group_priority'))

        try:
            # Ask dcmanager-manager to update the subcloud peer group priority
            # to peer site. It will do the real work...
            return self.rpc_client.update_subcloud_peer_group(
                context, association.id, peer_group_priority)
        except RemoteError as e:
            pecan.abort(httpclient.UNPROCESSABLE_ENTITY, e.value)
        except Exception as e:
            # additional exceptions.
            LOG.exception(e)
            pecan.abort(httpclient.INTERNAL_SERVER_ERROR,
                        _('Unable to update peer group association'))

    @index.when(method='delete', template='json')
    def delete(self, association_id):
        """Delete the peer group association.

        :param association_id: ID of peer group association to delete
        """
        policy.authorize(peer_group_association_policy.POLICY_ROOT % "delete",
                         {}, restcomm.extract_credentials_for_policy())
        context = restcomm.extract_context_from_environ()

        if association_id is None:
            pecan.abort(httpclient.BAD_REQUEST,
                        _('Peer Group Association ID required'))
        # Validate the ID
        if not association_id.isdigit():
            pecan.abort(httpclient.BAD_REQUEST,
                        _('Peer Group Association ID must be an integer'))

        try:
            association = db_api.peer_group_association_get(context,
                                                            association_id)
            sync_disabled = association.sync_status == consts.\
                ASSOCIATION_SYNC_STATUS_DISABLED
            if sync_disabled:
                return db_api.peer_group_association_destroy(context,
                                                             association_id)
            # Ask system-peer-manager to delete the association.
            # It will do all the real work...
            return self.rpc_client.delete_peer_group_association(
                context, association_id)
        except exception.PeerGroupAssociationNotFound:
            pecan.abort(httpclient.NOT_FOUND,
                        _('Peer Group Association not found'))
        except RemoteError as e:
            pecan.abort(httpclient.UNPROCESSABLE_ENTITY, e.value)
        except Exception as e:
            LOG.exception(e)
            pecan.abort(httpclient.INTERNAL_SERVER_ERROR,
                        _('Unable to delete peer group association'))
