#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import json

from collections import namedtuple

import base64
from oslo_config import cfg
from oslo_log import log as logging
from oslo_messaging import RemoteError

import pecan
from pecan import expose
from pecan import request as pecan_request
from pecan import response

from dcmanager.api.controllers import restcomm
from dcmanager.api.policies import subcloud_backup as subcloud_backup_policy
from dcmanager.api import policy
from dcmanager.common import consts
from dcmanager.common.i18n import _
from dcmanager.common import utils
from dcmanager.db import api as db_api
from dcmanager.db.sqlalchemy.models import Subcloud
from dcmanager.rpc import client as rpc_client

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

LOCK_NAME = 'SubcloudBackupController'

# Subcloud/group information to be retrieved from request params
RequestEntity = namedtuple('RequestEntity', ['type', 'id', 'name', 'subclouds'])


class SubcloudBackupController(object):
    def __init__(self):
        super(SubcloudBackupController, self).__init__()
        self.dcmanager_rpc_client = rpc_client.ManagerClient()

    @expose(generic=True, template='json')
    def index(self):
        # Route the request to specific methods with parameters
        pass

    @staticmethod
    def _get_payload(request, verb):
        expected_params = dict()
        if verb == 'create':
            expected_params = {
                "subcloud": "text",
                "group": "text",
                "local_only": "text",
                "registry_images": "text",
                "backup_values": "yaml",
                "sysadmin_password": "text"
            }
        elif verb == 'delete':
            expected_params = {
                "release": "text",
                "subcloud": "text",
                "group": "text",
                "local_only": "text",
                "sysadmin_password": "text"
            }
        elif verb == 'restore':
            expected_params = {
                "with_install": "text",
                "local_only": "text",
                "registry_images": "text",
                "sysadmin_password": "text",
                "restore_values": "text",
                "subcloud": "text",
                "group": "text"
            }
        else:
            pecan.abort(400, _("Unexpected verb received"))

        return SubcloudBackupController._get_json_payload(request,
                                                          expected_params)

    @staticmethod
    def _get_json_payload(request, expected_params):
        try:
            payload = json.loads(request.body)
        except Exception:
            error_msg = 'Request body is malformed.'
            LOG.exception(error_msg)
            pecan.abort(400, _(error_msg))
            return
        if not isinstance(payload, dict):
            pecan.abort(400, _('Invalid request body format'))
        if not set(payload.keys()).issubset(expected_params.keys()):
            LOG.info(payload.keys())
            pecan.abort(400, _("Unexpected parameter received"))

        return payload

    @staticmethod
    def _validate_and_decode_sysadmin_password(payload, param_name):
        sysadmin_password = payload.get(param_name)

        if not sysadmin_password:
            pecan.abort(400, _('subcloud sysadmin_password required'))
        try:
            payload['sysadmin_password'] = base64.b64decode(
                sysadmin_password).decode('utf-8')
        except Exception:
            msg = _('Failed to decode subcloud sysadmin_password, '
                    'verify the password is base64 encoded')
            LOG.exception(msg)
            pecan.abort(400, msg)

    @staticmethod
    def _convert_param_to_bool(payload, param_names, default=False):
        for param_name in param_names:
            param = payload.get(param_name)
            if param:
                if param.lower() == 'true':
                    payload[param_name] = True
                elif param.lower() == 'false':
                    payload[param_name] = False
                else:
                    pecan.abort(400, _('Invalid %s value, should be boolean'
                                       % param_name))
            else:
                payload[param_name] = default

    @staticmethod
    def _validate_subclouds(request_entity, operation):
        """Validate the subcloud according to the operation

        Create/Delete: The subcloud is managed, online and in complete state.
        Restore: The subcloud is unmanaged, and not in the process of
        installation, boostrap, deployment or rehoming.

        If none of the subclouds are valid, the operation will be aborted.

        Args:
            request_entity (namedtuple): Request entity
            operation (string): Subcloud backup operation
        """
        subclouds = request_entity.subclouds
        if operation == 'create' or operation == 'delete':
            valid_subclouds = [subcloud for subcloud in subclouds if
                               utils.is_valid_for_backup(subcloud)]
        elif operation == 'restore':
            valid_subclouds = [subcloud for subcloud in subclouds if
                               utils.is_valid_for_restore(subcloud)]
        else:
            pecan.abort(400, _('Operation %s is not valid' % operation))

        if not valid_subclouds:

            if request_entity.type == 'group':
                msg = _('None of the subclouds in group %s are in a valid '
                        'state for backup %s.') % (request_entity.name, operation)
            elif request_entity.type == 'subcloud':
                msg = _('Subcloud %s is not in a valid state for backup %s.') \
                    % (request_entity.name, operation)

            pecan.abort(400, msg)

    @staticmethod
    def _get_subclouds_from_group(group, context):
        if not group:
            pecan.abort(404, _('Group not found'))

        return db_api.subcloud_get_for_group(context, group.id)

    def _read_entity_from_request_params(self, context, payload):
        subcloud_ref = payload.get('subcloud')
        group_ref = payload.get('group')

        if subcloud_ref:
            if group_ref:
                pecan.abort(400, _("'subcloud' and 'group' parameters "
                                   "should not be given at the same time"))
            subcloud = utils.subcloud_get_by_ref(context, subcloud_ref)
            if not subcloud:
                pecan.abort(400, _('Subcloud not found'))
            return RequestEntity('subcloud', subcloud.id, subcloud_ref, [subcloud])
        elif group_ref:
            group = utils.subcloud_group_get_by_ref(context, group_ref)
            group_subclouds = self._get_subclouds_from_group(group, context)
            if not group_subclouds:
                pecan.abort(400, _('No subclouds present in group'))
            return RequestEntity('group', group.id, group_ref, group_subclouds)
        else:
            pecan.abort(400, _("'subcloud' or 'group' parameter is required"))

    @staticmethod
    def _reset_backup_status(context, subclouds):
        subcloud_ids = []
        for subcloud in subclouds:
            subcloud.backup_status = consts.BACKUP_STATE_INITIAL
            subcloud_ids.append(subcloud.id)

        update_form = {
            Subcloud.backup_status.name: consts.BACKUP_STATE_INITIAL
        }

        db_api.subcloud_bulk_update_by_ids(context, subcloud_ids, update_form)

    @utils.synchronized(LOCK_NAME)
    @index.when(method='POST', template='json')
    def post(self):
        """Create a new subcloud backup."""

        context = restcomm.extract_context_from_environ()
        payload = self._get_payload(pecan_request, 'create')

        policy.authorize(subcloud_backup_policy.POLICY_ROOT % "create", {},
                         restcomm.extract_credentials_for_policy())

        request_entity = self._read_entity_from_request_params(context, payload)
        self._validate_subclouds(request_entity, 'create')

        # Set subcloud/group ID as reference instead of name to ease processing
        payload[request_entity.type] = request_entity.id
        subclouds = request_entity.subclouds

        self._convert_param_to_bool(payload, ['local_only', 'registry_images'])

        if not payload.get('local_only') and payload.get('registry_images'):
            pecan.abort(400, _('Option registry_images can not be used without '
                               'local_only option.'))

        self._validate_and_decode_sysadmin_password(payload, 'sysadmin_password')

        try:
            self._reset_backup_status(context, subclouds)
            self.dcmanager_rpc_client.backup_subclouds(context, payload)
            return utils.subcloud_db_list_to_dict(request_entity.subclouds)
        except RemoteError as e:
            pecan.abort(422, e.value)
        except Exception:
            LOG.exception("Unable to backup subclouds")
            pecan.abort(500, _('Unable to backup subcloud'))

    @utils.synchronized(LOCK_NAME)
    @index.when(method='PATCH', template='json')
    def patch(self, verb, release_version=None):
        """Delete or restore a subcloud backup.

        :param verb: Specifies the patch action to be taken
        to the subcloud backup operation

        :param release_version: Backup release version to be deleted
        """
        context = restcomm.extract_context_from_environ()
        payload = self._get_payload(pecan_request, verb)

        if verb == 'delete':
            policy.authorize(subcloud_backup_policy.POLICY_ROOT % "delete", {},
                             restcomm.extract_credentials_for_policy())

            if not release_version:
                pecan.abort(400, _('Release version required'))

            self._convert_param_to_bool(payload, ['local_only'])

            # Backup delete in systemcontroller doesn't need sysadmin_password
            if payload.get('local_only'):
                self._validate_and_decode_sysadmin_password(
                    payload, 'sysadmin_password')

            request_entity = self._read_entity_from_request_params(context, payload)

            # Validate subcloud state when deleting locally
            # Not needed for centralized storage, since connection is not required
            local_only = payload.get('local_only')
            if local_only:
                self._validate_subclouds(request_entity, verb)

            # Set subcloud/group ID as reference instead of name to ease processing
            payload[request_entity.type] = request_entity.id

            try:
                message = self.dcmanager_rpc_client.delete_subcloud_backups(
                    context, release_version, payload)

                if message:
                    response.status_int = 207
                    return message
                else:
                    response.status_int = 204
            except RemoteError as e:
                pecan.abort(422, e.value)
            except Exception:
                LOG.exception("Unable to delete subcloud backups")
                pecan.abort(500, _('Unable to delete subcloud backups'))
        elif verb == 'restore':
            policy.authorize(subcloud_backup_policy.POLICY_ROOT % "restore", {},
                             restcomm.extract_credentials_for_policy())

            if not payload:
                pecan.abort(400, _('Body required'))

            self._validate_and_decode_sysadmin_password(payload, 'sysadmin_password')

            self._convert_param_to_bool(payload, ['local_only', 'with_install',
                                                  'registry_images'])

            if not payload['local_only'] and payload['registry_images']:
                pecan.abort(400, _('Option registry_images cannot be used '
                                   'without local_only option.'))

            request_entity = self._read_entity_from_request_params(context, payload)
            if len(request_entity.subclouds) == 0:
                msg = "No subclouds exist under %s %s" % (request_entity.type,
                                                          request_entity.id)
                pecan.abort(400, _(msg))

            self._validate_subclouds(request_entity, verb)

            payload[request_entity.type] = request_entity.id

            valid_subclouds = [subcloud for subcloud in
                               request_entity.subclouds if
                               subcloud.data_install]

            if not valid_subclouds:
                pecan.abort(400, _('Cannot proceed with the restore operation '
                                   'since the subcloud(s) do not contain '
                                   'install data.'))

            if payload.get('with_install'):
                # Confirm the active system controller load is still in dc-vault
                matching_iso, err_msg = utils.get_matching_iso()
                if err_msg:
                    LOG.exception(err_msg)
                    pecan.abort(400, _(err_msg))
                LOG.info("Restore operation will use image %s in subcloud "
                         "installation" % matching_iso)

            try:
                message = self.dcmanager_rpc_client.restore_subcloud_backups(
                    context, payload)
                return utils.subcloud_db_list_to_dict(request_entity.subclouds)
            except RemoteError as e:
                pecan.abort(422, e.value)
            except Exception:
                LOG.exception("Unable to restore subcloud")
                pecan.abort(500, _('Unable to restore subcloud'))
        else:
            pecan.abort(400, _('Invalid request'))
