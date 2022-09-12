#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from requests_toolbelt.multipart import decoder

import base64
import os
from oslo_config import cfg
from oslo_log import log as logging
from oslo_messaging import RemoteError
import yaml

import pecan
from pecan import expose
from pecan import request
from yaml.scanner import ScannerError

from dccommon import consts as dccommon_consts

from dcmanager.api.controllers import restcomm
from dcmanager.common import consts
from dcmanager.common.i18n import _
from dcmanager.common import utils
from dcmanager.db import api as db_api

from dcmanager.rpc import client as rpc_client

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

LOCK_NAME = 'SubcloudBackupController'


class SubcloudBackupController(object):
    def __init__(self):
        super(SubcloudBackupController, self).__init__()
        self.dcmanager_rpc_client = rpc_client.ManagerClient()

    @expose(generic=True, template='json')
    def index(self):
        # Route the request to specific methods with parameters
        pass

    @staticmethod
    def _get_backup_payload(request):
        return SubcloudBackupController._get_payload(request, {
            "subcloud": "text",
            "group": "text",
            "local_only": "text",
            "registry_images": "text",
            "backup_values": "yaml",
            "sysadmin_password": "text"
        })

    @staticmethod
    def _get_payload(request, expected_params):
        payload = dict()

        multipart_data = \
            decoder.MultipartDecoder(request.body,
                                     pecan.request.headers.get('Content-Type'))

        for part in multipart_data.parts:
            header = part.headers.get('Content-Disposition')
            try:
                param = next(param for param in expected_params.keys()
                             if param in header)
                if expected_params[param] == "yaml":
                    data = SubcloudBackupController.read_yaml_param(param, request)
                    payload.update({param: data})
                else:
                    payload.update({param: part.content})
            except StopIteration:
                pecan.abort(400, _("Unexpected parameter received"))

        return payload

    @staticmethod
    def read_yaml_param(param, request):
        invalid_yaml_msg = "Invalid format received on yaml parameter %s"

        file_item = request.POST[param]
        file_item.file.seek(0, os.SEEK_SET)
        try:
            data = yaml.safe_load(file_item.file.read().decode('utf8'))
            if not isinstance(data, dict):
                LOG.error(invalid_yaml_msg % param)
                pecan.abort(400, _(invalid_yaml_msg % param))
            return data

        except ScannerError:
            LOG.exception(invalid_yaml_msg % param)
            pecan.abort(400, _(invalid_yaml_msg % param))

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
    def _convert_param_to_bool(payload, param_name, default):
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
    def _validate_subcloud_for_backup(subcloud):
        if not subcloud:
            pecan.abort(404, _('Subcloud not found'))

        if subcloud.availability_status != dccommon_consts.AVAILABILITY_ONLINE:
            pecan.abort(400, _('Subcloud must be online for this operation'))

        if subcloud.management_state != dccommon_consts.MANAGEMENT_MANAGED:
            pecan.abort(400, _('Operation not allowed while subcloud is unmanaged. '
                               'Please manage the subcloud and try again.'))

        elif subcloud.deploy_status in consts.INVALID_DEPLOY_STATES_FOR_BACKUP:
            pecan.abort(400, _('This operation is not allowed while subcloud '
                               'install, bootstrap or deploy is in progress.'))

    @staticmethod
    def _validate_subcloud_group_for_backup(group, context):
        if not group:
            pecan.abort(404, _('Group not found'))

        group_subclouds = db_api.subcloud_get_for_group(context, group.id)

        if not group_subclouds:
            pecan.abort(400, _('No subclouds present in group'))

        online_subclouds = [subcloud for subcloud in group_subclouds
                            if subcloud.availability_status ==
                            dccommon_consts.AVAILABILITY_ONLINE]

        if not online_subclouds:
            pecan.abort(400, _('No online subclouds present in group'))

        managed_subclouds = [subcloud for subcloud in group_subclouds
                             if subcloud.management_state ==
                             dccommon_consts.MANAGEMENT_MANAGED]

        if not managed_subclouds:
            pecan.abort(400, _('No online and managed subclouds present in group. '
                               'Please manage subclouds and try again.'))

        invalid_states = consts.INVALID_DEPLOY_STATES_FOR_BACKUP
        valid_state_subclouds = [subcloud for subcloud in managed_subclouds
                                 if subcloud.deploy_status not in invalid_states]

        if not valid_state_subclouds:
            pecan.abort(400, _('This operation is not allowed while subcloud '
                               'install, bootstrap or deploy is in progress. '
                               'No online and managed subclouds in a valid '
                               'deploy state present for this group.'))

        return utils.subcloud_db_list_to_dict(group_subclouds)

    @utils.synchronized(LOCK_NAME)
    @index.when(method='POST', template='json')
    def post(self):
        """Create a new subcloud backup."""

        context = restcomm.extract_context_from_environ()

        payload = self._get_backup_payload(request)

        subcloud_ref = payload.get('subcloud')
        group_ref = payload.get('group')

        subcloud_dict = None

        if subcloud_ref:
            if group_ref:
                pecan.abort(400, _('\'subcloud\' and \'group\' parameters '
                                   'should not be given at the same time'))
            subcloud = utils.subcloud_get_by_ref(context, subcloud_ref)
            self._validate_subcloud_for_backup(subcloud)
            subcloud_dict = utils.subcloud_db_list_to_dict([subcloud])
            payload['subcloud'] = subcloud.id
        elif group_ref:
            group = utils.subcloud_group_get_by_ref(context, group_ref)
            subcloud_dict = \
                self._validate_subcloud_group_for_backup(group, context)
            payload['group'] = group.id
        else:
            pecan.abort(400, _('\'subcloud\' or \'group\' parameter required'))

        self._convert_param_to_bool(payload, 'local_only', False)
        self._convert_param_to_bool(payload, 'registry_images', False)

        if not payload.get('local_only') and payload.get('registry_images'):
            pecan.abort(400, _('Option registry_images can not be used without '
                               'local_only option.'))

        self._validate_and_decode_sysadmin_password(payload, 'sysadmin_password')

        try:
            self.dcmanager_rpc_client.backup_subclouds(context, payload)
            return subcloud_dict
        except RemoteError as e:
            pecan.abort(422, e.value)
        except Exception:
            LOG.exception("Unable to backup subclouds")
            pecan.abort(500, _('Unable to backup subcloud'))
