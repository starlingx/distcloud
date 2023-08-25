# Copyright (c) 2017 Ericsson AB.
# Copyright (c) 2017-2023 Wind River Systems, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# SPDX-License-Identifier: Apache-2.0
#


from requests_toolbelt.multipart import decoder

import base64
import json
import keyring
import os
from oslo_config import cfg
from oslo_log import log as logging
from oslo_messaging import RemoteError
import re
import yaml

import pecan
from pecan import expose
from pecan import request

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.fm import FmClient
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon import exceptions as dccommon_exceptions

from keystoneauth1 import exceptions as keystone_exceptions

import tsconfig.tsconfig as tsc

from dcmanager.api.controllers import restcomm
from dcmanager.api.policies import subclouds as subclouds_policy
from dcmanager.api import policy
from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.common.i18n import _
from dcmanager.common import phased_subcloud_deploy as psd_common
from dcmanager.common import prestage
from dcmanager.common import utils
from dcmanager.db import api as db_api

from dcmanager.rpc import client as rpc_client
from fm_api.constants import FM_ALARM_ID_UNSYNCHRONIZED_RESOURCE

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

LOCK_NAME = 'SubcloudsController'

BOOTSTRAP_VALUES = 'bootstrap_values'
INSTALL_VALUES = 'install_values'

SUBCLOUD_ADD_MANDATORY_FILE = [
    BOOTSTRAP_VALUES,
]

SUBCLOUD_RECONFIG_MANDATORY_FILE = [
    consts.DEPLOY_CONFIG,
]

SUBCLOUD_ADD_GET_FILE_CONTENTS = [
    BOOTSTRAP_VALUES,
    INSTALL_VALUES,
]

SUBCLOUD_REDEPLOY_GET_FILE_CONTENTS = [
    INSTALL_VALUES,
    BOOTSTRAP_VALUES,
    consts.DEPLOY_CONFIG
]

BOOTSTRAP_VALUES_ADDRESSES = [
    'bootstrap-address', 'bootstrap_address', 'management_start_address', 'management_end_address',
    'management_gateway_address', 'systemcontroller_gateway_address',
    'external_oam_gateway_address', 'external_oam_floating_address',
    'admin_start_address', 'admin_end_address', 'admin_gateway_address'
]

INSTALL_VALUES_ADDRESSES = [
    'bootstrap_address', 'bmc_address', 'nexthop_gateway',
    'network_address'
]

SUBCLOUD_MANDATORY_NETWORK_PARAMS = [
    'management_subnet', 'management_gateway_ip',
    'management_start_ip', 'management_end_ip'
]

ANSIBLE_BOOTSTRAP_VALIDATE_CONFIG_VARS = \
    consts.ANSIBLE_CURRENT_VERSION_BASE_PATH + \
    '/roles/bootstrap/validate-config/vars/main.yml'

FRESH_INSTALL_K8S_VERSION = 'fresh_install_k8s_version'
KUBERNETES_VERSION = 'kubernetes_version'


def _get_multipart_field_name(part):
    content = part.headers[b"Content-Disposition"].decode("utf8")
    regex = 'name="([^"]*)"'
    return re.search(regex, content).group(1)


class SubcloudsController(object):
    VERSION_ALIASES = {
        'Newton': '1.0',
    }

    def __init__(self):
        super(SubcloudsController, self).__init__()
        self.dcmanager_rpc_client = rpc_client.ManagerClient()
        self.dcmanager_state_rpc_client = rpc_client.SubcloudStateClient()

    # to do the version compatibility for future purpose
    def _determine_version_cap(self, target):
        version_cap = 1.0
        return version_cap

    @expose(generic=True, template='json')
    def index(self):
        # Route the request to specific methods with parameters
        pass

    @staticmethod
    def _get_patch_data(request):
        payload = dict()
        content_type = request.headers.get("Content-Type")
        multipart_data = decoder.MultipartDecoder(request.body, content_type)

        for part in multipart_data.parts:
            field_name = _get_multipart_field_name(part)
            field_content = part.text

            # only the install_values field is yaml, force should be bool
            if field_name in [INSTALL_VALUES, 'force']:
                field_content = yaml.safe_load(field_content)

            payload[field_name] = field_content

        return payload

    @staticmethod
    def _get_prestage_payload(request):
        fields = ['sysadmin_password', 'force', consts.PRESTAGE_REQUEST_RELEASE]
        payload = {
            'force': False
        }
        try:
            body = json.loads(request.body)
        except Exception:
            pecan.abort(400, _('Request body is malformed.'))

        for field in fields:
            val = body.get(field)
            if val is None:
                if field == 'sysadmin_password':
                    pecan.abort(400, _("%s is required." % field))
            else:
                if field == 'sysadmin_password':
                    try:
                        base64.b64decode(val).decode('utf-8')
                        payload['sysadmin_password'] = val
                    except Exception:
                        pecan.abort(
                            400,
                            _('Failed to decode subcloud sysadmin_password, '
                              'verify the password is base64 encoded'))
                elif field == 'force':
                    if val.lower() in ('true', 'false', 't', 'f'):
                        payload['force'] = val.lower() in ('true', 't')
                    else:
                        pecan.abort(
                            400, _('Invalid value for force option: %s' % val))
                elif field == consts.PRESTAGE_REQUEST_RELEASE:
                    payload[consts.PRESTAGE_REQUEST_RELEASE] = val
        return payload

    def _get_reconfig_payload(self, request, subcloud_name, software_version):
        payload = dict()
        multipart_data = decoder.MultipartDecoder(
            request.body, pecan.request.headers.get('Content-Type'))

        for filename in SUBCLOUD_RECONFIG_MANDATORY_FILE:
            for part in multipart_data.parts:
                for hk, hv in part.headers.items():
                    hv = hv.decode('utf8')
                    if hk.decode('utf8') == 'Content-Disposition':
                        if filename in hv:
                            fn = psd_common.get_config_file_path(
                                subcloud_name, consts.DEPLOY_CONFIG)
                            psd_common.upload_config_file(
                                part.content, fn, consts.DEPLOY_CONFIG)
                            payload.update({consts.DEPLOY_CONFIG: fn})
                        elif "sysadmin_password" in hv:
                            payload.update({'sysadmin_password': part.content})
        psd_common.get_common_deploy_files(payload, software_version)
        return payload

    @staticmethod
    def _get_updatestatus_payload(request):
        """retrieve payload of a patch request for update_status

        :param request: request from the http client
        :return: dict object submitted from the http client
        """

        payload = dict()
        payload.update(json.loads(request.body))
        return payload

    # TODO(nicodemos): Check if subcloud is online and network already exist in the
    # subcloud when the lock/unlock is not required for network reconfiguration
    def _validate_network_reconfiguration(self, payload, subcloud):
        if payload.get('management-state'):
            pecan.abort(422, _("Management state and network reconfiguration must "
                               "be updated separately"))
        if subcloud.management_state != dccommon_consts.MANAGEMENT_UNMANAGED:
            pecan.abort(422, _("A subcloud must be unmanaged to perform network "
                               "reconfiguration"))
        if not payload.get('bootstrap_address'):
            pecan.abort(422, _("The bootstrap_address parameter is required for "
                               "network reconfiguration"))
        # Check if all parameters exist
        if not all(payload.get(value) is not None for value in (
                SUBCLOUD_MANDATORY_NETWORK_PARAMS)):
            mandatory_params = ', '.join('--{}'.format(param.replace(
                '_', '-')) for param in SUBCLOUD_MANDATORY_NETWORK_PARAMS)
            abort_msg = (
                "The following parameters are necessary for "
                "subcloud network reconfiguration: {}".format(mandatory_params)
            )
            pecan.abort(422, _(abort_msg))

        # Check if any network values are already in use
        for param in SUBCLOUD_MANDATORY_NETWORK_PARAMS:
            if payload.get(param) == getattr(subcloud, param):
                pecan.abort(422, _("%s already in use by the subcloud.") % param)

        # Check password and decode it
        sysadmin_password = payload.get('sysadmin_password')
        if not sysadmin_password:
            pecan.abort(400, _('subcloud sysadmin_password required'))
        try:
            payload['sysadmin_password'] = utils.decode_and_normalize_passwd(
                sysadmin_password)
        except Exception:
            msg = _('Failed to decode subcloud sysadmin_password, '
                    'verify the password is base64 encoded')
            LOG.exception(msg)
            pecan.abort(400, msg)

    def _get_subcloud_users(self):
        """Get the subcloud users and passwords from keyring"""
        DEFAULT_SERVICE_PROJECT_NAME = 'services'
        # First entry is openstack user name, second entry is the user stored
        # in keyring. Not sure why heat_admin uses a different keystone name.
        SUBCLOUD_USERS = [
            ('sysinv', 'sysinv'),
            ('patching', 'patching'),
            ('vim', 'vim'),
            ('mtce', 'mtce'),
            ('fm', 'fm'),
            ('barbican', 'barbican'),
            ('smapi', 'smapi'),
            ('dcdbsync', 'dcdbsync')
        ]

        user_list = list()
        for user in SUBCLOUD_USERS:
            password = keyring.get_password(user[1],
                                            DEFAULT_SERVICE_PROJECT_NAME)
            if password:
                user_dict = dict()
                user_dict['name'] = user[0]
                user_dict['password'] = password
                user_list.append(user_dict)
            else:
                LOG.error("User %s not found in keyring as %s" % (user[0],
                                                                  user[1]))
                pecan.abort(500, _('System configuration error'))

        return user_list

    # TODO(gsilvatr): refactor to use implementation from common/utils and test
    def _get_oam_addresses(self, context, subcloud_name, sc_ks_client):
        """Get the subclouds oam addresses"""

        # First need to retrieve the Subcloud's Keystone session
        try:
            endpoint = sc_ks_client.endpoint_cache.get_endpoint('sysinv')
            sysinv_client = SysinvClient(subcloud_name,
                                         sc_ks_client.session,
                                         endpoint=endpoint)
            return sysinv_client.get_oam_addresses()
        except (keystone_exceptions.EndpointNotFound, IndexError) as e:
            message = ("Identity endpoint for subcloud: %s not found. %s" %
                       (subcloud_name, e))
            LOG.error(message)
        except dccommon_exceptions.OAMAddressesNotFound:
            message = ("OAM addresses for subcloud: %s not found." %
                       (subcloud_name))
            LOG.error(message)
        return None

    def _get_deploy_config_sync_status(self, context, subcloud_name, keystone_client):
        """Get the deploy configuration insync status of the subcloud """
        detected_alarms = None
        try:
            fm_client = FmClient(subcloud_name, keystone_client.session)
            detected_alarms = fm_client.get_alarms_by_id(
                FM_ALARM_ID_UNSYNCHRONIZED_RESOURCE)
        except Exception as ex:
            LOG.error(str(ex))
            return None

        out_of_date = False
        if detected_alarms:
            # Check if any alarm.entity_instance_id contains any of the values
            # in MONITORED_ALARM_ENTITIES.
            # We want to scope 260.002 alarms to the host entity only.
            out_of_date = any(
                any(entity_id in alarm.entity_instance_id
                    for entity_id in dccommon_consts.MONITORED_ALARM_ENTITIES)
                for alarm in detected_alarms
            )
        sync_status = dccommon_consts.DEPLOY_CONFIG_OUT_OF_DATE if out_of_date \
            else dccommon_consts.DEPLOY_CONFIG_UP_TO_DATE
        return sync_status

    def _validate_migrate(self, payload, subcloud):
        # Verify rehome data
        if not subcloud.rehome_data:
            LOG.exception("Unable to migrate subcloud %s, "
                          "required rehoming data is missing" % subcloud.name)
            pecan.abort(500, _("Unable to migrate subcloud %s, "
                               "required rehoming data is missing" % subcloud.name))
        rehome_data = json.loads(subcloud.rehome_data)
        if 'saved_payload' not in rehome_data:
            LOG.exception("Unable to migrate subcloud %s, "
                          "saved_payload is missing in rehoming data" % subcloud.name)
            pecan.abort(500, _("Unable to migrate subcloud %s, "
                               "saved_payload is missing in rehoming data" % subcloud.name))
        saved_payload = rehome_data['saved_payload']
        # Validate saved_payload
        if len(saved_payload) == 0:
            LOG.exception("Unable to migrate subcloud %s, "
                          "saved_payload is empty" % subcloud.name)
            pecan.abort(500, _("Unable to migrate subcloud %s, "
                               "saved_payload is empty" % subcloud.name))
        if 'bootstrap-address' not in saved_payload:
            LOG.exception("Unable to migrate subcloud %s, "
                          "bootstrap-address is missing in rehoming data" % subcloud.name)
            pecan.abort(500, _("Unable to migrate subcloud %s, "
                               "bootstrap-address is missing in rehoming data" % subcloud.name))
        # Validate sysadmin_password is in payload
        if 'sysadmin_password' not in payload:
            LOG.exception("Unable to migrate subcloud %s, "
                          "need sysadmin_password" % subcloud.name)
            pecan.abort(500, _("Unable to migrate subcloud %s, "
                               "need sysadmin_password" % subcloud.name))

    @staticmethod
    def _append_static_err_content(subcloud):
        err_dict = consts.ERR_MSG_DICT
        status = subcloud.get('deploy-status')
        err_msg = [subcloud.get('error-description')]
        err_code = \
            re.search(r"err_code\s*=\s*(\S*)", err_msg[0], re.IGNORECASE)
        if err_code and err_code.group(1) in err_dict:
            err_msg.append(err_dict.get(err_code.group(1)))
        if status == consts.DEPLOY_STATE_DEPLOY_FAILED:
            err_msg.append(err_dict.get(consts.DEPLOY_ERROR_MSG))
        elif status == consts.DEPLOY_STATE_BOOTSTRAP_FAILED:
            err_msg.append(err_dict.get(consts.BOOTSTRAP_ERROR_MSG))
        subcloud['error-description'] = '\n'.join(err_msg)
        return None

    @index.when(method='GET', template='json')
    def get(self, subcloud_ref=None, detail=None):
        """Get details about subcloud.

        :param subcloud_ref: ID or name of subcloud
        """
        policy.authorize(subclouds_policy.POLICY_ROOT % "get", {},
                         restcomm.extract_credentials_for_policy())
        context = restcomm.extract_context_from_environ()

        if subcloud_ref is None:
            # List of subclouds requested
            subclouds = db_api.subcloud_get_all_with_status(context)
            result = dict()
            result['subclouds'] = []
            first_time = True
            subcloud_list = []
            subcloud_status_list = []

            # We get back a subcloud, subcloud_status pair for every
            # subcloud_status entry corresponding to a subcloud.  (Subcloud
            # info repeats)
            # Aggregate all the sync status for each of the
            # endpoints per subcloud into an overall sync status
            for subcloud, subcloud_status in subclouds:
                subcloud_dict = db_api.subcloud_db_model_to_dict(subcloud)
                subcloud_status_dict = db_api.subcloud_status_db_model_to_dict(
                    subcloud_status)
                subcloud_dict.update(subcloud_status_dict)

                self._append_static_err_content(subcloud_dict)

                if not first_time:
                    if subcloud_list[-1]['id'] == subcloud_dict['id']:
                        # We have a match for this subcloud id already,
                        # check if we have a same sync_status
                        if subcloud_list[-1][consts.SYNC_STATUS] != \
                                subcloud_dict[consts.SYNC_STATUS]:
                            subcloud_list[-1][consts.SYNC_STATUS] = \
                                dccommon_consts.SYNC_STATUS_OUT_OF_SYNC

                        if subcloud_status:
                            subcloud_status_list.append(
                                db_api.subcloud_endpoint_status_db_model_to_dict(  # noqa
                                    subcloud_status))
                        subcloud_list[-1][
                            consts.ENDPOINT_SYNC_STATUS] = subcloud_status_list

                    else:
                        subcloud_status_list = []
                        if subcloud_status:
                            subcloud_status_list.append(
                                db_api.subcloud_endpoint_status_db_model_to_dict(  # noqa
                                    subcloud_status))

                        subcloud_list.append(subcloud_dict)
                else:
                    if subcloud_status:
                        subcloud_status_list.append(
                            db_api.subcloud_endpoint_status_db_model_to_dict(
                                subcloud_status))
                    subcloud_list.append(subcloud_dict)

                first_time = False

            for s in subcloud_list:
                result['subclouds'].append(s)

            return result
        else:
            # Single subcloud requested
            subcloud = None
            subcloud_dict = dict()
            subcloud_status_list = []
            endpoint_sync_dict = dict()

            if subcloud_ref.isdigit():
                # Look up subcloud as an ID
                try:
                    subcloud = db_api.subcloud_get(context, subcloud_ref)
                except exceptions.SubcloudNotFound:
                    pecan.abort(404, _('Subcloud not found'))
            else:
                # Look up subcloud by name
                try:
                    subcloud = db_api.subcloud_get_by_name(context,
                                                           subcloud_ref)
                except exceptions.SubcloudNameNotFound:
                    pecan.abort(404, _('Subcloud not found'))

            subcloud_id = subcloud.id

            # Data for this subcloud requested
            # Build up and append a dictionary of the endpoints
            # sync status to the result.
            for subcloud, subcloud_status in db_api. \
                    subcloud_get_with_status(context, subcloud_id):
                subcloud_dict = db_api.subcloud_db_model_to_dict(
                    subcloud)
                # may be empty subcloud_status entry, account for this
                if subcloud_status:
                    subcloud_status_list.append(
                        db_api.subcloud_endpoint_status_db_model_to_dict(
                            subcloud_status))
            endpoint_sync_dict = {consts.ENDPOINT_SYNC_STATUS:
                                  subcloud_status_list}
            subcloud_dict.update(endpoint_sync_dict)

            self._append_static_err_content(subcloud_dict)

            if detail is not None:
                oam_floating_ip = "unavailable"
                deploy_config_sync_status = "unknown"
                if subcloud.availability_status == dccommon_consts.AVAILABILITY_ONLINE:

                    # Get the keystone client that will be used
                    # for _get_deploy_config_sync_status and _get_oam_addresses
                    sc_ks_client = psd_common.get_ks_client(subcloud.name)
                    oam_addresses = self._get_oam_addresses(context,
                                                            subcloud.name, sc_ks_client)
                    if oam_addresses is not None:
                        oam_floating_ip = oam_addresses.oam_floating_ip

                    deploy_config_state = self._get_deploy_config_sync_status(
                        context, subcloud.name, sc_ks_client)
                    if deploy_config_state is not None:
                        deploy_config_sync_status = deploy_config_state

                extra_details = {"oam_floating_ip": oam_floating_ip,
                                 "deploy_config_sync_status": deploy_config_sync_status}

                subcloud_dict.update(extra_details)
            return subcloud_dict

    @utils.synchronized(LOCK_NAME)
    @index.when(method='POST', template='json')
    def post(self):
        """Create and deploy a new subcloud."""

        policy.authorize(subclouds_policy.POLICY_ROOT % "create", {},
                         restcomm.extract_credentials_for_policy())
        context = restcomm.extract_context_from_environ()

        payload = psd_common.get_request_data(request, None,
                                              SUBCLOUD_ADD_GET_FILE_CONTENTS)

        psd_common.validate_migrate_parameter(payload, request)

        psd_common.validate_secondary_parameter(payload, request)

        # No need sysadmin_password when add a secondary subcloud
        if 'secondary' not in payload:
            psd_common.validate_sysadmin_password(payload)

        psd_common.pre_deploy_create(payload, context, request)

        try:
            # Add the subcloud details to the database
            subcloud = psd_common.add_subcloud_to_database(context, payload)

            # Ask dcmanager-manager to add the subcloud.
            # It will do all the real work...
            self.dcmanager_rpc_client.add_subcloud(
                context, subcloud.id, payload)

            return db_api.subcloud_db_model_to_dict(subcloud)
        except RemoteError as e:
            pecan.abort(422, e.value)
        except Exception:
            LOG.exception(
                "Unable to add subcloud %s" % payload.get('name'))
            pecan.abort(500, _('Unable to add subcloud'))

    @utils.synchronized(LOCK_NAME)
    @index.when(method='PATCH', template='json')
    def patch(self, subcloud_ref=None, verb=None):
        """Update a subcloud.

        :param subcloud_ref: ID or name of subcloud to update

        :param verb: Specifies the patch action to be taken
        or subcloud update operation
        """

        policy.authorize(subclouds_policy.POLICY_ROOT % "modify", {},
                         restcomm.extract_credentials_for_policy())
        context = restcomm.extract_context_from_environ()
        subcloud = None

        if subcloud_ref is None:
            pecan.abort(400, _('Subcloud ID required'))

        if subcloud_ref.isdigit():
            # Look up subcloud as an ID
            try:
                subcloud = db_api.subcloud_get(context, subcloud_ref)
            except exceptions.SubcloudNotFound:
                pecan.abort(404, _('Subcloud not found'))
        else:
            # Look up subcloud by name
            try:
                subcloud = db_api.subcloud_get_by_name(context,
                                                       subcloud_ref)
            except exceptions.SubcloudNameNotFound:
                pecan.abort(404, _('Subcloud not found'))
        subcloud_id = subcloud.id

        if verb is None:
            # subcloud update
            payload = self._get_patch_data(request)
            if not payload:
                pecan.abort(400, _('Body required'))

            # Check if exist any network reconfiguration parameters
            reconfigure_network = any(payload.get(value) is not None for value in (
                SUBCLOUD_MANDATORY_NETWORK_PARAMS))

            if reconfigure_network:
                if utils.subcloud_is_secondary_state(subcloud.deploy_status):
                    pecan.abort(500, _("Cannot perform on %s "
                                       "state subcloud" % subcloud.deploy_status))
                system_controller_mgmt_pool = psd_common.get_network_address_pool()
                # Required parameters
                payload['name'] = subcloud.name
                payload['system_controller_network'] = (
                    system_controller_mgmt_pool.network)
                payload['system_controller_network_prefix'] = (
                    system_controller_mgmt_pool.prefix
                )
                # Needed for service endpoint reconfiguration
                payload['management_start_address'] = (
                    payload.get('management_start_ip', None)
                )
                # Validation
                self._validate_network_reconfiguration(payload, subcloud)

            management_state = payload.get('management-state')
            group_id = payload.get('group_id')
            description = payload.get('description')
            location = payload.get('location')
            bootstrap_values = payload.get('bootstrap_values')
            bootstrap_address = payload.get('bootstrap_address')

            # Syntax checking
            if management_state and \
                    management_state not in [dccommon_consts.MANAGEMENT_UNMANAGED,
                                             dccommon_consts.MANAGEMENT_MANAGED]:
                pecan.abort(400, _('Invalid management-state'))

            force_flag = payload.get('force')
            if force_flag is not None:
                if force_flag not in [True, False]:
                    pecan.abort(400, _('Invalid force value'))
                elif management_state != dccommon_consts.MANAGEMENT_MANAGED:
                    pecan.abort(400, _('Invalid option: force'))

            # Verify the group_id is valid
            if group_id is not None:
                try:
                    # group_id may be passed in the payload as an int or str
                    group_id = str(group_id)
                    if group_id.isdigit():
                        grp = db_api.subcloud_group_get(context, group_id)
                    else:
                        # replace the group_id (name) with the id
                        grp = db_api.subcloud_group_get_by_name(context,
                                                                group_id)
                    group_id = grp.id
                except (exceptions.SubcloudGroupNameNotFound,
                        exceptions.SubcloudGroupNotFound):
                    pecan.abort(400, _('Invalid group'))

            if INSTALL_VALUES in payload:
                psd_common.validate_install_values(payload, subcloud)
                payload['data_install'] = json.dumps(payload[INSTALL_VALUES])

            try:
                if reconfigure_network:
                    self.dcmanager_rpc_client.update_subcloud_with_network_reconfig(
                        context, subcloud_id, payload)
                    return db_api.subcloud_db_model_to_dict(subcloud)
                subcloud = self.dcmanager_rpc_client.update_subcloud(
                    context, subcloud_id, management_state=management_state,
                    description=description, location=location,
                    group_id=group_id, data_install=payload.get('data_install'),
                    force=force_flag,
                    bootstrap_values=bootstrap_values,
                    bootstrap_address=bootstrap_address)
                return subcloud
            except RemoteError as e:
                pecan.abort(422, e.value)
            except Exception as e:
                # additional exceptions.
                LOG.exception(e)
                pecan.abort(500, _('Unable to update subcloud'))
        elif verb == 'reconfigure':
            if utils.subcloud_is_secondary_state(subcloud.deploy_status):
                pecan.abort(500, _("Cannot perform on %s "
                                   "state subcloud" % subcloud.deploy_status))
            payload = self._get_reconfig_payload(
                request, subcloud.name, subcloud.software_version)
            if not payload:
                pecan.abort(400, _('Body required'))

            if (subcloud.deploy_status
                    not in [consts.DEPLOY_STATE_DONE,
                            consts.DEPLOY_STATE_DEPLOY_PREP_FAILED,
                            consts.DEPLOY_STATE_DEPLOY_FAILED]
                    and not prestage.is_deploy_status_prestage(
                        subcloud.deploy_status)):
                pecan.abort(400,
                            _('Subcloud deploy status must be either '
                              'complete, deploy-prep-failed, deploy-failed, '
                              'or prestage-...'))
            sysadmin_password = \
                payload.get('sysadmin_password')
            if not sysadmin_password:
                pecan.abort(400, _('subcloud sysadmin_password required'))

            try:
                payload['sysadmin_password'] = \
                    utils.decode_and_normalize_passwd(sysadmin_password)
            except Exception:
                msg = _('Failed to decode subcloud sysadmin_password, '
                        'verify the password is base64 encoded')
                LOG.exception(msg)
                pecan.abort(400, msg)

            try:
                subcloud = self.dcmanager_rpc_client.reconfigure_subcloud(
                    context, subcloud_id, payload)
                return subcloud
            except RemoteError as e:
                pecan.abort(422, e.value)
            except Exception:
                LOG.exception("Unable to reconfigure subcloud %s" % subcloud.name)
                pecan.abort(500, _('Unable to reconfigure subcloud'))
        elif verb == "reinstall":
            if utils.subcloud_is_secondary_state(subcloud.deploy_status):
                pecan.abort(500, _("Cannot perform on %s "
                                   "state subcloud" % subcloud.deploy_status))
            psd_common.check_required_parameters(request,
                                                 SUBCLOUD_ADD_MANDATORY_FILE)

            payload = psd_common.get_request_data(
                request, subcloud, SUBCLOUD_ADD_GET_FILE_CONTENTS)

            install_values = psd_common.get_subcloud_db_install_values(subcloud)

            if subcloud.availability_status == dccommon_consts.AVAILABILITY_ONLINE:
                msg = _('Cannot re-install an online subcloud')
                LOG.exception(msg)
                pecan.abort(400, msg)

            psd_common.validate_bootstrap_values(payload)

            psd_common.validate_sysadmin_password(payload)

            if payload.get('name') != subcloud.name:
                pecan.abort(400, _('name is incorrect for the subcloud'))

            psd_common.validate_subcloud_config(context, payload, verb)

            # If a subcloud release is not passed, use the current
            # system controller software_version
            payload['software_version'] = payload.get('release', tsc.SW_VERSION)

            psd_common.validate_k8s_version(payload)

            # If the software version of the subcloud is different from the
            # specified or active load, update the software version in install
            # value and delete the image path in install values, then the subcloud
            # will be reinstalled using the image in dc_vault.
            if install_values.get(
                    'software_version') != payload['software_version']:
                install_values['software_version'] = payload['software_version']
                install_values.pop('image', None)

            # Confirm the specified or active load is still in dc-vault if
            # image not in install values, add the matching image into the
            # install values.
            matching_iso, err_msg = utils.get_matching_iso(
                payload['software_version'])
            if err_msg:
                LOG.exception(err_msg)
                pecan.abort(400, _(err_msg))
            LOG.info("Image in install_values is set to %s" % matching_iso)
            install_values['image'] = matching_iso

            # Update the install values in payload
            payload.update({
                'bmc_password': install_values.get('bmc_password'),
                'install_values': install_values,
            })

            # Update data install(software version, image path)
            data_install = None
            if 'install_values' in payload:
                data_install = json.dumps(payload['install_values'])

            # Upload the deploy config files if it is included in the request
            psd_common.upload_deploy_config_file(request, payload)

            try:
                # Align the software version of the subcloud with reinstall
                # version. Update description, location and group id if offered,
                # update the deploy status as pre-install.
                subcloud = db_api.subcloud_update(
                    context,
                    subcloud_id,
                    description=payload.get('description', subcloud.description),
                    location=payload.get('location', subcloud.location),
                    software_version=payload['software_version'],
                    management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
                    deploy_status=consts.DEPLOY_STATE_PRE_INSTALL,
                    first_identity_sync_complete=False,
                    data_install=data_install)

                self.dcmanager_rpc_client.reinstall_subcloud(
                    context, subcloud_id, payload)

                return db_api.subcloud_db_model_to_dict(subcloud)
            except RemoteError as e:
                pecan.abort(422, e.value)
            except Exception:
                LOG.exception("Unable to reinstall subcloud %s" % subcloud.name)
                pecan.abort(500, _('Unable to reinstall subcloud'))
        elif verb == "redeploy":
            if utils.subcloud_is_secondary_state(subcloud.deploy_status):
                pecan.abort(500, _("Cannot perform on %s "
                                   "state subcloud" % subcloud.deploy_status))
            config_file = psd_common.get_config_file_path(subcloud.name,
                                                          consts.DEPLOY_CONFIG)
            has_bootstrap_values = consts.BOOTSTRAP_VALUES in request.POST
            has_original_config_values = os.path.exists(config_file)
            has_new_config_values = consts.DEPLOY_CONFIG in request.POST
            has_config_values = has_original_config_values or has_new_config_values
            payload = psd_common.get_request_data(
                request, subcloud, SUBCLOUD_REDEPLOY_GET_FILE_CONTENTS)

            if (subcloud.availability_status == dccommon_consts.AVAILABILITY_ONLINE or
                    subcloud.management_state == dccommon_consts.MANAGEMENT_MANAGED):
                msg = _('Cannot re-deploy an online and/or managed subcloud')
                LOG.warning(msg)
                pecan.abort(400, msg)

            # If a subcloud release is not passed, use the current
            # system controller software_version
            payload['software_version'] = payload.get('release', tsc.SW_VERSION)

            # Don't load previously stored bootstrap_values if they are present in
            # the request, as this would override the already loaded values from it.
            # As config_values are optional, only attempt to load previously stored
            # values if this phase should be executed.
            files_for_redeploy = SUBCLOUD_REDEPLOY_GET_FILE_CONTENTS.copy()
            if has_bootstrap_values:
                files_for_redeploy.remove(BOOTSTRAP_VALUES)
            if not has_config_values:
                files_for_redeploy.remove(consts.DEPLOY_CONFIG)

            psd_common.populate_payload_with_pre_existing_data(
                payload, subcloud, files_for_redeploy)

            psd_common.validate_sysadmin_password(payload)
            psd_common.pre_deploy_install(payload, validate_password=False)
            psd_common.pre_deploy_bootstrap(context, payload, subcloud,
                                            has_bootstrap_values,
                                            validate_password=False)
            payload['bootstrap-address'] = \
                payload['install_values']['bootstrap_address']

            try:
                # Align the software version of the subcloud with redeploy
                # version. Update description, location and group id if offered,
                # update the deploy status as pre-install.
                subcloud = db_api.subcloud_update(
                    context,
                    subcloud_id,
                    description=payload.get('description'),
                    location=payload.get('location'),
                    software_version=payload['software_version'],
                    deploy_status=consts.DEPLOY_STATE_PRE_INSTALL,
                    first_identity_sync_complete=False,
                    data_install=json.dumps(payload['install_values']))

                self.dcmanager_rpc_client.redeploy_subcloud(
                    context, subcloud_id, payload)

                return db_api.subcloud_db_model_to_dict(subcloud)
            except RemoteError as e:
                pecan.abort(422, e.value)
            except Exception:
                LOG.exception("Unable to redeploy subcloud %s" % subcloud.name)
                pecan.abort(500, _('Unable to redeploy subcloud'))
        elif verb == "restore":
            pecan.abort(410, _('This API is deprecated. '
                               'Please use /v1.0/subcloud-backup/restore'))
        elif verb == 'update_status':
            res = self.updatestatus(subcloud.name)
            return res
        elif verb == 'prestage':
            if utils.subcloud_is_secondary_state(subcloud.deploy_status):
                pecan.abort(500, _("Cannot perform on %s "
                                   "state subcloud" % subcloud.deploy_status))
            payload = self._get_prestage_payload(request)
            payload['subcloud_name'] = subcloud.name
            try:
                prestage.global_prestage_validate(payload)
            except exceptions.PrestagePreCheckFailedException as exc:
                LOG.exception("global_prestage_validate failed")
                pecan.abort(400, _(str(exc)))

            try:
                payload['oam_floating_ip'] = \
                    prestage.validate_prestage(subcloud, payload)
            except exceptions.PrestagePreCheckFailedException as exc:
                LOG.exception("validate_prestage failed")
                pecan.abort(400, _(str(exc)))

            prestage_software_version = payload.get(
                consts.PRESTAGE_REQUEST_RELEASE, tsc.SW_VERSION)

            try:
                self.dcmanager_rpc_client.prestage_subcloud(context, payload)
                # local update to deploy_status - this is just for CLI response:
                subcloud.deploy_status = consts.PRESTAGE_STATE_PACKAGES

                subcloud_dict = db_api.subcloud_db_model_to_dict(subcloud)
                subcloud_dict.update(
                    {consts.PRESTAGE_SOFTWARE_VERSION: prestage_software_version})
                return subcloud_dict
            except RemoteError as e:
                pecan.abort(422, e.value)
            except Exception:
                LOG.exception("Unable to prestage subcloud %s" % subcloud.name)
                pecan.abort(500, _('Unable to prestage subcloud'))
        elif verb == 'migrate':
            try:
                # Reject if not in secondary/rehome-failed/rehome-prep-failed state
                if subcloud.deploy_status not in [consts.DEPLOY_STATE_SECONDARY,
                                                  consts.DEPLOY_STATE_REHOME_FAILED,
                                                  consts.DEPLOY_STATE_REHOME_PREP_FAILED]:
                    LOG.exception("Unable to migrate subcloud %s, "
                                  "must be in secondary or rehome failure state" % subcloud.name)
                    pecan.abort(400, _("Unable to migrate subcloud %s, "
                                       "must be in secondary or rehome failure state" %
                                       subcloud.name))
                payload = json.loads(request.body)
                self._validate_migrate(payload, subcloud)

                # Call migrate
                self.dcmanager_rpc_client.migrate_subcloud(context, subcloud.id, payload)
                return db_api.subcloud_db_model_to_dict(subcloud)
            except RemoteError as e:
                pecan.abort(422, e.value)
            except Exception:
                LOG.exception(
                    "Unable to migrate subcloud %s" % subcloud.name)
                pecan.abort(500, _('Unable to migrate subcloud'))

    @utils.synchronized(LOCK_NAME)
    @index.when(method='delete', template='json')
    def delete(self, subcloud_ref):
        """Delete a subcloud.

        :param subcloud_ref: ID or name of subcloud to delete.
        """
        policy.authorize(subclouds_policy.POLICY_ROOT % "delete", {},
                         restcomm.extract_credentials_for_policy())
        context = restcomm.extract_context_from_environ()
        subcloud = None

        if subcloud_ref.isdigit():
            # Look up subcloud as an ID
            try:
                subcloud = db_api.subcloud_get(context, subcloud_ref)
            except exceptions.SubcloudNotFound:
                pecan.abort(404, _('Subcloud not found'))
        else:
            # Look up subcloud by name
            try:
                subcloud = db_api.subcloud_get_by_name(context,
                                                       subcloud_ref)
            except exceptions.SubcloudNameNotFound:
                pecan.abort(404, _('Subcloud not found'))

        subcloud_id = subcloud.id

        try:
            # Ask dcmanager-manager to delete the subcloud.
            # It will do all the real work...
            return self.dcmanager_rpc_client.delete_subcloud(context,
                                                             subcloud_id)
        except RemoteError as e:
            pecan.abort(422, e.value)
        except Exception as e:
            LOG.exception(e)
            pecan.abort(500, _('Unable to delete subcloud'))

    def updatestatus(self, subcloud_name):
        """Update subcloud sync status

        :param subcloud_name: name of the subcloud
        :return: json result object for the operation on success
        """

        payload = self._get_updatestatus_payload(request)
        if not payload:
            pecan.abort(400, _('Body required'))

        endpoint = payload.get('endpoint')
        if not endpoint:
            pecan.abort(400, _('endpoint required'))
        allowed_endpoints = [dccommon_consts.ENDPOINT_TYPE_DC_CERT]
        if endpoint not in allowed_endpoints:
            pecan.abort(400, _('updating endpoint %s status is not allowed'
                               % endpoint))

        status = payload.get('status')
        if not status:
            pecan.abort(400, _('status required'))

        allowed_status = [dccommon_consts.SYNC_STATUS_IN_SYNC,
                          dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
                          dccommon_consts.SYNC_STATUS_UNKNOWN]
        if status not in allowed_status:
            pecan.abort(400, _('status %s in invalid.' % status))

        LOG.info('update %s set %s=%s' % (subcloud_name, endpoint, status))
        context = restcomm.extract_context_from_environ()
        self.dcmanager_state_rpc_client.update_subcloud_endpoint_status(
            context, subcloud_name, endpoint, status)

        result = {'result': 'OK'}
        return result
