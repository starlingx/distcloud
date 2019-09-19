# Copyright (c) 2017 Ericsson AB.
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
# Copyright (c) 2017-2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import keyring
from netaddr import IPAddress
from netaddr import IPNetwork
from netaddr import IPRange
from oslo_config import cfg
from oslo_log import log as logging
from oslo_messaging import RemoteError
import yaml

import pecan
from pecan import expose
from pecan import request

from controllerconfig.common.exceptions import ValidateFail
from controllerconfig.utils import validate_address_str
from controllerconfig.utils import validate_network_str

from dcorch.drivers.openstack.keystone_v3 import KeystoneClient

from dcmanager.api.controllers import restcomm
from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.common.i18n import _
from dcmanager.db import api as db_api
from dcmanager.drivers.openstack.sysinv_v1 import SysinvClient
from dcmanager.rpc import client as rpc_client


CONF = cfg.CONF
LOG = logging.getLogger(__name__)
# System mode
SYSTEM_MODE_DUPLEX = "duplex"
SYSTEM_MODE_SIMPLEX = "simplex"
SYSTEM_MODE_DUPLEX_DIRECT = "duplex-direct"


class SubcloudsController(object):
    VERSION_ALIASES = {
        'Newton': '1.0',
    }

    def __init__(self):
        super(SubcloudsController, self).__init__()
        self.rpc_client = rpc_client.ManagerClient()

    # to do the version compatibility for future purpose
    def _determine_version_cap(self, target):
        version_cap = 1.0
        return version_cap

    @expose(generic=True, template='json')
    def index(self):
        # Route the request to specific methods with parameters
        pass

    def _validate_subcloud_config(self,
                                  context,
                                  name,
                                  management_subnet_str,
                                  management_start_ip_str,
                                  management_end_ip_str,
                                  management_gateway_ip_str,
                                  external_oam_subnet_str,
                                  external_oam_gateway_address_str,
                                  external_oam_floating_address_str,
                                  systemcontroller_gateway_ip_str):
        """Check whether subcloud config is valid."""

        # Validate the name
        if name.isdigit():
            pecan.abort(400, _("name must contain alphabetic characters"))

        if name in [consts.DEFAULT_REGION_NAME,
                    consts.SYSTEM_CONTROLLER_NAME]:
            pecan.abort(400, _("name cannot be %(bad_name1)s or %(bad_name2)s")
                        % {'bad_name1': consts.DEFAULT_REGION_NAME,
                           'bad_name2': consts.SYSTEM_CONTROLLER_NAME})

        # Parse/validate the management subnet
        subcloud_subnets = []
        subclouds = db_api.subcloud_get_all(context)
        for subcloud in subclouds:
            subcloud_subnets.append(IPNetwork(subcloud.management_subnet))

        MIN_MANAGEMENT_SUBNET_SIZE = 8
        # subtract 3 for network, gateway and broadcast addresses.
        MIN_MANAGEMENT_ADDRESSES = MIN_MANAGEMENT_SUBNET_SIZE - 3

        management_subnet = None
        try:
            management_subnet = validate_network_str(
                management_subnet_str,
                minimum_size=MIN_MANAGEMENT_SUBNET_SIZE,
                existing_networks=subcloud_subnets)
        except ValidateFail as e:
            LOG.exception(e)
            pecan.abort(400, _("management_subnet invalid: %s") % e)

        # Parse/validate the start/end addresses
        management_start_ip = None
        try:
            management_start_ip = validate_address_str(
                management_start_ip_str, management_subnet)
        except ValidateFail as e:
            LOG.exception(e)
            pecan.abort(400, _("management_start_address invalid: %s") % e)

        management_end_ip = None
        try:
            management_end_ip = validate_address_str(
                management_end_ip_str, management_subnet)
        except ValidateFail as e:
            LOG.exception(e)
            pecan.abort(400, _("management_end_address invalid: %s") % e)

        if not management_start_ip < management_end_ip:
            pecan.abort(
                400,
                _("management_start_address  not less than "
                  "management_end_address"))

        if not len(IPRange(management_start_ip, management_end_ip)) >= \
                MIN_MANAGEMENT_ADDRESSES:
            pecan.abort(
                400,
                _("management address range must contain at least %d "
                  "addresses") % MIN_MANAGEMENT_ADDRESSES)

        # Parse/validate the gateway
        try:
            validate_address_str(
                management_gateway_ip_str, management_subnet)
        except ValidateFail as e:
            LOG.exception(e)
            pecan.abort(400, _("management_gateway_address invalid: %s") % e)

        # Ensure subcloud management gateway is not within the actual subcloud
        # management subnet address pool for consistency with the
        # systemcontroller gateway restriction below. Address collision
        # is not a concern as the address is added to sysinv.
        subcloud_mgmt_address_start = IPAddress(management_start_ip_str)
        subcloud_mgmt_address_end = IPAddress(management_end_ip_str)
        subcloud_mgmt_gw_ip = IPAddress(management_gateway_ip_str)
        if ((subcloud_mgmt_gw_ip >= subcloud_mgmt_address_start) and
                (subcloud_mgmt_gw_ip <= subcloud_mgmt_address_end)):
            pecan.abort(400, _("management_gateway_address invalid, "
                               "is within management pool: %(start)s - "
                               "%(end)s") %
                        {'start': subcloud_mgmt_address_start,
                         'end': subcloud_mgmt_address_end})

        # Ensure systemcontroller gateway is in the management subnet
        # for the systemcontroller region.
        management_address_pool = self._get_management_address_pool(context)
        systemcontroller_subnet_str = "%s/%d" % (
            management_address_pool.network,
            management_address_pool.prefix)
        systemcontroller_subnet = IPNetwork(systemcontroller_subnet_str)
        try:
            validate_address_str(
                systemcontroller_gateway_ip_str, systemcontroller_subnet)
        except ValidateFail as e:
            LOG.exception(e)
            pecan.abort(400,
                        _("systemcontroller_gateway_address invalid: %s") % e)
        # Ensure systemcontroller gateway is not within the actual
        # management subnet address pool to prevent address collision.
        mgmt_address_start = IPAddress(management_address_pool.ranges[0][0])
        mgmt_address_end = IPAddress(management_address_pool.ranges[0][1])
        systemcontroller_gw_ip = IPAddress(systemcontroller_gateway_ip_str)
        if ((systemcontroller_gw_ip >= mgmt_address_start) and
                (systemcontroller_gw_ip <= mgmt_address_end)):
            pecan.abort(400, _("systemcontroller_gateway_address invalid, "
                               "is within management pool: %(start)s - "
                               "%(end)s") %
                        {'start': mgmt_address_start, 'end': mgmt_address_end})

        # Parse/validate the oam subnet
        MIN_OAM_SUBNET_SIZE = 3
        oam_subnet = None
        try:
            oam_subnet = validate_network_str(
                external_oam_subnet_str,
                minimum_size=MIN_OAM_SUBNET_SIZE,
                existing_networks=subcloud_subnets)
        except ValidateFail as e:
            LOG.exception(e)
            pecan.abort(400, _("external_oam_subnet invalid: %s") % e)

        # Parse/validate the addresses
        try:
            validate_address_str(
                external_oam_gateway_address_str, oam_subnet)
        except ValidateFail as e:
            LOG.exception(e)
            pecan.abort(400, _("oam_gateway_address invalid: %s") % e)

        try:
            validate_address_str(
                external_oam_floating_address_str, oam_subnet)
        except ValidateFail as e:
            LOG.exception(e)
            pecan.abort(400, _("oam_floating_address invalid: %s") % e)

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

    def _get_management_address_pool(self, context):
        """Get the system controller's management address pool"""
        session = KeystoneClient().endpoint_cache.get_session_from_token(
            context.auth_token, context.project)
        sysinv_client = SysinvClient(consts.DEFAULT_REGION_NAME, session)
        return sysinv_client.get_management_address_pool()

    @index.when(method='GET', template='json')
    def get(self, subcloud_ref=None):
        """Get details about subcloud.

        :param subcloud_ref: ID or name of subcloud
        """
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

                if not first_time:
                    if subcloud_list[-1]['id'] == subcloud_dict['id']:
                        # We have a match for this subcloud id already,
                        # check if we have a same sync_status
                        if subcloud_list[-1][consts.SYNC_STATUS] != \
                                subcloud_dict[consts.SYNC_STATUS]:
                            subcloud_list[-1][consts.SYNC_STATUS] = \
                                consts.SYNC_STATUS_OUT_OF_SYNC

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

            return subcloud_dict

    @index.when(method='POST', template='json')
    def post(self, subcloud_ref=None):
        """Create and deploy a new subcloud.

        :param subcloud_ref: ID of or name subcloud (only used when generating
                             config)
        """

        context = restcomm.extract_context_from_environ()

        if subcloud_ref is None:
            payload = yaml.safe_load(request.body)

            if not payload:
                pecan.abort(400, _('Body required'))
            name = payload.get('name')
            if not name:
                pecan.abort(400, _('name required'))
            system_mode = payload.get('system_mode')
            if not system_mode:
                pecan.abort(400, _('system_mode required'))

            management_subnet = payload.get('management_subnet')
            if not management_subnet:
                pecan.abort(400, _('management_subnet required'))

            management_start_ip = payload.get('management_start_address')
            if not management_start_ip:
                pecan.abort(400, _('management_start_address required'))

            management_end_ip = payload.get('management_end_address')
            if not management_end_ip:
                pecan.abort(400, _('management_end_address required'))

            management_gateway_ip = payload.get('management_gateway_address')
            if not management_gateway_ip:
                pecan.abort(400, _('management_gateway_address required'))

            systemcontroller_gateway_ip = \
                payload.get('systemcontroller_gateway_address')
            if not systemcontroller_gateway_ip:
                pecan.abort(400,
                            _('systemcontroller_gateway_address required'))

            external_oam_subnet = payload.get('external_oam_subnet')
            if not external_oam_subnet:
                pecan.abort(400, _('external_oam_subnet required'))

            external_oam_gateway_ip = \
                payload.get('external_oam_gateway_address')
            if not external_oam_gateway_ip:
                pecan.abort(400, _('external_oam_gateway_address required'))

            external_oam_floating_ip = \
                payload.get('external_oam_floating_address')
            if not external_oam_floating_ip:
                pecan.abort(400, _('external_oam_floating_address required'))

            subcloud_password = \
                payload.get('subcloud_password')
            if not subcloud_password:
                pecan.abort(400, _('subcloud_password required'))

            self._validate_subcloud_config(context,
                                           name,
                                           management_subnet,
                                           management_start_ip,
                                           management_end_ip,
                                           management_gateway_ip,
                                           external_oam_subnet,
                                           external_oam_gateway_ip,
                                           external_oam_floating_ip,
                                           systemcontroller_gateway_ip)

            try:
                # Ask dcmanager-manager to add the subcloud.
                # It will do all the real work...
                return self.rpc_client.add_subcloud(context, payload)
            except RemoteError as e:
                pecan.abort(422, e.value)
            except Exception as e:
                LOG.exception(e)
                pecan.abort(500, _('Unable to create subcloud'))
        else:
            pecan.abort(400, _('Invalid request'))

    @index.when(method='PATCH', template='json')
    def patch(self, subcloud_ref=None):
        """Update a subcloud.

        :param subcloud_ref: ID or name of subcloud to update
        """

        context = restcomm.extract_context_from_environ()
        subcloud = None

        if subcloud_ref is None:
            pecan.abort(400, _('Subcloud ID required'))

        payload = eval(request.body)
        if not payload:
            pecan.abort(400, _('Body required'))

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

        management_state = payload.get('management-state')
        description = payload.get('description')
        location = payload.get('location')

        if not (management_state or description or location):
            pecan.abort(400, _('nothing to update'))

        # Syntax checking
        if management_state and \
                management_state not in [consts.MANAGEMENT_UNMANAGED,
                                         consts.MANAGEMENT_MANAGED]:
            pecan.abort(400, _('Invalid management-state'))

        try:
            # Inform dcmanager-manager that subcloud has been updated.
            # It will do all the real work...
            subcloud = self.rpc_client.update_subcloud(
                context, subcloud_id, management_state=management_state,
                description=description, location=location)
            return subcloud
        except RemoteError as e:
            pecan.abort(422, e.value)
        except Exception as e:
            # additional exceptions.
            LOG.exception(e)
            pecan.abort(500, _('Unable to update subcloud'))

    @index.when(method='delete', template='json')
    def delete(self, subcloud_ref):
        """Delete a subcloud.

        :param subcloud_ref: ID or name of subcloud to delete.
        """
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
            return self.rpc_client.delete_subcloud(context, subcloud_id)
        except RemoteError as e:
            pecan.abort(422, e.value)
        except Exception as e:
            LOG.exception(e)
            pecan.abort(500, _('Unable to delete subcloud'))
