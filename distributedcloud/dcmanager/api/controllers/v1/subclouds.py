# Copyright (c) 2017 Ericsson AB.
# Copyright (c) 2017-2025 Wind River Systems, Inc.
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

import base64
import collections
import datetime
import json
import os
import re

from fm_api.constants import FM_ALARM_ID_UNSYNCHRONIZED_RESOURCE
from oslo_config import cfg
from oslo_log import log as logging
from oslo_messaging import RemoteError
from oslo_utils import timeutils
import pecan
from pecan import expose
from pecan import request
from requests_toolbelt.multipart import decoder
import yaml

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.fm import FmClient
from dccommon.drivers.openstack import software_v1
from dccommon.drivers.openstack import vim
from dccommon.endpoint_cache import EndpointCache
from dccommon import utils as cutils
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

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

LOCK_NAME = "SubcloudsController"

SUBCLOUD_ADD_GET_FILE_CONTENTS = [
    consts.BOOTSTRAP_VALUES,
    consts.INSTALL_VALUES,
]

SUBCLOUD_REDEPLOY_GET_FILE_CONTENTS = [
    consts.INSTALL_VALUES,
    consts.BOOTSTRAP_VALUES,
    consts.DEPLOY_CONFIG,
]

SUBCLOUD_MANDATORY_NETWORK_PARAMS = [
    "management_subnet",
    "management_gateway_ip",
    "management_start_ip",
    "management_end_ip",
]


def _get_multipart_field_name(part):
    content = part.headers[b"Content-Disposition"].decode("utf8")
    regex = 'name="([^"]*)"'
    return re.search(regex, content).group(1)


class SubcloudsController(object):
    VERSION_ALIASES = {
        "Newton": "1.0",
    }

    software_deploy_state_cache = collections.defaultdict(dict)

    def __init__(self):
        super(SubcloudsController, self).__init__()
        self.dcmanager_rpc_client = rpc_client.ManagerClient()
        self.dcmanager_state_rpc_client = rpc_client.SubcloudStateClient()

    @expose(generic=True, template="json")
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
            if field_name in [consts.INSTALL_VALUES, "force"]:
                field_content = utils.yaml_safe_load(field_content, field_name)

            payload[field_name] = field_content

        return payload

    @staticmethod
    def _get_prestage_payload(request):
        fields = [
            "sysadmin_password",
            "force",
            consts.PRESTAGE_REQUEST_RELEASE,
            consts.PRESTAGE_FOR_INSTALL,
            consts.PRESTAGE_FOR_SW_DEPLOY,
        ]
        payload = {"force": False}
        try:
            body = json.loads(request.body)
        except Exception:
            pecan.abort(400, _("Request body is malformed."))

        for field in fields:
            val = body.get(field)
            if val is None:
                if field == "sysadmin_password":
                    pecan.abort(400, _("%s is required." % field))
            else:
                if field == "sysadmin_password":
                    try:
                        base64.b64decode(val).decode("utf-8")
                        payload["sysadmin_password"] = val
                    except Exception:
                        pecan.abort(
                            400,
                            _(
                                "Failed to decode subcloud sysadmin_password, "
                                "verify the password is base64 encoded"
                            ),
                        )
                elif field == "force":
                    if val.lower() in ("true", "false", "t", "f"):
                        payload["force"] = val.lower() in ("true", "t")
                    else:
                        pecan.abort(400, _("Invalid value for force option: %s" % val))
                elif field in (
                    consts.PRESTAGE_FOR_INSTALL,
                    consts.PRESTAGE_FOR_SW_DEPLOY,
                ):
                    if val.lower() in ("true", "false", "t", "f"):
                        payload[field] = val.lower() in ("true", "t")
                    else:
                        errmsg = f"Invalid value for {field} option: {val}"
                        pecan.abort(400, _(errmsg))

                elif field == consts.PRESTAGE_REQUEST_RELEASE:
                    payload[consts.PRESTAGE_REQUEST_RELEASE] = val
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

    def _check_existing_vim_strategy(self, context, subcloud):
        """Check existing vim strategy by state.

        An on-going vim strategy may interfere with subcloud reconfiguration
        attempt and result in unrecoverable failure. Check if there is an
        on-going strategy and whether it is in a state that is safe to proceed.

        :param context: request context object.
        :param subcloud: subcloud object.

        :returns bool: True if on-going vim strategy found or not searchable,
                       otherwise False.
        """

        # Firstly, check the DC orchestrated vim strategies from database
        if utils.verify_ongoing_subcloud_strategy(context, subcloud):
            return True

        # Then check the system config update strategy
        try:
            keystone_endpoint = cutils.build_subcloud_endpoint(
                subcloud.management_start_ip, dccommon_consts.ENDPOINT_NAME_KEYSTONE
            )
            admin_session = EndpointCache.get_admin_session(auth_url=keystone_endpoint)
            vim_client = vim.VimClient(
                admin_session,
                endpoint=cutils.build_subcloud_endpoint(
                    subcloud.management_start_ip, dccommon_consts.ENDPOINT_NAME_VIM
                ),
            )
            strategy = vim_client.get_strategy(
                strategy_name=vim.STRATEGY_NAME_SYS_CONFIG_UPDATE,
                raise_error_if_missing=False,
            )
        except Exception:
            # Don't block the operation when the vim service is inaccessible
            LOG.warning(
                f"Openstack admin endpoints on subcloud: {subcloud.name} "
                "are unaccessible"
            )
            return False

        return strategy and strategy.state in vim.TRANSITORY_STATES

    # TODO(nicodemos): Check if subcloud is online and network already exist in the
    # subcloud when the lock/unlock is not required for network reconfiguration
    def _validate_network_reconfiguration(self, context, payload, subcloud):
        if payload.get("management-state"):
            pecan.abort(
                422,
                _(
                    "Management state and network reconfiguration must "
                    "be updated separately"
                ),
            )
        if subcloud.management_state != dccommon_consts.MANAGEMENT_UNMANAGED:
            pecan.abort(
                422,
                _("A subcloud must be unmanaged to perform network reconfiguration"),
            )
        if not payload.get("bootstrap_address"):
            pecan.abort(
                422,
                _(
                    "The bootstrap_address parameter is required for "
                    "network reconfiguration"
                ),
            )
        # Check if all parameters exist
        if not all(
            payload.get(value) is not None
            for value in (SUBCLOUD_MANDATORY_NETWORK_PARAMS)
        ):
            mandatory_params = ", ".join(
                "--{}".format(param.replace("_", "-"))
                for param in SUBCLOUD_MANDATORY_NETWORK_PARAMS
            )
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
        sysadmin_password = payload.get("sysadmin_password")
        if not sysadmin_password:
            pecan.abort(400, _("subcloud sysadmin_password required"))
        try:
            payload["sysadmin_password"] = base64.b64decode(sysadmin_password).decode(
                "utf-8"
            )
        except Exception:
            msg = _(
                "Failed to decode subcloud sysadmin_password, "
                "verify the password is base64 encoded"
            )
            LOG.exception(msg)
            pecan.abort(400, msg)

        subclouds = db_api.subcloud_get_all(context)

        psd_common.validate_admin_network_config(
            payload.get("management_subnet"),
            payload.get("management_start_ip"),
            payload.get("management_end_ip"),
            payload.get("management_gateway_ip"),
            existing_subclouds=subclouds,
        )

    def _get_deploy_config_sync_status(self, subcloud, admin_session):
        """Get the deploy configuration insync status of the subcloud"""
        detected_alarms = None
        try:
            fm_client = FmClient(
                subcloud.name,
                admin_session,
                endpoint=cutils.build_subcloud_endpoint(
                    subcloud.management_start_ip, dccommon_consts.ENDPOINT_NAME_FM
                ),
            )
            detected_alarms = fm_client.get_alarms_by_id(
                FM_ALARM_ID_UNSYNCHRONIZED_RESOURCE
            )
        except Exception as ex:
            LOG.error(str(ex))
            return None

        out_of_date = False
        if detected_alarms:
            # Check if any alarm.entity_instance_id contains any of the values
            # in MONITORED_ALARM_ENTITIES.
            # We want to scope 260.002 alarms to the host entity only.
            out_of_date = any(
                any(
                    entity_id in alarm.entity_instance_id
                    for entity_id in dccommon_consts.MONITORED_ALARM_ENTITIES
                )
                for alarm in detected_alarms
            )
        sync_status = (
            dccommon_consts.DEPLOY_CONFIG_OUT_OF_DATE
            if out_of_date
            else dccommon_consts.DEPLOY_CONFIG_UP_TO_DATE
        )
        return sync_status

    def _validate_rehome_pending(self, subcloud, management_state, request):
        unmanaged = dccommon_consts.MANAGEMENT_UNMANAGED
        error_msg = None

        # Can only set the subcloud to rehome-pending
        # if the deployment is done or request from another site.
        # The reason that we skip the validation if the request is from
        # another site is when migrating the subcloud back to a peer site,
        # the site will attempt to set the remote subcloud's deploy status
        # to "rehome-pending." However, the remote subcloud might be in a
        # "rehome-failed" state from a previous failed rehoming attempt.
        if (
            subcloud.deploy_status != consts.DEPLOY_STATE_DONE
            and not utils.is_req_from_another_dc(request)
        ):
            error_msg = (
                "The deploy status can only be updated to "
                f"'{consts.DEPLOY_STATE_REHOME_PENDING}' if the current "
                f"deploy status is '{consts.DEPLOY_STATE_DONE}'"
            )

        # Can only set the subcloud to rehome-pending if the subcloud is
        # being unmanaged or is already unmanaged
        if management_state != unmanaged and (
            management_state or subcloud.management_state != unmanaged
        ):
            error_msg = (
                f"Subcloud must be {unmanaged} for its deploy status to "
                f"be updated to '{consts.DEPLOY_STATE_REHOME_PENDING}'"
            )

        if error_msg:
            pecan.abort(400, error_msg)

    @staticmethod
    def _append_static_err_content(subcloud):
        err_dict = consts.ERR_MSG_DICT
        status = subcloud.get("deploy-status")
        err_msg = [subcloud.get("error-description")]
        err_code = re.search(r"err_code\s*=\s*(\S*)", err_msg[0], re.IGNORECASE)
        if err_code and err_code.group(1) in err_dict:
            err_msg.append(err_dict.get(err_code.group(1)))
        if status == consts.DEPLOY_STATE_CONFIG_FAILED:
            err_msg.append(err_dict.get(consts.CONFIG_ERROR_MSG))
        elif status == consts.DEPLOY_STATE_BOOTSTRAP_FAILED:
            err_msg.append(err_dict.get(consts.BOOTSTRAP_ERROR_MSG))
        subcloud["error-description"] = "\n".join(err_msg)
        return None

    @index.when(method="GET", template="json")
    def get(self, subcloud_ref=None, detail=None):
        """Get details about subcloud.

        :param subcloud_ref: ID or name of subcloud
        """
        policy.authorize(
            subclouds_policy.POLICY_ROOT % "get",
            {},
            restcomm.extract_credentials_for_policy(),
        )
        context = restcomm.extract_context_from_environ()

        if subcloud_ref is None:
            # List of subclouds requested
            subclouds = db_api.subcloud_get_all_with_status(context)
            result = {"subclouds": []}
            subcloud_dict = {}

            for subcloud, endpoint_type, sync_status in subclouds:
                subcloud_id = subcloud.id
                if subcloud_id not in subcloud_dict:
                    subcloud_dict[subcloud_id] = db_api.subcloud_db_model_to_dict(
                        subcloud
                    )
                    self._append_static_err_content(subcloud_dict[subcloud_id])

                    subcloud_dict[subcloud_id].update({consts.SYNC_STATUS: sync_status})
                    subcloud_dict[subcloud_id][consts.ENDPOINT_SYNC_STATUS] = []

                subcloud_dict[subcloud_id][consts.ENDPOINT_SYNC_STATUS].append(
                    {
                        consts.ENDPOINT_TYPE: endpoint_type,
                        consts.SYNC_STATUS: sync_status,
                    }
                )

                # If any of the endpoint sync status is out of sync, then
                # the subcloud sync status is out of sync
                if sync_status != subcloud_dict[subcloud_id][consts.SYNC_STATUS]:
                    subcloud_dict[subcloud_id][
                        consts.SYNC_STATUS
                    ] = dccommon_consts.SYNC_STATUS_OUT_OF_SYNC

            for subcloud in subcloud_dict.values():
                # This is to reduce changes on cert-mon
                # Overwrites the name value with region
                if utils.is_req_from_cert_mon_agent(request):
                    subcloud["name"] = subcloud["region-name"]
                result["subclouds"].append(subcloud)
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
                    pecan.abort(404, _("Subcloud not found"))
            else:
                try:
                    # When the request comes from the cert-monitor or another
                    # DC, it is based on the region name (which is UUID format).
                    # Whereas, if the request comes from a client other
                    # than cert-monitor, it will do the lookup based on
                    # the subcloud name.
                    if utils.is_req_from_cert_mon_agent(
                        request
                    ) or utils.is_req_from_another_dc(request):
                        subcloud = db_api.subcloud_get_by_region_name(
                            context, subcloud_ref
                        )
                    else:
                        subcloud = db_api.subcloud_get_by_name(context, subcloud_ref)
                except (
                    exceptions.SubcloudRegionNameNotFound,
                    exceptions.SubcloudNameNotFound,
                ):
                    pecan.abort(404, _("Subcloud not found"))

            subcloud_id = subcloud.id

            # Data for this subcloud requested
            # Build up and append a dictionary of the endpoints
            # sync status to the result.
            for subcloud, subcloud_status in db_api.subcloud_get_with_status(
                context, subcloud_id
            ):
                subcloud_dict = db_api.subcloud_db_model_to_dict(subcloud)
                # may be empty subcloud_status entry, account for this
                if subcloud_status:
                    subcloud_status_list.append(
                        db_api.subcloud_endpoint_status_db_model_to_dict(
                            subcloud_status
                        )
                    )
            endpoint_sync_dict = {consts.ENDPOINT_SYNC_STATUS: subcloud_status_list}
            subcloud_dict.update(endpoint_sync_dict)

            self._append_static_err_content(subcloud_dict)

            subcloud_region = subcloud.region_name
            if detail is not None:
                oam_floating_ip = "unavailable"
                deploy_config_sync_status = "unknown"
                if subcloud.availability_status == dccommon_consts.AVAILABILITY_ONLINE:
                    keystone_endpoint = cutils.build_subcloud_endpoint(
                        subcloud.management_start_ip,
                        dccommon_consts.ENDPOINT_NAME_KEYSTONE,
                    )
                    admin_session = EndpointCache.get_admin_session(
                        auth_url=keystone_endpoint
                    )

                    # Only interested in subcloud's primary OAM pool's address
                    oam_floating_ip_primary = utils.get_oam_floating_ip_primary(
                        subcloud, admin_session
                    )
                    if oam_floating_ip_primary is not None:
                        oam_floating_ip = oam_floating_ip_primary

                    deploy_config_state = self._get_deploy_config_sync_status(
                        subcloud, admin_session
                    )
                    if deploy_config_state is not None:
                        deploy_config_sync_status = deploy_config_state

                # The region name is also sent as 'region_name' to maintain backwards
                # compatibility with previous DC client versions
                extra_details = {
                    "oam_floating_ip": oam_floating_ip,
                    "deploy_config_sync_status": deploy_config_sync_status,
                    "region_name": subcloud_region,
                }

                subcloud_dict.update(extra_details)
            return subcloud_dict

    @staticmethod
    @utils.synchronized("software-deploy-state-cache", external=False)
    def is_valid_software_deploy_state():
        try:
            if (
                not SubcloudsController.software_deploy_state_cache
                or not SubcloudsController.software_deploy_state_cache.get("expiry")
                or SubcloudsController.software_deploy_state_cache["expiry"]
                <= timeutils.utcnow()
            ):
                SubcloudsController.software_deploy_state_cache["result"] = True
                admin_session = EndpointCache.get_admin_session()
                software_client = software_v1.SoftwareClient(
                    admin_session,
                    region=cutils.get_region_one_name(),
                )
                software_list = software_client.list()
                for release in software_list:
                    if release["state"] not in (
                        software_v1.AVAILABLE,
                        software_v1.COMMITTED,
                        software_v1.DEPLOYED,
                        software_v1.UNAVAILABLE,
                    ):
                        LOG.info(
                            "is_valid_software_deploy_state, not valid for: %s",
                            software_list,
                        )
                        SubcloudsController.software_deploy_state_cache["result"] = (
                            False
                        )
                        break

                if SubcloudsController.software_deploy_state_cache["result"]:
                    LOG.debug(
                        "is_valid_software_deploy_state, valid: %s", software_list
                    )

                SubcloudsController.software_deploy_state_cache["expiry"] = (
                    timeutils.utcnow() + datetime.timedelta(minutes=1)
                )

        except Exception:
            LOG.exception("Failure initializing OS Client, disallowing.")
            SubcloudsController.software_deploy_state_cache["result"] = False

        return SubcloudsController.software_deploy_state_cache["result"]

    @staticmethod
    def validate_software_deploy_state():
        if not SubcloudsController.is_valid_software_deploy_state():
            pecan.abort(
                400,
                _(
                    "A local software deployment operation is in progress. "
                    "Please finish the software deployment operation before "
                    "(re)installing/updating the subcloud."
                ),
            )

    @utils.synchronized(LOCK_NAME)
    @index.when(method="POST", template="json")
    def post(self):
        """Create and deploy a new subcloud."""

        context = restcomm.extract_context_from_environ()
        context.is_admin = policy.authorize(
            subclouds_policy.POLICY_ROOT % "create",
            {},
            restcomm.extract_credentials_for_policy(),
        )

        self.validate_software_deploy_state()

        bootstrap_sc_name = psd_common.get_bootstrap_subcloud_name(request)

        payload = psd_common.get_request_data(
            request, None, SUBCLOUD_ADD_GET_FILE_CONTENTS
        )

        psd_common.validate_migrate_parameter(payload)

        psd_common.validate_secondary_parameter(payload, request)

        # Compares to match both supplied and bootstrap name param
        # of the subcloud if migrate is on
        if payload.get("migrate") == "true" and bootstrap_sc_name is not None:
            if bootstrap_sc_name != payload.get("name"):
                pecan.abort(
                    400,
                    _(
                        "subcloud name does not match the "
                        "name defined in bootstrap file"
                    ),
                )

        # No need sysadmin_password when add a secondary subcloud
        # If the subcloud is not secondary, a unique UUID
        # for the subcloud region will be generated.
        if "secondary" not in payload:
            psd_common.validate_sysadmin_password(payload)
            psd_common.subcloud_region_create(payload, context)

        psd_common.pre_deploy_create(payload, context, request)

        if payload.get("enroll"):
            psd_common.validate_enroll_parameter(payload)
            psd_common.upload_cloud_init_config(request, payload)

        try:
            # Add the subcloud details to the database
            subcloud = psd_common.add_subcloud_to_database(context, payload)

            # Ask dcmanager-manager to add the subcloud.
            # It will do all the real work...
            # If the subcloud is secondary, it will be synchronous operation.
            # A normal subcloud add will be asynchronous operation.
            if "secondary" in payload:
                self.dcmanager_rpc_client.add_secondary_subcloud(
                    context, subcloud.id, payload
                )
            else:
                self.dcmanager_rpc_client.add_subcloud(context, subcloud.id, payload)

            return db_api.subcloud_db_model_to_dict(subcloud)
        except RemoteError as e:
            pecan.abort(422, e.value)
        except Exception:
            LOG.exception("Unable to add subcloud %s" % payload.get("name"))
            pecan.abort(500, _("Unable to add subcloud"))

    @utils.synchronized(LOCK_NAME)
    @index.when(method="PATCH", template="json")
    def patch(self, subcloud_ref=None, verb=None):
        """Update a subcloud.

        :param subcloud_ref: ID or name of subcloud to update

        :param verb: Specifies the patch action to be taken
        or subcloud update operation
        """
        context = restcomm.extract_context_from_environ()
        context.is_admin = self.authorize_user(verb)
        subcloud = None

        if subcloud_ref is None:
            pecan.abort(400, _("Subcloud ID required"))

        if subcloud_ref.isdigit():
            # Look up subcloud as an ID
            try:
                subcloud = db_api.subcloud_get(context, subcloud_ref)
            except exceptions.SubcloudNotFound:
                pecan.abort(404, _("Subcloud not found"))
        else:
            try:
                # When the request comes from the cert-monitor or another DC,
                # it is based on the region name (which is UUID format).
                # Whereas, if the request comes from a client other
                # than cert-monitor, it will do the lookup based on
                # the subcloud name.
                if utils.is_req_from_cert_mon_agent(
                    request
                ) or utils.is_req_from_another_dc(request):
                    subcloud = db_api.subcloud_get_by_region_name(context, subcloud_ref)
                else:
                    subcloud = db_api.subcloud_get_by_name(context, subcloud_ref)
            except (
                exceptions.SubcloudRegionNameNotFound,
                exceptions.SubcloudNameNotFound,
            ):
                pecan.abort(404, _("Subcloud not found"))

        subcloud_id = subcloud.id

        if verb is None:
            # subcloud update
            payload = self._get_patch_data(request)
            if not payload:
                pecan.abort(400, _("Body required"))

            # Create a set to store the affected SPG(s) that need to be
            # synced due to the subcloud update. This set will be utilized to
            # update the sync_status in the corresponding PGA on each site.
            sync_peer_groups = set()

            req_from_another_dc = utils.is_req_from_another_dc(request)
            original_pgrp = None
            leader_on_local_site = False
            peer_site_available = True
            pga = None
            update_in_non_primary_site = False
            if subcloud.peer_group_id is not None:
                # Get the original peer group of the subcloud
                original_pgrp = db_api.subcloud_peer_group_get(
                    context, subcloud.peer_group_id
                )
                leader_on_local_site = utils.is_leader_on_local_site(original_pgrp)
                # A sync command is required after updating a subcloud
                # in an SPG that is already associated with a PGA in the primary
                # and leader site. The existence of the PGA will be checked
                # by the update_association_sync_status method later.
                if (
                    original_pgrp.group_priority == 0
                    and leader_on_local_site
                    and not req_from_another_dc
                ):
                    sync_peer_groups.add(subcloud.peer_group_id)

                # Get the peer site availability and PGA sync status
                # TODO(lzhu1): support multiple sites
                associations = db_api.peer_group_association_get_by_peer_group_id(
                    context, original_pgrp.id
                )
                for association in associations:
                    pga = association
                    system_peer = db_api.system_peer_get(
                        context, association.system_peer_id
                    )
                    peer_site_available = (
                        system_peer.availability_state
                        == consts.SYSTEM_PEER_AVAILABILITY_STATE_AVAILABLE
                    )

            peer_group = payload.get("peer_group")
            # Verify the peer_group is valid
            peer_group_id = None
            if peer_group is not None:
                # peer_group may be passed in the payload as an int or str
                peer_group = str(peer_group)
                # Check if user wants to remove a subcloud
                # from a subcloud-peer-group by
                # setting peer_group_id as 'none',
                # then we will pass 'none' string as
                # the peer_group_id,
                # update_subcloud() will handle it and
                # Set the peer_group_id DB into None.
                if peer_group.lower() == "none":
                    if original_pgrp:
                        # Check the system leader is not on this site
                        if not leader_on_local_site:
                            pecan.abort(
                                400,
                                _(
                                    "Removing subcloud from a peer group not led by "
                                    "the current site is prohibited."
                                ),
                            )
                        # If system peer is available, then does not allow
                        # to remove the subcloud from secondary peer group
                        if peer_site_available and original_pgrp.group_priority > 0:
                            pecan.abort(
                                400,
                                _(
                                    "Removing subcloud from a peer group associated "
                                    "with an available system peer is prohibited."
                                ),
                            )
                        peer_group_id = "none"
                else:
                    if not (
                        subcloud.rehome_data
                        or (
                            payload.get("bootstrap_values")
                            and payload.get("bootstrap_address")
                        )
                    ):
                        pecan.abort(
                            400,
                            _(
                                "Cannot update the subcloud peer group: must provide "
                                "both the bootstrap-values and bootstrap-address."
                            ),
                        )
                    if (
                        original_pgrp
                        and original_pgrp.group_priority > 0
                        and str(subcloud.peer_group_id) != peer_group
                    ):
                        pecan.abort(
                            400,
                            _(
                                "Cannot move subcloud to a new peer group if the "
                                "original peer group is not primary (non-zero "
                                "priority)."
                            ),
                        )
                    pgrp = utils.subcloud_peer_group_get_by_ref(context, peer_group)
                    if not pgrp:
                        pecan.abort(400, _("Invalid peer group"))
                    if not req_from_another_dc:
                        if pgrp.group_priority > 0:
                            pecan.abort(
                                400,
                                _(
                                    "Cannot set the subcloud to a peer "
                                    "group with non-zero priority."
                                ),
                            )
                        elif not utils.is_leader_on_local_site(pgrp):
                            pecan.abort(
                                400,
                                _(
                                    "Update subcloud to a peer group that is not led "
                                    "by the current site is prohibited."
                                ),
                            )
                        elif not (
                            subcloud.deploy_status == consts.DEPLOY_STATE_DONE
                            and subcloud.management_state
                            == dccommon_consts.MANAGEMENT_MANAGED
                            and subcloud.availability_status
                            == dccommon_consts.AVAILABILITY_ONLINE
                        ):
                            pecan.abort(
                                400,
                                _(
                                    "Only subclouds that are managed and online can be "
                                    "added to a peer group."
                                ),
                            )
                        sync_peer_groups.add(pgrp.id)
                    peer_group_id = pgrp.id

            bootstrap_values = payload.get("bootstrap_values")
            bootstrap_address = payload.get("bootstrap_address")

            # Subcloud can only be updated while it is managed in
            # the primary site because the sync command can only be issued
            # in the site where the SPG was created. However, bootstrap
            # values or address update is an exception.
            if original_pgrp and peer_group_id is None and not req_from_another_dc:
                if original_pgrp.group_priority > 0:
                    if bootstrap_values or bootstrap_address:
                        if any(
                            field not in ("bootstrap_values", "bootstrap_address")
                            for field in payload
                        ):
                            pecan.abort(
                                400,
                                _(
                                    "Only bootstrap values and address "
                                    "can be updated in the non-primary site"
                                ),
                            )
                        if (
                            subcloud.deploy_status == consts.DEPLOY_STATE_REHOME_FAILED
                            and not peer_site_available
                        ):
                            update_in_non_primary_site = True
                        else:
                            pecan.abort(
                                400,
                                _(
                                    "Subcloud bootstrap values or address update in "
                                    "the non-primary site is only allowed when rehome "
                                    "failed and the primary site is unavailable."
                                ),
                            )
                    if not update_in_non_primary_site:
                        pecan.abort(
                            400,
                            _(
                                "Subcloud update is only allowed when "
                                "its peer group priority value is 0."
                            ),
                        )

                # Updating a subcloud under the peer group on primary site
                # that the peer group should be led by the primary site.
                if not leader_on_local_site and not update_in_non_primary_site:
                    pecan.abort(
                        400,
                        _(
                            "Updating subcloud from a peer group not led by the "
                            "current site is prohibited."
                        ),
                    )

            # Rename the subcloud
            new_subcloud_name = payload.get("name")
            if new_subcloud_name is not None:
                # To be renamed the subcloud must be in unmanaged, valid deploy
                # state, and no going prestage
                if (
                    subcloud.management_state != dccommon_consts.MANAGEMENT_UNMANAGED
                    or subcloud.deploy_status != consts.DEPLOY_STATE_DONE
                    or subcloud.prestage_status in consts.STATES_FOR_ONGOING_PRESTAGE
                ):
                    msg = (
                        "Subcloud %s must be deployed, unmanaged and no "
                        "ongoing prestage for the subcloud rename operation."
                        % subcloud.name
                    )
                    pecan.abort(400, msg)

                # Validates new name
                if not utils.is_subcloud_name_format_valid(new_subcloud_name):
                    pecan.abort(400, _("new name must contain alphabetic characters"))

                # Checks if new subcloud name is the same as the current subcloud
                if new_subcloud_name == subcloud.name:
                    pecan.abort(
                        400,
                        _(
                            "Provided subcloud name %s is the same as the current "
                            "subcloud %s. A different name is required to "
                            "rename the subcloud" % (new_subcloud_name, subcloud.name)
                        ),
                    )

                error_msg = (
                    "Unable to rename subcloud %s with their region %s to %s"
                    % (subcloud.name, subcloud.region_name, new_subcloud_name)
                )

                try:
                    LOG.info(
                        "Renaming subcloud %s to: %s\n"
                        % (subcloud.name, new_subcloud_name)
                    )
                    sc = self.dcmanager_rpc_client.rename_subcloud(
                        context, subcloud_id, subcloud.name, new_subcloud_name
                    )
                    subcloud.name = sc["name"]
                except RemoteError as e:
                    LOG.error(error_msg)
                    pecan.abort(422, e.value)
                except Exception:
                    LOG.error(error_msg)
                    pecan.abort(500, _("Unable to rename subcloud"))

            # Check if exist any network reconfiguration parameters
            reconfigure_network = any(
                payload.get(value) is not None
                for value in (SUBCLOUD_MANDATORY_NETWORK_PARAMS)
            )

            if reconfigure_network:
                if utils.subcloud_is_secondary_state(subcloud.deploy_status):
                    pecan.abort(
                        500,
                        _(
                            "Cannot perform on %s state subcloud"
                            % subcloud.deploy_status
                        ),
                    )

                if payload.get("management_gateway_ip") is None:
                    mandatory_params = ", ".join(
                        "--{}".format(param.replace("_", "-"))
                        for param in SUBCLOUD_MANDATORY_NETWORK_PARAMS
                    )
                    abort_msg = (
                        "The following parameters are necessary for "
                        "subcloud network reconfiguration: {}".format(mandatory_params)
                    )
                    pecan.abort(422, _(abort_msg))

                # reconfigure network update provides management_gateway_ip instead of
                # management_gateway_address on payload.
                # Needed for get_primary_management_gateway_address_ip_family
                payload["management_gateway_address"] = payload.get(
                    "management_gateway_ip", None
                )

                system_controller_mgmt_pools = psd_common.get_network_address_pools()
                # Subcloud will use primary management_gateway_address to
                # access one of dual-stack systemcontroller admin/mgmt subnets, based
                # upon IP family of primary gateway address.
                try:
                    system_controller_mgmt_pool = utils.get_pool_by_ip_family(
                        system_controller_mgmt_pools,
                        utils.get_primary_management_gateway_address_ip_family(payload),
                    )
                except Exception as e:
                    error_msg = (
                        "subcloud primary management gateway IP's IP family does "
                        "not exist on system controller managements"
                    )
                    LOG.exception(error_msg)
                    pecan.abort(400, _("%s: %s") % (error_msg, e))

                # Required parameters
                payload["name"] = subcloud.name
                payload["region_name"] = subcloud.region_name
                payload["system_controller_network"] = (
                    system_controller_mgmt_pool.network
                )
                payload["system_controller_network_prefix"] = (
                    system_controller_mgmt_pool.prefix
                )
                # Needed for service endpoint reconfiguration
                payload["management_start_address"] = payload.get(
                    "management_start_ip", None
                )
                # Validation
                self._validate_network_reconfiguration(context, payload, subcloud)
                # Validate there's no on-going vim strategy
                if self._check_existing_vim_strategy(context, subcloud):
                    error_msg = (
                        "Reconfiguring subcloud network is not allowed while there "
                        "is an on-going orchestrated operation in this subcloud. "
                        "Please try again after the strategy has completed."
                    )
                    pecan.abort(400, error_msg)

            # If the peer-controller-gateway-address attribute of the
            # system_peer object on the peer site is updated, the route needs
            # to be updated, so we validate it here.
            if bootstrap_values is not None and req_from_another_dc:
                try:
                    bootstrap_values_dict = yaml.load(
                        bootstrap_values, Loader=yaml.SafeLoader
                    )
                except Exception:
                    error_msg = "bootstrap_values is malformed."
                    LOG.exception(error_msg)
                    pecan.abort(400, _(error_msg))

                systemcontroller_gateway_address = bootstrap_values_dict.get(
                    "systemcontroller_gateway_address"
                )

                if systemcontroller_gateway_address is not None and (
                    systemcontroller_gateway_address.split(",")[0]
                    != subcloud.systemcontroller_gateway_ip
                ):
                    # Pass bootstrap_values_dict for patch operations where these
                    # values aren't in payload, unlike subcloud add where they are.
                    # Function needs management/admin_subnet for validation
                    psd_common.validate_systemcontroller_gateway_address(
                        systemcontroller_gateway_address, bootstrap_values_dict
                    )

            management_state = payload.get("management-state")
            group_id = payload.get("group_id")
            description = payload.get("description")
            location = payload.get("location")

            # If the migrate flag is present we need to update the deploy status
            # to consts.DEPLOY_STATE_REHOME_PENDING
            deploy_status = None
            if (
                payload.get("migrate") == "true"
                and subcloud.deploy_status != consts.DEPLOY_STATE_REHOME_PENDING
            ):
                self._validate_rehome_pending(subcloud, management_state, request)
                deploy_status = consts.DEPLOY_STATE_REHOME_PENDING

            # Syntax checking
            if management_state and management_state not in [
                dccommon_consts.MANAGEMENT_UNMANAGED,
                dccommon_consts.MANAGEMENT_MANAGED,
            ]:
                pecan.abort(400, _("Invalid management-state"))
            if (
                management_state
                and subcloud.peer_group_id is not None
                and not utils.is_req_from_another_dc(request)
            ):
                pecan.abort(
                    400,
                    _(
                        "Cannot update the management state of a subcloud that is "
                        "associated with a peer group."
                    ),
                )

            force_flag = payload.get("force")
            if force_flag is not None:
                if force_flag not in [True, False]:
                    pecan.abort(400, _("Invalid force value"))
                elif management_state != dccommon_consts.MANAGEMENT_MANAGED:
                    pecan.abort(400, _("Invalid option: force"))

            # Verify the group_id is valid
            if group_id is not None:
                try:
                    # group_id may be passed in the payload as an int or str
                    group_id = str(group_id)
                    if group_id.isdigit():
                        grp = db_api.subcloud_group_get(context, group_id)
                    else:
                        # replace the group_id (name) with the id
                        grp = db_api.subcloud_group_get_by_name(context, group_id)
                    group_id = grp.id
                except (
                    exceptions.SubcloudGroupNameNotFound,
                    exceptions.SubcloudGroupNotFound,
                ):
                    pecan.abort(400, _("Invalid group"))

            if consts.INSTALL_VALUES in payload:
                # install_values of secondary subclouds are validated on
                # peer site
                if utils.subcloud_is_secondary_state(
                    subcloud.deploy_status
                ) and utils.is_req_from_another_dc(request):
                    LOG.debug(
                        "Skipping install_values validation for subcloud "
                        f"{subcloud.name}. Subcloud is secondary and "
                        "request is from a peer site."
                    )
                else:
                    psd_common.validate_install_values(payload, subcloud)
                payload["data_install"] = json.dumps(payload[consts.INSTALL_VALUES])

            try:
                if reconfigure_network:
                    self.dcmanager_rpc_client.update_subcloud_with_network_reconfig(
                        context, subcloud_id, payload
                    )
                    return db_api.subcloud_db_model_to_dict(subcloud)
                subcloud = self.dcmanager_rpc_client.update_subcloud(
                    context,
                    subcloud_id,
                    management_state=management_state,
                    description=description,
                    location=location,
                    group_id=group_id,
                    data_install=payload.get("data_install"),
                    force=force_flag,
                    peer_group_id=peer_group_id,
                    bootstrap_values=bootstrap_values,
                    bootstrap_address=bootstrap_address,
                    deploy_status=deploy_status,
                )

                # Update the PGA sync_status to out-of-sync locally
                # in the non-primary site. This only occurs when the primary site
                # is unavailable and rehome fails due to the issue with bootstrap
                # values or address.
                if (
                    update_in_non_primary_site
                    and pga.sync_status != consts.ASSOCIATION_SYNC_STATUS_OUT_OF_SYNC
                ):
                    db_api.peer_group_association_update(
                        context,
                        pga.id,
                        sync_status=consts.ASSOCIATION_SYNC_STATUS_OUT_OF_SYNC,
                    )
                    LOG.debug(
                        f"Updated Local Peer Group Association {pga.id} "
                        "sync_status to out-of-sync."
                    )
                # Sync the PGA out-of-sync status across all sites launched by
                # the primary site.
                elif sync_peer_groups:
                    # Collect the affected peer group association IDs.
                    association_ids = set()
                    for pg_id in sync_peer_groups:
                        association_ids.update(
                            self.dcmanager_rpc_client.update_association_sync_status(
                                context,
                                pg_id,
                                consts.ASSOCIATION_SYNC_STATUS_OUT_OF_SYNC,
                            )
                        )
                    # Generate an informative message for reminding the operator
                    # that the sync command(s) should be executed.
                    info_message = utils.generate_sync_info_message(association_ids)
                    if info_message:
                        subcloud["info_message"] = info_message

                return subcloud
            except RemoteError as e:
                pecan.abort(422, e.value)
            except Exception as e:
                # additional exceptions.
                LOG.exception(e)
                pecan.abort(500, _("Unable to update subcloud"))
        elif verb == "redeploy":
            if utils.subcloud_is_secondary_state(subcloud.deploy_status):
                pecan.abort(
                    500,
                    _("Cannot perform on %s state subcloud" % subcloud.deploy_status),
                )
            self.validate_software_deploy_state()
            config_file = psd_common.get_config_file_path(
                subcloud.name, consts.DEPLOY_CONFIG
            )
            has_bootstrap_values = consts.BOOTSTRAP_VALUES in request.POST
            has_original_config_values = os.path.exists(config_file)
            has_new_config_values = consts.DEPLOY_CONFIG in request.POST
            has_config_values = has_original_config_values or has_new_config_values
            payload = psd_common.get_request_data(
                request, subcloud, SUBCLOUD_REDEPLOY_GET_FILE_CONTENTS
            )

            if (
                subcloud.availability_status == dccommon_consts.AVAILABILITY_ONLINE
                or subcloud.management_state == dccommon_consts.MANAGEMENT_MANAGED
            ):
                msg = _("Cannot re-deploy an online and/or managed subcloud")
                LOG.warning(msg)
                pecan.abort(400, msg)

            payload["software_version"] = utils.get_sw_version(payload.get("release"))

            # Don't load previously stored bootstrap_values if they are present in
            # the request, as this would override the already loaded values from it.
            # As config_values are optional, only attempt to load previously stored
            # values if this phase should be executed.
            files_for_redeploy = SUBCLOUD_REDEPLOY_GET_FILE_CONTENTS.copy()
            if has_bootstrap_values:
                files_for_redeploy.remove(consts.BOOTSTRAP_VALUES)
            if not has_config_values:
                files_for_redeploy.remove(consts.DEPLOY_CONFIG)

            psd_common.populate_payload_with_pre_existing_data(
                payload, subcloud, files_for_redeploy
            )

            payload["bootstrap-address"] = payload["install_values"][
                "bootstrap_address"
            ]
            psd_common.validate_sysadmin_password(payload)
            psd_common.pre_deploy_install(payload, validate_password=False)
            psd_common.pre_deploy_bootstrap(
                context,
                payload,
                subcloud,
                has_bootstrap_values,
                validate_password=False,
            )
            if has_config_values:
                psd_common.pre_deploy_config(payload, subcloud, validate_password=False)

            try:
                # Align the software version of the subcloud with redeploy
                # version. Update description, location and group id if offered,
                # update the deploy status as pre-install.
                previous_version = subcloud.software_version
                subcloud = db_api.subcloud_update(
                    context,
                    subcloud_id,
                    description=payload.get("description"),
                    location=payload.get("location"),
                    software_version=payload["software_version"],
                    deploy_status=consts.DEPLOY_STATE_PRE_INSTALL,
                    first_identity_sync_complete=False,
                    data_install=json.dumps(payload["install_values"]),
                )

                self.dcmanager_rpc_client.redeploy_subcloud(
                    context, subcloud_id, payload, previous_version
                )

                return db_api.subcloud_db_model_to_dict(subcloud)
            except RemoteError as e:
                pecan.abort(422, e.value)
            except Exception:
                LOG.exception("Unable to redeploy subcloud %s" % subcloud.name)
                pecan.abort(500, _("Unable to redeploy subcloud"))
        elif verb == "restore":
            pecan.abort(
                410,
                _("This API is deprecated. Please use /v1.0/subcloud-backup/restore"),
            )
        elif verb == "reconfigure":
            pecan.abort(
                410,
                _(
                    "This API is deprecated. "
                    "Please use /v1.0/phased-subcloud-deploy/{subcloud}/configure"
                ),
            )
        elif verb == "reinstall":
            pecan.abort(
                410,
                _(
                    "This API is deprecated. "
                    "Please use /v1.0/subclouds/{subcloud}/redeploy"
                ),
            )
        elif verb == "update_status":
            res = self.updatestatus(subcloud.name, subcloud.region_name)
            return res
        elif verb == "prestage":
            if utils.subcloud_is_secondary_state(subcloud.deploy_status):
                pecan.abort(
                    500,
                    _("Cannot perform on %s state subcloud" % subcloud.deploy_status),
                )
            payload = self._get_prestage_payload(request)
            payload["subcloud_name"] = subcloud.name
            try:
                prestage.global_prestage_validate(payload)
            except exceptions.PrestagePreCheckFailedException as exc:
                LOG.exception("global_prestage_validate failed")
                pecan.abort(400, _(str(exc)))

            try:
                payload["oam_floating_ip"] = prestage.validate_prestage(
                    subcloud, payload
                )
            except exceptions.PrestagePreCheckFailedException as exc:
                LOG.exception("validate_prestage failed")
                pecan.abort(400, _(str(exc)))

            try:
                self.dcmanager_rpc_client.prestage_subcloud(context, payload)
                # local update to prestage_status - this is just for CLI response:
                subcloud.prestage_status = consts.PRESTAGE_STATE_PRESTAGING

                subcloud_dict = db_api.subcloud_db_model_to_dict(subcloud)
                subcloud_dict.update(
                    {
                        consts.PRESTAGE_SOFTWARE_VERSION: payload.get(
                            consts.PRESTAGE_REQUEST_RELEASE
                        )
                    }
                )
                return subcloud_dict
            except RemoteError as e:
                pecan.abort(422, e.value)
            except Exception:
                LOG.exception("Unable to prestage subcloud %s" % subcloud.name)
                pecan.abort(500, _("Unable to prestage subcloud"))

    @utils.synchronized(LOCK_NAME)
    @index.when(method="delete", template="json")
    def delete(self, subcloud_ref):
        """Delete a subcloud.

        :param subcloud_ref: ID or name of subcloud to delete.
        """

        context = restcomm.extract_context_from_environ()
        context.is_admin = policy.authorize(
            subclouds_policy.POLICY_ROOT % "delete",
            {},
            restcomm.extract_credentials_for_policy(),
        )
        subcloud = None

        if subcloud_ref.isdigit():
            # Look up subcloud as an ID
            try:
                subcloud = db_api.subcloud_get(context, subcloud_ref)
            except exceptions.SubcloudNotFound:
                pecan.abort(404, _("Subcloud not found"))
        else:
            # Look up subcloud by name
            try:
                subcloud = db_api.subcloud_get_by_name(context, subcloud_ref)
            except exceptions.SubcloudNameNotFound:
                pecan.abort(404, _("Subcloud not found"))

        subcloud_id = subcloud.id
        peer_group_id = subcloud.peer_group_id
        subcloud_management_state = subcloud.management_state

        # Check if the subcloud is "managed" status
        if (
            subcloud_management_state == dccommon_consts.MANAGEMENT_MANAGED
            and not utils.is_req_from_another_dc(request)
        ):
            pecan.abort(400, _("Cannot delete a subcloud that is 'managed' status"))

        if subcloud.deploy_status in consts.INVALID_DEPLOY_STATES_FOR_DELETE:
            pecan.abort(400, _("Cannot delete a subcloud during an active operation."))

        # Check if the subcloud is part of a peer group
        if peer_group_id is not None and not utils.is_req_from_another_dc(request):
            pecan.abort(
                400,
                _("Cannot delete a subcloud that is part of a peer group on this site"),
            )

        try:
            # Ask dcmanager-manager to delete the subcloud.
            # It will do all the real work...
            return self.dcmanager_rpc_client.delete_subcloud(context, subcloud_id)
        except RemoteError as e:
            pecan.abort(422, e.value)
        except Exception as e:
            LOG.exception(e)
            pecan.abort(500, _("Unable to delete subcloud"))

    def updatestatus(self, subcloud_name, subcloud_region):
        """Update subcloud sync status

        :param subcloud_name: name of the subcloud
        :param subcloud_region: name of the subcloud region
        :return: json result object for the operation on success
        """

        payload = self._get_updatestatus_payload(request)
        if not payload:
            pecan.abort(400, _("Body required"))

        endpoint = payload.get("endpoint")
        if not endpoint:
            pecan.abort(400, _("endpoint required"))
        allowed_endpoints = [dccommon_consts.ENDPOINT_TYPE_DC_CERT]
        if endpoint not in allowed_endpoints:
            pecan.abort(400, _("updating endpoint %s status is not allowed" % endpoint))

        status = payload.get("status")
        if not status:
            pecan.abort(400, _("status required"))

        allowed_status = [
            dccommon_consts.SYNC_STATUS_IN_SYNC,
            dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
            dccommon_consts.SYNC_STATUS_UNKNOWN,
        ]
        if status not in allowed_status:
            pecan.abort(400, _("status %s in invalid." % status))

        LOG.info("update %s set %s=%s" % (subcloud_name, endpoint, status))
        context = restcomm.extract_context_from_environ()
        self.dcmanager_state_rpc_client.update_subcloud_endpoint_status(
            context, subcloud_name, subcloud_region, endpoint, status
        )

        result = {"result": "OK"}
        return result

    def authorize_user(self, verb):
        """check the user has access to the API call

        :param verb: None,redeploy,prestage,reconfigure,restore
        """
        rule = subclouds_policy.POLICY_ROOT % "modify"
        if verb is None:
            payload = self._get_patch_data(request)
            if not payload:
                pecan.abort(400, _("Body required"))
            if payload.get("management-state"):
                rule = subclouds_policy.POLICY_ROOT % "manage_unmanage"
        has_api_access = policy.authorize(
            rule, {}, restcomm.extract_credentials_for_policy()
        )
        return has_api_access
