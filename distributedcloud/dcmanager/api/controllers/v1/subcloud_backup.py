#
# Copyright (c) 2022,2024-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import base64
from collections import namedtuple
import json
import os

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
from dcmanager.common import exceptions
from dcmanager.common.i18n import _
from dcmanager.common import utils
from dcmanager.db import api as db_api
from dcmanager.rpc import client as rpc_client


CONF = cfg.CONF
LOG = logging.getLogger(__name__)

LOCK_NAME = "SubcloudBackupController"

# Subcloud/group information to be retrieved from request params
RequestEntity = namedtuple("RequestEntity", ["type", "id", "name", "subclouds"])


class SubcloudBackupController(object):
    def __init__(self):
        super(SubcloudBackupController, self).__init__()
        self.dcmanager_rpc_client = rpc_client.ManagerClient(
            timeout=consts.RPC_SUBCLOUD_BACKUP_TIMEOUT
        )

    @expose(generic=True, template="json")
    def index(self):
        # Route the request to specific methods with parameters
        pass

    @staticmethod
    def _get_payload(request, verb):
        expected_params = dict()
        if verb == "create":
            expected_params = {
                "subcloud": str,
                "group": str,
                "local_only": str,
                "registry_images": str,
                "backup_values": dict,
                "sysadmin_password": str,
            }
        elif verb == "delete":
            expected_params = {
                "release": str,
                "subcloud": str,
                "group": str,
                "local_only": str,
                "sysadmin_password": str,
            }
        elif verb == "restore":
            expected_params = {
                "with_install": str,
                "release": str,
                "local_only": str,
                "registry_images": str,
                "sysadmin_password": str,
                "restore_values": dict,
                "subcloud": str,
                "group": str,
                "auto": str,
                "factory": str,
            }
        else:
            pecan.abort(400, _("Unexpected verb received"))

        content_type = request.headers.get("content-type")
        LOG.info("Request content-type: %s" % content_type)
        if "multipart/form-data" in content_type.lower():

            return SubcloudBackupController._get_multipart_payload(
                request, expected_params
            )

        else:
            return SubcloudBackupController._get_json_payload(request, expected_params)

    @staticmethod
    def _get_multipart_payload(request, expected_params):
        payload = dict()
        file_params = ["backup_values", "restore_values"]
        for param in file_params:
            if param in request.POST:
                file_item = request.POST[param]
                file_item.file.seek(0, os.SEEK_SET)
                data = utils.yaml_safe_load(file_item.file.read().decode("utf8"), param)
                payload.update({param: data})
                del request.POST[param]

        payload.update(request.POST)

        if not set(payload.keys()).issubset(expected_params.keys()):
            LOG.info("Got an unexpected parameter in: %s" % payload)
            pecan.abort(400, _("Unexpected parameter received"))

        for key, value in payload.items():
            expected_type = expected_params[key]

            if key == "sysadmin_password":
                # Do nothing, let _validate_and_decode_sysadmin_password
                # handle this case
                continue
            if not isinstance(value, expected_type):
                _msg = (
                    f"Invalid type for {key}: Expected "
                    f"{expected_type.__name__}, got {type(value).__name__}"
                )
                pecan.abort(400, _msg)

        return payload

    @staticmethod
    def _get_json_payload(request, expected_params):
        try:
            payload = json.loads(request.body)
        except Exception:
            error_msg = "Request body is malformed."
            LOG.exception(error_msg)
            pecan.abort(400, _(error_msg))
            return
        if not isinstance(payload, dict):
            pecan.abort(400, _("Invalid request body format"))
        if not set(payload.keys()).issubset(expected_params.keys()):
            LOG.info("Got an unexpected parameter in: %s" % payload)
            pecan.abort(400, _("Unexpected parameter received"))

        return payload

    @staticmethod
    def _validate_and_decode_sysadmin_password(payload, param_name):
        sysadmin_password = payload.get(param_name)

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

    @staticmethod
    def _convert_param_to_bool(payload, param_names, default=False):
        for param_name in param_names:
            param = payload.get(param_name)
            if param:
                if param.lower() == "true":
                    payload[param_name] = True
                elif param.lower() == "false":
                    payload[param_name] = False
                else:
                    pecan.abort(
                        400, _("Invalid %s value, should be boolean" % param_name)
                    )
            else:
                payload[param_name] = default

    @staticmethod
    def _validate_subclouds(request_entity, operation, bootstrap_address_dict=None):
        """Validate the subcloud according to the operation

        Create/Delete: The subcloud is managed, online and in complete state.
        Restore: The subcloud is unmanaged, and not in the process of
        installation, bootstrap, deployment or rehoming. It should also have
        one of the following to obtain the bootstrap_address:
        - Restore values with bootstrap_address information
        - Install values
        - Previous inventory

        If none of the subclouds are valid, the operation will be aborted.

        Args:
            request_entity (namedtuple): Request entity
            operation (string): Subcloud backup operation
        """
        subclouds = request_entity.subclouds
        error_msg = _("Subcloud(s) must be in a valid state for backup %s." % operation)
        has_valid_subclouds = False
        valid_subclouds = list()
        for subcloud in subclouds:
            try:
                is_valid = utils.is_valid_for_backup_operation(
                    operation, subcloud, bootstrap_address_dict
                )

                if operation == "create":
                    backup_in_progress = (
                        subcloud.backup_status in consts.STATES_FOR_ONGOING_BACKUP
                    )
                    if is_valid and not backup_in_progress:
                        has_valid_subclouds = True
                    else:
                        error_msg = _(
                            "Subcloud(s) already have a backup operation in progress."
                        )
                else:
                    if is_valid:
                        valid_subclouds.append(subcloud)
                        has_valid_subclouds = True

            except exceptions.ValidateFail as e:
                error_msg = e.message

            if (
                operation == "create"
                and has_valid_subclouds
                and request_entity.type == "subcloud"
            ):
                # Check the system health only if the command was issued
                # to a single subcloud to avoid huge delays.
                if not utils.is_subcloud_healthy(
                    subcloud.region_name, subcloud.management_start_ip
                ):
                    msg = _(
                        "Subcloud %s must be in good health for subcloud-backup create."
                        % subcloud.name
                    )
                    pecan.abort(400, msg)

        if not has_valid_subclouds:
            if request_entity.type == "group":
                msg = _(
                    "None of the subclouds in group %s are in a valid "
                    "state for subcloud-backup %s"
                ) % (request_entity.name, operation)
            elif request_entity.type == "subcloud":
                msg = error_msg

            pecan.abort(400, msg)
        return valid_subclouds

    @staticmethod
    def _get_subclouds_from_group(group, context):
        if not group:
            pecan.abort(404, _("Group not found"))

        return db_api.subcloud_get_for_group(context, group.id)

    def _read_entity_from_request_params(self, context, payload):
        subcloud_ref = payload.get("subcloud")
        group_ref = payload.get("group")

        if subcloud_ref:
            if group_ref:
                pecan.abort(
                    400,
                    _(
                        "'subcloud' and 'group' parameters should not be given at "
                        "the same time"
                    ),
                )
            subcloud = utils.subcloud_get_by_ref(context, subcloud_ref)
            if not subcloud:
                pecan.abort(400, _("Subcloud not found"))
            return RequestEntity("subcloud", subcloud.id, subcloud_ref, [subcloud])
        elif group_ref:
            group = utils.subcloud_group_get_by_ref(context, group_ref)
            group_subclouds = self._get_subclouds_from_group(group, context)
            if not group_subclouds:
                pecan.abort(400, _("No subclouds present in group"))
            return RequestEntity("group", group.id, group_ref, group_subclouds)
        else:
            pecan.abort(400, _("'subcloud' or 'group' parameter is required"))

    @utils.synchronized(LOCK_NAME)
    @index.when(method="POST", template="json")
    def post(self):
        """Create a new subcloud backup."""
        context = restcomm.extract_context_from_environ()
        payload = self._get_payload(pecan_request, "create")
        context.is_admin = self.authorize_user("create")

        self._validate_and_decode_sysadmin_password(payload, "sysadmin_password")

        if not payload.get("local_only") and payload.get("registry_images"):
            pecan.abort(
                400,
                _("Option registry_images can not be used without local_only option."),
            )

        request_entity = self._read_entity_from_request_params(context, payload)
        self._validate_subclouds(request_entity, "create")

        # Set subcloud/group ID as reference instead of name to ease processing
        payload[request_entity.type] = request_entity.id
        self._convert_param_to_bool(payload, ["local_only", "registry_images"])

        try:
            self.dcmanager_rpc_client.backup_subclouds(context, payload)
            return utils.subcloud_db_list_to_dict(request_entity.subclouds)
        except RemoteError as e:
            pecan.abort(422, e.value)
        except Exception:
            LOG.exception("Unable to backup subclouds")
            pecan.abort(500, _("Unable to backup subcloud"))

    @utils.synchronized(LOCK_NAME)
    @index.when(method="PATCH", template="json")
    def patch(self, verb, release_version=None):
        """Delete or restore a subcloud backup.

        :param verb: Specifies the patch action to be taken
        to the subcloud backup operation

        :param release_version: Backup release version to be deleted
        """
        context = restcomm.extract_context_from_environ()
        payload = self._get_payload(pecan_request, verb)
        context.is_admin = self.authorize_user(verb)

        if verb == "delete":
            if not release_version:
                pecan.abort(400, _("Release version required"))

            self._convert_param_to_bool(payload, ["local_only"])

            # Backup delete in systemcontroller doesn't need sysadmin_password
            if payload.get("local_only"):
                self._validate_and_decode_sysadmin_password(
                    payload, "sysadmin_password"
                )

            request_entity = self._read_entity_from_request_params(context, payload)

            # Validate subcloud state when deleting locally
            # Not needed for centralized storage, since connection is not required
            local_only = payload.get("local_only")
            if local_only:
                self._validate_subclouds(request_entity, verb)

            # Set subcloud/group ID as reference instead of name to ease processing
            payload[request_entity.type] = request_entity.id

            try:
                message = self.dcmanager_rpc_client.delete_subcloud_backups(
                    context, release_version, payload
                )

                if message:
                    response.status_int = 207
                    return message
                else:
                    response.status_int = 204
            except RemoteError as e:
                pecan.abort(422, e.value)
            except Exception:
                LOG.exception("Unable to delete subcloud backups")
                pecan.abort(500, _("Unable to delete subcloud backups"))
        elif verb == "restore":

            if not payload:
                pecan.abort(400, _("Body required"))

            self._validate_and_decode_sysadmin_password(payload, "sysadmin_password")

            self._convert_param_to_bool(
                payload,
                ("local_only", "with_install", "registry_images", "auto", "factory"),
            )

            if not payload["local_only"] and payload["registry_images"]:
                pecan.abort(
                    400,
                    _(
                        "Option registry_images cannot be used "
                        "without local_only option."
                    ),
                )

            if payload.get("release") and not (
                payload["with_install"] or payload["auto"] or payload["factory"]
            ):
                pecan.abort(
                    400,
                    _(
                        "Option release cannot be used without one of the "
                        "following options: with_install, auto or factory."
                    ),
                )

            request_entity = self._read_entity_from_request_params(context, payload)
            if len(request_entity.subclouds) == 0:
                msg = "No subclouds exist under %s %s" % (
                    request_entity.type,
                    request_entity.id,
                )
                pecan.abort(400, _(msg))

            bootstrap_address_dict = payload.get("restore_values", {}).get(
                "bootstrap_address", {}
            )

            if not isinstance(bootstrap_address_dict, dict):
                pecan.abort(
                    400,
                    _(
                        "The bootstrap_address provided in restore_values "
                        "is in invalid format."
                    ),
                )

            restore_subclouds = self._validate_subclouds(
                request_entity, verb, bootstrap_address_dict
            )

            payload[request_entity.type] = request_entity.id

            if (
                payload.get("with_install")
                or payload.get("auto")
                or payload.get("factory")
            ):
                subclouds_without_install_values = [
                    subcloud.name
                    for subcloud in request_entity.subclouds
                    if not subcloud.data_install
                ]
                if subclouds_without_install_values:
                    subclouds_str = ", ".join(subclouds_without_install_values)
                    pecan.abort(
                        400,
                        _(
                            "The restore operation was requested with with_install, "
                            "auto or factory, but the following subcloud(s) does "
                            "not contain install values: %s" % subclouds_str
                        ),
                    )
                # Confirm the requested or active load is still in dc-vault
                payload["software_version"] = utils.get_sw_version(
                    payload.get("release")
                )
                matching_iso, err_msg = utils.get_matching_iso(
                    payload["software_version"]
                )
                if err_msg:
                    LOG.exception(err_msg)
                    pecan.abort(400, _(err_msg))
                LOG.info(
                    "Restore operation will use image %s in subcloud installation"
                    % matching_iso
                )

            # An auto or factory restore implies with-install and registry-images
            if payload.get("auto") or payload.get("factory"):
                payload["with_install"] = True
                payload["registry_images"] = True

                # TODO(gherzmann): Remove this after auto-restore is implemented
                pecan.abort(
                    400,
                    _("Auto or factory restore is currently unsupported"),
                )

            try:
                # local update to deploy_status - this is just for CLI response
                # pylint: disable-next=consider-using-enumerate
                for i in range(len(restore_subclouds)):
                    restore_subclouds[i].deploy_status = consts.DEPLOY_STATE_PRE_RESTORE
                message = self.dcmanager_rpc_client.restore_subcloud_backups(
                    context, payload
                )
                return utils.subcloud_db_list_to_dict(restore_subclouds)
            except RemoteError as e:
                pecan.abort(422, e.value)
            except Exception:
                LOG.exception("Unable to restore subcloud")
                pecan.abort(500, _("Unable to restore subcloud"))
        else:
            pecan.abort(400, _("Invalid request"))

    def authorize_user(self, verb):
        """check the user has access to the API call

        :param verb: None,delete,restore,create
        :request: True or False
        """

        rule = subcloud_backup_policy.POLICY_ROOT % verb
        has_api_access = policy.authorize(
            rule, {}, restcomm.extract_credentials_for_policy()
        )
        return has_api_access
