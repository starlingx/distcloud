#
# Copyright (c) 2023-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import http.client as httpclient
import os

from oslo_log import log as logging
from oslo_messaging import RemoteError
import pecan

from dccommon import consts as dccommon_consts
from dcmanager.api.controllers import restcomm
from dcmanager.api.controllers.v1.subclouds import SubcloudsController
from dcmanager.api.policies import (
    phased_subcloud_deploy as phased_subcloud_deploy_policy,
)
from dcmanager.api import policy
from dcmanager.common import consts
from dcmanager.common.context import RequestContext
from dcmanager.common import exceptions
from dcmanager.common.i18n import _
from dcmanager.common import phased_subcloud_deploy as psd_common
from dcmanager.common import utils
from dcmanager.db import api as db_api
from dcmanager.db.sqlalchemy import models
from dcmanager.rpc import client as rpc_client

LOG = logging.getLogger(__name__)
LOCK_NAME = "PhasedSubcloudDeployController"

INSTALL = consts.DEPLOY_PHASE_INSTALL
BOOTSTRAP = consts.DEPLOY_PHASE_BOOTSTRAP
CONFIG = consts.DEPLOY_PHASE_CONFIG
COMPLETE = consts.DEPLOY_PHASE_COMPLETE
ABORT = consts.DEPLOY_PHASE_ABORT
RESUME = consts.DEPLOY_PHASE_RESUME
ENROLL = consts.DEPLOY_PHASE_ENROLL

SUBCLOUD_CREATE_REQUIRED_PARAMETERS = (
    consts.BOOTSTRAP_VALUES,
    consts.BOOTSTRAP_ADDRESS,
)
# The consts.DEPLOY_CONFIG is missing here because it's handled differently
# by the upload_deploy_config_file() function
SUBCLOUD_CREATE_GET_FILE_CONTENTS = (
    consts.BOOTSTRAP_VALUES,
    consts.INSTALL_VALUES,
)
SUBCLOUD_INSTALL_GET_FILE_CONTENTS = (consts.INSTALL_VALUES,)
SUBCLOUD_BOOTSTRAP_GET_FILE_CONTENTS = (consts.BOOTSTRAP_VALUES,)
SUBCLOUD_ENROLL_GET_FILE_CONTENTS = (consts.BOOTSTRAP_VALUES, consts.INSTALL_VALUES)
SUBCLOUD_CONFIG_GET_FILE_CONTENTS = (consts.DEPLOY_CONFIG,)

VALID_STATES_FOR_DEPLOY_INSTALL = (
    consts.DEPLOY_STATE_CREATED,
    consts.DEPLOY_STATE_PRE_INSTALL_FAILED,
    consts.DEPLOY_STATE_INSTALL_FAILED,
    consts.DEPLOY_STATE_INSTALLED,
    consts.DEPLOY_STATE_INSTALL_ABORTED,
)
VALID_STATES_FOR_DEPLOY_BOOTSTRAP = [
    consts.DEPLOY_STATE_INSTALLED,
    consts.DEPLOY_STATE_PRE_BOOTSTRAP_FAILED,
    consts.DEPLOY_STATE_BOOTSTRAP_FAILED,
    consts.DEPLOY_STATE_BOOTSTRAP_ABORTED,
    consts.DEPLOY_STATE_BOOTSTRAPPED,
    # The subcloud can be installed manually (without remote install) so we need
    # to allow the bootstrap operation when the state == DEPLOY_STATE_CREATED
    consts.DEPLOY_STATE_CREATED,
]
VALID_STATES_FOR_DEPLOY_CONFIG = (
    consts.DEPLOY_STATE_DONE,
    consts.DEPLOY_STATE_PRE_CONFIG_FAILED,
    consts.DEPLOY_STATE_CONFIG_FAILED,
    consts.DEPLOY_STATE_BOOTSTRAPPED,
    consts.DEPLOY_STATE_ENROLLED,
    consts.DEPLOY_STATE_CONFIG_ABORTED,
)
VALID_STATES_FOR_DEPLOY_COMPLETE = (
    consts.DEPLOY_STATE_BOOTSTRAPPED,
    consts.DEPLOY_STATE_ENROLLED,
)
VALID_STATES_FOR_DEPLOY_ABORT = (
    consts.DEPLOY_STATE_INSTALLING,
    consts.DEPLOY_STATE_BOOTSTRAPPING,
    consts.DEPLOY_STATE_CONFIGURING,
)
VALID_STATES_FOR_DEPLOY_ENROLL = (
    consts.DEPLOY_STATE_CREATED,
    consts.DEPLOY_STATE_ENROLL_FAILED,
    consts.DEPLOY_STATE_PRE_ENROLL_FAILED,
    consts.DEPLOY_STATE_PRE_INIT_ENROLL_FAILED,
    consts.DEPLOY_STATE_INIT_ENROLL_FAILED,
    consts.DEPLOY_STATE_FACTORY_RESTORE_COMPLETE,
)

FILES_FOR_RESUME_INSTALL = (
    SUBCLOUD_INSTALL_GET_FILE_CONTENTS
    + SUBCLOUD_BOOTSTRAP_GET_FILE_CONTENTS
    + SUBCLOUD_CONFIG_GET_FILE_CONTENTS
)
FILES_FOR_RESUME_BOOTSTRAP = (
    SUBCLOUD_BOOTSTRAP_GET_FILE_CONTENTS + SUBCLOUD_CONFIG_GET_FILE_CONTENTS
)
FILES_FOR_RESUME_CONFIG = SUBCLOUD_CONFIG_GET_FILE_CONTENTS
RESUMABLE_STATES = {
    consts.DEPLOY_STATE_CREATED: [INSTALL, BOOTSTRAP, CONFIG],
    consts.DEPLOY_STATE_INSTALLED: [BOOTSTRAP, CONFIG],
    consts.DEPLOY_STATE_PRE_INSTALL_FAILED: [INSTALL, BOOTSTRAP, CONFIG],
    consts.DEPLOY_STATE_INSTALL_FAILED: [INSTALL, BOOTSTRAP, CONFIG],
    consts.DEPLOY_STATE_INSTALL_ABORTED: [INSTALL, BOOTSTRAP, CONFIG],
    consts.DEPLOY_STATE_BOOTSTRAPPED: [CONFIG],
    consts.DEPLOY_STATE_PRE_BOOTSTRAP_FAILED: [BOOTSTRAP, CONFIG],
    consts.DEPLOY_STATE_BOOTSTRAP_FAILED: [BOOTSTRAP, CONFIG],
    consts.DEPLOY_STATE_BOOTSTRAP_ABORTED: [BOOTSTRAP, CONFIG],
    consts.DEPLOY_STATE_PRE_CONFIG_FAILED: [CONFIG],
    consts.DEPLOY_STATE_CONFIG_FAILED: [CONFIG],
    consts.DEPLOY_STATE_CONFIG_ABORTED: [CONFIG],
}
DEPLOY_PHASES = [INSTALL, BOOTSTRAP, CONFIG]
FILES_MAPPING = {
    INSTALL: SUBCLOUD_INSTALL_GET_FILE_CONTENTS,
    BOOTSTRAP: SUBCLOUD_BOOTSTRAP_GET_FILE_CONTENTS,
    CONFIG: SUBCLOUD_CONFIG_GET_FILE_CONTENTS,
}
RESUME_PREP_UPDATE_STATUS = {
    INSTALL: consts.DEPLOY_STATE_PRE_INSTALL,
    BOOTSTRAP: consts.DEPLOY_STATE_PRE_BOOTSTRAP,
    CONFIG: consts.DEPLOY_STATE_PRE_CONFIG,
}


def get_create_payload(request: pecan.Request) -> dict:
    payload = dict()

    for f in SUBCLOUD_CREATE_GET_FILE_CONTENTS:
        if f in request.POST:
            file_item = request.POST[f]
            file_item.file.seek(0, os.SEEK_SET)
            data = utils.yaml_safe_load(file_item.file.read().decode("utf8"), f)
            if f == consts.BOOTSTRAP_VALUES:
                payload.update(data)
            else:
                payload.update({f: data})
            del request.POST[f]
    payload.update(request.POST)

    return payload


class PhasedSubcloudDeployController(object):

    def __init__(self):
        super().__init__()
        self.dcmanager_rpc_client = rpc_client.ManagerClient()

    def _deploy_create(self, context: RequestContext, request: pecan.Request):
        context.is_admin = policy.authorize(
            phased_subcloud_deploy_policy.POLICY_ROOT % "create",
            {},
            restcomm.extract_credentials_for_policy(),
        )
        psd_common.check_required_parameters(
            request, SUBCLOUD_CREATE_REQUIRED_PARAMETERS
        )

        payload = get_create_payload(request)

        psd_common.subcloud_region_create(payload, context)

        psd_common.pre_deploy_create(payload, context, request)

        try:
            # Add the subcloud details to the database
            subcloud = psd_common.add_subcloud_to_database(context, payload)

            # Ask dcmanager-manager to create the subcloud.
            # It will do all the real work...
            subcloud_dict = self.dcmanager_rpc_client.subcloud_deploy_create(
                context, subcloud.id, payload
            )

            return subcloud_dict

        except RemoteError as e:
            pecan.abort(httpclient.UNPROCESSABLE_ENTITY, e.value)
        except Exception:
            LOG.exception("Unable to create subcloud %s" % payload.get("name"))
            pecan.abort(
                httpclient.INTERNAL_SERVER_ERROR, _("Unable to create subcloud")
            )

    def _deploy_install(
        self, context: RequestContext, request: pecan.Request, subcloud
    ):
        payload = psd_common.get_request_data(
            request, subcloud, SUBCLOUD_INSTALL_GET_FILE_CONTENTS
        )
        if not payload:
            pecan.abort(400, _("Body required"))

        SubcloudsController.validate_software_deploy_state()

        if subcloud.deploy_status not in VALID_STATES_FOR_DEPLOY_INSTALL:
            allowed_states_str = ", ".join(VALID_STATES_FOR_DEPLOY_INSTALL)
            pecan.abort(
                400, _("Subcloud deploy status must be either: %s") % allowed_states_str
            )

        initial_deployment = psd_common.is_initial_deployment(subcloud.name)
        if not initial_deployment:
            pecan.abort(
                400,
                _(
                    "The deploy install command can only be used "
                    "during initial deployment."
                ),
            )

        unvalidated_sw_version = payload.get("release", subcloud.software_version)
        # get_sw_version will simply return back
        # the passed unvalidated_sw_version after validating it.
        payload["software_version"] = utils.get_sw_version(unvalidated_sw_version)

        psd_common.populate_payload_with_pre_existing_data(
            payload, subcloud, SUBCLOUD_INSTALL_GET_FILE_CONTENTS
        )

        psd_common.pre_deploy_install(payload, subcloud)

        try:
            self.dcmanager_rpc_client.subcloud_deploy_install(
                context,
                subcloud.id,
                payload,
                initial_deployment=True,
                previous_version=subcloud.software_version,
            )
            subcloud_dict = db_api.subcloud_db_model_to_dict(subcloud)
            subcloud_dict["deploy-status"] = consts.DEPLOY_STATE_PRE_INSTALL
            subcloud_dict["software-version"] = payload["software_version"]

            return subcloud_dict
        except RemoteError as e:
            pecan.abort(422, e.value)
        except Exception:
            LOG.exception("Unable to install subcloud %s" % subcloud.name)
            pecan.abort(500, _("Unable to install subcloud"))

    def _deploy_bootstrap(
        self, context: RequestContext, request: pecan.Request, subcloud: models.Subcloud
    ):
        if subcloud.deploy_status not in VALID_STATES_FOR_DEPLOY_BOOTSTRAP:
            valid_states_str = ", ".join(VALID_STATES_FOR_DEPLOY_BOOTSTRAP)
            pecan.abort(
                400, _("Subcloud deploy status must be either: %s") % valid_states_str
            )

        has_bootstrap_values = consts.BOOTSTRAP_VALUES in request.POST

        payload = psd_common.get_request_data(
            request, subcloud, SUBCLOUD_BOOTSTRAP_GET_FILE_CONTENTS
        )

        # Try to load the existing override values
        override_file = psd_common.get_config_file_path(subcloud.name)
        if os.path.exists(override_file):
            if not has_bootstrap_values:
                psd_common.populate_payload_with_pre_existing_data(
                    payload, subcloud, SUBCLOUD_BOOTSTRAP_GET_FILE_CONTENTS
                )
        elif not has_bootstrap_values:
            msg = _(
                "Required bootstrap-values file was not provided and it was "
                "not previously available at %s"
            ) % (override_file)
            pecan.abort(400, msg)

        payload["software_version"] = subcloud.software_version

        psd_common.pre_deploy_bootstrap(
            context, payload, subcloud, has_bootstrap_values
        )

        try:
            # Ask dcmanager-manager to bootstrap the subcloud.
            self.dcmanager_rpc_client.subcloud_deploy_bootstrap(
                context, subcloud.id, payload, initial_deployment=True
            )

            # Change the response to correctly display the values
            # that will be updated on the manager.
            subcloud_dict = db_api.subcloud_db_model_to_dict(subcloud)
            subcloud_dict["deploy-status"] = consts.DEPLOY_STATE_PRE_BOOTSTRAP
            subcloud_dict["description"] = payload.get(
                "description", subcloud.description
            )
            subcloud_dict["location"] = payload.get("location", subcloud.location)
            subcloud_dict["management-subnet"] = utils.get_primary_management_subnet(
                payload
            )
            subcloud_dict["management-gateway-ip"] = (
                utils.get_primary_management_gateway_address(payload)
            )
            subcloud_dict["management-start-ip"] = (
                utils.get_primary_management_start_address(payload)
            )
            subcloud_dict["management-end-ip"] = (
                utils.get_primary_management_end_address(payload)
            )
            systemcontroller_primary_gw = (
                utils.get_primary_systemcontroller_gateway_address(payload)
            )
            subcloud_dict["systemcontroller-gateway-ip"] = (
                systemcontroller_primary_gw
                if systemcontroller_primary_gw
                else subcloud.systemcontroller_gateway_ip
            )
            return subcloud_dict

        except RemoteError as e:
            pecan.abort(httpclient.UNPROCESSABLE_ENTITY, e.value)
        except Exception:
            LOG.exception("Unable to bootstrap subcloud %s" % payload.get("name"))
            pecan.abort(
                httpclient.INTERNAL_SERVER_ERROR, _("Unable to bootstrap subcloud")
            )

    def _deploy_config(self, context: RequestContext, request: pecan.Request, subcloud):
        payload = psd_common.get_request_data(
            request, subcloud, SUBCLOUD_CONFIG_GET_FILE_CONTENTS
        )
        if not payload:
            pecan.abort(400, _("Body required"))

        if subcloud.deploy_status not in VALID_STATES_FOR_DEPLOY_CONFIG:
            allowed_states_str = ", ".join(VALID_STATES_FOR_DEPLOY_CONFIG)
            pecan.abort(
                400, _("Subcloud deploy status must be %s") % allowed_states_str
            )

        if subcloud.prestage_status in consts.STATES_FOR_ONGOING_PRESTAGE:
            pecan.abort(
                400, _("Subcloud prestage is ongoing %s") % subcloud.prestage_status
            )

        # If the subcloud belongs to a peer group, ensure that
        # it's not being configured in a secondary site.
        if subcloud.peer_group_id is not None:
            peer_group = utils.subcloud_peer_group_get_by_ref(
                context, str(subcloud.peer_group_id)
            )
            if peer_group is not None:
                if peer_group.group_priority != consts.PEER_GROUP_PRIMARY_PRIORITY:
                    pecan.abort(
                        400,
                        _("Subcloud can only be configured in its primary site."),
                    )

        psd_common.populate_payload_with_pre_existing_data(
            payload, subcloud, SUBCLOUD_CONFIG_GET_FILE_CONTENTS
        )

        psd_common.pre_deploy_config(payload, subcloud)

        try:
            self.dcmanager_rpc_client.subcloud_deploy_config(
                context, subcloud.id, payload, initial_deployment=True
            )
            subcloud_dict = db_api.subcloud_db_model_to_dict(subcloud)
            subcloud_dict["deploy-status"] = consts.DEPLOY_STATE_PRE_CONFIG
            return subcloud_dict
        except RemoteError as e:
            pecan.abort(422, e.value)
        except Exception:
            LOG.exception("Unable to configure subcloud %s" % subcloud.name)
            pecan.abort(500, _("Unable to configure subcloud"))

    def _deploy_complete(self, context: RequestContext, subcloud):

        # The deployment should be able to be completed when the deploy state
        # is VALID_STATES_FOR_DEPLOY_COMPLETE because the user could have
        # configured the subcloud manually
        if subcloud.deploy_status not in VALID_STATES_FOR_DEPLOY_COMPLETE:
            allowed_states_str = ", ".join(VALID_STATES_FOR_DEPLOY_COMPLETE)
            pecan.abort(
                400,
                _(
                    "Subcloud deploy can only be completed when "
                    "its deploy status is: %s"
                )
                % allowed_states_str,
            )

        try:
            # Ask dcmanager-manager to complete the subcloud deployment
            subcloud = self.dcmanager_rpc_client.subcloud_deploy_complete(
                context, subcloud.id
            )
            return subcloud

        except RemoteError as e:
            pecan.abort(httpclient.UNPROCESSABLE_ENTITY, e.value)
        except Exception:
            LOG.exception("Unable to complete subcloud %s deployment" % subcloud.name)
            pecan.abort(
                httpclient.INTERNAL_SERVER_ERROR,
                _("Unable to complete subcloud deployment"),
            )

    def _deploy_abort(self, context, subcloud):

        if subcloud.deploy_status not in VALID_STATES_FOR_DEPLOY_ABORT:
            allowed_states_str = ", ".join(VALID_STATES_FOR_DEPLOY_ABORT)
            pecan.abort(
                400,
                _("Subcloud deploy status must be in one of the following states: %s")
                % allowed_states_str,
            )

        initial_deployment = psd_common.is_initial_deployment(subcloud.name)
        if not initial_deployment:
            pecan.abort(
                400, _("The subcloud can only be aborted during initial deployment.")
            )

        try:
            self.dcmanager_rpc_client.subcloud_deploy_abort(
                context, subcloud.id, subcloud.deploy_status
            )
            subcloud_dict = db_api.subcloud_db_model_to_dict(subcloud)
            subcloud_dict["deploy-status"] = utils.ABORT_UPDATE_STATUS[
                subcloud.deploy_status
            ]
            return subcloud_dict
        except RemoteError as e:
            pecan.abort(422, e.value)
        except Exception:
            LOG.exception("Unable to abort subcloud %s deployment" % subcloud.name)
            pecan.abort(500, _("Unable to abort subcloud deployment"))

    def _deploy_resume(self, context: RequestContext, request: pecan.Request, subcloud):

        if subcloud.deploy_status not in RESUMABLE_STATES:
            allowed_states_str = ", ".join(RESUMABLE_STATES)
            pecan.abort(
                400, _("Subcloud deploy status must be either: %s") % allowed_states_str
            )

        initial_deployment = psd_common.is_initial_deployment(subcloud.name)
        if not initial_deployment:
            pecan.abort(
                400, _("The subcloud can only be resumed during initial deployment.")
            )

        # Since both install and config are optional phases,
        # it's necessary to check if they should be executed
        config_file = psd_common.get_config_file_path(
            subcloud.name, consts.DEPLOY_CONFIG
        )
        has_original_install_values = subcloud.data_install
        has_original_config_values = os.path.exists(config_file)
        has_new_install_values = consts.INSTALL_VALUES in request.POST
        has_new_config_values = consts.DEPLOY_CONFIG in request.POST
        has_bootstrap_values = consts.BOOTSTRAP_VALUES in request.POST
        has_config_values = has_original_config_values or has_new_config_values
        has_install_values = has_original_install_values or has_new_install_values

        base_deploy_states = RESUMABLE_STATES[subcloud.deploy_status]
        if base_deploy_states == [CONFIG] and not has_config_values:
            msg = (
                _(
                    "Only deploy phase left is deploy config. "
                    "Required %s file was not provided and it was not "
                    "previously available. If manually configuring the "
                    "subcloud, please run 'dcmanager subcloud deploy complete'"
                )
                % consts.DEPLOY_CONFIG
            )
            pecan.abort(400, msg)

        # Since the subcloud can be installed manually and the config is optional,
        # skip those phases if the user doesn't provide the install or config values
        # and they are not available from previous executions.
        # Add the deploy complete phase if deploy config is not going to be executed.
        files_for_resume = []
        deploy_states_to_run = []
        for state in base_deploy_states:
            if state == INSTALL and not has_install_values:
                continue
            elif state == CONFIG and not has_config_values:
                deploy_states_to_run.append(COMPLETE)
            else:
                deploy_states_to_run.append(state)
                files_for_resume.extend(FILES_MAPPING[state])

        payload = psd_common.get_request_data(request, subcloud, files_for_resume)

        # Only when the deploy state is created, all files should be sent.
        # If the subcloud is in any other state and it receives a file mapping that
        # does not relate to the current state, the deploy resume should be aborted
        states_executed = list(set(DEPLOY_PHASES) - set(base_deploy_states))

        for state_executed in states_executed:
            if FILES_MAPPING[state_executed][0] in payload.keys():
                message = (
                    f"{state_executed.title()} was already executed and "
                    f"{FILES_MAPPING[state_executed][0].replace('_', '-')} is not "
                    "required"
                )
                pecan.abort(httpclient.BAD_REQUEST, _(message))

        # Consider the incoming release parameter only if install is one
        # of the pending deploy states
        if INSTALL in deploy_states_to_run:
            SubcloudsController.validate_software_deploy_state()
            unvalidated_sw_version = payload.get("release", subcloud.software_version)
        else:
            LOG.debug(
                "Disregarding release parameter for %s as installation is complete."
                % subcloud.name
            )
            unvalidated_sw_version = subcloud.software_version

        # get_sw_version will simply return back the passed
        # unvalidated_sw_version after validating it.
        payload["software_version"] = utils.get_sw_version(unvalidated_sw_version)

        # Need to remove bootstrap_values from the list of files to populate
        # pre existing data so it does not overwrite newly loaded values
        if has_bootstrap_values:
            files_for_resume = [
                f for f in files_for_resume if f not in FILES_MAPPING[BOOTSTRAP]
            ]
        psd_common.populate_payload_with_pre_existing_data(
            payload, subcloud, files_for_resume
        )

        utils.validate_sysadmin_password(payload)
        for state in deploy_states_to_run:
            if state == INSTALL:
                psd_common.pre_deploy_install(payload, validate_password=False)
            elif state == BOOTSTRAP:
                psd_common.pre_deploy_bootstrap(
                    context,
                    payload,
                    subcloud,
                    has_bootstrap_values,
                    validate_password=False,
                )
            elif state == CONFIG:
                psd_common.pre_deploy_config(payload, subcloud, validate_password=False)

        try:
            self.dcmanager_rpc_client.subcloud_deploy_resume(
                context,
                subcloud.id,
                subcloud.name,
                payload,
                deploy_states_to_run,
                subcloud.software_version,
            )

            # Change the response to correctly display the values
            # that will be updated on the manager.
            subcloud_dict = db_api.subcloud_db_model_to_dict(subcloud)
            next_deploy_phase = RESUMABLE_STATES[subcloud.deploy_status][0]
            next_deploy_state = RESUME_PREP_UPDATE_STATUS[next_deploy_phase]
            subcloud_dict["deploy-status"] = next_deploy_state
            subcloud_dict["software-version"] = payload["software_version"]
            subcloud_dict["description"] = payload.get(
                "description", subcloud.description
            )
            subcloud_dict["location"] = payload.get("location", subcloud.location)
            subcloud_dict["management-subnet"] = utils.get_primary_management_subnet(
                payload
            )
            subcloud_dict["management-gateway-ip"] = (
                utils.get_primary_management_gateway_address(payload)
            )
            subcloud_dict["management-start-ip"] = (
                utils.get_primary_management_start_address(payload)
            )
            subcloud_dict["management-end-ip"] = (
                utils.get_primary_management_end_address(payload)
            )
            systemcontroller_primary_gw = (
                utils.get_primary_systemcontroller_gateway_address(payload)
            )
            subcloud_dict["systemcontroller-gateway-ip"] = (
                systemcontroller_primary_gw
                if systemcontroller_primary_gw
                else subcloud.systemcontroller_gateway_ip
            )
            return subcloud_dict
        except RemoteError as e:
            pecan.abort(422, e.value)
        except Exception:
            LOG.exception("Unable to resume subcloud %s deployment" % subcloud.name)
            pecan.abort(500, _("Unable to resume subcloud deployment"))

    def _deploy_enroll(
        self, context: RequestContext, request: pecan.Request, subcloud: models.Subcloud
    ):
        if subcloud.deploy_status not in VALID_STATES_FOR_DEPLOY_ENROLL:
            valid_states_str = ", ".join(VALID_STATES_FOR_DEPLOY_ENROLL)
            msg = f"Subcloud deploy status must be either: {valid_states_str}"
            pecan.abort(400, _(msg))

        has_bootstrap_values = consts.BOOTSTRAP_VALUES in request.POST
        has_install_values = consts.INSTALL_VALUES in request.POST
        has_cloud_init_config = dccommon_consts.CLOUD_INIT_CONFIG in request.POST

        payload = psd_common.get_request_data(
            request, subcloud, SUBCLOUD_ENROLL_GET_FILE_CONTENTS
        )

        # Try to load the existing override values
        override_file = psd_common.get_config_file_path(subcloud.name)
        if os.path.exists(override_file):
            if not has_bootstrap_values:
                psd_common.populate_payload_with_pre_existing_data(
                    payload, subcloud, [consts.BOOTSTRAP_VALUES]
                )
        elif not has_bootstrap_values:
            msg = (
                "Required bootstrap-values file was not provided and it was "
                f"not previously available at {override_file}"
            )
            pecan.abort(400, _(msg))

        if not has_install_values:
            psd_common.populate_payload_with_pre_existing_data(
                payload, subcloud, [consts.INSTALL_VALUES]
            )

        unvalidated_sw_version = payload.get("release", subcloud.software_version)
        payload["software_version"] = utils.get_sw_version(unvalidated_sw_version)

        psd_common.validate_enroll_parameter(payload)

        if has_cloud_init_config:
            psd_common.upload_cloud_init_config(request, payload)

        # Use bootstrap file verification
        psd_common.pre_deploy_bootstrap(
            context, payload, subcloud, has_bootstrap_values
        )
        try:
            self.dcmanager_rpc_client.subcloud_deploy_enroll(
                context, subcloud.id, payload
            )
            subcloud_dict = db_api.subcloud_db_model_to_dict(subcloud)
            subcloud_dict["deploy-status"] = consts.DEPLOY_STATE_PRE_INIT_ENROLL
            subcloud_dict["software-version"] = payload["software_version"]
            subcloud_dict["description"] = payload.get(
                "description", subcloud.description
            )
            subcloud_dict["location"] = payload.get("location", subcloud.location)
            subcloud_dict["management-subnet"] = utils.get_primary_management_subnet(
                payload
            )
            subcloud_dict["management-gateway-ip"] = (
                utils.get_primary_management_gateway_address(payload)
            )
            subcloud_dict["management-start-ip"] = (
                utils.get_primary_management_start_address(payload)
            )
            subcloud_dict["management-end-ip"] = (
                utils.get_primary_management_end_address(payload)
            )
            systemcontroller_primary_gw = (
                utils.get_primary_systemcontroller_gateway_address(payload)
            )
            subcloud_dict["systemcontroller-gateway-ip"] = (
                systemcontroller_primary_gw
                if systemcontroller_primary_gw
                else subcloud.systemcontroller_gateway_ip
            )
            return subcloud_dict
        except RemoteError as e:
            pecan.abort(httpclient.UNPROCESSABLE_ENTITY, e.value)
        except Exception:
            LOG.exception("Unable to enroll subcloud %s" % payload.get("name"))
            pecan.abort(
                httpclient.INTERNAL_SERVER_ERROR, _("Unable to enroll subcloud")
            )

    @pecan.expose(generic=True, template="json")
    def index(self):
        # Route the request to specific methods with parameters
        pass

    @utils.synchronized(LOCK_NAME)
    @index.when(method="POST", template="json")
    def post(self):
        context = restcomm.extract_context_from_environ()
        return self._deploy_create(context, pecan.request)

    @utils.synchronized(LOCK_NAME)
    @index.when(method="PATCH", template="json")
    def patch(self, subcloud_ref=None, verb=None):
        """Modify the subcloud deployment.

        :param subcloud_ref: ID or name of subcloud to update

        :param verb: Specifies the patch action to be taken
        or subcloud operation
        """

        context = restcomm.extract_context_from_environ()
        context.is_admin = policy.authorize(
            phased_subcloud_deploy_policy.POLICY_ROOT % "modify",
            {},
            restcomm.extract_credentials_for_policy(),
        )

        if not subcloud_ref:
            pecan.abort(400, _("Subcloud ID required"))

        try:
            if subcloud_ref.isdigit():
                subcloud = db_api.subcloud_get(context, subcloud_ref)
            else:
                subcloud = db_api.subcloud_get_by_name(context, subcloud_ref)
        except (exceptions.SubcloudNotFound, exceptions.SubcloudNameNotFound):
            pecan.abort(404, _("Subcloud not found"))

        if verb == ABORT:
            subcloud = self._deploy_abort(context, subcloud)
        elif verb == RESUME:
            subcloud = self._deploy_resume(context, pecan.request, subcloud)
        elif verb == INSTALL:
            subcloud = self._deploy_install(context, pecan.request, subcloud)
        elif verb == BOOTSTRAP:
            subcloud = self._deploy_bootstrap(context, pecan.request, subcloud)
        elif verb == CONFIG:
            subcloud = self._deploy_config(context, pecan.request, subcloud)
        elif verb == COMPLETE:
            subcloud = self._deploy_complete(context, subcloud)
        elif verb == ENROLL:
            subcloud = self._deploy_enroll(context, pecan.request, subcloud)
        else:
            pecan.abort(400, _("Invalid request"))

        return subcloud
