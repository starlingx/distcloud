#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import http.client as httpclient
import json
import os

from oslo_log import log as logging
from oslo_messaging import RemoteError
import pecan
import tsconfig.tsconfig as tsc
import yaml

from dccommon import consts as dccommon_consts
from dcmanager.api.controllers import restcomm
from dcmanager.api.policies import phased_subcloud_deploy as \
    phased_subcloud_deploy_policy
from dcmanager.api import policy
from dcmanager.common import consts
from dcmanager.common.context import RequestContext
from dcmanager.common import exceptions
from dcmanager.common.i18n import _
from dcmanager.common import phased_subcloud_deploy as psd_common
from dcmanager.common import prestage
from dcmanager.common import utils
from dcmanager.db import api as db_api
from dcmanager.db.sqlalchemy import models
from dcmanager.rpc import client as rpc_client

LOG = logging.getLogger(__name__)
LOCK_NAME = 'PhasedSubcloudDeployController'

SUBCLOUD_CREATE_REQUIRED_PARAMETERS = (
    consts.BOOTSTRAP_VALUES,
    consts.BOOTSTRAP_ADDRESS
)

# The consts.DEPLOY_CONFIG is missing here because it's handled differently
# by the upload_deploy_config_file() function
SUBCLOUD_CREATE_GET_FILE_CONTENTS = (
    consts.BOOTSTRAP_VALUES,
    consts.INSTALL_VALUES,
)

SUBCLOUD_INSTALL_GET_FILE_CONTENTS = (
    consts.INSTALL_VALUES,
)

SUBCLOUD_BOOTSTRAP_GET_FILE_CONTENTS = (
    consts.BOOTSTRAP_VALUES,
)

SUBCLOUD_CONFIG_GET_FILE_CONTENTS = (
    consts.DEPLOY_CONFIG,
)

VALID_STATES_FOR_DEPLOY_INSTALL = (
    consts.DEPLOY_STATE_CREATED,
    consts.DEPLOY_STATE_PRE_INSTALL_FAILED,
    consts.DEPLOY_STATE_INSTALL_FAILED,
    consts.DEPLOY_STATE_INSTALLED
)

VALID_STATES_FOR_DEPLOY_BOOTSTRAP = [
    consts.DEPLOY_STATE_INSTALLED,
    consts.DEPLOY_STATE_BOOTSTRAP_FAILED,
    consts.DEPLOY_STATE_BOOTSTRAP_ABORTED,
    consts.DEPLOY_STATE_BOOTSTRAPPED,
    # The subcloud can be installed manually (without remote install) so we need
    # to allow the bootstrap operation when the state == DEPLOY_STATE_CREATED
    consts.DEPLOY_STATE_CREATED
]

# TODO(vgluzrom): remove deploy_failed once 'subcloud reconfig'
# has been deprecated
VALID_STATES_FOR_DEPLOY_CONFIG = (
    consts.DEPLOY_STATE_DONE,
    consts.DEPLOY_STATE_PRE_CONFIG_FAILED,
    consts.DEPLOY_STATE_CONFIG_FAILED,
    consts.DEPLOY_STATE_DEPLOY_FAILED,
    consts.DEPLOY_STATE_BOOTSTRAPPED
)


def get_create_payload(request: pecan.Request) -> dict:
    payload = dict()

    for f in SUBCLOUD_CREATE_GET_FILE_CONTENTS:
        if f in request.POST:
            file_item = request.POST[f]
            file_item.file.seek(0, os.SEEK_SET)
            data = yaml.safe_load(file_item.file.read().decode('utf8'))
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
        policy.authorize(phased_subcloud_deploy_policy.POLICY_ROOT % "create",
                         {}, restcomm.extract_credentials_for_policy())
        psd_common.check_required_parameters(
            request, SUBCLOUD_CREATE_REQUIRED_PARAMETERS)

        payload = get_create_payload(request)

        if not payload:
            pecan.abort(400, _('Body required'))

        psd_common.validate_bootstrap_values(payload)

        # If a subcloud release is not passed, use the current
        # system controller software_version
        payload['software_version'] = payload.get('release', tsc.SW_VERSION)

        psd_common.validate_subcloud_name_availability(context, payload['name'])

        psd_common.validate_system_controller_patch_status("create")

        psd_common.validate_subcloud_config(context, payload)

        psd_common.validate_install_values(payload)

        psd_common.validate_k8s_version(payload)

        psd_common.format_ip_address(payload)

        # Upload the deploy config files if it is included in the request
        # It has a dependency on the subcloud name, and it is called after
        # the name has been validated
        psd_common.upload_deploy_config_file(request, payload)

        try:
            # Add the subcloud details to the database
            subcloud = psd_common.add_subcloud_to_database(context, payload)

            # Ask dcmanager-manager to add the subcloud.
            # It will do all the real work...
            subcloud = self.dcmanager_rpc_client.subcloud_deploy_create(
                context, subcloud.id, payload)
            return subcloud

        except RemoteError as e:
            pecan.abort(httpclient.UNPROCESSABLE_ENTITY, e.value)
        except Exception:
            LOG.exception("Unable to create subcloud %s" % payload.get('name'))
            pecan.abort(httpclient.INTERNAL_SERVER_ERROR,
                        _('Unable to create subcloud'))

    def _deploy_install(self, context: RequestContext,
                        request: pecan.Request, subcloud):
        payload = psd_common.get_request_data(
            request, subcloud, SUBCLOUD_INSTALL_GET_FILE_CONTENTS)
        if not payload:
            pecan.abort(400, _('Body required'))

        if subcloud.deploy_status not in VALID_STATES_FOR_DEPLOY_INSTALL:
            allowed_states_str = ', '.join(VALID_STATES_FOR_DEPLOY_INSTALL)
            pecan.abort(400, _('Subcloud deploy status must be either: %s')
                        % allowed_states_str)

        payload['software_version'] = payload.get('release', tsc.SW_VERSION)
        psd_common.populate_payload_with_pre_existing_data(
            payload, subcloud, SUBCLOUD_INSTALL_GET_FILE_CONTENTS)

        psd_common.validate_sysadmin_password(payload)
        psd_common.pre_deploy_install(payload, subcloud)

        try:
            # Align the software version of the subcloud with install
            # version. Update the deploy status as pre-install.
            subcloud = db_api.subcloud_update(
                context,
                subcloud.id,
                description=payload.get('description', subcloud.description),
                location=payload.get('location', subcloud.location),
                software_version=payload['software_version'],
                management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
                deploy_status=consts.DEPLOY_STATE_PRE_INSTALL,
                data_install=json.dumps(payload['install_values']))

            self.dcmanager_rpc_client.subcloud_deploy_install(
                context, subcloud.id, payload)

            return db_api.subcloud_db_model_to_dict(subcloud)
        except RemoteError as e:
            pecan.abort(422, e.value)
        except Exception:
            LOG.exception("Unable to install subcloud %s" % subcloud.name)
            pecan.abort(500, _('Unable to install subcloud'))

    def _deploy_bootstrap(self, context: RequestContext,
                          request: pecan.Request,
                          subcloud: models.Subcloud):
        if subcloud.deploy_status not in VALID_STATES_FOR_DEPLOY_BOOTSTRAP:
            valid_states_str = ', '.join(VALID_STATES_FOR_DEPLOY_BOOTSTRAP)
            pecan.abort(400, _('Subcloud deploy status must be either: %s')
                        % valid_states_str)

        has_bootstrap_values = consts.BOOTSTRAP_VALUES in request.POST
        payload = {}

        # Try to load the existing override values
        override_file = psd_common.get_config_file_path(subcloud.name)
        if os.path.exists(override_file):
            psd_common.populate_payload_with_pre_existing_data(
                payload, subcloud, SUBCLOUD_BOOTSTRAP_GET_FILE_CONTENTS)
        elif not has_bootstrap_values:
            msg = _("Required bootstrap-values file was not provided and it was"
                    " not previously available at %s") % (override_file)
            pecan.abort(400, msg)

        request_data = psd_common.get_request_data(
            request, subcloud, SUBCLOUD_BOOTSTRAP_GET_FILE_CONTENTS)

        # Update the existing values with new ones from the request
        payload.update(request_data)

        psd_common.validate_sysadmin_password(payload)

        if has_bootstrap_values:
            # Need to validate the new values
            playload_name = payload.get('name')
            if playload_name != subcloud.name:
                pecan.abort(400, _('The bootstrap-values "name" value (%s) '
                                   'must match the current subcloud name (%s)' %
                                   (playload_name, subcloud.name)))

            # Verify if payload contains all required bootstrap values
            psd_common.validate_bootstrap_values(payload)

            # It's ok for the management subnet to conflict with itself since we
            # are only going to update it if it was modified, conflicts with
            # other subclouds are still verified.
            psd_common.validate_subcloud_config(context, payload,
                                                ignore_conflicts_with=subcloud)
            psd_common.format_ip_address(payload)

        # Patch status and fresh_install_k8s_version may have been changed
        # between deploy create and deploy bootstrap commands. Validate them
        # again:
        psd_common.validate_system_controller_patch_status("bootstrap")
        psd_common.validate_k8s_version(payload)

        try:
            # Ask dcmanager-manager to bootstrap the subcloud.
            self.dcmanager_rpc_client.subcloud_deploy_bootstrap(
                context, subcloud.id, payload)
            return db_api.subcloud_db_model_to_dict(subcloud)

        except RemoteError as e:
            pecan.abort(httpclient.UNPROCESSABLE_ENTITY, e.value)
        except Exception:
            LOG.exception("Unable to bootstrap subcloud %s" %
                          payload.get('name'))
            pecan.abort(httpclient.INTERNAL_SERVER_ERROR,
                        _('Unable to bootstrap subcloud'))

    def _deploy_config(self, context: RequestContext,
                       request: pecan.Request, subcloud):
        payload = psd_common.get_request_data(
            request, subcloud, SUBCLOUD_CONFIG_GET_FILE_CONTENTS)
        if not payload:
            pecan.abort(400, _('Body required'))

        if not (subcloud.deploy_status in VALID_STATES_FOR_DEPLOY_CONFIG or
                prestage.is_deploy_status_prestage(subcloud.deploy_status)):
            allowed_states_str = ', '.join(VALID_STATES_FOR_DEPLOY_CONFIG)
            pecan.abort(400, _('Subcloud deploy status must be either '
                               '%s or prestage-...') % allowed_states_str)

        psd_common.populate_payload_with_pre_existing_data(
            payload, subcloud, SUBCLOUD_CONFIG_GET_FILE_CONTENTS)

        psd_common.validate_sysadmin_password(payload)

        try:
            subcloud = self.dcmanager_rpc_client.subcloud_deploy_config(
                context, subcloud.id, payload)
            return subcloud
        except RemoteError as e:
            pecan.abort(422, e.value)
        except Exception:
            LOG.exception("Unable to configure subcloud %s" % subcloud.name)
            pecan.abort(500, _('Unable to configure subcloud'))

    @pecan.expose(generic=True, template='json')
    def index(self):
        # Route the request to specific methods with parameters
        pass

    @utils.synchronized(LOCK_NAME)
    @index.when(method='POST', template='json')
    def post(self):
        context = restcomm.extract_context_from_environ()
        return self._deploy_create(context, pecan.request)

    @utils.synchronized(LOCK_NAME)
    @index.when(method='PATCH', template='json')
    def patch(self, subcloud_ref=None, verb=None):
        """Modify the subcloud deployment.

        :param subcloud_ref: ID or name of subcloud to update

        :param verb: Specifies the patch action to be taken
        or subcloud operation
        """

        policy.authorize(phased_subcloud_deploy_policy.POLICY_ROOT % "modify", {},
                         restcomm.extract_credentials_for_policy())
        context = restcomm.extract_context_from_environ()

        if not subcloud_ref:
            pecan.abort(400, _('Subcloud ID required'))

        try:
            if subcloud_ref.isdigit():
                subcloud = db_api.subcloud_get(context, subcloud_ref)
            else:
                subcloud = db_api.subcloud_get_by_name(context, subcloud_ref)
        except (exceptions.SubcloudNotFound, exceptions.SubcloudNameNotFound):
            pecan.abort(404, _('Subcloud not found'))

        if verb == 'install':
            subcloud = self._deploy_install(context, pecan.request, subcloud)
        elif verb == 'bootstrap':
            subcloud = self._deploy_bootstrap(context, pecan.request, subcloud)
        elif verb == 'configure':
            subcloud = self._deploy_config(context, pecan.request, subcloud)
        else:
            pecan.abort(400, _('Invalid request'))

        return subcloud
