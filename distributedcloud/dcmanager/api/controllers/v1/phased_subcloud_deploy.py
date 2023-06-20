#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import http.client as httpclient
import os

from oslo_log import log as logging
from oslo_messaging import RemoteError
import pecan
import tsconfig.tsconfig as tsc
import yaml

from dcmanager.api.controllers import restcomm
from dcmanager.api.policies import phased_subcloud_deploy as \
    phased_subcloud_deploy_policy
from dcmanager.api import policy
from dcmanager.common.context import RequestContext
from dcmanager.common.i18n import _
from dcmanager.common import phased_subcloud_deploy as psd_common
from dcmanager.common import utils
from dcmanager.rpc import client as rpc_client

LOG = logging.getLogger(__name__)
LOCK_NAME = 'PhasedSubcloudDeployController'

BOOTSTRAP_ADDRESS = 'bootstrap-address'
BOOTSTRAP_VALUES = 'bootstrap_values'
INSTALL_VALUES = 'install_values'

SUBCLOUD_CREATE_REQUIRED_PARAMETERS = (
    BOOTSTRAP_VALUES,
    BOOTSTRAP_ADDRESS
)

# The consts.DEPLOY_CONFIG is missing here because it's handled differently
# by the upload_deploy_config_file() function
SUBCLOUD_CREATE_GET_FILE_CONTENTS = (
    BOOTSTRAP_VALUES,
    INSTALL_VALUES,
)


def get_create_payload(request: pecan.Request) -> dict:
    payload = dict()

    for f in SUBCLOUD_CREATE_GET_FILE_CONTENTS:
        if f in request.POST:
            file_item = request.POST[f]
            file_item.file.seek(0, os.SEEK_SET)
            data = yaml.safe_load(file_item.file.read().decode('utf8'))
            if f == BOOTSTRAP_VALUES:
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

    @pecan.expose(generic=True, template='json')
    def index(self):
        # Route the request to specific methods with parameters
        pass

    @utils.synchronized(LOCK_NAME)
    @index.when(method='POST', template='json')
    def post(self):
        context = restcomm.extract_context_from_environ()
        return self._deploy_create(context, pecan.request)
