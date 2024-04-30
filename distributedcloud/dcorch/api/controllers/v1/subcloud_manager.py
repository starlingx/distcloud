# Copyright (c) 2017 Ericsson AB.
# Copyright (c) 2018-2019, 2024 Wind River Systems, Inc.
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

from oslo_log import log as logging
import oslo_messaging
from oslo_utils import uuidutils

import pecan
from pecan import expose
from pecan import request

from dcorch.api.controllers import restcomm
from dcorch.common.i18n import _
from dcorch.rpc import client as rpc_client


LOG = logging.getLogger(__name__)


class SubcloudController(object):
    VERSION_ALIASES = {
        'Newton': '1.0',
    }

    def __init__(self, *args, **kwargs):
        super(SubcloudController, self).__init__(*args, **kwargs)
        self.rpc_client = rpc_client.EngineWorkerClient()

    # to do the version compatibility for future purpose
    def _determine_version_cap(self, target):
        version_cap = 1.0
        return version_cap

    @expose(generic=True, template='json')
    def index(self):
        # Route the request to specific methods with parameters
        pass

    @index.when(method='POST', template='json')
    def post(self, project):
        """Sync resources present in one region to another region.

        """
        context = restcomm.extract_context_from_environ()
        payload = eval(request.body)
        if not payload:
            pecan.abort(400, _('Body required'))
        if not payload.get('subcloud'):
            pecan.abort(400, _('subcloud required'))
        job_id = uuidutils.generate_uuid()
        return self._add_subcloud(job_id, payload, context)

    @index.when(method='delete', template='json')
    def delete(self, project, subcloud):
        """Delete the database entries of a given job_id.

        :param project: It's UUID of the project.
        :param job_id: ID of the job for which the database entries
            have to be deleted.
        """
        context = restcomm.extract_context_from_environ()
        try:
            self.rpc_client.del_subcloud(context, subcloud)
            return {'deleted': {'subcloud': subcloud}}
        except oslo_messaging.RemoteError as ex:
            if ex.exc_type == 'SubcloudNotFound':
                pecan.abort(404, _('Subcloud not found'))

    def _add_subcloud(self, job_id, payload, context):
        """Make an rpc call to engine.

        :param job_id: ID of the job to update values in database based on
            the job_id.
        :param payload: payload object.
        :param context: context of the request.
        :param result: Result object to return an output.
        """
        name = payload['subcloud']
        version = '17.06'
        self.rpc_client.add_subcloud(context, name, version)
        return {'added': {'subcloud': name}}
