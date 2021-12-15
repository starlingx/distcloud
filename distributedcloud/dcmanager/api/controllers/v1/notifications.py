# Copyright (c) 2021 Wind River Systems, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#

from oslo_config import cfg
from oslo_log import log as logging

import http.client as httpclient
import pecan
from pecan import expose
from pecan import request

from dcmanager.api.controllers import restcomm
from dcmanager.audit import rpcapi as audit_rpc_client


CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class NotificationsController(object):

    def __init__(self):
        super(NotificationsController, self).__init__()
        self.audit_rpc_client = audit_rpc_client.ManagerAuditClient()

    @expose(generic=True, template='json')
    def index(self):
        # Route the request to specific methods with parameters
        pass

    @index.when(method='POST', template='json')
    def post(self):
        if 'events' not in request.json_body:
            pecan.abort(httpclient.BAD_REQUEST,
                        "Missing required notification events")

        events = request.json_body['events']
        if 'platform-upgrade-completed' in events:
            # We're being notified that a platform upgrade has completed,
            # so we want to trigger a load audit of all subclouds on the
            # next audit cycle.
            context = restcomm.extract_context_from_environ()
            self.audit_rpc_client.trigger_load_audit(context)
        if 'k8s-upgrade-completed' in events:
            # We're being notified that a kubernetes upgrade has completed,
            # so we want to trigger a kubernetes audit of all subclouds on
            # the next audit cycle.
            context = restcomm.extract_context_from_environ()
            self.audit_rpc_client.trigger_kubernetes_audit(context)
        if 'kube-rootca-update-completed' in events:
            # We're being notified that a kube rootca update has completed, so
            # we want to trigger a kube rootca update audit of all subclouds on
            # the next audit cycle.
            context = restcomm.extract_context_from_environ()
            self.audit_rpc_client.trigger_kube_rootca_update_audit(context)
        return
