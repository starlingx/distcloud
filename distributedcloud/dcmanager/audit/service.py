# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

import six

from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_service import service

from dcmanager.audit.subcloud_audit_manager import SubcloudAuditManager
from dcmanager.common import consts
from dcmanager.common.i18n import _
from dcmanager.common import messaging as rpc_messaging
from dcmanager.common import scheduler

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class DCManagerAuditService(service.Service):
    """Lifecycle manager for a running audit service."""

    def __init__(self):

        super(DCManagerAuditService, self).__init__()
        self.host = cfg.CONF.host
        # To be used by the sw update manager to trigger the patch audit
        self.rpc_api_version = consts.RPC_API_VERSION
        self.topic = consts.TOPIC_DC_MANAGER_AUDIT
        # The following are initialized here, but assigned in start() which
        # happens after the fork when spawning multiple worker processes
        self.TG = None
        self.target = None
        self._rpc_server = None
        self.subcloud_audit_manager = None

    def start(self):
        self.init_tgm()
        self.init_audit_managers()
        target = oslo_messaging.Target(version=self.rpc_api_version,
                                       server=self.host,
                                       topic=self.topic)
        self.target = target
        self._rpc_server = rpc_messaging.get_rpc_server(self.target, self)
        self._rpc_server.start()
        super(DCManagerAuditService, self).start()

    def init_tgm(self):
        self.TG = scheduler.ThreadGroupManager()

    def init_audit_managers(self):
        self.subcloud_audit_manager = SubcloudAuditManager()
        # Audit availability of all subclouds.
        # Note this will run in a separate green thread
        self.TG.start(self.subcloud_audit_manager.periodic_subcloud_audit)

    def _stop_rpc_server(self):
        # Stop RPC connection to prevent new requests
        LOG.debug(_("Attempting to stop engine service..."))
        try:
            self._rpc_server.stop()
            self._rpc_server.wait()
            LOG.info('Engine service stopped successfully')
        except Exception as ex:
            LOG.error('Failed to stop engine service: %s',
                      six.text_type(ex))

    def stop(self):
        self._stop_rpc_server()

        self.TG.stop()

        # Terminate the engine process
        LOG.info("All threads were gone, terminating engine")
        super(DCManagerAuditService, self).stop()
