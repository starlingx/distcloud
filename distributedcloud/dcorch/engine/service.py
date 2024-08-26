# Copyright (c) 2020-2024 Wind River Systems, Inc.
# All Rights Reserved.
#
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

import functools
import resource
import time

from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_service import service
from oslo_utils import uuidutils

from dccommon import consts as dccommon_consts
from dcorch.common import consts
from dcorch.common import context
from dcorch.common import exceptions
from dcorch.common.i18n import _
from dcorch.common import messaging as rpc_messaging
from dcorch.engine.fernet_key_manager import FernetKeyManager
from dcorch.engine.generic_sync_manager import GenericSyncManager
from dcorch.engine.generic_sync_worker_manager import GenericSyncWorkerManager
from dcorch.engine.initial_sync_manager import InitialSyncManager
from dcorch.engine.initial_sync_worker_manager import InitialSyncWorkerManager
from dcorch.engine.quota_manager import QuotaManager
from dcorch.engine import scheduler

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


def request_context(func):
    @functools.wraps(func)
    def wrapped(self, ctx, *args, **kwargs):
        if ctx is not None and not isinstance(ctx, context.RequestContext):
            ctx = context.RequestContext.from_dict(ctx.to_dict())
        try:
            return func(self, ctx, *args, **kwargs)
        except exceptions.OrchestratorException:
            raise oslo_messaging.rpc.dispatcher.ExpectedException()

    return wrapped


class EngineService(service.Service):
    """Lifecycle manager for a running audit service."""

    def __init__(self):

        super(EngineService, self).__init__()
        self.host = cfg.CONF.host
        self.rpc_api_version = consts.RPC_API_VERSION
        self.topic = consts.TOPIC_ORCH_ENGINE
        # The following are initialized here, but assigned in start() which
        # happens after the fork when spawning multiple worker processes
        self.TG = None
        self.periodic_enable = cfg.CONF.scheduler.periodic_enable
        self.target = None
        self._rpc_server = None
        self.qm = None
        self.gsm = None
        self.fkm = None
        self.ism = None

    def start(self):
        target = oslo_messaging.Target(
            version=self.rpc_api_version, server=self.host, topic=self.topic
        )
        self.target = target
        self._rpc_server = rpc_messaging.get_rpc_server(self.target, self)
        self._rpc_server.start()

        self.init_tgm()
        self.init_qm()
        self.init_gsm()
        self.init_fkm()
        self.init_ism()

        super(EngineService, self).start()

        if self.periodic_enable:
            LOG.info("Adding periodic tasks for the engine to perform")
            self.TG.add_timer(
                CONF.fernet.key_rotation_interval * dccommon_consts.SECONDS_IN_HOUR,
                self.periodic_key_rotation,
                initial_delay=(
                    CONF.fernet.key_rotation_interval * dccommon_consts.SECONDS_IN_HOUR
                ),
            )

    def init_tgm(self):
        self.TG = scheduler.ThreadGroupManager()

    def init_qm(self):
        self.qm = QuotaManager()

    def init_gsm(self):
        self.gsm = GenericSyncManager()
        self.TG.start(self.gsm.sync_job_thread)
        self.TG.start(self.gsm.sync_audit_thread)

    def init_fkm(self):
        self.fkm = FernetKeyManager()

    def init_ism(self):
        self.ism = InitialSyncManager()
        self.ism.init_actions()
        self.TG.start(self.ism.initial_sync_thread)

    def periodic_balance_all(self):
        # Automated Quota Sync for all the keystone projects
        LOG.info("Periodic quota sync job started at: %s", time.strftime("%c"))
        self.qm.periodic_balance_all()

    @request_context
    def get_usage_for_project_and_user(
        self, context, endpoint_type, project_id, user_id=None
    ):
        # Returns cached usage as of last quota sync audit so will be
        # slightly stale.
        return self.qm.get_usage_for_project_and_user(
            endpoint_type, project_id, user_id
        )

    @request_context
    def quota_sync_for_project(self, context, project_id, user_id):
        # On Demand Quota Sync for a project, will be triggered by KB-API
        LOG.info("On Demand Quota Sync Called for: %s %s", project_id, user_id)
        self.qm.quota_sync_for_project(project_id, user_id)

    def _stop_rpc_server(self):
        # Stop RPC connection to prevent new requests
        LOG.debug(_("Attempting to stop engine service..."))
        try:
            self._rpc_server.stop()
            self._rpc_server.wait()
            LOG.info("Engine service stopped successfully")
        except Exception as ex:
            LOG.error(f"Failed to stop engine service: {str(ex)}")

    def stop(self):
        self._stop_rpc_server()

        if self.TG:
            self.TG.stop()

        # Terminate the engine process
        LOG.info("All threads were gone, terminating engine")
        super(EngineService, self).stop()

    def periodic_key_rotation(self):
        """Periodic key rotation."""
        LOG.info("Periodic key rotation started at: %s", time.strftime("%c"))
        return self.fkm.rotate_fernet_keys()


class EngineWorkerService(service.Service):
    """Lifecycle manager for a running service engine.

    - All the methods in here are called from the RPC client.
    - If a RPC call does not have a corresponding method here, an exceptions
      will be thrown.
    - Arguments to these calls are added dynamically and will be treated as
      keyword arguments by the RPC client.
    """

    def __init__(self):

        super(EngineWorkerService, self).__init__()
        self.host = cfg.CONF.host
        self.rpc_api_version = consts.RPC_API_VERSION
        self.topic = consts.TOPIC_ORCH_ENGINE_WORKER
        # The following are initialized here, but assigned in start() which
        # happens after the fork when spawning multiple worker processes
        self.engine_id = None
        self.target = None
        self._rpc_server = None
        self.gswm = None
        self.iswm = None

    def init_gswm(self):
        self.gswm = GenericSyncWorkerManager(self.engine_id)

    def init_iswm(self):
        self.iswm = InitialSyncWorkerManager(self.gswm, self.engine_id)

    def start(self):
        LOG.info("Starting %s", self.__class__.__name__)
        self.engine_id = uuidutils.generate_uuid()
        target = oslo_messaging.Target(
            version=self.rpc_api_version, server=self.host, topic=self.topic
        )
        self.target = target
        self._rpc_server = rpc_messaging.get_rpc_server(self.target, self)
        self._rpc_server.start()

        self.init_gswm()
        self.init_iswm()

        self.set_resource_limit()

        super(EngineWorkerService, self).start()

    def set_resource_limit(self):
        try:
            resource.setrlimit(
                resource.RLIMIT_NOFILE, (cfg.CONF.rlimit_nofile, cfg.CONF.rlimit_nofile)
            )
        except Exception as ex:
            LOG.error(
                "Engine id %s: failed to set the NOFILE resource limit: "
                "%s" % (self.engine_id, ex)
            )

    @request_context
    def add_subcloud(self, ctxt, subcloud_name, sw_version, management_ip):
        self.gswm.add_subcloud(ctxt, subcloud_name, sw_version, management_ip)

    @request_context
    # todo: add authentication since ctxt not actually needed later
    def del_subcloud(self, ctxt, subcloud_name):
        self.gswm.del_subcloud(ctxt, subcloud_name)

    @request_context
    # todo: add authentication since ctxt not actually needed later
    def update_subcloud_states(
        self, ctxt, subcloud_name, management_state, availability_status
    ):
        """Handle subcloud state updates from dcmanager

        These state updates must be processed quickly. Any work triggered by
        these state updates must be done asynchronously, without delaying the
        reply to the dcmanager. For example, it is not acceptable to
        communicate with a subcloud while handling the state update.
        """

        # Check if state has changed before doing anything
        if self.gswm.subcloud_state_matches(
            subcloud_name,
            management_state=management_state,
            availability_status=availability_status,
        ):
            # No change in state - nothing to do.
            LOG.debug("Ignoring unchanged state update for %s" % subcloud_name)
            return

        initial_sync_state = consts.INITIAL_SYNC_STATE_NONE
        subsequent_sync = None

        # Check if the subcloud is ready to sync.
        if management_state == dccommon_consts.MANAGEMENT_MANAGED:
            if availability_status == dccommon_consts.AVAILABILITY_ONLINE:
                # Update the subcloud state and schedule an initial sync
                initial_sync_state = consts.INITIAL_SYNC_STATE_REQUESTED
        else:
            # If the subcloud is unmanaged, reset the subsequent_sync, because it
            # needs to run the initial sync when it becomes managed again.
            # If only its availability changed, then subsequent_sync should remain
            # the same
            subsequent_sync = False

        self.gswm.update_subcloud_state(
            ctxt,
            subcloud_name,
            management_state=management_state,
            availability_status=availability_status,
            initial_sync_state=initial_sync_state,
            subsequent_sync=subsequent_sync,
        )

    @request_context
    def update_subcloud_state(
        self,
        ctxt,
        subcloud_name,
        management_state=None,
        availability_status=None,
        initial_sync_state=None,
    ):
        LOG.info("Trigger update state for subcloud %s", subcloud_name)
        self.gswm.update_subcloud_state(
            ctxt,
            subcloud_name,
            management_state,
            availability_status,
            initial_sync_state,
        )

    @request_context
    def add_subcloud_sync_endpoint_type(
        self, ctxt, subcloud_name, endpoint_type_list=None
    ):
        try:
            self.gswm.add_subcloud_sync_endpoint_type(
                ctxt, subcloud_name, endpoint_type_list=endpoint_type_list
            )
        except Exception as ex:
            LOG.warning(
                "Add subcloud endpoint type failed for %s: %s", subcloud_name, str(ex)
            )
            raise

    @request_context
    def remove_subcloud_sync_endpoint_type(
        self, ctxt, subcloud_name, endpoint_type_list=None
    ):
        try:
            self.gswm.remove_subcloud_sync_endpoint_type(
                ctxt, subcloud_name, endpoint_type_list=endpoint_type_list
            )
        except Exception as ex:
            LOG.warning(
                "Remove subcloud endpoint type failed for %s: %s",
                subcloud_name,
                str(ex),
            )
            raise

    @request_context
    def sync_subclouds(self, ctxt, subcloud_sync_list):
        self.gswm.sync_subclouds(ctxt, subcloud_sync_list)

    @request_context
    def run_sync_audit(self, ctxt, subcloud_sync_list):
        self.gswm.run_sync_audit(ctxt, subcloud_sync_list)

    @request_context
    def initial_sync_subclouds(self, ctxt, subcloud_capabilities):
        self.iswm.initial_sync_subclouds(ctxt, subcloud_capabilities)

    @request_context
    # todo: add authentication since ctxt not actually needed later
    def update_subcloud_version(self, ctxt, subcloud_name, sw_version):
        self.gswm.update_subcloud_version(ctxt, subcloud_name, sw_version)

    @request_context
    def update_subcloud_management_ip(self, ctxt, subcloud_name, management_ip):
        self.gswm.update_subcloud_management_ip(ctxt, subcloud_name, management_ip)

    def _stop_rpc_server(self):
        # Stop RPC connection to prevent new requests
        LOG.debug(_("Attempting to stop engine-worker service..."))
        try:
            if self._rpc_server:
                self._rpc_server.stop()
                self._rpc_server.wait()
                LOG.info("Engine-worker service stopped successfully")
        except Exception as ex:
            LOG.error(f"Failed to stop engine-worker service: {str(ex)}")

    def stop(self, graceful=False):
        self._stop_rpc_server()

        # Terminate the engine process
        LOG.info("All threads were gone, terminating engine-worker")
        super(EngineWorkerService, self).stop(graceful)

    @request_context
    # The sync job info has been written to the DB, alert the sync engine
    # that there is work to do.
    # TODO(lzhu1): add authentication since ctxt not actually needed later
    def sync_request(self, ctxt, endpoint_type):
        self.gswm.sync_request(ctxt, endpoint_type)
