# Copyright (c) 2020-2021, 2024-2025 Wind River Systems, Inc.
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

import functools

from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_service import service

from dccommon.subprocess_cleanup import SubprocessCleanup
from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common import exceptions
from dcmanager.common import messaging as rpc_messaging
from dcmanager.common import scheduler
from dcmanager.common import utils
from dcmanager.orchestrator.orchestrator_manager import OrchestratorManager
from dcmanager.orchestrator.orchestrator_worker import OrchestratorWorker

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


def request_context(func):
    @functools.wraps(func)
    def wrapped(self, ctx, *args, **kwargs):
        if ctx is not None and not isinstance(ctx, context.RequestContext):
            ctx = context.RequestContext.from_dict(ctx.to_dict())
        try:
            return func(self, ctx, *args, **kwargs)
        except exceptions.DCManagerException:
            raise oslo_messaging.rpc.dispatcher.ExpectedException()

    return wrapped


class DCManagerOrchestratorService(service.Service):
    """Lifecycle manager for a running orchestrator service."""

    def __init__(self):

        super().__init__()
        self.host = cfg.CONF.host
        self.rpc_api_version = consts.RPC_API_VERSION
        self.topic = consts.TOPIC_DC_MANAGER_ORCHESTRATOR
        # The following are initialized here, but assigned in start() which
        # happens after the fork when spawning multiple worker processes
        self.TG = None
        self.target = None
        self._rpc_server = None
        self.orchestrator_manager = None

    def start(self):
        utils.set_open_file_limit(cfg.CONF.orchestrator_worker_rlimit_nofile)
        self.init_tgm()
        self.init_manager()
        target = oslo_messaging.Target(
            version=self.rpc_api_version, server=self.host, topic=self.topic
        )
        self.target = target
        self._rpc_server = rpc_messaging.get_rpc_server(self.target, self)
        self._rpc_server.start()
        super().start()

    def init_tgm(self):
        self.TG = scheduler.ThreadGroupManager()

    def init_manager(self):
        self.orchestrator_manager = OrchestratorManager()

    def _stop_rpc_server(self):
        # Stop RPC connection to prevent new requests
        LOG.debug("Attempting to stop RPC service...")
        if self._rpc_server is not None:
            try:
                self._rpc_server.stop()
                self._rpc_server.wait()
                self._rpc_server = None
                LOG.info("RPC service stopped successfully")
            except Exception as ex:
                LOG.error("Failed to stop engine service: %s", str(ex))

    def stop(self):
        """Stop anything initiated by start"""
        SubprocessCleanup.shutdown_cleanup(origin="service")
        self._stop_rpc_server()
        if self.TG is not None:
            self.TG.stop()
            self.TG = None
        if self.orchestrator_manager is not None:
            self.orchestrator_manager.stop()
            self.orchestrator_manager = None
        # Terminate the engine process
        LOG.info("All threads were gone, terminating engine")
        super().stop()

    @request_context
    def create_sw_update_strategy(self, context, payload):
        # Creates a software update strategy
        LOG.info(
            "Handling create_sw_update_strategy request of type %s"
            % payload.get("type")
        )
        return self.orchestrator_manager.create_sw_update_strategy(context, payload)

    @request_context
    def delete_sw_update_strategy(self, context, update_type=None):
        # Deletes the software update strategy
        LOG.info("Handling delete_sw_update_strategy request")
        return self.orchestrator_manager.delete_sw_update_strategy(
            context, update_type=update_type
        )

    @request_context
    def apply_sw_update_strategy(self, context, update_type=None):
        # Applies the software update strategy
        LOG.info("Handling apply_sw_update_strategy request")
        return self.orchestrator_manager.apply_sw_update_strategy(
            context, update_type=update_type
        )

    @request_context
    def abort_sw_update_strategy(self, context, update_type=None):
        # Aborts the software update strategy
        LOG.info("Handling abort_sw_update_strategy request")
        return self.orchestrator_manager.abort_sw_update_strategy(
            context, update_type=update_type
        )

    @request_context
    def stop_strategy(self, context, strategy_type):
        LOG.info("Handling stop_strategy request")
        return self.orchestrator_manager.stop_strategy(strategy_type)


class DCManagerOrchestratorWorkerService(service.Service):
    """Lifecycle manager for a running orchestrator-worker service."""

    def __init__(self):

        super().__init__()
        self.host = cfg.CONF.host
        self.rpc_api_version = consts.RPC_API_VERSION
        self.topic = consts.TOPIC_DC_MANAGER_ORCHESTRATOR_WORKER
        # The following are initialized here, but assigned in start() which
        # happens after the fork when spawning multiple worker processes
        self.TG = None
        self.target = None
        self._rpc_server = None
        self.orchestrator_worker = None

    def start(self):
        utils.set_open_file_limit(cfg.CONF.orchestrator_worker_rlimit_nofile)
        self.init_tgm()
        self.init_worker()
        target = oslo_messaging.Target(
            version=self.rpc_api_version, server=self.host, topic=self.topic
        )
        self.target = target
        self._rpc_server = rpc_messaging.get_rpc_server(self.target, self)
        self._rpc_server.start()
        super().start()

    def init_tgm(self):
        self.TG = scheduler.ThreadGroupManager()

    def init_worker(self):
        self.orchestrator_worker = OrchestratorWorker()

    def _stop_rpc_server(self):
        # Stop RPC connection to prevent new requests
        LOG.debug("Attempting to stop RPC service...")
        if self._rpc_server is not None:
            try:
                self._rpc_server.stop()
                self._rpc_server.wait()
                self._rpc_server = None
                LOG.info("RPC service stopped successfully")
            except Exception as ex:
                LOG.error("Failed to stop engine service: %s", str(ex))

    def stop(self):
        """Stop anything initiated by start"""
        SubprocessCleanup.shutdown_cleanup(origin="service")
        self._stop_rpc_server()
        if self.TG is not None:
            self.TG.stop()
            self.TG = None
        if self.orchestrator_worker is not None:
            self.orchestrator_worker.stop()
            self.orchestrator_worker = None
        # Terminate the engine process
        LOG.info("All threads were gone, terminating engine")
        super().stop()

    @request_context
    def orchestrate(self, context, steps_data, strategy_type):
        LOG.info(f"Handling orchestrate request for strategy of type {strategy_type}")
        return self.orchestrator_worker.orchestrate(steps_data, strategy_type)

    @request_context
    def stop_processing(self, context):
        LOG.info("Handling stop_processing")
        return self.orchestrator_worker.stop_processing()
