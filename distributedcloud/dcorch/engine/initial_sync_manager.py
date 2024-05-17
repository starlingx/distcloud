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
# Copyright (c) 2020, 2024 Wind River Systems, Inc.
#

import eventlet
from oslo_config import cfg
from oslo_log import log as logging

from dcorch.common import consts
from dcorch.common import context
from dcorch.db import api as db_api
from dcorch.rpc import client

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

# How often the initial sync thread will wake up
SYNC_INTERVAL = 10
# How long to wait after a failed sync before retrying
SYNC_FAIL_HOLD_OFF = 60


class InitialSyncManager(object):
    """Manages the initial sync for each subcloud."""

    def __init__(self, *args, **kwargs):
        self.context = context.get_admin_context()
        self.engine_worker_rpc_client = client.EngineWorkerClient()

    def init_actions(self):
        """Perform actions on initialization"""

        # Since we are starting up, any initial syncs that were in progress
        # should be considered failed and must be redone.
        subclouds = db_api.subcloud_update_all_initial_state(
            self.context,
            pre_initial_sync_state=consts.INITIAL_SYNC_STATE_IN_PROGRESS,
            initial_sync_state=consts.INITIAL_SYNC_STATE_REQUESTED)
        if subclouds > 0:
            LOG.info("Initial sync for subclouds were in progress and "
                     "will be re-attempted.")

        # Since we are starting up, any failed syncs won't be re-attempted
        # because the timer will not be running. Reattempt them.
        subclouds = db_api.subcloud_update_all_initial_state(
            self.context,
            pre_initial_sync_state=consts.INITIAL_SYNC_STATE_FAILED,
            initial_sync_state=consts.INITIAL_SYNC_STATE_REQUESTED)
        if subclouds > 0:
            LOG.info(
                "Initial sync for subclouds were failed and will be re-attempted.")

    def initial_sync_thread(self):
        """Perform initial sync for subclouds as required."""

        while True:
            # Catch exceptions so the thread does not die.
            try:
                eventlet.greenthread.sleep(SYNC_INTERVAL)
                self._initial_sync_subclouds()
            except eventlet.greenlet.GreenletExit:
                # We have been told to exit
                return
            except Exception as e:
                LOG.exception(e)

    def _initial_sync_subclouds(self):
        """Perform initial sync for subclouds that require it."""
        subclouds = db_api.subcloud_capabilities_get_all(
            self.context,
            initial_sync_state=consts.INITIAL_SYNC_STATE_REQUESTED)
        if not subclouds:
            LOG.debug("No eligible subclouds for initial sync.")
            return

        LOG.info("Starting initial sync loop.")

        # We want a chunksize of  least 1 so add the number of workers.
        chunksize = (len(subclouds) + CONF.workers) // (CONF.workers)

        subcloud_capabilities = {}
        for region_name, capabilities_and_ip in subclouds.items():
            subcloud_capabilities[region_name] = capabilities_and_ip
            if len(subcloud_capabilities) == chunksize:
                # We've gathered a batch of subclouds, send it to engine worker
                # to process.
                try:
                    self.engine_worker_rpc_client.initial_sync_subclouds(
                        self.context,
                        subcloud_capabilities)
                    LOG.debug(f"Sent initial sync request message for "
                              f"{len(subcloud_capabilities)} subclouds")
                except Exception as e:
                    LOG.error(f"Exception occurred in initial_sync for subclouds "
                              f"{list(subcloud_capabilities.keys())}: {e}")
                subcloud_capabilities = {}
        if subcloud_capabilities:
            # We've got a partial batch...send it off for processing.
            try:
                self.engine_worker_rpc_client.initial_sync_subclouds(
                    self.context,
                    subcloud_capabilities)
                LOG.debug(f"Sent initial sync request message for "
                          f"{len(subcloud_capabilities)} subclouds")
            except Exception as e:
                LOG.error(f"Exception occurred in initial_sync for subclouds "
                          f"{list(subcloud_capabilities.keys())}: {e}")
        LOG.debug("Done sending initial sync request messages.")
