# Copyright 2017 Ericsson AB.
# Copyright (c) 2020-2024 Wind River Systems, Inc.
# All Rights Reserved.
#
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

import eventlet
from oslo_config import cfg
from oslo_log import log as logging

from dccommon import consts as dccommon_consts
from dcorch.common import consts as dco_consts
from dcorch.common import context
from dcorch.db import api as db_api
from dcorch.rpc import client

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

CHECK_AUDIT_INTERVAL = 300  # frequency to check for audit work
CHECK_SYNC_INTERVAL = 5  # frequency to check for sync work
AUDIT_INTERVAL = 1200  # Default audit interval


class GenericSyncManager(object):
    """Manages tasks related to resource management."""

    def __init__(self, *args, **kwargs):
        self.context = context.get_admin_context()
        self.engine_worker_rpc_client = client.EngineWorkerClient()

    def sync_job_thread(self):
        """Perform sync request for subclouds as required."""

        while True:
            try:
                self.sync_subclouds()
                eventlet.greenthread.sleep(CHECK_SYNC_INTERVAL)
            except eventlet.greenlet.GreenletExit:
                # We have been told to exit
                return
            except Exception as e:
                LOG.exception(e)

    def sync_audit_thread(self):
        """Perform sync request for subclouds as required."""

        while True:
            try:
                self.run_sync_audit()
                eventlet.greenthread.sleep(CHECK_AUDIT_INTERVAL)
            except eventlet.greenlet.GreenletExit:
                # We have been told to exit
                return
            except Exception as e:
                LOG.exception(e)

    def _process_subclouds(self, rpc_method, subcloud_sync_list):
        # We want a chunksize of at least 1 so add the number of workers.
        chunksize = (len(subcloud_sync_list) + CONF.workers) // (CONF.workers)

        subcloud_sync_chunk = []
        for subcloud_sync in subcloud_sync_list:
            subcloud_sync_chunk.append(subcloud_sync)
            if len(subcloud_sync_chunk) == chunksize:
                # We've gathered a batch of subclouds, send it to engine worker
                # to process.
                self._send_chunk(rpc_method, subcloud_sync_chunk)
                subcloud_sync_chunk = []
        if subcloud_sync_chunk:
            # We've got a partial batch...send it off for processing.
            self._send_chunk(rpc_method, subcloud_sync_chunk)
        LOG.debug(f"Done sending {rpc_method.__name__} request messages.")

    def sync_subclouds(self):
        # get a list of eligible subclouds (region_name, endpoint_type),
        # and mark them as in-progress.
        subcloud_sync_list = db_api.subcloud_sync_update_all_to_in_progress(
            self.context,
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            initial_sync_state=dco_consts.INITIAL_SYNC_STATE_COMPLETED,
            sync_requests=[
                dco_consts.SYNC_STATUS_REQUESTED,
                dco_consts.SYNC_STATUS_FAILED,
            ],
        )

        if subcloud_sync_list:
            LOG.info("Start sync_subclouds")
            self._process_subclouds(
                self.engine_worker_rpc_client.sync_subclouds, subcloud_sync_list
            )
            LOG.info("End sync_subclouds")
        else:
            LOG.debug("No eligible subclouds for sync.")

    def run_sync_audit(self):
        LOG.info("Start run_sync_audit")

        # get a list of eligible subclouds (region_name, endpoint_type),
        # and mark them as in-progress.
        # check if the last audit time is equal or greater than the audit
        # interval only if the status is completed or in progress (in case
        # the process is dead while audit is in progress), or go ahead with
        # audit if the status is failed or none.
        subcloud_sync_list = db_api.subcloud_audit_update_all_to_in_progress(
            self.context,
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            initial_sync_state=dco_consts.INITIAL_SYNC_STATE_COMPLETED,
            audit_interval=AUDIT_INTERVAL,
        )

        if subcloud_sync_list:
            self._process_subclouds(
                self.engine_worker_rpc_client.run_sync_audit, subcloud_sync_list
            )
        else:
            LOG.debug("No eligible subclouds for audit.")

    def _send_chunk(self, rpc_method, subcloud_sync_chunk):
        try:
            rpc_method(self.context, subcloud_sync_chunk)
            LOG.debug(
                f"Sent {rpc_method.__name__} request message for "
                f"{len(subcloud_sync_chunk)} (subcloud, endpoint_type) "
                f"pairs."
            )
        except Exception as e:
            LOG.error(
                f"Exception occurred in {rpc_method.__name__} for "
                f"subclouds {subcloud_sync_chunk}: {e}"
            )
