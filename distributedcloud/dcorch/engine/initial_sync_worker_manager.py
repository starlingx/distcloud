#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import eventlet

from oslo_log import log as logging

from dcorch.common import consts
from dcorch.common import context
from dcorch.db import api as db_api
from dcorch.engine.fernet_key_manager import FernetKeyManager
from dcorch.engine import scheduler


LOG = logging.getLogger(__name__)

# How often the initial sync thread will wake up
SYNC_INTERVAL = 10
# How long to wait after a failed sync before retrying
SYNC_FAIL_HOLD_OFF = 60


class InitialSyncWorkerManager(object):
    """Manages the initial sync for each subcloud."""

    def __init__(self, gswm, engine_id, *args, **kwargs):
        self.gswm = gswm
        self.engine_id = engine_id
        self.context = context.get_admin_context()
        # Keeps track of greenthreads we create to do work.
        self.thread_group_manager = scheduler.ThreadGroupManager(thread_pool_size=100)

    def initial_sync_subclouds(self, context, subcloud_capabilities):
        """Perform initial sync for subclouds that require it."""
        LOG.info(
            f"Engine id:({self.engine_id}) Start initial sync for "
            f"{len(subcloud_capabilities)} subclouds."
        )
        LOG.debug(
            f"Engine id:({self.engine_id}) Start initial sync for "
            f"subclouds {list(subcloud_capabilities.keys())}."
        )

        for sc_region_name, sc_capabilities_and_ip in subcloud_capabilities.items():
            # Create a new greenthread for each subcloud to allow the
            # initial syncs to be done in parallel. If there are not enough
            # greenthreads in the pool, this will block until one becomes
            # available.
            try:
                self.thread_group_manager.start(
                    self._initial_sync_subcloud,
                    self.context,
                    sc_region_name,
                    sc_capabilities_and_ip[0],
                    sc_capabilities_and_ip[1],
                )
            except Exception as e:
                LOG.error(
                    "Exception occurred when running initial_sync for "
                    f"subcloud {sc_region_name}: {e}"
                )

    def _initial_sync_subcloud(
        self, context, subcloud_name, subcloud_capabilities, management_ip
    ):
        """Perform initial sync for a subcloud.

        This runs in a separate greenthread for each subcloud.
        """
        LOG.info(f"Initial sync for subcloud {subcloud_name}")

        # Verify that the sync state hasn't changed (there can be a delay
        # before the greenthread runs).
        result = db_api.subcloud_update_initial_state(
            context,
            subcloud_name,
            consts.INITIAL_SYNC_STATE_REQUESTED,
            consts.INITIAL_SYNC_STATE_IN_PROGRESS,
        )
        if result == 0:
            # Sync is no longer required
            LOG.debug(f"Initial sync for subcloud {subcloud_name} no longer required")
            return

        # sync_objs stores the sync object per endpoint
        sync_objs = self.gswm.create_sync_objects(
            subcloud_name, subcloud_capabilities, management_ip
        )

        # Initial sync. It's synchronous so that identity
        # get synced before fernet token keys are synced. This is
        # necessary since we want to revoke all existing tokens on
        # this subcloud after its services user IDs and project
        # IDs are changed. Otherwise subcloud services will fail
        # authentication since they keep on using their existing tokens
        # issued before these IDs change, until these tokens expires.
        new_state = consts.INITIAL_SYNC_STATE_COMPLETED
        try:
            self.initial_sync(subcloud_name, sync_objs)
            FernetKeyManager.distribute_keys(subcloud_name)
            self.init_subcloud_sync_audit(subcloud_name)
            LOG.info(f"End of initial sync for subcloud {subcloud_name}")
        except Exception as e:
            LOG.exception(f"Initial sync failed for {subcloud_name}: {e}")
            # We need to try again
            new_state = consts.INITIAL_SYNC_STATE_FAILED

        # Verify that the sync wasn't cancelled while we did the sync (for
        # example, the subcloud could have been unmanaged).
        result = db_api.subcloud_update_initial_state(
            context, subcloud_name, consts.INITIAL_SYNC_STATE_IN_PROGRESS, new_state
        )
        if result > 0:
            if new_state == consts.INITIAL_SYNC_STATE_COMPLETED:
                # The initial sync was completed and we have updated the
                # subcloud state. Now we can enable syncing for the subcloud.
                self.enable_subcloud(subcloud_name, sync_objs)
            elif new_state == consts.INITIAL_SYNC_STATE_FAILED:
                # Start a "timer" to wait a bit before re-attempting the sync.
                # This thread is not taken from the thread pool, because we
                # don't want a large number of failed syncs to prevent new
                # subclouds from syncing.
                eventlet.greenthread.spawn_after(
                    SYNC_FAIL_HOLD_OFF, self._reattempt_sync, subcloud_name
                )
                pass
            else:
                LOG.error(
                    f"Unexpected new_state {new_state} for subcloud {subcloud_name}"
                )
        else:
            LOG.debug(
                f"Initial sync was cancelled for subcloud {subcloud_name} "
                "while in progress"
            )

    def _reattempt_sync(self, subcloud_name):
        # Verify that the sync state hasn't changed since the last attempt.
        result = db_api.subcloud_update_initial_state(
            self.context,
            subcloud_name,
            consts.INITIAL_SYNC_STATE_FAILED,
            consts.INITIAL_SYNC_STATE_REQUESTED,
        )
        if result == 0:
            # Sync is no longer required
            LOG.debug(
                f"Reattempt initial sync for subcloud {subcloud_name} "
                f"no longer required"
            )
            return

    def enable_subcloud(self, subcloud_name, sync_objs):
        LOG.debug(f"enabling subcloud {subcloud_name}")
        for endpoint_type, sync_obj in sync_objs.items():
            LOG.debug(
                f"Engine id: {self.engine_id} enabling sync thread for subcloud "
                f"{subcloud_name} and endpoint type {endpoint_type}."
            )
            sync_obj.enable()

    def init_subcloud_sync_audit(self, subcloud_name):
        LOG.debug(f"Initialize subcloud sync audit for subcloud %{subcloud_name}")

        for endpoint_type in consts.SYNC_ENDPOINT_TYPES_LIST:
            db_api.subcloud_sync_update(
                self.context,
                subcloud_name,
                endpoint_type,
                values={
                    "audit_status": consts.AUDIT_STATUS_NONE,
                    "sync_status_reported": consts.SYNC_STATUS_NONE,
                    "sync_status_report_time": None,
                    "last_audit_time": None,
                },
            )

    def initial_sync(self, subcloud_name, sync_objs):
        LOG.debug(f"Initial sync subcloud {subcloud_name} {self.engine_id}")
        for sync_obj in sync_objs.values():
            sync_obj.initial_sync()
