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
# Copyright (c) 2020 Wind River Systems, Inc.
#

import eventlet

from oslo_log import log as logging

from dcorch.common import consts
from dcorch.common import context
from dcorch.db import api as db_api
from dcorch.engine import scheduler

LOG = logging.getLogger(__name__)

# How often the initial sync thread will wake up
SYNC_INTERVAL = 10
# How long to wait after a failed sync before retrying
SYNC_FAIL_HOLD_OFF = 60


class InitialSyncManager(object):
    """Manages the initial sync for each subcloud."""

    def __init__(self, gsm, fkm, *args, **kwargs):
        super(InitialSyncManager, self).__init__()
        self.gsm = gsm
        self.fkm = fkm
        self.context = context.get_admin_context()
        # Keeps track of greenthreads we create to do work.
        self.thread_group_manager = scheduler.ThreadGroupManager(
            thread_pool_size=50)
        # Track greenthreads created for each subcloud.
        self.subcloud_threads = dict()

    def init_actions(self):
        """Perform actions on initialization"""

        # Since we are starting up, any initial syncs that were in progress
        # should be considered failed and must be redone.
        for subcloud in db_api.subcloud_get_all(
                self.context,
                initial_sync_state=consts.INITIAL_SYNC_STATE_IN_PROGRESS):
            LOG.info('Initial sync for subcloud %s was in progress and will '
                     'be re-attempted' % subcloud.region_name)
            self.gsm.update_subcloud_state(
                subcloud.region_name,
                initial_sync_state=consts.INITIAL_SYNC_STATE_REQUESTED)

        # Since we are starting up, any failed syncs won't be re-attempted
        # because the timer will not be running. Reattempt them.
        for subcloud in db_api.subcloud_get_all(
                self.context,
                initial_sync_state=consts.INITIAL_SYNC_STATE_FAILED):
            LOG.info('Initial sync for subcloud %s was failed and will '
                     'be re-attempted' % subcloud.region_name)
            self.gsm.update_subcloud_state(
                subcloud.region_name,
                initial_sync_state=consts.INITIAL_SYNC_STATE_REQUESTED)

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
        LOG.debug('Starting initial sync loop.')

        for subcloud in db_api.subcloud_get_all(
                self.context,
                initial_sync_state=consts.INITIAL_SYNC_STATE_REQUESTED):
            # Create a new greenthread for each subcloud to allow the
            # initial syncs to be done in parallel. If there are not enough
            # greenthreads in the pool, this will block until one becomes
            # available.
            self.subcloud_threads[subcloud.region_name] = \
                self.thread_group_manager.start(
                    self._initial_sync_subcloud, subcloud.region_name)

        # Wait for all greenthreads to complete. This both throttles the
        # initial syncs and ensures we don't attempt to do an initial sync
        # for a subcloud before a previous initial sync completes.
        LOG.debug('Waiting for initial syncs to complete.')
        for thread in self.subcloud_threads.values():
            thread.wait()

        # Clear the list of threads before next audit
        self.subcloud_threads = dict()
        LOG.debug('All subcloud initial syncs have completed.')

    def _initial_sync_subcloud(self, subcloud_name):
        """Perform initial sync for a subcloud.

        This runs in a separate greenthread for each subcloud.
        """
        LOG.info('Initial sync for subcloud %s' % subcloud_name)

        # Verify that the sync state hasn't changed (there can be a delay
        # before the greenthread runs).
        if not self.gsm.subcloud_state_matches(
                subcloud_name,
                initial_sync_state=consts.INITIAL_SYNC_STATE_REQUESTED):
            # Sync is no longer required
            LOG.info('Initial sync for subcloud %s no longer required' %
                     subcloud_name)
            return

        # Indicate that initial sync has started
        self.gsm.update_subcloud_state(
            subcloud_name,
            initial_sync_state=consts.INITIAL_SYNC_STATE_IN_PROGRESS)

        # Initial sync. It's synchronous so that identity
        # get synced before fernet token keys are synced. This is
        # necessary since we want to revoke all existing tokens on
        # this subcloud after its services user IDs and project
        # IDs are changed. Otherwise subcloud services will fail
        # authentication since they keep on using their existing tokens
        # issued before these IDs change, until these tokens expires.
        new_state = consts.INITIAL_SYNC_STATE_COMPLETED
        try:
            self.gsm.initial_sync(self.context, subcloud_name)
            self.fkm.distribute_keys(self.context, subcloud_name)
        except Exception as e:
            LOG.exception('Initial sync failed for %s: %s', subcloud_name, e)
            # We need to try again
            new_state = consts.INITIAL_SYNC_STATE_FAILED

        # Verify that the sync wasn't cancelled while we did the sync (for
        # example, the subcloud could have been unmanaged).
        if self.gsm.subcloud_state_matches(
                subcloud_name,
                initial_sync_state=consts.INITIAL_SYNC_STATE_IN_PROGRESS):
            # Update initial sync state
            self.gsm.update_subcloud_state(subcloud_name,
                                           initial_sync_state=new_state)
            if new_state == consts.INITIAL_SYNC_STATE_COMPLETED:
                # The initial sync was completed and we have updated the
                # subcloud state. Now we can enable syncing for the subcloud.
                self.gsm.enable_subcloud(self.context, subcloud_name)
            elif new_state == consts.INITIAL_SYNC_STATE_FAILED:
                # Start a "timer" to wait a bit before re-attempting the sync.
                # This thread is not taken from the thread pool, because we
                # don't want a large number of failed syncs to prevent new
                # subclouds from syncing.
                eventlet.greenthread.spawn_after(SYNC_FAIL_HOLD_OFF,
                                                 self._reattempt_sync,
                                                 subcloud_name)
                pass
            else:
                LOG.error('Unexpected new_state %s for subcloud %s' %
                          (new_state, subcloud_name))
        else:
            LOG.info('Initial sync was cancelled for subcloud %s while in '
                     'progress' % subcloud_name)

    def _reattempt_sync(self, subcloud_name):
        # Verify that the sync state hasn't changed since the last attempt.
        if not self.gsm.subcloud_state_matches(
                subcloud_name,
                initial_sync_state=consts.INITIAL_SYNC_STATE_FAILED):
            # Sync is no longer required
            LOG.info('Reattempt initial sync for subcloud %s no longer '
                     'required' % subcloud_name)
            return

        self.gsm.update_subcloud_state(
            subcloud_name,
            initial_sync_state=consts.INITIAL_SYNC_STATE_REQUESTED)
