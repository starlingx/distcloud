# Copyright 2017 Ericsson AB.
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
#
# Copyright (c) 2017-2021 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#
import datetime
import os
import threading
import time

from keystoneauth1 import exceptions as keystone_exceptions
from oslo_log import log as logging

from dccommon.drivers.openstack import patching_v1
from dccommon.drivers.openstack.patching_v1 import PatchingClient
from dccommon.drivers.openstack.sdk_platform import OpenStackDriver
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon.drivers.openstack import vim

from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common import exceptions
from dcmanager.common import scheduler
from dcmanager.common import utils
from dcmanager.db import api as db_api

LOG = logging.getLogger(__name__)


class PatchOrchThread(threading.Thread):
    """Patch Orchestration Thread

    This thread is responsible for executing the patch orchestration strategy.
    Here is how it works:
    - The user creates a patch strategy from the CLI (or REST API).
    - This ends up being handled by the SwUpdateManager class (above), which
      runs under the main dcmanager thread. The strategy is created and stored
      in the database.
    - The user then applies the strategy from the CLI (or REST API). The
      SwUpdateManager code updates the state of the strategy in the database.
    - The PatchOrchThread wakes up periodically and checks the database for
      a strategy that is in an active state (applying, aborting, etc...). If
      so, it executes the strategy, updating the strategy and steps in the
      database as it goes, with state and progress information.
    """

    def __init__(self, strategy_lock, audit_rpc_client):
        super(PatchOrchThread, self).__init__()
        self.context = context.get_admin_context()
        self._stop = threading.Event()
        # Used to protect strategy when an atomic read/update is required.
        self.strategy_lock = strategy_lock
        # Used to notify dcmanager-audit to trigger a patch audit
        self.audit_rpc_client = audit_rpc_client
        # Keeps track of greenthreads we create to do work.
        self.thread_group_manager = scheduler.ThreadGroupManager(
            thread_pool_size=500)
        # Track worker created for each subcloud.
        self.subcloud_workers = dict()
        # Used to store RegionOne patches.
        self.regionone_patches = dict()
        # Used to store the list of patch ids that should be applied, based on
        # their state in the central region.
        self.regionone_applied_patch_ids = list()
        # Used to store the list patch ids are committed in the central region.
        self.regionone_committed_patch_ids = list()

    def stopped(self):
        return self._stop.isSet()

    def stop(self):
        LOG.info("PatchOrchThread Stopping")
        self._stop.set()

    def run(self):
        self.patch_orch()
        # Stop any greenthreads that are still running
        self.thread_group_manager.stop()
        LOG.info("PatchOrchThread Stopped")

    @staticmethod
    def get_ks_client(region_name=consts.DEFAULT_REGION_NAME):
        """This will get a cached keystone client (and token)"""
        try:
            os_client = OpenStackDriver(
                region_name=region_name,
                region_clients=None)
            return os_client.keystone_client
        except Exception:
            LOG.warn('Failure initializing KeystoneClient %s' % region_name)
            raise

    def get_sysinv_client(self, region_name=consts.DEFAULT_REGION_NAME):
        ks_client = self.get_ks_client(region_name)
        return SysinvClient(region_name, ks_client.session,
                            endpoint=ks_client.endpoint_cache.get_endpoint('sysinv'))

    def get_patching_client(self, region_name=consts.DEFAULT_REGION_NAME):
        ks_client = self.get_ks_client(region_name)
        return PatchingClient(region_name, ks_client.session,
                              endpoint=ks_client.endpoint_cache.get_endpoint('patching'))

    def get_vim_client(self, region_name=consts.DEFAULT_REGION_NAME):
        ks_client = self.get_ks_client(region_name)
        return vim.VimClient(region_name, ks_client.session,
                             endpoint=ks_client.endpoint_cache.get_endpoint('vim'))

    @staticmethod
    def get_region_name(strategy_step):
        """Get the region name for a strategy step"""
        if strategy_step.subcloud_id is None:
            # This is the SystemController.
            return consts.DEFAULT_REGION_NAME
        else:
            return strategy_step.subcloud.name

    def strategy_step_update(self, subcloud_id, state=None, details=None):
        """Update the strategy step in the DB

        Sets the start and finished timestamp if necessary, based on state.
        """
        started_at = None
        finished_at = None
        if state in [consts.STRATEGY_STATE_UPDATING_PATCHES]:
            started_at = datetime.datetime.now()
        elif state in [consts.STRATEGY_STATE_COMPLETE,
                       consts.STRATEGY_STATE_ABORTED,
                       consts.STRATEGY_STATE_FAILED]:
            finished_at = datetime.datetime.now()
        db_api.strategy_step_update(
            self.context,
            subcloud_id,
            state=state,
            details=details,
            started_at=started_at,
            finished_at=finished_at)

    def get_region_one_patches(self):
        """Query the RegionOne to determine what patches should be applied/committed."""

        self.regionone_patches = \
            self.get_patching_client(consts.DEFAULT_REGION_NAME).query()
        LOG.debug("regionone_patches: %s" % self.regionone_patches)

        # Build lists of patches that should be applied in this subcloud,
        # based on their state in RegionOne. Check repostate (not patchstate)
        # as we only care if the patch has been applied to the repo (not
        # whether it is installed on the hosts). If we were to check the
        # patchstate, we could end up removing patches from this subcloud
        # just because a single host in RegionOne reported that it was not
        # patch current.
        self.regionone_applied_patch_ids = [
            patch_id for patch_id in self.regionone_patches.keys()
            if self.regionone_patches[patch_id]['repostate'] in [
                patching_v1.PATCH_STATE_APPLIED,
                patching_v1.PATCH_STATE_COMMITTED]]

        # Then query RegionOne to determine what patches should be committed.
        regionone_committed_patches = self.get_patching_client(
            consts.DEFAULT_REGION_NAME).query(
                state=patching_v1.PATCH_STATE_COMMITTED)
        LOG.debug("regionone_committed_patches: %s" %
                  regionone_committed_patches)

        self.regionone_committed_patch_ids = [
            patch_id for patch_id in regionone_committed_patches.keys()]

    def patch_orch(self):
        while not self.stopped():
            try:
                LOG.debug('Running patch orchestration')

                sw_update_strategy = db_api.sw_update_strategy_get(
                    self.context,
                    update_type=consts.SW_UPDATE_TYPE_PATCH)

                if sw_update_strategy.type == consts.SW_UPDATE_TYPE_PATCH:
                    if sw_update_strategy.state in [
                            consts.SW_UPDATE_STATE_APPLYING,
                            consts.SW_UPDATE_STATE_ABORTING]:
                        self.apply(sw_update_strategy)
                    elif sw_update_strategy.state == \
                            consts.SW_UPDATE_STATE_ABORT_REQUESTED:
                        self.abort(sw_update_strategy)
                    elif sw_update_strategy.state == \
                            consts.SW_UPDATE_STATE_DELETING:
                        self.delete(sw_update_strategy)

            except exceptions.NotFound:
                # Nothing to do if a strategy doesn't exist
                pass

            except Exception as e:
                # We catch all exceptions to avoid terminating the thread.
                LOG.exception(e)

            # Wake up every 10 seconds to see if there is work to do.
            time.sleep(10)

        LOG.info("PatchOrchThread ended main loop")

    def apply(self, sw_update_strategy):
        """Apply a patch strategy"""

        LOG.info("Applying patch strategy")
        strategy_steps = db_api.strategy_step_get_all(self.context)

        # Figure out which stage we are working on
        current_stage = None
        stop_after_stage = None
        failure_detected = False
        abort_detected = False
        for strategy_step in strategy_steps:
            if strategy_step.state == consts.STRATEGY_STATE_COMPLETE:
                # This step is complete
                continue
            elif strategy_step.state == consts.STRATEGY_STATE_ABORTED:
                # This step was aborted
                abort_detected = True
                continue
            elif strategy_step.state == consts.STRATEGY_STATE_FAILED:
                failure_detected = True
                # This step has failed and needs no further action
                if strategy_step.subcloud_id is None:
                    # Strategy on SystemController failed. We are done.
                    LOG.info("Stopping strategy due to failure while "
                             "patching SystemController")
                    with self.strategy_lock:
                        db_api.sw_update_strategy_update(
                            self.context, state=consts.SW_UPDATE_STATE_FAILED)
                    # Trigger patch audit to update the sync status for
                    # each subcloud.
                    self.audit_rpc_client.trigger_patch_audit(self.context)
                    return
                elif sw_update_strategy.stop_on_failure:
                    # We have been told to stop on failures
                    stop_after_stage = strategy_step.stage
                    current_stage = strategy_step.stage
                    break
                continue
            # We have found the first step that isn't complete or failed.
            # This is the stage we are working on now.
            current_stage = strategy_step.stage
            break
        else:
            # The strategy application is complete
            if failure_detected:
                LOG.info("Strategy application has failed.")
                with self.strategy_lock:
                    db_api.sw_update_strategy_update(
                        self.context, state=consts.SW_UPDATE_STATE_FAILED)
            elif abort_detected:
                LOG.info("Strategy application was aborted.")
                with self.strategy_lock:
                    db_api.sw_update_strategy_update(
                        self.context, state=consts.SW_UPDATE_STATE_ABORTED)
            else:
                LOG.info("Strategy application is complete.")
                with self.strategy_lock:
                    db_api.sw_update_strategy_update(
                        self.context, state=consts.SW_UPDATE_STATE_COMPLETE)
            # Trigger patch audit to update the sync status for each subcloud.
            self.audit_rpc_client.trigger_patch_audit(self.context)
            return

        if stop_after_stage is not None:
            work_remaining = False
            # We are going to stop after the steps in this stage have finished.
            for strategy_step in strategy_steps:
                if strategy_step.stage == stop_after_stage:
                    if strategy_step.state != consts.STRATEGY_STATE_COMPLETE \
                            and strategy_step.state != \
                            consts.STRATEGY_STATE_FAILED:
                        # There is more work to do in this stage
                        work_remaining = True
                        break

            if not work_remaining:
                # We have completed the stage that failed
                LOG.info("Stopping strategy due to failure in stage %d" %
                         stop_after_stage)
                with self.strategy_lock:
                    db_api.sw_update_strategy_update(
                        self.context, state=consts.SW_UPDATE_STATE_FAILED)
                # Trigger patch audit to update the sync status for each
                # subcloud.
                self.audit_rpc_client.trigger_patch_audit(self.context)
                return

        LOG.debug("Working on stage %d" % current_stage)
        for strategy_step in strategy_steps:
            if strategy_step.stage == current_stage:
                region = self.get_region_name(strategy_step)

                if strategy_step.state == \
                        consts.STRATEGY_STATE_INITIAL:

                    # Retrieve the list of patches from RegionOne once. This list
                    # will be referenced when the subcloud patch strategy is executed.
                    if strategy_step.subcloud_id is None:
                        self.get_region_one_patches()

                    # Don't start patching this subcloud if it has been
                    # unmanaged by the user. If orchestration was already
                    # started, it will be allowed to complete.
                    if strategy_step.subcloud_id is not None and \
                            strategy_step.subcloud.management_state == \
                            consts.MANAGEMENT_UNMANAGED:
                        message = ("Subcloud %s is unmanaged." %
                                   strategy_step.subcloud.name)
                        LOG.warn(message)
                        self.strategy_step_update(
                            strategy_step.subcloud_id,
                            state=consts.STRATEGY_STATE_FAILED,
                            details=message)
                        continue

                    # We are just getting started, enter the first state
                    self.strategy_step_update(
                        strategy_step.subcloud_id,
                        state=consts.STRATEGY_STATE_UPDATING_PATCHES)
                    if region in self.subcloud_workers:
                        # A worker already exists. Let it finish whatever it
                        # was doing.
                        LOG.error("Worker should not exist for %s." % region)
                    else:
                        # Create a greenthread to do the update patches
                        self.subcloud_workers[region] = \
                            self.thread_group_manager.start(
                                self.update_subcloud_patches,
                                strategy_step)
                elif strategy_step.state == \
                        consts.STRATEGY_STATE_UPDATING_PATCHES:
                    if region in self.subcloud_workers:
                        # The update is in progress
                        LOG.debug("Update worker exists for %s." % region)
                    else:
                        # Create a greenthread to do the update patches
                        self.subcloud_workers[region] = \
                            self.thread_group_manager.start(
                                self.update_subcloud_patches,
                                strategy_step)
                elif strategy_step.state == \
                        consts.STRATEGY_STATE_CREATING_STRATEGY:
                    if region in self.subcloud_workers:
                        # The create is in progress
                        LOG.debug("Create strategy worker exists for %s." %
                                  region)
                    else:
                        # Create a greenthread to do the create strategy
                        self.subcloud_workers[region] = \
                            self.thread_group_manager.start(
                                self.create_subcloud_strategy,
                                strategy_step)
                elif strategy_step.state == \
                        consts.STRATEGY_STATE_APPLYING_STRATEGY:
                    if region in self.subcloud_workers:
                        # The apply is in progress
                        LOG.debug("Apply strategy worker exists for %s." %
                                  region)
                    else:
                        # Create a greenthread to do the apply strategy
                        self.subcloud_workers[region] = \
                            self.thread_group_manager.start(
                                self.apply_subcloud_strategy,
                                strategy_step)
                elif strategy_step.state == \
                        consts.STRATEGY_STATE_FINISHING:
                    if region in self.subcloud_workers:
                        # The finish is in progress
                        LOG.debug("Finish worker exists for %s." % region)
                    else:
                        # Create a greenthread to do the finish
                        self.subcloud_workers[region] = \
                            self.thread_group_manager.start(
                                self.finish,
                                strategy_step)

                if self.stopped():
                    LOG.info("Exiting because task is stopped")
                    return

    def update_subcloud_patches(self, strategy_step):
        """Upload/Apply/Remove patches in this subcloud

        Removes the worker reference after the operation is complete.
        """

        try:
            self.do_update_subcloud_patches(strategy_step)
        except Exception as e:
            LOG.exception(e)
        finally:
            # The worker is done.
            region = self.get_region_name(strategy_step)
            if region in self.subcloud_workers:
                del self.subcloud_workers[region]

    def do_update_subcloud_patches(self, strategy_step):
        """Upload/Apply/Remove patches in this subcloud"""

        if strategy_step.subcloud_id is None:
            # This is the SystemController. It is the master so no update
            # is necessary.
            LOG.info("Skipping update patches for SystemController")
            self.strategy_step_update(
                strategy_step.subcloud_id,
                state=consts.STRATEGY_STATE_CREATING_STRATEGY)
            return

        LOG.info("Updating patches for subcloud %s" %
                 strategy_step.subcloud.name)

        # Retrieve all the patches that are present in this subcloud.
        try:
            subcloud_patches = self.get_patching_client(
                strategy_step.subcloud.name).query()
            LOG.debug("Patches for subcloud %s: %s" %
                      (strategy_step.subcloud.name, subcloud_patches))
        except Exception:
            message = ('Cannot retrieve patches for subcloud: %s' %
                       strategy_step.subcloud.name)
            LOG.warn(message)
            self.strategy_step_update(
                strategy_step.subcloud_id,
                state=consts.STRATEGY_STATE_FAILED,
                details=message)
            return

        # Determine which loads are present in this subcloud. During an
        # upgrade, there will be more than one load installed.
        try:
            loads = self.get_sysinv_client(
                strategy_step.subcloud.name).get_loads()
        except Exception:
            message = ('Cannot retrieve loads for subcloud: %s' %
                       strategy_step.subcloud.name)
            LOG.warn(message)
            self.strategy_step_update(
                strategy_step.subcloud_id,
                state=consts.STRATEGY_STATE_FAILED,
                details=message)
            return
        installed_loads = utils.get_loads_for_patching(loads)

        patches_to_upload = list()
        patches_to_apply = list()
        patches_to_remove = list()

        # Figure out which patches in this subcloud need to be applied and
        # removed to match the applied patches in RegionOne. Check the
        # repostate, which indicates whether it is applied or removed in
        # the repo.
        subcloud_patch_ids = list(subcloud_patches.keys())
        for patch_id in subcloud_patch_ids:
            if subcloud_patches[patch_id]['repostate'] == \
                    patching_v1.PATCH_STATE_APPLIED:
                if patch_id not in self.regionone_applied_patch_ids:
                    LOG.info("Patch %s will be removed from subcloud %s" %
                             (patch_id, strategy_step.subcloud.name))
                    patches_to_remove.append(patch_id)
            elif subcloud_patches[patch_id]['repostate'] == \
                    patching_v1.PATCH_STATE_COMMITTED:
                if patch_id not in self.regionone_applied_patch_ids:
                    message = ("Patch %s is committed in subcloud %s but "
                               "not applied in SystemController" %
                               (patch_id, strategy_step.subcloud.name))
                    LOG.warn(message)
                    self.strategy_step_update(
                        strategy_step.subcloud_id,
                        state=consts.STRATEGY_STATE_FAILED,
                        details=message)
                    return
            elif subcloud_patches[patch_id]['repostate'] == \
                    patching_v1.PATCH_STATE_AVAILABLE:
                if patch_id in self.regionone_applied_patch_ids:
                    LOG.info("Patch %s will be applied to subcloud %s" %
                             (patch_id, strategy_step.subcloud.name))
                    patches_to_apply.append(patch_id)
            else:
                # This patch is in an invalid state
                message = ('Patch %s in subcloud %s in unexpected state %s' %
                           (patch_id, strategy_step.subcloud.name,
                            subcloud_patches[patch_id]['repostate']))
                LOG.warn(message)
                self.strategy_step_update(
                    strategy_step.subcloud_id,
                    state=consts.STRATEGY_STATE_FAILED,
                    details=message)
                return

        # Check that all applied patches in RegionOne are present in the
        # subcloud.
        for patch_id in self.regionone_applied_patch_ids:
            if self.regionone_patches[patch_id]['sw_version'] in \
                    installed_loads and patch_id not in subcloud_patch_ids:
                LOG.info("Patch %s missing from %s" %
                         (patch_id, strategy_step.subcloud.name))
                patches_to_upload.append(patch_id)
                patches_to_apply.append(patch_id)

        if patches_to_remove:
            LOG.info("Removing patches %s from subcloud %s" %
                     (patches_to_remove, strategy_step.subcloud.name))
            try:
                self.get_patching_client(
                    strategy_step.subcloud.name).remove(patches_to_remove)
            except Exception:
                message = ('Failed to remove patches %s from subcloud %s' %
                           (patches_to_remove, strategy_step.subcloud.name))
                LOG.warn(message)
                self.strategy_step_update(
                    strategy_step.subcloud_id,
                    state=consts.STRATEGY_STATE_FAILED,
                    details=message)
                return

        if patches_to_upload:
            LOG.info("Uploading patches %s to subcloud %s" %
                     (patches_to_upload, strategy_step.subcloud.name))
            for patch in patches_to_upload:
                patch_sw_version = self.regionone_patches[patch]['sw_version']
                patch_file = "%s/%s/%s.patch" % (consts.PATCH_VAULT_DIR,
                                                 patch_sw_version,
                                                 patch)
                if not os.path.isfile(patch_file):
                    message = ('Patch file %s is missing' % patch_file)
                    LOG.error(message)
                    self.strategy_step_update(
                        strategy_step.subcloud_id,
                        state=consts.STRATEGY_STATE_FAILED,
                        details=message)
                    return

                try:
                    self.get_patching_client(
                        strategy_step.subcloud.name).upload([patch_file])
                except Exception:
                    message = ('Failed to upload patch file %s to subcloud %s'
                               % (patch_file, strategy_step.subcloud.name))
                    LOG.warn(message)
                    self.strategy_step_update(
                        strategy_step.subcloud_id,
                        state=consts.STRATEGY_STATE_FAILED,
                        details=message)
                    return

                if self.stopped():
                    LOG.info("Exiting because task is stopped")
                    return

        if patches_to_apply:
            LOG.info("Applying patches %s to subcloud %s" %
                     (patches_to_apply, strategy_step.subcloud.name))
            try:
                self.get_patching_client(
                    strategy_step.subcloud.name).apply(patches_to_apply)
            except Exception:
                message = ("Failed to apply patches %s to subcloud %s" %
                           (patches_to_apply, strategy_step.subcloud.name))
                LOG.warn(message)
                self.strategy_step_update(
                    strategy_step.subcloud_id,
                    state=consts.STRATEGY_STATE_FAILED,
                    details=message)
                return

        # Now that we have applied/removed/uploaded patches, we need to give
        # the patch controller on this subcloud time to determine whether
        # each host on that subcloud is patch current.
        wait_count = 0
        while True:
            try:
                subcloud_hosts = self.get_patching_client(
                    strategy_step.subcloud.name).query_hosts()
            except Exception:
                message = ("Failed to query patch status of hosts on "
                           "subcloud %s" % strategy_step.subcloud.name)
                LOG.warn(message)
                self.strategy_step_update(
                    strategy_step.subcloud_id,
                    state=consts.STRATEGY_STATE_FAILED,
                    details=message)
                return

            LOG.debug("query_hosts for subcloud %s: %s" %
                      (strategy_step.subcloud.name, subcloud_hosts))
            for host in subcloud_hosts:
                if host['interim_state']:
                    # This host is not yet ready.
                    LOG.debug("Host %s in subcloud %s in interim state" %
                              (host["hostname"], strategy_step.subcloud.name))
                    break
            else:
                # All hosts in the subcloud are updated
                break
            wait_count += 1
            if wait_count >= 6:
                # We have waited at least 60 seconds. This is too long. We
                # will just log it and move on without failing the step.
                message = ("Too much time expired after applying patches to "
                           "subcloud %s - continuing." %
                           strategy_step.subcloud.name)
                LOG.warn(message)
                break

            if self.stopped():
                LOG.info("Exiting because task is stopped")
                return

            # Wait 10 seconds before doing another query.
            time.sleep(10)

        # Move on to the next state
        self.strategy_step_update(
            strategy_step.subcloud_id,
            state=consts.STRATEGY_STATE_CREATING_STRATEGY)

    def create_subcloud_strategy(self, strategy_step):
        """Create the patch strategy in this subcloud

        Removes the worker reference after the operation is complete.
        """

        try:
            self.do_create_subcloud_strategy(strategy_step)
        except Exception as e:
            LOG.exception(e)
        finally:
            # The worker is done.
            region = self.get_region_name(strategy_step)
            if region in self.subcloud_workers:
                del self.subcloud_workers[region]

    def do_create_subcloud_strategy(self, strategy_step):
        """Create the patch strategy in this subcloud"""

        region = self.get_region_name(strategy_step)

        LOG.info("Creating patch strategy for %s" % region)

        # First check if the strategy has been created.
        try:
            subcloud_strategy = self.get_vim_client(region).get_strategy(
                strategy_name=vim.STRATEGY_NAME_SW_PATCH)
        except (keystone_exceptions.EndpointNotFound, IndexError):
            message = ("Endpoint for subcloud: %s not found." %
                       region)
            LOG.error(message)
            self.strategy_step_update(
                strategy_step.subcloud_id,
                state=consts.STRATEGY_STATE_FAILED,
                details=message)
            return
        except Exception:
            # Strategy doesn't exist yet
            subcloud_strategy = None

        if subcloud_strategy is not None:
            # if a strategy exists, it should be deleted and a new one created
            LOG.info("Patch VIM strategy for: %s already exists with state: %s"
                     % (region, subcloud_strategy.state))
            # A VIM strategy in building/applying/aborting can not be deleted.
            # Set as FAILED if we encounter a strategy in one of those states.
            if subcloud_strategy.state in [vim.STATE_BUILDING,
                                           vim.STATE_APPLYING,
                                           vim.STATE_ABORTING]:
                # Can't delete a strategy in these states
                message = ("Failed to create a VIM strategy for %s. "
                           "There already is an existing strategy in %s state"
                           % (region, subcloud_strategy.state))
                LOG.warn(message)
                self.strategy_step_update(strategy_step.subcloud_id,
                                          state=consts.STRATEGY_STATE_FAILED,
                                          details=message)
                return
            else:
                try:
                    self.get_vim_client(region).delete_strategy(
                        strategy_name=vim.STRATEGY_NAME_SW_PATCH)
                    # If we get here, the delete worked, so set it to None
                    subcloud_strategy = None
                except Exception:
                    # we were unable to delete (and set to None) the strategy
                    message = ("Strategy delete for %s failed" % region)
                    LOG.warn(message)
                    self.strategy_step_update(
                        strategy_step.subcloud_id,
                        state=consts.STRATEGY_STATE_FAILED,
                        details=message)
                    return

        if subcloud_strategy is None:
            # Check whether any patch orchestration is actually required. We
            # always create a step for the SystemController and it may have
            # been done (e.g. in a previous attempt). Also, if we are just
            # committing patches, patch orchestration is not required.
            orch_required = False
            try:
                cloud_hosts = self.get_patching_client(region).query_hosts()
            except Exception:
                message = ("Failed to query patch status of hosts on %s" %
                           region)
                LOG.warn(message)
                self.strategy_step_update(
                    strategy_step.subcloud_id,
                    state=consts.STRATEGY_STATE_FAILED,
                    details=message)
                return

            LOG.debug("query_hosts for %s: %s" % (region, cloud_hosts))
            for host in cloud_hosts:
                if not host['patch_current']:
                    LOG.debug("Host %s in %s is not patch current" %
                              (host["hostname"], region))
                    orch_required = True
                    break

            if not orch_required:
                self.strategy_step_update(
                    strategy_step.subcloud_id,
                    state=consts.STRATEGY_STATE_FINISHING,
                    details="")
                return

            # Retrieve sw update options.  For the controller, the default
            # options will be used, as subcloud_id will be None

            opts_dict = \
                utils.get_sw_update_opts(self.context,
                                         for_sw_update=True,
                                         subcloud_id=strategy_step.subcloud_id)

            # If we are here, we need to create the strategy
            try:
                subcloud_strategy = self.get_vim_client(region).create_strategy(
                    strategy_name=vim.STRATEGY_NAME_SW_PATCH,
                    storage_apply_type=opts_dict['storage-apply-type'],
                    worker_apply_type=opts_dict['worker-apply-type'],
                    max_parallel_worker_hosts=opts_dict[
                        'max-parallel-workers'],
                    default_instance_action=opts_dict[
                        'default-instance-action'],
                    alarm_restrictions=opts_dict['alarm-restriction-type'])
            except Exception:
                message = "Strategy creation failed for %s" % region
                LOG.warn(message)
                self.strategy_step_update(strategy_step.subcloud_id,
                                          state=consts.STRATEGY_STATE_FAILED,
                                          details=message)
                return

            if subcloud_strategy.state == vim.STATE_BUILDING:
                LOG.info("Strategy build in progress for %s" % region)
            else:
                message = ("Strategy build failed - unexpected strategy state "
                           "%s for %s" %
                           (subcloud_strategy.state, region))
                LOG.warn(message)
                self.strategy_step_update(strategy_step.subcloud_id,
                                          state=consts.STRATEGY_STATE_FAILED,
                                          details=message)
                return

        # Wait for the strategy to be built.
        WAIT_INTERVAL = 10
        WAIT_LIMIT = 2 * 60  # 2 minutes
        wait_count = 0
        while True:
            try:
                subcloud_strategy = self.get_vim_client(region).get_strategy(
                    strategy_name=vim.STRATEGY_NAME_SW_PATCH)
            except Exception:
                message = ("Failed to get patch strategy for %s" % region)
                LOG.warn(message)
                self.strategy_step_update(
                    strategy_step.subcloud_id,
                    state=consts.STRATEGY_STATE_FAILED,
                    details=message)
                return

            if subcloud_strategy.state == vim.STATE_READY_TO_APPLY:
                # Move on to the next state
                self.strategy_step_update(
                    strategy_step.subcloud_id,
                    state=consts.STRATEGY_STATE_APPLYING_STRATEGY)
                return
            elif subcloud_strategy.state == vim.STATE_BUILDING:
                # Strategy is being built
                LOG.debug("Strategy build in progress for %s" % region)
            elif subcloud_strategy.state in [vim.STATE_BUILD_FAILED,
                                             vim.STATE_BUILD_TIMEOUT]:
                # Build failed
                message = "Strategy build failed for %s - %s" % \
                          (region, subcloud_strategy.build_phase.reason)
                LOG.warn(message)
                self.strategy_step_update(strategy_step.subcloud_id,
                                          state=consts.STRATEGY_STATE_FAILED,
                                          details=message)
                return
            else:
                # Other states are bad
                message = "Strategy build failed for %s - unexpected " \
                          "state %s" % (region, subcloud_strategy.state)
                LOG.warn(message)
                self.strategy_step_update(strategy_step.subcloud_id,
                                          state=consts.STRATEGY_STATE_FAILED,
                                          details=message)
                return

            wait_count += 1
            if wait_count >= (WAIT_LIMIT // WAIT_INTERVAL):
                # We have waited too long.
                message = ("Too much time expired after creating strategy for "
                           "%s." % region)
                LOG.warn(message)
                self.strategy_step_update(strategy_step.subcloud_id,
                                          state=consts.STRATEGY_STATE_FAILED,
                                          details=message)
                return

            if self.stopped():
                LOG.info("Exiting because task is stopped")
                return

            # Wait before doing another query.
            time.sleep(WAIT_INTERVAL)

    def apply_subcloud_strategy(self, strategy_step):
        """Apply the patch strategy in this subcloud

        Removes the worker reference after the operation is complete.
        """

        try:
            self.do_apply_subcloud_strategy(strategy_step)
        except Exception as e:
            LOG.exception(e)
        finally:
            # The worker is done.
            region = self.get_region_name(strategy_step)
            if region in self.subcloud_workers:
                del self.subcloud_workers[region]

    def do_apply_subcloud_strategy(self, strategy_step):
        """Apply the patch strategy in this subcloud"""

        region = self.get_region_name(strategy_step)

        LOG.info("Applying patch strategy for %s" % region)

        # First check if the strategy has been created.
        try:
            subcloud_strategy = self.get_vim_client(region).get_strategy(
                strategy_name=vim.STRATEGY_NAME_SW_PATCH)
        except Exception:
            # Strategy doesn't exist
            message = "Strategy does not exist for %s" % region
            LOG.warn(message)
            raise

        if subcloud_strategy.state == vim.STATE_READY_TO_APPLY:
            try:
                subcloud_strategy = self.get_vim_client(region).apply_strategy(
                    strategy_name=vim.STRATEGY_NAME_SW_PATCH)
            except Exception:
                message = "Strategy apply failed for %s" % region
                LOG.warn(message)
                self.strategy_step_update(strategy_step.subcloud_id,
                                          state=consts.STRATEGY_STATE_FAILED,
                                          details=message)
                return

            if subcloud_strategy.state == vim.STATE_APPLYING:
                LOG.info("Strategy apply in progress for %s" % region)
            else:
                message = ("Strategy apply failed - unexpected strategy state "
                           "%s for %s" %
                           (subcloud_strategy.state, region))
                LOG.warn(message)
                self.strategy_step_update(strategy_step.subcloud_id,
                                          state=consts.STRATEGY_STATE_FAILED,
                                          details=message)
                return

        # Wait for the strategy to be applied. This could potentially take
        # hours. We will wait up to 60 minutes for the current phase or
        # completion percentage to change before we give up.
        WAIT_INTERVAL = 60
        WAIT_LIMIT = 60 * 60  # 60 minutes
        GET_FAIL_LIMIT = 30 * 60  # 30 minutes
        wait_count = 0
        get_fail_count = 0
        last_details = ""
        while True:
            try:
                subcloud_strategy = self.get_vim_client(region).get_strategy(
                    strategy_name=vim.STRATEGY_NAME_SW_PATCH)
                get_fail_count = 0
            except Exception as e:
                # When applying the strategy to a subcloud, the VIM can
                # be unreachable for a significant period of time when
                # there is a controller swact, or in the case of AIO-SX,
                # when the controller reboots.
                get_fail_count += 1
                wait_count += 1
                if get_fail_count >= (GET_FAIL_LIMIT // WAIT_INTERVAL):
                    # We have waited too long.
                    message = ("Failed to get patch strategy for %s" %
                               region)
                    LOG.warn(message)
                    self.strategy_step_update(
                        strategy_step.subcloud_id,
                        state=consts.STRATEGY_STATE_FAILED,
                        details=message)
                    return
                else:
                    LOG.info("Unable to get patch strategy for %s - "
                             "attempt %d - reason: %s" %
                             (region, get_fail_count, e))

                if self.stopped():
                    LOG.info("Exiting because task is stopped")
                    return

                # Wait before doing another query.
                time.sleep(WAIT_INTERVAL)

            if subcloud_strategy.state == vim.STATE_APPLIED:
                # Move on to the next state
                self.strategy_step_update(
                    strategy_step.subcloud_id,
                    state=consts.STRATEGY_STATE_FINISHING,
                    details="")
                return
            elif subcloud_strategy.state == vim.STATE_APPLYING:
                # Still applying. Update the details for this step if they have
                # changed.
                new_details = ("%s phase is %s%% complete" % (
                    subcloud_strategy.current_phase,
                    subcloud_strategy.current_phase_completion_percentage))
                if new_details != last_details:
                    # Progress is being made
                    wait_count = 0
                    self.strategy_step_update(
                        strategy_step.subcloud_id,
                        details=new_details)
            elif subcloud_strategy.state in [vim.STATE_APPLY_FAILED,
                                             vim.STATE_APPLY_TIMEOUT]:
                # Apply failed
                message = "Strategy apply failed for %s - %s" % \
                          (region, subcloud_strategy.apply_phase.reason)
                LOG.warn(message)
                self.strategy_step_update(strategy_step.subcloud_id,
                                          state=consts.STRATEGY_STATE_FAILED,
                                          details=message)
                return
            else:
                # Other states are bad
                message = "Strategy apply failed for %s - unexpected " \
                          "state %s" % (region, subcloud_strategy.state)
                LOG.warn(message)
                self.strategy_step_update(strategy_step.subcloud_id,
                                          state=consts.STRATEGY_STATE_FAILED,
                                          details=message)
                return

            wait_count += 1
            if wait_count >= (WAIT_LIMIT // WAIT_INTERVAL):
                # We have waited too long.
                message = ("Too much time expired while applying strategy for "
                           "%s." % region)
                LOG.warn(message)
                self.strategy_step_update(strategy_step.subcloud_id,
                                          state=consts.STRATEGY_STATE_FAILED,
                                          details=message)
                return

            if self.stopped():
                LOG.info("Exiting because task is stopped")
                return

            # Wait before doing another query.
            time.sleep(WAIT_INTERVAL)

    def delete_subcloud_strategy(self, strategy_step):
        """Delete the patch strategy in this subcloud

        Removes the worker reference after the operation is complete.
        """

        try:
            self.do_delete_subcloud_strategy(strategy_step)
        except Exception as e:
            LOG.exception(e)
        finally:
            # The worker is done.
            region = self.get_region_name(strategy_step)
            if region in self.subcloud_workers:
                del self.subcloud_workers[region]

    def do_delete_subcloud_strategy(self, strategy_step):
        """Delete the patch strategy in this subcloud"""

        region = self.get_region_name(strategy_step)

        LOG.info("Deleting patch strategy for %s" % region)

        # First check if the strategy has been created.
        try:
            subcloud_strategy = self.get_vim_client(region).get_strategy(
                strategy_name=vim.STRATEGY_NAME_SW_PATCH)
        except (keystone_exceptions.EndpointNotFound, IndexError):
            message = ("Endpoint for subcloud: %s not found." %
                       region)
            LOG.warn(message)
            return
        except Exception:
            # Strategy doesn't exist so there is nothing to do
            return

        if subcloud_strategy.state in [vim.STATE_BUILDING,
                                       vim.STATE_APPLYING,
                                       vim.STATE_ABORTING]:
            # Can't delete a strategy in these states
            message = ("Strategy for %s in wrong state (%s)for delete" %
                       (region, subcloud_strategy.state))
            LOG.warn(message)
            return

        # If we are here, we need to delete the strategy
        try:
            self.get_vim_client(region).delete_strategy(
                strategy_name=vim.STRATEGY_NAME_SW_PATCH)
        except Exception:
            message = "Strategy delete failed for %s" % region
            LOG.warn(message)
            return

    def finish(self, strategy_step):
        """Clean up patches in this subcloud (commit, delete)

        Removes the worker reference after the operation is complete.
        """

        try:
            self.do_finish(strategy_step)
        except Exception as e:
            LOG.exception(e)
        finally:
            # The worker is done.
            region = self.get_region_name(strategy_step)
            if region in self.subcloud_workers:
                del self.subcloud_workers[region]

    def do_finish(self, strategy_step):
        """Clean up patches in this subcloud (commit, delete)."""

        if strategy_step.subcloud_id is None:
            # This is the SystemController. No cleanup is required.
            LOG.info("Skipping finish for SystemController")
            self.strategy_step_update(
                strategy_step.subcloud_id,
                state=consts.STRATEGY_STATE_COMPLETE)
            return

        LOG.info("Finishing patch strategy for %s" %
                 strategy_step.subcloud.name)

        try:
            subcloud_patches = self.get_patching_client(
                strategy_step.subcloud.name).query()
            LOG.debug("Patches for subcloud %s: %s" %
                      (strategy_step.subcloud.name, subcloud_patches))
        except Exception:
            message = ('Cannot retrieve patches for subcloud: %s' %
                       strategy_step.subcloud.name)
            LOG.warn(message)
            self.strategy_step_update(
                strategy_step.subcloud_id,
                state=consts.STRATEGY_STATE_FAILED,
                details=message)
            return

        patches_to_commit = list()
        patches_to_delete = list()

        # For this subcloud, determine which patches should be committed and
        # which should be deleted. We check the patchstate here because
        # patches cannot be deleted or committed if they are in a partial
        # state (e.g. Partial-Apply or Partial-Remove).
        subcloud_patch_ids = list(subcloud_patches.keys())
        for patch_id in subcloud_patch_ids:
            if subcloud_patches[patch_id]['patchstate'] == \
                    patching_v1.PATCH_STATE_AVAILABLE:
                LOG.info("Patch %s will be deleted from subcloud %s" %
                         (patch_id, strategy_step.subcloud.name))
                patches_to_delete.append(patch_id)
            elif subcloud_patches[patch_id]['patchstate'] == \
                    patching_v1.PATCH_STATE_APPLIED:
                if patch_id in self.regionone_committed_patch_ids:
                    LOG.info("Patch %s will be committed in subcloud %s" %
                             (patch_id, strategy_step.subcloud.name))
                    patches_to_commit.append(patch_id)

        if patches_to_delete:
            LOG.info("Deleting patches %s from subcloud %s" %
                     (patches_to_delete, strategy_step.subcloud.name))
            try:
                self.get_patching_client(
                    strategy_step.subcloud.name).delete(patches_to_delete)
            except Exception:
                message = ('Failed to delete patches %s from subcloud %s' %
                           (patches_to_delete, strategy_step.subcloud.name))
                LOG.warn(message)
                self.strategy_step_update(
                    strategy_step.subcloud_id,
                    state=consts.STRATEGY_STATE_FAILED,
                    details=message)
                return

        if self.stopped():
            LOG.info("Exiting because task is stopped")
            return

        if patches_to_commit:
            LOG.info("Committing patches %s in subcloud %s" %
                     (patches_to_commit, strategy_step.subcloud.name))
            try:
                self.get_patching_client(
                    strategy_step.subcloud.name).commit(patches_to_commit)
            except Exception:
                message = ('Failed to commit patches %s in subcloud %s' %
                           (patches_to_commit, strategy_step.subcloud.name))
                LOG.warn(message)
                self.strategy_step_update(
                    strategy_step.subcloud_id,
                    state=consts.STRATEGY_STATE_FAILED,
                    details=message)
                return

        # We are done.
        self.strategy_step_update(
            strategy_step.subcloud_id,
            state=consts.STRATEGY_STATE_COMPLETE)

    def abort(self, sw_update_strategy):
        """Abort a patch strategy"""

        LOG.info("Aborting patch strategy")

        # Mark any steps that have not yet started as aborted,
        # so we will not run them later.
        strategy_steps = db_api.strategy_step_get_all(self.context)

        for strategy_step in strategy_steps:
            if strategy_step.state == consts.STRATEGY_STATE_INITIAL:
                LOG.info("Aborting step for subcloud %s" %
                         self.get_region_name(strategy_step))
                self.strategy_step_update(
                    strategy_step.subcloud_id,
                    state=consts.STRATEGY_STATE_ABORTED,
                    details="")

        with self.strategy_lock:
            db_api.sw_update_strategy_update(
                self.context, state=consts.SW_UPDATE_STATE_ABORTING)

    def delete(self, sw_update_strategy):
        """Delete a patch strategy"""

        LOG.info("Deleting patch strategy")

        strategy_steps = db_api.strategy_step_get_all(self.context)

        for strategy_step in strategy_steps:
            region = self.get_region_name(strategy_step)
            if region in self.subcloud_workers:
                # A worker already exists. Let it finish whatever it
                # was doing.
                LOG.debug("Worker already exists for %s." % region)
            else:
                # Create a greenthread to delete the subcloud strategy
                self.subcloud_workers[region] = \
                    self.thread_group_manager.start(
                        self.delete_subcloud_strategy,
                        strategy_step)

            if self.stopped():
                LOG.info("Exiting because task is stopped")
                return

        # Wait for 180 seconds so that last 100 workers can
        # complete their execution
        counter = 0
        while len(self.subcloud_workers) > 0:
            time.sleep(10)
            counter = counter + 1
            if counter > 18:
                break

        # Remove the strategy from the database if all workers
        # have completed their execution
        try:
            db_api.strategy_step_destroy_all(self.context)
            db_api.sw_update_strategy_destroy(self.context)
        except Exception as e:
            LOG.exception(e)
            raise e
