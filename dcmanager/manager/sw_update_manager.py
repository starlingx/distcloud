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
# Copyright (c) 2017 Wind River Systems, Inc.
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

from dcorch.common import consts as dcorch_consts
from dcorch.drivers.openstack.keystone_v3 import KeystoneClient

from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common import exceptions
from dcmanager.common.i18n import _
from dcmanager.common import manager
from dcmanager.common import utils
from dcmanager.db import api as db_api
from dcmanager.drivers.openstack import patching_v1
from dcmanager.drivers.openstack.patching_v1 import PatchingClient
from dcmanager.drivers.openstack.sysinv_v1 import SysinvClient
from dcmanager.drivers.openstack import vim
from dcmanager.manager.patch_audit_manager import PatchAuditManager
from dcmanager.manager import scheduler


LOG = logging.getLogger(__name__)


class SwUpdateManager(manager.Manager):
    """Manages tasks related to software updates."""

    def __init__(self, *args, **kwargs):
        LOG.debug(_('SwUpdateManager initialization...'))

        super(SwUpdateManager, self).__init__(service_name="sw_update_manager",
                                              *args, **kwargs)
        # Start a new thread that will do all the patch orchestration work
        self.patch_orch_thread = PatchOrchThread()
        self.patch_orch_thread.start()

    def stop(self):
        self.patch_orch_thread.stop()
        self.patch_orch_thread.join()

    def create_sw_update_strategy(self, context, payload):
        """Create software update strategy.

        :param context: request context object
        :param payload: strategy configuration
        """
        LOG.info("Creating software update strategy of type %s." %
                 payload['type'])

        # Don't create a strategy if one already exists.
        try:
            db_api.sw_update_strategy_get(context)
        except exceptions.NotFound:
            pass
        else:
            raise exceptions.BadRequest(
                resource='strategy',
                msg='Strategy already exists')

        strategy_type = payload.get('type')
        subcloud_apply_type = payload.get('subcloud-apply-type')
        if not subcloud_apply_type:
            subcloud_apply_type = consts.SUBCLOUD_APPLY_TYPE_PARALLEL

        max_parallel_subclouds_str = payload.get('max-parallel-subclouds')
        if not max_parallel_subclouds_str:
            # Default will be 20 subclouds in parallel
            max_parallel_subclouds = 20
        else:
            max_parallel_subclouds = int(max_parallel_subclouds_str)

        stop_on_failure_str = payload.get('stop-on-failure')
        if not stop_on_failure_str:
            stop_on_failure = False
        else:
            if stop_on_failure_str in ['true']:
                stop_on_failure = True
            else:
                stop_on_failure = False

        # Has the user specified a specific subcloud?
        cloud_name = payload.get('cloud_name')
        if cloud_name and cloud_name != consts.SYSTEM_CONTROLLER_NAME:
            # Make sure subcloud exists
            try:
                subcloud = db_api.subcloud_get_by_name(context, cloud_name)
            except exceptions.SubcloudNameNotFound:
                raise exceptions.BadRequest(
                    resource='strategy',
                    msg='Subcloud %s does not exist' % cloud_name)

            # Make sure subcloud requires patching
            subcloud_status = db_api.subcloud_status_get(
                context, subcloud.id, dcorch_consts.ENDPOINT_TYPE_PATCHING)
            if subcloud_status.sync_status == consts.SYNC_STATUS_IN_SYNC:
                raise exceptions.BadRequest(
                    resource='strategy',
                    msg='Subcloud %s does not require patching' % cloud_name)

        # Don't create a strategy if the patching sync status is unknown for
        # any subcloud we will be patching that is managed and online.
        subclouds = db_api.subcloud_get_all_with_status(context)
        for subcloud, subcloud_status in subclouds:
            if cloud_name and subcloud.name != cloud_name:
                # We are not patching this subcloud
                continue
            if (subcloud.management_state != consts.MANAGEMENT_MANAGED or
                    subcloud.availability_status !=
                    consts.AVAILABILITY_ONLINE):
                continue

            if (subcloud_status.endpoint_type ==
                    dcorch_consts.ENDPOINT_TYPE_PATCHING and
                    subcloud_status.sync_status == consts.SYNC_STATUS_UNKNOWN):
                raise exceptions.BadRequest(
                    resource='strategy',
                    msg='Patching sync status is unknown for one or more '
                        'subclouds')

        # Create the strategy
        strategy = db_api.sw_update_strategy_create(
            context,
            strategy_type,
            subcloud_apply_type,
            max_parallel_subclouds,
            stop_on_failure,
            consts.SW_UPDATE_STATE_INITIAL)

        # Always create a strategy step for the system controller
        db_api.strategy_step_create(
            context,
            None,
            stage=1,
            state=consts.STRATEGY_STATE_INITIAL,
            details='')

        # Create a strategy step for each subcloud that is managed, online and
        # out of sync
        current_stage = 2
        stage_size = 0
        for subcloud, subcloud_status in subclouds:
            if cloud_name and subcloud.name != cloud_name:
                # We are not patching this subcloud
                continue
            if (subcloud.management_state != consts.MANAGEMENT_MANAGED or
                    subcloud.availability_status !=
                    consts.AVAILABILITY_ONLINE):
                continue
            if (subcloud_status.endpoint_type ==
                    dcorch_consts.ENDPOINT_TYPE_PATCHING and
                    subcloud_status.sync_status ==
                    consts.SYNC_STATUS_OUT_OF_SYNC):
                db_api.strategy_step_create(
                    context,
                    subcloud.id,
                    stage=current_stage,
                    state=consts.STRATEGY_STATE_INITIAL,
                    details='')

                # We have added a subcloud to this stage
                stage_size += 1
                if subcloud_apply_type == consts.SUBCLOUD_APPLY_TYPE_SERIAL:
                    # For serial apply type always move to next stage
                    current_stage += 1
                elif stage_size >= max_parallel_subclouds:
                    # For parallel apply type, move to next stage if we have
                    # reached the maximum subclouds for this stage
                    current_stage += 1
                    stage_size = 0

        strategy_dict = db_api.sw_update_strategy_db_model_to_dict(
            strategy)
        return strategy_dict

    def delete_sw_update_strategy(self, context):
        """Delete software update strategy.

        :param context: request context object.
        """
        LOG.info("Deleting software update strategy.")

        # Ensure our read/update of the strategy is done without interference
        with self.patch_orch_thread.strategy_lock:
            # Retrieve the existing strategy from the database
            sw_update_strategy = db_api.sw_update_strategy_get(context)

            # Semantic checking
            if sw_update_strategy.state not in [
                    consts.SW_UPDATE_STATE_INITIAL,
                    consts.SW_UPDATE_STATE_COMPLETE,
                    consts.SW_UPDATE_STATE_FAILED,
                    consts.SW_UPDATE_STATE_ABORTED]:
                raise exceptions.BadRequest(
                    resource='strategy',
                    msg='Strategy in state %s cannot be deleted' %
                        sw_update_strategy.state)

            # Set the state to deleting, which will trigger the orchestration
            # to delete it...
            sw_update_strategy = db_api.sw_update_strategy_update(
                context, state=consts.SW_UPDATE_STATE_DELETING)

        strategy_dict = db_api.sw_update_strategy_db_model_to_dict(
            sw_update_strategy)
        return strategy_dict

    def apply_sw_update_strategy(self, context):
        """Apply software update strategy.

        :param context: request context object.
        """
        LOG.info("Applying software update strategy.")

        # Ensure our read/update of the strategy is done without interference
        with self.patch_orch_thread.strategy_lock:
            # Retrieve the existing strategy from the database
            sw_update_strategy = db_api.sw_update_strategy_get(context)

            # Semantic checking
            if sw_update_strategy.state != consts.SW_UPDATE_STATE_INITIAL:
                raise exceptions.BadRequest(
                    resource='strategy',
                    msg='Strategy in state %s cannot be applied' %
                        sw_update_strategy.state)

            # Set the state to applying, which will trigger the orchestration
            # to begin...
            sw_update_strategy = db_api.sw_update_strategy_update(
                context, state=consts.SW_UPDATE_STATE_APPLYING)
        strategy_dict = db_api.sw_update_strategy_db_model_to_dict(
            sw_update_strategy)
        return strategy_dict

    def abort_sw_update_strategy(self, context):
        """Abort software update strategy.

        :param context: request context object.
        """
        LOG.info("Aborting software update strategy.")

        # Ensure our read/update of the strategy is done without interference
        with self.patch_orch_thread.strategy_lock:
            # Retrieve the existing strategy from the database
            sw_update_strategy = db_api.sw_update_strategy_get(context)

            # Semantic checking
            if sw_update_strategy.state != consts.SW_UPDATE_STATE_APPLYING:
                raise exceptions.BadRequest(
                    resource='strategy',
                    msg='Strategy in state %s cannot be aborted' %
                        sw_update_strategy.state)

            # Set the state to abort requested, which will trigger
            # the orchestration to abort...
            sw_update_strategy = db_api.sw_update_strategy_update(
                context, state=consts.SW_UPDATE_STATE_ABORT_REQUESTED)
        strategy_dict = db_api.sw_update_strategy_db_model_to_dict(
            sw_update_strategy)
        return strategy_dict


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

    def __init__(self):
        super(PatchOrchThread, self).__init__()
        self.context = context.get_admin_context()
        self._stop = threading.Event()
        # Used to protect strategy when an atomic read/update is required.
        self.strategy_lock = threading.Lock()
        # Keeps track of greenthreads we create to do work.
        self.thread_group_manager = scheduler.ThreadGroupManager()
        # Track worker created for each subcloud.
        self.subcloud_workers = dict()

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
    def get_ks_client(region_name=None):
        """This will get a new keystone client (and new token)"""
        try:
            return KeystoneClient(region_name)
        except Exception:
            LOG.warn('Failure initializing KeystoneClient')
            raise

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

    def patch_orch(self):
        while not self.stopped():
            try:
                LOG.debug('Running patch orchestration')

                sw_update_strategy = db_api.sw_update_strategy_get(
                    self.context)

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
                    PatchAuditManager.trigger_audit()
                    return
                elif sw_update_strategy.stop_on_failure:
                    # We have been told to stop on failures
                    stop_after_stage = strategy_step.stage
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
            PatchAuditManager.trigger_audit()
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
                PatchAuditManager.trigger_audit()
                return

        LOG.debug("Working on stage %d" % current_stage)
        for strategy_step in strategy_steps:
            if strategy_step.stage == current_stage:
                region = self.get_region_name(strategy_step)

                if strategy_step.state == \
                        consts.STRATEGY_STATE_INITIAL:
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

        ks_client = self.get_ks_client()

        # First query RegionOne to determine what patches should be applied.
        patching_client = PatchingClient(
            consts.DEFAULT_REGION_NAME, ks_client.session)
        regionone_patches = patching_client.query()
        LOG.debug("regionone_patches: %s" % regionone_patches)

        # Build lists of patches that should be applied in this subcloud,
        # based on their state in RegionOne. Check repostate (not patchstate)
        # as we only care if the patch has been applied to the repo (not
        # whether it is installed on the hosts). If we were to check the
        # patchstate, we could end up removing patches from this subcloud
        # just because a single host in RegionOne reported that it was not
        # patch current.
        applied_patch_ids = list()
        for patch_id in regionone_patches.keys():
            if regionone_patches[patch_id]['repostate'] in [
                    patching_v1.PATCH_STATE_APPLIED,
                    patching_v1.PATCH_STATE_COMMITTED]:
                applied_patch_ids.append(patch_id)
        LOG.debug("RegionOne applied_patch_ids: %s" % applied_patch_ids)

        # First need to retrieve the Subcloud's Keystone session
        try:
            sc_ks_client = self.get_ks_client(strategy_step.subcloud_name)
        except (keystone_exceptions.EndpointNotFound, IndexError) as e:
            message = ("Identity endpoint for subcloud: %s not found. %s" %
                       (strategy_step.subcloud.name, e))
            LOG.error(message)
            self.strategy_step_update(
                strategy_step.subcloud_id,
                state=consts.STRATEGY_STATE_FAILED,
                details=message)
            return

        try:
            patching_client = PatchingClient(
                strategy_step.subcloud.name, sc_ks_client.session)
        except keystone_exceptions.EndpointNotFound:
            message = ("Patching endpoint for subcloud: %s not found." %
                       strategy_step.subcloud.name)
            LOG.error(message)
            self.strategy_step_update(
                strategy_step.subcloud_id,
                state=consts.STRATEGY_STATE_FAILED,
                details=message)
            return

        try:
            sysinv_client = SysinvClient(strategy_step.subcloud.name,
                                         sc_ks_client.session)
        except keystone_exceptions.EndpointNotFound:
            message = ("Sysinv endpoint for subcloud: %s not found." %
                       strategy_step.subcloud.name)
            LOG.error(message)
            self.strategy_step_update(
                strategy_step.subcloud_id,
                state=consts.STRATEGY_STATE_FAILED,
                details=message)
            return

        # Retrieve all the patches that are present in this subcloud.
        try:
            subcloud_patches = patching_client.query()
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
        installed_loads = list()
        try:
            loads = sysinv_client.get_loads()
        except Exception:
            message = ('Cannot retrieve loads for subcloud: %s' %
                       strategy_step.subcloud.name)
            LOG.warn(message)
            self.strategy_step_update(
                strategy_step.subcloud_id,
                state=consts.STRATEGY_STATE_FAILED,
                details=message)
            return
        for load in loads:
            installed_loads.append(load.software_version)

        patches_to_upload = list()
        patches_to_apply = list()
        patches_to_remove = list()

        # Figure out which patches in this subcloud need to be applied and
        # removed to match the applied patches in RegionOne. Check the
        # repostate, which indicates whether it is applied or removed in
        # the repo.
        subcloud_patch_ids = subcloud_patches.keys()
        for patch_id in subcloud_patch_ids:
            if subcloud_patches[patch_id]['repostate'] == \
                    patching_v1.PATCH_STATE_APPLIED:
                if patch_id not in applied_patch_ids:
                    LOG.info("Patch %s will be removed from subcloud %s" %
                             (patch_id, strategy_step.subcloud.name))
                    patches_to_remove.append(patch_id)
            elif subcloud_patches[patch_id]['repostate'] == \
                    patching_v1.PATCH_STATE_COMMITTED:
                if patch_id not in applied_patch_ids:
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
                if patch_id in applied_patch_ids:
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
        for patch_id in applied_patch_ids:
            if regionone_patches[patch_id]['sw_version'] in \
                    installed_loads and patch_id not in subcloud_patch_ids:
                LOG.info("Patch %s missing from %s" %
                         (patch_id, strategy_step.subcloud.name))
                patches_to_upload.append(patch_id)
                patches_to_apply.append(patch_id)

        if patches_to_remove:
            LOG.info("Removing patches %s from subcloud %s" %
                     (patches_to_remove, strategy_step.subcloud.name))
            try:
                patching_client.remove(patches_to_remove)
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
                patch_sw_version = regionone_patches[patch]['sw_version']
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
                    patching_client.upload([patch_file])
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
                patching_client.apply(patches_to_apply)
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
                subcloud_hosts = patching_client.query_hosts()
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

        # TODO(knasim-wrs): memoize the keystone client in the class
        # instance instead of instantiating a new keystone client
        # at each subcloud strategy step.
        try:
            ks_client = self.get_ks_client(region)
        except (keystone_exceptions.EndpointNotFound, IndexError) as e:
            message = ("Identity endpoint for subcloud: %s not found. %s" %
                       (region, e))
            LOG.error(message)
            self.strategy_step_update(
                strategy_step.subcloud_id,
                state=consts.STRATEGY_STATE_FAILED,
                details=message)
            return

        vim_client = vim.VimClient(region, ks_client.session)

        # First check if the strategy has been created.
        try:
            subcloud_strategy = vim_client.get_strategy(
                strategy_name=vim.STRATEGY_NAME_SW_PATCH)
        except Exception:
            # Strategy doesn't exist yet
            subcloud_strategy = None

        if subcloud_strategy is None:
            # Check whether any patch orchestration is actually required. We
            # always create a step for the SystemController and it may have
            # been done (e.g. in a previous attempt). Also, if we are just
            # committing patches, patch orchestration is not required.
            orch_required = False
            patching_client = PatchingClient(region, ks_client.session)
            try:
                cloud_hosts = patching_client.query_hosts()
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
                subcloud_strategy = vim_client.create_strategy(
                    strategy_name=vim.STRATEGY_NAME_SW_PATCH,
                    storage_apply_type=opts_dict['storage-apply-type'],
                    compute_apply_type=opts_dict['compute-apply-type'],
                    max_parallel_compute_hosts=opts_dict[
                        'max-parallel-computes'],
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
                subcloud_strategy = vim_client.get_strategy(
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
            if wait_count >= (WAIT_LIMIT / WAIT_INTERVAL):
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

        try:
            ks_client = self.get_ks_client(region)
        except (keystone_exceptions.EndpointNotFound, IndexError) as e:
            message = ("Identity endpoint for subcloud: %s not found." %
                       region)
            LOG.error(message)
            self.strategy_step_update(
                strategy_step.subcloud_id,
                state=consts.STRATEGY_STATE_FAILED,
                details=message)
            return

        vim_client = vim.VimClient(region, ks_client.session)

        # First check if the strategy has been created.
        try:
            subcloud_strategy = vim_client.get_strategy(
                strategy_name=vim.STRATEGY_NAME_SW_PATCH)
        except Exception:
            # Strategy doesn't exist
            message = "Strategy does not exist for %s" % region
            LOG.warn(message)
            raise

        if subcloud_strategy.state == vim.STATE_READY_TO_APPLY:
            try:
                subcloud_strategy = vim_client.apply_strategy(
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
        auth_failure = False
        while True:
            try:
                subcloud_strategy = vim_client.get_strategy(
                    strategy_name=vim.STRATEGY_NAME_SW_PATCH)
                auth_failure = False
                get_fail_count = 0
            except Exception as e:
                if e.message == "Authorization failed":
                    # Since it can take hours to apply a strategy, there is a
                    # chance our keystone token will expire. Attempt to get
                    # a new token (by re-creating the client) and re-try the
                    # request, but only once.
                    if not auth_failure:
                        auth_failure = True
                        LOG.info("Authorization failure getting strategy for "
                                 "%s. Retrying..." % region)
                        vim_client = vim.VimClient(region, ks_client.session)
                        continue
                    else:
                        message = ("Repeated authorization failure getting "
                                   "patch strategy for %s" % region)
                        LOG.warn(message)
                        self.strategy_step_update(
                            strategy_step.subcloud_id,
                            state=consts.STRATEGY_STATE_FAILED,
                            details=message)
                        return
                else:
                    # When applying the strategy to a subcloud, the VIM can
                    # be unreachable for a significant period of time when
                    # there is a controller swact, or in the case of AIO-SX,
                    # when the controller reboots.
                    get_fail_count += 1
                    wait_count += 1
                    if get_fail_count >= (GET_FAIL_LIMIT / WAIT_INTERVAL):
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
            if wait_count >= (WAIT_LIMIT / WAIT_INTERVAL):
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
        """Delete the patch strategy in this subcloud"""

        region = self.get_region_name(strategy_step)

        LOG.info("Deleting patch strategy for %s" % region)

        try:
            ks_client = self.get_ks_client(region)
        except (keystone_exceptions.EndpointNotFound, IndexError) as e:
            message = ("Identity endpoint for subcloud: %s not found. %s" %
                       (region, e))
            LOG.error(message)
            self.strategy_step_update(
                strategy_step.subcloud_id,
                state=consts.STRATEGY_STATE_FAILED,
                details=message)
            return

        vim_client = vim.VimClient(region, ks_client.session)

        # First check if the strategy has been created.
        try:
            subcloud_strategy = vim_client.get_strategy(
                strategy_name=vim.STRATEGY_NAME_SW_PATCH)
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
            raise Exception(message)

        # If we are here, we need to delete the strategy
        try:
            vim_client.delete_strategy(
                strategy_name=vim.STRATEGY_NAME_SW_PATCH)
        except Exception:
            message = "Strategy delete failed for %s" % region
            LOG.warn(message)
            raise

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

        ks_client = self.get_ks_client()

        # First query RegionOne to determine what patches should be committed.
        patching_client = PatchingClient(
            consts.DEFAULT_REGION_NAME, ks_client.session)
        regionone_committed_patches = patching_client.query(
            state=patching_v1.PATCH_STATE_COMMITTED)
        LOG.debug("regionone_committed_patches: %s" %
                  regionone_committed_patches)

        committed_patch_ids = list()
        for patch_id in regionone_committed_patches.keys():
            committed_patch_ids.append(patch_id)
        LOG.debug("RegionOne committed_patch_ids: %s" % committed_patch_ids)

        # First need to retrieve the Subcloud's Keystone session
        try:
            sc_ks_client = self.get_ks_client(strategy_step.subcloud_name)
        except (keystone_exceptions.EndpointNotFound, IndexError) as e:
            message = ("Identity endpoint for subcloud: %s not found. %s" %
                       (strategy_step.subcloud.name, e))
            LOG.error(message)
            self.strategy_step_update(
                strategy_step.subcloud_id,
                state=consts.STRATEGY_STATE_FAILED,
                details=message)
            return

        try:
            patching_client = PatchingClient(
                strategy_step.subcloud.name, sc_ks_client.session)
        except keystone_exceptions.EndpointNotFound:
            message = ("Patching endpoint for subcloud: %s not found." %
                       strategy_step.subcloud.name)
            LOG.error(message)
            self.strategy_step_update(
                strategy_step.subcloud_id,
                state=consts.STRATEGY_STATE_FAILED,
                details=message)
            return

        try:
            subcloud_patches = patching_client.query()
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
        subcloud_patch_ids = subcloud_patches.keys()
        for patch_id in subcloud_patch_ids:
            if subcloud_patches[patch_id]['patchstate'] == \
                    patching_v1.PATCH_STATE_AVAILABLE:
                LOG.info("Patch %s will be deleted from subcloud %s" %
                         (patch_id, strategy_step.subcloud.name))
                patches_to_delete.append(patch_id)
            elif subcloud_patches[patch_id]['patchstate'] == \
                    patching_v1.PATCH_STATE_APPLIED:
                if patch_id in committed_patch_ids:
                    LOG.info("Patch %s will be committed in subcloud %s" %
                             (patch_id, strategy_step.subcloud.name))
                    patches_to_commit.append(patch_id)

        if patches_to_delete:
            LOG.info("Deleting patches %s from subcloud %s" %
                     (patches_to_delete, strategy_step.subcloud.name))
            try:
                patching_client.delete(patches_to_delete)
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
                patching_client.commit(patches_to_commit)
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
            self.delete_subcloud_strategy(strategy_step)

            if self.stopped():
                LOG.info("Exiting because task is stopped")
                return

        # Remove the strategy from the database
        try:
            db_api.strategy_step_destroy_all(self.context)
            db_api.sw_update_strategy_destroy(self.context)
        except Exception as e:
            LOG.exception(e)
            raise e
