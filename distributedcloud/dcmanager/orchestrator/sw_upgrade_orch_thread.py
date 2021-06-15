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
# Copyright (c) 2017-2020 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#
import datetime
import threading
import time

from keystoneauth1 import exceptions as keystone_exceptions
from oslo_log import log as logging

from dccommon.drivers.openstack.sdk_platform import OpenStackDriver
from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common import exceptions
from dcmanager.common import scheduler
from dcmanager.db import api as db_api
from dcmanager.orchestrator.states.upgrade.activating import ActivatingUpgradeState
from dcmanager.orchestrator.states.upgrade.applying_vim_upgrade_strategy \
    import ApplyingVIMUpgradeStrategyState
from dcmanager.orchestrator.states.upgrade.completing import CompletingUpgradeState
from dcmanager.orchestrator.states.upgrade.creating_vim_upgrade_strategy \
    import CreatingVIMUpgradeStrategyState
from dcmanager.orchestrator.states.upgrade.deleting_load import DeletingLoadState
from dcmanager.orchestrator.states.upgrade.finishing_patch_strategy \
    import FinishingPatchStrategyState
from dcmanager.orchestrator.states.upgrade.importing_load import ImportingLoadState
from dcmanager.orchestrator.states.upgrade.installing_license \
    import InstallingLicenseState
from dcmanager.orchestrator.states.upgrade.lock_duplex import LockDuplexState
from dcmanager.orchestrator.states.upgrade.lock_simplex import LockSimplexState
from dcmanager.orchestrator.states.upgrade.migrating_data \
    import MigratingDataState
from dcmanager.orchestrator.states.upgrade.pre_check import PreCheckState
from dcmanager.orchestrator.states.upgrade.starting_upgrade \
    import StartingUpgradeState
from dcmanager.orchestrator.states.upgrade.swact_to_controller_0 \
    import SwactToController0State
from dcmanager.orchestrator.states.upgrade.swact_to_controller_1 \
    import SwactToController1State
from dcmanager.orchestrator.states.upgrade.unlock_duplex import UnlockDuplexState
from dcmanager.orchestrator.states.upgrade.unlock_simplex import UnlockSimplexState
from dcmanager.orchestrator.states.upgrade.updating_patches import UpdatingPatchesState
from dcmanager.orchestrator.states.upgrade.upgrading_duplex \
    import UpgradingDuplexState
from dcmanager.orchestrator.states.upgrade.upgrading_simplex \
    import UpgradingSimplexState

LOG = logging.getLogger(__name__)

# every state should have an operator
STATE_OPERATORS = {
    consts.STRATEGY_STATE_PRE_CHECK: PreCheckState,
    consts.STRATEGY_STATE_INSTALLING_LICENSE: InstallingLicenseState,
    consts.STRATEGY_STATE_IMPORTING_LOAD: ImportingLoadState,
    consts.STRATEGY_STATE_UPDATING_PATCHES: UpdatingPatchesState,
    consts.STRATEGY_STATE_FINISHING_PATCH_STRATEGY: FinishingPatchStrategyState,
    consts.STRATEGY_STATE_STARTING_UPGRADE: StartingUpgradeState,
    consts.STRATEGY_STATE_LOCKING_CONTROLLER_0: LockSimplexState,
    consts.STRATEGY_STATE_LOCKING_CONTROLLER_1: LockDuplexState,
    consts.STRATEGY_STATE_UPGRADING_SIMPLEX: UpgradingSimplexState,
    consts.STRATEGY_STATE_UPGRADING_DUPLEX: UpgradingDuplexState,
    consts.STRATEGY_STATE_MIGRATING_DATA: MigratingDataState,
    consts.STRATEGY_STATE_SWACTING_TO_CONTROLLER_0: SwactToController0State,
    consts.STRATEGY_STATE_SWACTING_TO_CONTROLLER_1: SwactToController1State,
    consts.STRATEGY_STATE_UNLOCKING_CONTROLLER_0: UnlockSimplexState,
    consts.STRATEGY_STATE_UNLOCKING_CONTROLLER_1: UnlockDuplexState,
    consts.STRATEGY_STATE_ACTIVATING_UPGRADE: ActivatingUpgradeState,
    consts.STRATEGY_STATE_COMPLETING_UPGRADE: CompletingUpgradeState,
    consts.STRATEGY_STATE_CREATING_VIM_UPGRADE_STRATEGY:
        CreatingVIMUpgradeStrategyState,
    consts.STRATEGY_STATE_APPLYING_VIM_UPGRADE_STRATEGY:
        ApplyingVIMUpgradeStrategyState,
    consts.STRATEGY_STATE_DELETING_LOAD: DeletingLoadState,
}


class SwUpgradeOrchThread(threading.Thread):
    """SwUpgrade Orchestration Thread

    This thread is responsible for executing the upgrade orchestration strategy.
    Here is how it works:
    - The user creates an update strategy from CLI (or REST API) of 'upgrade'
    - This ends up being handled by the SwUpdateManager class, which
      runs under the main dcmanager thread. The strategy is created and stored
      in the database.
    - The user then applies the strategy from the CLI (or REST API). The
      SwUpdateManager code updates the state of the strategy in the database.
    - The SwUpgradeOrchThread wakes up periodically and checks the database for
      a strategy that is in an active state (applying, aborting, etc...). If
      so, it executes the strategy, updating the strategy and steps in the
      database as it goes, with state and progress information.
    """

    def __init__(self, strategy_lock, audit_rpc_client):
        super(SwUpgradeOrchThread, self).__init__()
        self.context = context.get_admin_context()
        self._stop = threading.Event()
        # Used to protect strategy when an atomic read/update is required.
        self.strategy_lock = strategy_lock
        # Used to notify dcmanager-audit to trigger a patch audit
        self.audit_rpc_client = audit_rpc_client
        # Keeps track of greenthreads we create to do work.
        self.thread_group_manager = scheduler.ThreadGroupManager(
            thread_pool_size=100)
        # Track worker created for each subcloud.
        self.subcloud_workers = dict()

        # When an upgrade is initiated, this is the first state
        self.starting_state = consts.STRATEGY_STATE_PRE_CHECK

    def stopped(self):
        return self._stop.isSet()

    def stop(self):
        LOG.info("SwUpgradeOrchThread Stopping")
        self._stop.set()

    def run(self):
        self.upgrade_orch()
        # Stop any greenthreads that are still running
        self.thread_group_manager.stop()
        LOG.info("SwUpgradeOrchThread Stopped")

    @staticmethod
    def get_region_name(strategy_step):
        """Get the region name for a strategy step"""
        if strategy_step.subcloud_id is None:
            # This is the SystemController.
            return consts.DEFAULT_REGION_NAME
        return strategy_step.subcloud.name

    @staticmethod
    def get_ks_client(region_name=consts.DEFAULT_REGION_NAME):
        """This will get a cached keystone client (and token)"""
        try:
            os_client = OpenStackDriver(
                region_name=region_name,
                region_clients=None)
            return os_client.keystone_client
        except Exception:
            LOG.warn('Failure initializing KeystoneClient')
            raise

    def get_vim_client(self, region_name=consts.DEFAULT_REGION_NAME):
        ks_client = self.get_ks_client(region_name)
        return vim.VimClient(region_name, ks_client.session)

    @staticmethod
    def format_update_details(last_state, info):
        # include the last state, since the current state is likely 'failed'
        details = "%s: %s" % (last_state, info)
        # details cannot exceed 255 chars. truncate and add '..'
        if len(details) > 255:
            details = details[:253] + '..'
        return details

    @staticmethod
    def determine_state_operator(strategy_step):
        """Return the state operator for the current state"""
        state_operator = STATE_OPERATORS.get(strategy_step.state)
        # instantiate and return the state_operator class
        return state_operator(region_name=SwUpgradeOrchThread.get_region_name(strategy_step))

    def strategy_step_update(self, subcloud_id, state=None, details=None):
        """Update the strategy step in the DB

        Sets the start and finished timestamp if necessary, based on state.
        """
        started_at = None
        finished_at = None
        if state == self.starting_state:
            started_at = datetime.datetime.now()
        elif state in [consts.STRATEGY_STATE_COMPLETE,
                       consts.STRATEGY_STATE_ABORTED,
                       consts.STRATEGY_STATE_FAILED]:
            finished_at = datetime.datetime.now()
        # Return the updated object, in case we need to use its updated values
        return db_api.strategy_step_update(self.context,
                                           subcloud_id,
                                           state=state,
                                           details=details,
                                           started_at=started_at,
                                           finished_at=finished_at)

    def upgrade_orch(self):
        while not self.stopped():
            try:
                LOG.debug('Running upgrade orchestration')

                sw_update_strategy = db_api.sw_update_strategy_get(
                    self.context,
                    update_type=consts.SW_UPDATE_TYPE_UPGRADE)

                if sw_update_strategy.type == consts.SW_UPDATE_TYPE_UPGRADE:
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

        LOG.info("SwUpgradeOrchThread ended main loop")

    def apply(self, sw_update_strategy):
        """Apply an upgrade strategy"""

        LOG.debug("Applying upgrade strategy")
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
                             "processing upgrade step on SystemController")
                    with self.strategy_lock:
                        db_api.sw_update_strategy_update(
                            self.context,
                            state=consts.SW_UPDATE_STATE_FAILED,
                            update_type=consts.SW_UPDATE_TYPE_UPGRADE)
                    # Trigger audit to update the sync status for
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
                        self.context,
                        state=consts.SW_UPDATE_STATE_FAILED,
                        update_type=consts.SW_UPDATE_TYPE_UPGRADE)
            elif abort_detected:
                LOG.info("Strategy application was aborted.")
                with self.strategy_lock:
                    db_api.sw_update_strategy_update(
                        self.context,
                        state=consts.SW_UPDATE_STATE_ABORTED,
                        update_type=consts.SW_UPDATE_TYPE_UPGRADE)
            else:
                LOG.info("Strategy application is complete.")
                with self.strategy_lock:
                    db_api.sw_update_strategy_update(
                        self.context,
                        state=consts.SW_UPDATE_STATE_COMPLETE,
                        update_type=consts.SW_UPDATE_TYPE_UPGRADE)
            # Trigger audit to update the sync status for each subcloud.
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
                        self.context,
                        state=consts.SW_UPDATE_STATE_FAILED,
                        update_type=consts.SW_UPDATE_TYPE_UPGRADE)
                # Trigger audit to update the sync status for each subcloud.
                self.audit_rpc_client.trigger_patch_audit(self.context)
                return

        LOG.debug("Working on stage %d" % current_stage)
        for strategy_step in strategy_steps:
            if strategy_step.stage == current_stage:
                region = self.get_region_name(strategy_step)
                if self.stopped():
                    LOG.info("Exiting because task is stopped")
                    return
                if strategy_step.state == \
                        consts.STRATEGY_STATE_FAILED:
                    LOG.debug("Intermediate step is failed")
                    continue
                elif strategy_step.state == \
                        consts.STRATEGY_STATE_COMPLETE:
                    LOG.debug("Intermediate step is complete")
                    continue
                elif strategy_step.state == \
                        consts.STRATEGY_STATE_INITIAL:
                    # Don't start upgrading this subcloud if it has been
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
                    # Use the updated value for calling process_upgrade_step
                    strategy_step = self.strategy_step_update(
                        strategy_step.subcloud_id,
                        state=self.starting_state)
                    # Starting state should log an error if greenthread exists
                    self.process_upgrade_step(region,
                                              strategy_step,
                                              log_error=True)
                else:
                    self.process_upgrade_step(region,
                                              strategy_step,
                                              log_error=False)

    def abort(self, sw_update_strategy):
        """Abort an upgrade strategy"""

        LOG.info("Aborting upgrade strategy")

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
                self.context,
                state=consts.SW_UPDATE_STATE_ABORTING,
                update_type=consts.SW_UPDATE_TYPE_UPGRADE)

    def delete(self, sw_update_strategy):
        """Delete an upgrade strategy"""

        LOG.info("Deleting upgrade strategy")

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

    # todo(abailey): refactor delete to reuse patch orch code
    def delete_subcloud_strategy(self, strategy_step):
        """Delete the vim strategy in this subcloud"""

        strategy_name = vim.STRATEGY_NAME_FW_UPDATE
        region = self.get_region_name(strategy_step)

        LOG.info("Deleting vim strategy %s for %s" % (strategy_name, region))

        # First check if the strategy has been created.
        try:
            subcloud_strategy = self.get_vim_client(region).get_strategy(
                strategy_name=strategy_name)
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
            self.get_vim_client(region).delete_strategy(
                strategy_name=strategy_name)
        except Exception:
            message = "Strategy delete failed for %s" % region
            LOG.warn(message)
            raise

    def process_upgrade_step(self, region, strategy_step, log_error=False):
        """manage the green thread for calling perform_state_action"""
        if region in self.subcloud_workers:
            # A worker already exists. Let it finish whatever it was doing.
            if log_error:
                LOG.error("Worker should not exist for %s." % region)
            else:
                LOG.debug("Update worker exists for %s." % region)
        else:
            # Create a greenthread to start processing the upgrade for the
            # subcloud and invoke the specified upgrade_thread_method
            self.subcloud_workers[region] = \
                self.thread_group_manager.start(self.perform_state_action,
                                                strategy_step)

    def perform_state_action(self, strategy_step):
        """Extensible state handler for processing and transitioning states """
        try:
            LOG.info("Stage: %s, State: %s, Subcloud: %s"
                     % (strategy_step.stage,
                        strategy_step.state,
                        self.get_region_name(strategy_step)))
            # Instantiate the state operator and perform the state actions
            state_operator = self.determine_state_operator(strategy_step)
            state_operator.registerStopEvent(self._stop)
            next_state = state_operator.perform_state_action(strategy_step)
            # If we get here without an exception raised, proceed to next state
            self.strategy_step_update(strategy_step.subcloud_id,
                                      state=next_state)
        except Exception as e:
            # Catch ALL exceptions and set the strategy to failed
            LOG.exception("Failed! Stage: %s, State: %s, Subcloud: %s"
                          % (strategy_step.stage,
                             strategy_step.state,
                             self.get_region_name(strategy_step)))
            details = self.format_update_details(strategy_step.state, str(e))
            self.strategy_step_update(strategy_step.subcloud_id,
                                      state=consts.STRATEGY_STATE_FAILED,
                                      details=details)
        finally:
            # The worker is done.
            region = self.get_region_name(strategy_step)
            if region in self.subcloud_workers:
                del self.subcloud_workers[region]
