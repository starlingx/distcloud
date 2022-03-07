# Copyright 2017 Ericsson AB.
# Copyright (c) 2017-2021 Wind River Systems, Inc.
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
import abc
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

LOG = logging.getLogger(__name__)


class OrchThread(threading.Thread):
    """Abstract Orchestration Thread

    This thread is responsible for the orchestration strategy.
    Here is how it works:
    - The user creates an update strategy from CLI (or REST API)
    - This is being handled by the SwUpdateManager class, which
      runs under the main dcmanager thread. The strategy is created and stored
      in the database.
    - The user then applies the strategy from the CLI (or REST API). The
      SwUpdateManager code updates the state of the strategy in the database.
    - The OrchThread wakes up periodically and checks the database for
      a strategy of its expected type that is in an active state. If
      so, it executes the strategy, updating the strategy and steps in the
      database as it goes, with state and progress information.
    """
    # each subclass must provide the STATE_OPERATORS
    STATE_OPERATORS = {}

    def __init__(self,
                 strategy_lock,
                 audit_rpc_client,
                 update_type,
                 vim_strategy_name,
                 starting_state):
        super(OrchThread, self).__init__()
        # Used to protect strategy when an atomic read/update is required.
        self.strategy_lock = strategy_lock
        # Used to notify dcmanager-audit to trigger an audit
        self.audit_rpc_client = audit_rpc_client
        # The update type for the orch thread
        self.update_type = update_type
        # The vim strategy name for the orch thread
        self.vim_strategy_name = vim_strategy_name
        # When an apply is initiated, this is the first state
        self.starting_state = starting_state

        self.context = context.get_admin_context()
        self._stop = threading.Event()
        # Keeps track of greenthreads we create to do work.
        self.thread_group_manager = scheduler.ThreadGroupManager(
            thread_pool_size=500)
        # Track worker created for each subcloud.
        self.subcloud_workers = dict()

    @abc.abstractmethod
    def trigger_audit(self):
        """Subclass MUST override this method"""
        LOG.warn("(%s) OrchThread subclass must override trigger_audit"
                 % self.update_type)

    def stopped(self):
        return self._stop.isSet()

    def stop(self):
        LOG.info("(%s) OrchThread Stopping" % self.update_type)
        self._stop.set()

    def run(self):
        self.run_orch()
        # Stop any greenthreads that are still running
        self.thread_group_manager.stop()
        LOG.info("(%s) OrchThread Stopped" % self.update_type)

    @staticmethod
    def get_ks_client(region_name=consts.DEFAULT_REGION_NAME):
        """This will get a cached keystone client (and token)

        throws an exception if keystone client cannot be initialized
        """
        os_client = OpenStackDriver(region_name=region_name,
                                    region_clients=None)
        return os_client.keystone_client

    @staticmethod
    def get_vim_client(region_name=consts.DEFAULT_REGION_NAME):
        ks_client = OrchThread.get_ks_client(region_name)
        return vim.VimClient(region_name, ks_client.session)

    @staticmethod
    def get_region_name(strategy_step):
        """Get the region name for a strategy step"""
        if strategy_step.subcloud_id is None:
            # This is the SystemController.
            return consts.DEFAULT_REGION_NAME
        return strategy_step.subcloud.name

    @staticmethod
    def format_update_details(last_state, info):
        # Optionally include the last state, since the current state
        # is likely 'failed'
        if last_state:
            details = "%s: %s" % (last_state, info)
        else:
            details = str(info)
        # details cannot exceed 255 chars. truncate and add '..'
        if len(details) > 255:
            details = details[:253] + '..'
        return details

    def determine_state_operator(self, strategy_step):
        """Return the state operator for the current state"""
        state_operator = self.STATE_OPERATORS.get(strategy_step.state)
        # instantiate and return the state_operator class
        return state_operator(
            region_name=OrchThread.get_region_name(strategy_step))

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

    def _delete_subcloud_worker(self, region):
        if region in self.subcloud_workers:
            # The orchestration for this subcloud has either
            # completed/failed/aborted, remove it from the
            # dictionary.
            LOG.debug("Remove %s from subcloud_workers dict" % region)
            del self.subcloud_workers[region]

    def run_orch(self):
        while not self.stopped():
            try:
                LOG.debug('(%s) OrchThread Running' % self.update_type)

                sw_update_strategy = db_api.sw_update_strategy_get(
                    self.context,
                    update_type=self.update_type)

                if sw_update_strategy.type == self.update_type:
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

            except Exception:
                # We catch all exceptions to avoid terminating the thread.
                LOG.exception("(%s) OrchThread unexpected exception"
                              % self.update_type)

            # Wake up every 10 seconds to see if there is work to do.
            time.sleep(10)

        LOG.info("(%s) OrchThread ended main loop" % self.update_type)

    def apply(self, sw_update_strategy):
        """Apply a sw update strategy"""

        LOG.debug("(%s) Applying update strategy" % self.update_type)
        strategy_steps = db_api.strategy_step_get_all(self.context)

        # Figure out which stage we are working on
        current_stage = None
        stop_after_stage = None
        failure_detected = False
        abort_detected = False
        for strategy_step in strategy_steps:
            if strategy_step.state == consts.STRATEGY_STATE_COMPLETE:
                # This step is complete
                self._delete_subcloud_worker(strategy_step.subcloud.name)
                continue
            elif strategy_step.state == consts.STRATEGY_STATE_ABORTED:
                # This step was aborted
                self._delete_subcloud_worker(strategy_step.subcloud.name)
                abort_detected = True
                continue
            elif strategy_step.state == consts.STRATEGY_STATE_FAILED:
                failure_detected = True
                self._delete_subcloud_worker(strategy_step.subcloud.name)
                # This step has failed and needs no further action
                if strategy_step.subcloud_id is None:
                    # Strategy on SystemController failed. We are done.
                    LOG.info("(%s) Stopping strategy due to failure while "
                             "processing update step on SystemController"
                             % self.update_type)
                    with self.strategy_lock:
                        db_api.sw_update_strategy_update(
                            self.context,
                            state=consts.SW_UPDATE_STATE_FAILED,
                            update_type=self.update_type)
                    # Trigger audit to update the sync status for
                    # each subcloud.
                    self.trigger_audit()
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
                LOG.info("(%s) Strategy application has failed."
                         % self.update_type)
                with self.strategy_lock:
                    db_api.sw_update_strategy_update(
                        self.context,
                        state=consts.SW_UPDATE_STATE_FAILED,
                        update_type=self.update_type)
            elif abort_detected:
                LOG.info("(%s) Strategy application was aborted."
                         % self.update_type)
                with self.strategy_lock:
                    db_api.sw_update_strategy_update(
                        self.context,
                        state=consts.SW_UPDATE_STATE_ABORTED,
                        update_type=self.update_type)
            else:
                LOG.info("(%s) Strategy application is complete."
                         % self.update_type)
                with self.strategy_lock:
                    db_api.sw_update_strategy_update(
                        self.context,
                        state=consts.SW_UPDATE_STATE_COMPLETE,
                        update_type=self.update_type)

            self.subcloud_workers.clear()
            # Trigger audit to update the sync status for each subcloud.
            self.trigger_audit()
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
                LOG.info("(%s) Stopping strategy due to failure in stage %d"
                         % (self.update_type, stop_after_stage))
                with self.strategy_lock:
                    db_api.sw_update_strategy_update(
                        self.context,
                        state=consts.SW_UPDATE_STATE_FAILED,
                        update_type=self.update_type)
                # Trigger audit to update the sync status for each subcloud.
                self.trigger_audit()
                return

        LOG.debug("(%s) Working on stage %d"
                  % (self.update_type, current_stage))
        for strategy_step in strategy_steps:
            if strategy_step.stage == current_stage:
                region = self.get_region_name(strategy_step)
                if self.stopped():
                    LOG.info("(%s) Exiting because task is stopped"
                             % self.update_type)
                    self.subcloud_workers.clear()
                    return
                if strategy_step.state == \
                        consts.STRATEGY_STATE_FAILED:
                    LOG.debug("(%s) Intermediate step is failed"
                              % self.update_type)
                    self._delete_subcloud_worker(region)
                    continue
                elif strategy_step.state == \
                        consts.STRATEGY_STATE_COMPLETE:
                    LOG.debug("(%s) Intermediate step is complete"
                              % self.update_type)
                    self._delete_subcloud_worker(region)
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
                    # Use the updated value for calling process_update_step
                    strategy_step = self.strategy_step_update(
                        strategy_step.subcloud_id,
                        state=self.starting_state)
                    # Starting state should log an error if greenthread exists
                    self.process_update_step(region,
                                             strategy_step,
                                             log_error=True)
                else:
                    self.process_update_step(region,
                                             strategy_step,
                                             log_error=False)

    def abort(self, sw_update_strategy):
        """Abort an update strategy"""

        LOG.info("(%s) Aborting update strategy" % self.update_type)

        # Mark any steps that have not yet started as aborted,
        # so we will not run them later.
        strategy_steps = db_api.strategy_step_get_all(self.context)

        for strategy_step in strategy_steps:
            if strategy_step.state == consts.STRATEGY_STATE_INITIAL:
                LOG.info("(%s) Aborting step for subcloud %s"
                         % (self.update_type,
                            self.get_region_name(strategy_step)))
                self.strategy_step_update(
                    strategy_step.subcloud_id,
                    state=consts.STRATEGY_STATE_ABORTED,
                    details="")

        with self.strategy_lock:
            db_api.sw_update_strategy_update(
                self.context,
                state=consts.SW_UPDATE_STATE_ABORTING,
                update_type=self.update_type)

    def delete(self, sw_update_strategy):
        """Delete an update strategy"""

        LOG.info("(%s) Deleting update strategy" % self.update_type)

        strategy_steps = db_api.strategy_step_get_all(self.context)

        for strategy_step in strategy_steps:
            region = self.get_region_name(strategy_step)
            if region in self.subcloud_workers:
                # A worker already exists. Let it finish whatever it
                # was doing.
                LOG.debug("Worker already exists for %s." % region)
            else:
                # Create a greenthread to delete the subcloud strategy
                delete_thread = \
                    self.thread_group_manager.start(
                        self.delete_subcloud_strategy,
                        strategy_step)
                if delete_thread:
                    self.subcloud_workers[region] = delete_thread

            if self.stopped():
                LOG.info("(%s) Exiting because task is stopped"
                         % self.update_type)
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
            LOG.exception("(%s) exception during delete"
                          % self.update_type)
            raise e
        LOG.info("(%s) Finished deleting update strategy" % self.update_type)

    def delete_subcloud_strategy(self, strategy_step):
        """Delete the update strategy in this subcloud

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
        """Delete the vim strategy in this subcloud"""

        if self.vim_strategy_name is None:
            return

        region = self.get_region_name(strategy_step)

        LOG.info("(%s) Deleting vim strategy:(%s) for region:(%s)"
                 % (self.update_type, self.vim_strategy_name, region))

        # First check if the strategy has been created.
        try:
            subcloud_strategy = OrchThread.get_vim_client(region).get_strategy(
                strategy_name=self.vim_strategy_name)
        except (keystone_exceptions.EndpointNotFound, IndexError):
            message = ("(%s) Endpoint for subcloud: %s not found." %
                       (self.update_type, region))
            LOG.warn(message)
            return
        except Exception:
            # Strategy doesn't exist so there is nothing to do
            return

        if subcloud_strategy.state in [vim.STATE_BUILDING,
                                       vim.STATE_APPLYING,
                                       vim.STATE_ABORTING]:
            # Can't delete a vim strategy in these states
            message = ("(%s) Vim strategy:(%s) for region:(%s)"
                       " in wrong state:(%s) for delete."
                       % (self.update_type, self.vim_strategy_name, region,
                          subcloud_strategy.state))
            LOG.warn(message)
            return

        # If we are here, we need to delete the strategy
        try:
            OrchThread.get_vim_client(region).delete_strategy(
                strategy_name=self.vim_strategy_name)
        except Exception:
            message = ("(%s) Vim strategy:(%s) delete failed for region:(%s)"
                       % (self.update_type, self.vim_strategy_name, region))
            LOG.warn(message)
            return

    def process_update_step(self, region, strategy_step, log_error=False):
        """manage the green thread for calling perform_state_action"""
        if region in self.subcloud_workers:
            if self.subcloud_workers[region][0] == strategy_step.state:
                # A worker already exists. Let it finish whatever it was doing.
                if log_error:
                    LOG.error("(%s) Worker should not exist for %s."
                              % (self.update_type, region))
                else:
                    LOG.debug("(%s) Update worker exists for %s."
                              % (self.update_type, region))
            else:
                LOG.debug("Starting a new worker for region %s at state %s (update)"
                          % (region, strategy_step.state))
                # Advance to the next state. The previous greenthread has exited,
                # create a new one.
                self.subcloud_workers[region] = \
                    (strategy_step.state, self.thread_group_manager.start(
                     self.perform_state_action, strategy_step))
        else:
            # This is the first state. create a greenthread to start processing
            # the update for the subcloud and invoke the perform_state_action method.
            LOG.debug("Starting a new worker for region %s at state %s"
                      % (region, strategy_step.state))
            self.subcloud_workers[region] = \
                (strategy_step.state, self.thread_group_manager.start(
                 self.perform_state_action, strategy_step))

    def perform_state_action(self, strategy_step):
        """Extensible state handler for processing and transitioning states """
        try:
            LOG.info("(%s) Stage: %s, State: %s, Subcloud: %s"
                     % (self.update_type,
                        strategy_step.stage,
                        strategy_step.state,
                        self.get_region_name(strategy_step)))
            # Instantiate the state operator and perform the state actions
            state_operator = self.determine_state_operator(strategy_step)
            state_operator.registerStopEvent(self._stop)
            next_state = state_operator.perform_state_action(strategy_step)
            self.strategy_step_update(strategy_step.subcloud_id,
                                      state=next_state,
                                      details="")
        except exceptions.StrategySkippedException as ex:
            LOG.info("(%s) Skipping subcloud, Stage: %s, State: %s, Subcloud: %s"
                     % (self.update_type,
                        strategy_step.stage,
                        strategy_step.state,
                        self.get_region_name(strategy_step)))
            # Transition immediately to complete. Update the details to show
            # that this subcloud has been skipped
            details = self.format_update_details(None, str(ex))
            self.strategy_step_update(strategy_step.subcloud_id,
                                      state=consts.STRATEGY_STATE_COMPLETE,
                                      details=details)
        except Exception as ex:
            # Catch ALL exceptions and set the strategy to failed
            LOG.exception("(%s) Failed! Stage: %s, State: %s, Subcloud: %s"
                          % (self.update_type,
                             strategy_step.stage,
                             strategy_step.state,
                             self.get_region_name(strategy_step)))
            details = self.format_update_details(strategy_step.state, str(ex))
            self.strategy_step_update(strategy_step.subcloud_id,
                                      state=consts.STRATEGY_STATE_FAILED,
                                      details=details)
