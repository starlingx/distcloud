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

from oslo_log import log as logging

from dccommon.drivers.openstack.sdk_platform import OpenStackDriver
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient

from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common import exceptions
from dcmanager.common import scheduler
from dcmanager.db import api as db_api
from dcmanager.manager.patch_audit_manager import PatchAuditManager

LOG = logging.getLogger(__name__)

# When a license is not installed, this will be part of the API error string
LICENSE_FILE_NOT_FOUND_SUBSTRING = "License file not found"


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

    def __init__(self, strategy_lock):
        super(SwUpgradeOrchThread, self).__init__()
        self.context = context.get_admin_context()
        self._stop = threading.Event()
        # Used to protect strategy when an atomic read/update is required.
        self.strategy_lock = strategy_lock
        # Keeps track of greenthreads we create to do work.
        self.thread_group_manager = scheduler.ThreadGroupManager(
            thread_pool_size=100)
        # Track worker created for each subcloud.
        self.subcloud_workers = dict()

        # When an upgrade is initiated, this is the first state
        self.starting_state = consts.STRATEGY_STATE_INSTALLING_LICENSE

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

    @staticmethod
    def get_sysinv_client(region_name, session):
        return SysinvClient(region_name, session)

    @staticmethod
    def get_region_name(strategy_step):
        """Get the region name for a strategy step"""
        if strategy_step.subcloud_id is None:
            # This is the SystemController.
            return consts.DEFAULT_REGION_NAME
        return strategy_step.subcloud.name

    @staticmethod
    def license_up_to_date(target_license, existing_license):
        return target_license == existing_license

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
        db_api.strategy_step_update(
            self.context,
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
                    self.context)

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

        LOG.info("Applying upgrade strategy")
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
                            self.context, state=consts.SW_UPDATE_STATE_FAILED)
                    # Trigger audit to update the sync status for
                    # each subcloud.
                    PatchAuditManager.trigger_audit()
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
            # Trigger audit to update the sync status for each subcloud.
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
                # Trigger audit to update the sync status for each subcloud.
                PatchAuditManager.trigger_audit()
                return

        LOG.info("Working on stage %d" % current_stage)
        for strategy_step in strategy_steps:
            if strategy_step.stage == current_stage:
                region = self.get_region_name(strategy_step)

                if strategy_step.state == \
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
                    self.strategy_step_update(
                        strategy_step.subcloud_id,
                        state=consts.STRATEGY_STATE_INSTALLING_LICENSE)

                    # Initial step should log an error if a greenthread exists
                    # All other steps should not.
                    self.process_upgrade_step(region,
                                              strategy_step,
                                              self.install_subcloud_license,
                                              log_error=True)
                elif strategy_step.state == \
                        consts.STRATEGY_STATE_INSTALLING_LICENSE:
                    self.process_upgrade_step(region,
                                              strategy_step,
                                              self.install_subcloud_license,
                                              log_error=False)
                elif strategy_step.state == \
                        consts.STRATEGY_STATE_IMPORTING_LOAD:
                    self.process_upgrade_step(region,
                                              strategy_step,
                                              self.install_subcloud_load,
                                              log_error=False)
                # todo(abailey): Add calls to self.process_upgrade_step
                # for each additional state, with the appropriate thread
                # method called.
                else:
                    LOG.error("Unimplemented state %s" % strategy_step.state)
                    self.strategy_step_update(
                        strategy_step.subcloud_id,
                        state=consts.STRATEGY_STATE_FAILED,
                        details=("Upgrade state not implemented: %s"
                                 % strategy_step.state))

                if self.stopped():
                    LOG.info("Exiting because task is stopped")
                    return

    def process_upgrade_step(self,
                             region,
                             strategy_step,
                             upgrade_thread_method,
                             log_error=False):
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
                self.thread_group_manager.start(upgrade_thread_method,
                                                strategy_step)

    def install_subcloud_license(self, strategy_step):
        """Install the license for the upgrade in this subcloud

        Removes the worker reference after the operation is complete.
        """

        try:
            LOG.info("Stage: %s for subcloud %s"
                     % (strategy_step.stage,
                        self.get_region_name(strategy_step)))
            self.do_install_subcloud_license(strategy_step)
        except Exception:
            # Catch ALL exceptions and set the strategy to failed
            LOG.exception("Install license failed for %s"
                          % self.get_region_name(strategy_step))
            self.strategy_step_update(strategy_step.subcloud_id,
                                      state=consts.STRATEGY_STATE_FAILED,
                                      details=("Install license failed"))
        finally:
            # The worker is done.
            region = self.get_region_name(strategy_step)
            if region in self.subcloud_workers:
                del self.subcloud_workers[region]

    def install_subcloud_load(self, strategy_step):
        """Install the load on the subcloud

        Removes the worker reference after the operation is complete.
        """

        try:
            # self.do_install_subcloud_load(strategy_step)
            raise NotImplementedError
        except Exception:
            # Catch ALL exceptions and set the strategy to failed
            LOG.exception("Install load failed")
            self.strategy_step_update(strategy_step.subcloud_id,
                                      state=consts.STRATEGY_STATE_FAILED,
                                      details=("Install load failed"))
        finally:
            # The worker is done.
            region = self.get_region_name(strategy_step)
            if region in self.subcloud_workers:
                del self.subcloud_workers[region]

    def do_install_subcloud_license(self, strategy_step):
        """Install the License for a software upgrade in this subcloud"""

        # Note: no need to catch exceptions in this method.

        # next_state is the next state that the strategy will use on
        # successful completion of this state
        next_state = consts.STRATEGY_STATE_IMPORTING_LOAD

        # We check the system controller license for system controller and
        # subclouds
        local_ks_client = self.get_ks_client()
        local_sysinv_client = \
            self.get_sysinv_client(consts.DEFAULT_REGION_NAME,
                                   local_ks_client.session)
        system_controller_license = local_sysinv_client.get_license()
        # get_license returns a dictionary with keys: content and error
        # 'content' can be an empty string in success or failure case.
        # 'error' is an empty string only in success case.
        target_license = system_controller_license.get('content')
        target_error = system_controller_license.get('error')

        # If the system controller does not have a license, do not attempt
        # to install licenses on subcluds, and simply proceed to the next stage
        if len(target_error) != 0:
            if LICENSE_FILE_NOT_FOUND_SUBSTRING in target_error:
                LOG.debug("Stage:<%s>, Subcloud:<%s>. "
                          "System Controller License missing: %s."
                          % (strategy_step.stage,
                             self.get_region_name(strategy_step),
                             target_error))
                self.strategy_step_update(strategy_step.subcloud_id,
                                          state=next_state)
                return
            else:
                # An unexpected API error was returned. Fail this stage.
                LOG.warning("Stage:<%s>, Subcloud:<%s>. "
                            "System Controller License query failed: %s."
                            % (strategy_step.stage,
                               self.get_region_name(strategy_step),
                               target_error))
                raise exceptions.LicenseMissingError(
                    subcloud_id="SystemController")

        # retrieve the keystone session for the subcloud and query its license
        subcloud_ks_client = self.get_ks_client(strategy_step.subcloud.name)
        subcloud_sysinv_client = \
            self.get_sysinv_client(strategy_step.subcloud.name,
                                   subcloud_ks_client.session)
        subcloud_license_response = subcloud_sysinv_client.get_license()
        subcloud_license = subcloud_license_response.get('content')
        subcloud_error = subcloud_license_response.get('error')

        # Skip license install if the license is already up to date
        # If there was not an error, there might be a license
        if len(subcloud_error) == 0:
            if self.license_up_to_date(target_license, subcloud_license):
                LOG.debug("Stage:<%s>, Subcloud:<%s>. License up to date."
                          % (strategy_step.stage,
                             self.get_region_name(strategy_step)))
                self.strategy_step_update(strategy_step.subcloud_id,
                                          state=next_state)
                return
            else:
                LOG.debug("Stage:<%s>, Subcloud:<%s>. "
                          "License mismatch. Updating."
                          % (strategy_step.stage,
                             self.get_region_name(strategy_step)))
        else:
            LOG.debug("Stage:<%s>, Subcloud:<%s>. "
                      "License missing. Installing."
                      % (strategy_step.stage,
                         self.get_region_name(strategy_step)))

        # Install the license
        install_rc = subcloud_sysinv_client.install_license(target_license)
        install_error = install_rc.get('error')
        if len(install_error) != 0:
            LOG.warning("Stage:<%s>, Subcloud:<%s>. "
                        "License install failed:<%s>."
                        % (strategy_step.stage,
                           self.get_region_name(strategy_step),
                           install_error))
            raise exceptions.LicenseInstallError(
                subcloud_id=strategy_step.subcloud_id)

        # The license has been successfully installed. Move to the next stage
        LOG.debug("Stage:<%s>, Subcloud:<%s>. "
                  "License installed."
                  % (strategy_step.stage,
                     self.get_region_name(strategy_step)))
        self.strategy_step_update(strategy_step.subcloud_id, state=next_state)

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
                self.context, state=consts.SW_UPDATE_STATE_ABORTING)

    def delete(self, sw_update_strategy):
        """Delete an upgrade strategy"""

        LOG.info("Deleting upgrade strategy")

        # todo(abailey): determine if we should validate the strategy_steps
        # before allowing the delete

        # Remove the strategy from the database
        try:
            db_api.strategy_step_destroy_all(self.context)
            db_api.sw_update_strategy_destroy(self.context)
        except Exception as e:
            LOG.exception(e)
            raise e
