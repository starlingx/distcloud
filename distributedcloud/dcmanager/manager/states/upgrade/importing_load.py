#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import time

from dcmanager.common import consts
from dcmanager.common.exceptions import StrategyStoppedException
from dcmanager.manager.states.base import BaseState
from dcmanager.manager.states.upgrade import utils

# Max time: 30 minutes = 180 queries x 10 seconds between
DEFAULT_MAX_QUERIES = 180
DEFAULT_SLEEP_DURATION = 10


class ImportingLoadState(BaseState):
    """Upgrade state for importing a load"""

    def __init__(self):
        super(ImportingLoadState, self).__init__(
            next_state=consts.STRATEGY_STATE_STARTING_UPGRADE)
        # max time to wait (in seconds) is: sleep_duration * max_queries
        self.sleep_duration = DEFAULT_SLEEP_DURATION
        self.max_queries = DEFAULT_MAX_QUERIES

    def perform_state_action(self, strategy_step):
        """Import a load on a subcloud

        Returns the next state in the state machine on success.
        Any exceptions raised by this method set the strategy to FAILED.
        """
        # determine the version of the system controller in region one
        local_ks_client = self.get_keystone_client()
        local_sysinv_client = \
            self.get_sysinv_client(consts.DEFAULT_REGION_NAME,
                                   local_ks_client.session)
        target_version = local_sysinv_client.get_system().software_version

        # get the keystone and sysinv clients for the subcloud
        ks_client = self.get_keystone_client(strategy_step.subcloud.name)
        sysinv_client = self.get_sysinv_client(strategy_step.subcloud.name,
                                               ks_client.session)

        # Check if the load is already imported by checking the version
        current_loads = sysinv_client.get_loads()
        for load in current_loads:
            if load.software_version == target_version:
                self.info_log(strategy_step,
                              "Load:%s already found" % target_version)
                return self.next_state

        # If we are here, the load needs to be imported
        # ISO and SIG files are found in the vault under a version directory
        iso_path, sig_path = utils.get_vault_load_files(target_version)

        # Call the API. import_load blocks until the load state is 'importing'
        imported_load = sysinv_client.import_load(iso_path, sig_path)
        new_load = imported_load.get('new_load', {})
        if new_load.get('software_version') != target_version:
            raise Exception("The imported load was not the expected version")

        new_load_id = new_load.get('id')
        # repeatedly query until load state changes to 'imported' or we timeout
        counter = 0
        while True:
            # If event handler stop has been triggered, fail the state
            if self.stopped():
                raise StrategyStoppedException()
            # query the load state to see if it is in the new state
            # get_load returns a Load object
            load = sysinv_client.get_load(new_load_id)
            if load.state == 'imported':
                msg = "Load: %s is now: %s" % (target_version,
                                               load.state)
                self.info_log(strategy_step, msg)
                break
            counter += 1
            if counter >= self.max_queries:
                raise Exception("Timeout waiting for import to complete")
            time.sleep(self.sleep_duration)

        # When we return from this method without throwing an exception, the
        # state machine can proceed to the next state
        return self.next_state
