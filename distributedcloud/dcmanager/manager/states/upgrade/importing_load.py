#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import time

from dcmanager.common import consts
from dcmanager.common.exceptions import StrategyStoppedException
from dcmanager.common import utils
from dcmanager.manager.states.base import BaseState

# Max time: 30 minutes = 180 queries x 10 seconds between
DEFAULT_MAX_QUERIES = 180
DEFAULT_SLEEP_DURATION = 10
LOAD_IMPORT_REQUEST_TYPE = 'import'
LOAD_DELETE_REQUEST_TYPE = 'delete'


class ImportingLoadState(BaseState):
    """Upgrade state for importing a load"""

    def __init__(self, region_name):
        super(ImportingLoadState, self).__init__(
            next_state=consts.STRATEGY_STATE_STARTING_UPGRADE, region_name=region_name)
        # max time to wait (in seconds) is: sleep_duration * max_queries
        self.sleep_duration = DEFAULT_SLEEP_DURATION
        self.max_queries = DEFAULT_MAX_QUERIES

    def _wait_for_request_to_complete(self, strategy_step, request_info):
        load_id = request_info.get('load_id')
        load_version = request_info.get('load_version')
        request_type = request_info.get('type')
        counter = 0

        while True:
            # If event handler stop has been triggered, fail the state
            if self.stopped():
                raise StrategyStoppedException()

            if request_type == LOAD_DELETE_REQUEST_TYPE:
                # repeatedly query until only one load, the active load, remains
                if len(self.subcloud_sysinv.get_loads()) == 1:
                    msg = "Load: %s has been removed." % load_version
                    self.info_log(strategy_step, msg)
                    break
            else:
                # repeatedly query until load state changes to 'imported'
                load = self.subcloud_sysinv.get_load(load_id)
                if load.state == consts.IMPORTED_LOAD_STATE:
                    msg = "Load: %s is now: %s" % (load_version,
                                                   load.state)
                    self.info_log(strategy_step, msg)
                    break
                elif load.state == consts.ERROR_LOAD_STATE:
                    self.error_log(strategy_step,
                                   "Load %s failed import" % load_version)
                    raise Exception("Failed to import load. Please check sysinv.log "
                                    "on the subcloud for details.")

            counter += 1
            if counter >= self.max_queries:
                raise Exception("Timeout waiting for %s to complete"
                                % request_type)
            time.sleep(self.sleep_duration)

    def perform_state_action(self, strategy_step):
        """Import a load on a subcloud

        Returns the next state in the state machine on success.
        Any exceptions raised by this method set the strategy to FAILED.
        """
        req_info = {}

        # determine the version of the system controller in region one
        target_version = self.local_sysinv.get_system().software_version

        # Check if the load is already imported by checking the version
        current_loads = self.subcloud_sysinv.get_loads()

        for load in current_loads:
            if load.software_version == target_version:
                self.info_log(strategy_step,
                              "Load:%s already found" % target_version)
                return self.next_state
            elif load.state == consts.IMPORTED_LOAD_STATE or load.state == consts.ERROR_LOAD_STATE:
                req_info['load_id'] = load.id
                req_info['load_version'] = load.software_version

        load_id_to_be_deleted = req_info.get('load_id')

        if load_id_to_be_deleted is not None:
            self.subcloud_sysinv.delete_load(load_id_to_be_deleted)
            req_info['type'] = LOAD_DELETE_REQUEST_TYPE
            self._wait_for_request_to_complete(strategy_step, req_info)

        try:
            subcloud_type = self.subcloud_sysinv.get_system().system_mode
            if subcloud_type == consts.SYSTEM_MODE_SIMPLEX:
                # For simplex we only import the load record, not the entire ISO
                loads = self.local_sysinv.get_loads()
                matches = [load for load in loads if load.software_version == target_version]
                target_load = matches[0].to_dict()
                # Send only the required fields
                creation_keys = ['software_version', 'compatible_version', 'required_patches']
                target_load = {key: target_load[key] for key in creation_keys}
                load = self.subcloud_sysinv.import_load_metadata(target_load)
                self.info_log(strategy_step,
                              "Load: %s is now: %s" % (load.software_version, load.state))
            else:
                # ISO and SIG files are found in the vault under a version directory
                iso_path, sig_path = utils.get_vault_load_files(target_version)
                # Call the API. import_load blocks until the load state is 'importing'
                new_load = self.subcloud_sysinv.import_load(iso_path, sig_path)
                if new_load.software_version != target_version:
                    raise Exception("The imported load was not the expected version.")

                self.info_log(strategy_step,
                              "Load import request accepted, load software version = %s"
                              % new_load.software_version)
                req_info['load_id'] = new_load.id
                req_info['load_version'] = target_version
                req_info['type'] = LOAD_IMPORT_REQUEST_TYPE
                self._wait_for_request_to_complete(strategy_step, req_info)
        except Exception as e:
            self.error_log(strategy_step, str(e))
            raise Exception("Failed to import load. Please check sysinv.log on "
                            "the subcloud for details.")

        # When we return from this method without throwing an exception, the
        # state machine can proceed to the next state
        return self.next_state
