#
# Copyright (c) 2020-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import time

from dccommon.exceptions import LoadMaxReached
from dcmanager.common import consts
from dcmanager.common import utils

from dcmanager.common.exceptions import StrategyStoppedException
from dcmanager.common.exceptions import VaultLoadMissingError
from dcmanager.db import api as db_api
from dcmanager.orchestrator.states.base import BaseState
from dcmanager.orchestrator.states.upgrade.cache.cache_specifications import \
    REGION_ONE_SYSTEM_INFO_CACHE_TYPE
from dcmanager.orchestrator.states.upgrade.cache.cache_specifications import \
    REGION_ONE_SYSTEM_LOAD_CACHE_TYPE

# Max time: 30 minutes = 180 queries x 10 seconds between
DEFAULT_MAX_QUERIES = 180
DEFAULT_SLEEP_DURATION = 10
MAX_FAILED_RETRIES = 5
LOAD_IMPORT_REQUEST_TYPE = 'import'
LOAD_DELETE_REQUEST_TYPE = 'delete'


class ImportingLoadState(BaseState):
    """Upgrade state for importing a load"""

    def __init__(self, region_name):
        super(ImportingLoadState, self).__init__(
            next_state=consts.STRATEGY_STATE_UPDATING_PATCHES,
            region_name=region_name)
        # max time to wait (in seconds) is: sleep_duration * max_queries
        self.sleep_duration = DEFAULT_SLEEP_DURATION
        self.max_queries = DEFAULT_MAX_QUERIES
        self.max_load_import_retries = MAX_FAILED_RETRIES

    def get_load(self, strategy_step, request_info):
        self.info_log(strategy_step, "Checking load state...")
        load_id = request_info.get('load_id')
        load_version = request_info.get('load_version')
        request_type = request_info.get('type')

        load = None
        try:
            if request_type == LOAD_DELETE_REQUEST_TYPE:
                self.info_log(strategy_step, "Retrieving load list from subcloud...")
                # success when only one load, the active load, remains
                if len(self.get_sysinv_client(
                        strategy_step.subcloud.region_name).get_loads()) == 1:
                    msg = "Load: %s has been removed." % load_version
                    self.info_log(strategy_step, msg)
                    return True
            else:
                load = self.get_sysinv_client(
                    strategy_step.subcloud.region_name).get_load(load_id)
                if load.state == consts.IMPORTED_LOAD_STATE:
                    # success when load is imported
                    msg = "Load: %s is now: %s" % (load_version,
                                                   load.state)
                    self.info_log(strategy_step, msg)
                    return True
        except Exception as exception:
            self.warn_log(strategy_step,
                          "Encountered exception: %s, "
                          "retry load operation %s."
                          % (str(exception), request_type))

        if load and load.state == consts.ERROR_LOAD_STATE:
            self.error_log(strategy_step,
                           "Load %s failed import" % load_version)
            raise Exception("Failed to import load. Please check sysinv.log "
                            "on the subcloud for details.")

        # return False to allow for retry if not at limit
        return False

    def _wait_for_request_to_complete(self, strategy_step, request_info):
        counter = 0
        request_type = request_info.get('type')

        while True:
            # If event handler stop has been triggered, fail the state
            if self.stopped():
                raise StrategyStoppedException()

            # query for load operation success
            if self.get_load(strategy_step, request_info):
                break

            counter += 1
            self.debug_log(
                strategy_step,
                "Waiting for load %s to complete, iter=%d" % (request_type, counter))
            if counter >= self.max_queries:
                raise Exception("Timeout waiting for %s to complete"
                                % request_type)
            time.sleep(self.sleep_duration)

    def _get_subcloud_load_info(self, strategy_step, target_version):
        load_info = {}
        # Check if the load is already imported by checking the version
        current_loads = self.get_sysinv_client(
            strategy_step.subcloud.region_name).get_loads()

        for load in current_loads:
            if load.software_version == target_version:
                load_info['load_id'] = load.id
                load_info['load_version'] = load.software_version
                self.info_log(strategy_step,
                              "Load:%s already found" % target_version)
                return True, load_info
            elif load.state == consts.IMPORTED_LOAD_STATE or \
                    load.state == consts.ERROR_LOAD_STATE:
                load_info['load_id'] = load.id
                load_info['load_version'] = load.software_version

        return False, load_info

    def perform_state_action(self, strategy_step):
        """Import a load on a subcloud

        Returns the next state in the state machine on success.
        Any exceptions raised by this method set the strategy to FAILED.
        """

        # determine the version of the system controller in region one
        target_version = self._read_from_cache(REGION_ONE_SYSTEM_INFO_CACHE_TYPE)\
            .software_version

        load_applied, req_info =\
            self._get_subcloud_load_info(strategy_step, target_version)

        if load_applied:
            return self.next_state

        load_id_to_be_deleted = req_info.get('load_id')

        if load_id_to_be_deleted is not None:
            self.info_log(strategy_step,
                          "Deleting load %s..." % load_id_to_be_deleted)
            self.get_sysinv_client(strategy_step.subcloud.region_name).\
                delete_load(load_id_to_be_deleted)
            req_info['type'] = LOAD_DELETE_REQUEST_TYPE
            self._wait_for_request_to_complete(strategy_step, req_info)

        subcloud_type = self.get_sysinv_client(
            strategy_step.subcloud.region_name).get_system().system_mode
        load_import_retry_counter = 0
        load = None
        if subcloud_type == consts.SYSTEM_MODE_SIMPLEX:
            # For simplex we only import the load record, not the entire ISO
            loads = self._read_from_cache(REGION_ONE_SYSTEM_LOAD_CACHE_TYPE)
            matches = [
                load for load in loads if load.software_version == target_version]
            target_load = matches[0].to_dict()
            # Send only the required fields
            creation_keys = ['software_version',
                             'compatible_version',
                             'required_patches']
            target_load = {key: target_load[key] for key in creation_keys}
            try:
                load = self.get_sysinv_client(strategy_step.subcloud.region_name).\
                    import_load_metadata(target_load)
                self.info_log(strategy_step,
                              "Load: %s is now: %s" % (
                                  load.software_version, load.state))
            except Exception as e:
                msg = ("Failed to import load metadata. %s" %
                       str(e))
                db_api.subcloud_update(
                    self.context, strategy_step.subcloud_id,
                    error_description=msg[0:consts.ERROR_DESCRIPTION_LENGTH])
                self.error_log(strategy_step, msg)
                raise
        else:
            while True:
                # If event handler stop has been triggered, fail the state
                if self.stopped():
                    raise StrategyStoppedException()

                load_import_retry_counter += 1
                try:
                    # ISO and SIG files are found in the vault under a version
                    # directory
                    self.info_log(strategy_step, "Getting vault load files...")
                    iso_path, sig_path = utils.get_vault_load_files(target_version)

                    if not iso_path:
                        message = (
                            "Failed to get upgrade load info for subcloud %s" %
                            strategy_step.subcloud.name)
                        raise Exception(message)

                    # Call the API. import_load blocks until the load state is
                    # 'importing'
                    self.info_log(strategy_step, "Sending load import request...")
                    load = self.get_sysinv_client(
                        strategy_step.subcloud.region_name
                    ).import_load(iso_path, sig_path)

                    break
                except VaultLoadMissingError:
                    raise
                except LoadMaxReached:
                    # A prior import request may have encountered an exception but
                    # the request actually continued with the import operation in the
                    # subcloud. This has been observed when performing multiple
                    # parallel upgrade in which resource/link may be saturated.
                    # In such case allow continue for further checks
                    # (i.e. at wait_for_request_to_complete)
                    self.info_log(strategy_step,
                                  "Load at max number of loads")
                    break
                except Exception as e:
                    self.warn_log(strategy_step,
                                  "load import retry required due to %s iter: %d" %
                                  (e, load_import_retry_counter))
                    if load_import_retry_counter >= self.max_load_import_retries:
                        self.error_log(strategy_step, str(e))
                        raise Exception("Failed to import load. Please check "
                                        "sysinv.log on the subcloud for details.")

                time.sleep(self.sleep_duration)

            if load is None:
                _, load_info = self._get_subcloud_load_info(
                    strategy_step, target_version)
                load_id = load_info.get('load_id')
                software_version = load_info['load_version']
            else:
                load_id = load.id
                software_version = load.software_version

            if not load_id:
                raise Exception("The subcloud load was not found.")

            if software_version != target_version:
                raise Exception("The imported load was not the expected version.")
            try:
                self.info_log(
                    strategy_step,
                    "Load import request accepted, load software version = %s"
                    % software_version)
                req_info['load_id'] = load_id
                req_info['load_version'] = target_version
                req_info['type'] = LOAD_IMPORT_REQUEST_TYPE
                self.info_log(
                    strategy_step,
                    "Waiting for state to change from importing to imported...")
                self._wait_for_request_to_complete(strategy_step, req_info)
            except Exception as e:
                self.error_log(strategy_step, str(e))
                raise Exception("Failed to import load. Please check sysinv.log on "
                                "the subcloud for details.")

        # When we return from this method without throwing an exception, the
        # state machine can proceed to the next state
        return self.next_state
