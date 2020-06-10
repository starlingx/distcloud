#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dcmanager.common import consts
from dcmanager.manager.states.base import BaseState
from dcmanager.manager.states.upgrade import utils


class ImportingLoadState(BaseState):
    """Upgrade state for importing a load"""

    def __init__(self):
        super(ImportingLoadState, self).__init__()

    def perform_state_action(self, strategy_step):
        """Import a load on a subcloud

        Any exceptions raised by this method set the strategy to FAILED
        Returning normally from this method set the strategy to the next step
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

        # Check if the load is already imported by checking what the version is
        current_loads = sysinv_client.get_loads()
        for load in current_loads:
            if load.software_version == target_version:
                self.info_log(strategy_step,
                              "Load:%s already found" % target_version)
                return True

        # If we are here, the load needs to be imported
        # ISO and SIG files are found in the vault under a version directory
        iso_path, sig_path = utils.get_vault_load_files(target_version)

        # Call the API.
        imported_load = sysinv_client.import_load(iso_path, sig_path)
        new_load = imported_load.get('new_load', {})
        if new_load.get('software_version') != target_version:
            raise Exception("The imported load was not the expected version")

        # When we return from this method without throwing an exception, the
        # state machine can proceed to the next state
        return True
