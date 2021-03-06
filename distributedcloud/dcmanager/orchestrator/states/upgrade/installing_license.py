#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.orchestrator.states.base import BaseState

# When a license is not installed, this will be part of the API error string
LICENSE_FILE_NOT_FOUND_SUBSTRING = "License file not found"


class InstallingLicenseState(BaseState):
    """Upgrade state action for installing a license"""

    def __init__(self, region_name):
        super(InstallingLicenseState, self).__init__(
            next_state=consts.STRATEGY_STATE_IMPORTING_LOAD, region_name=region_name)

    @staticmethod
    def license_up_to_date(target_license, existing_license):
        return target_license == existing_license

    def perform_state_action(self, strategy_step):
        """Install the License for a software upgrade in this subcloud

        Returns the next state in the state machine on success.
        Any exceptions raised by this method set the strategy to FAILED.
        """

        # check if the the system controller has a license
        local_sysinv_client = \
            self.get_sysinv_client(consts.DEFAULT_REGION_NAME)
        system_controller_license = local_sysinv_client.get_license()
        # get_license returns a dictionary with keys: content and error
        # 'content' can be an empty string in success or failure case.
        # 'error' is an empty string only in success case.
        target_license = system_controller_license.get('content')
        target_error = system_controller_license.get('error')

        # If the system controller does not have a license, do not attempt
        # to install licenses on subclouds, simply proceed to the next stage
        if len(target_error) != 0:
            if LICENSE_FILE_NOT_FOUND_SUBSTRING in target_error:
                self.info_log(strategy_step,
                              "System Controller License missing: %s."
                              % target_error)
                return self.next_state
            else:
                # An unexpected error occurred querying the license
                raise exceptions.LicenseInstallError(
                    subcloud_id=consts.SYSTEM_CONTROLLER_NAME)

        # retrieve the keystone session for the subcloud and query its license
        subcloud_sysinv_client = \
            self.get_sysinv_client(strategy_step.subcloud.name)
        subcloud_license_response = subcloud_sysinv_client.get_license()
        subcloud_license = subcloud_license_response.get('content')
        subcloud_error = subcloud_license_response.get('error')

        # Skip license install if the license is already up to date
        # If there was not an error, there might be a license
        if len(subcloud_error) == 0:
            if self.license_up_to_date(target_license, subcloud_license):
                self.info_log(strategy_step, "License up to date.")
                return self.next_state
            else:
                self.debug_log(strategy_step, "License mismatch. Updating.")
        else:
            self.debug_log(strategy_step, "License missing. Installing.")

        # Install the license
        install_rc = subcloud_sysinv_client.install_license(target_license)
        install_error = install_rc.get('error')
        if len(install_error) != 0:
            raise exceptions.LicenseInstallError(
                subcloud_id=strategy_step.subcloud_id)

        # The license has been successfully installed. Move to the next stage
        self.info_log(strategy_step, "License installed.")
        return self.next_state
