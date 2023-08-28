#
# Copyright (c) 2020-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dccommon import consts as dccommon_consts
from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.db import api as db_api
from dcmanager.orchestrator.states.base import BaseState
from dcmanager.orchestrator.states.upgrade.cache.cache_specifications import \
    REGION_ONE_LICENSE_CACHE_TYPE

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

        # check if the system controller has a license
        system_controller_license = self._read_from_cache(
            REGION_ONE_LICENSE_CACHE_TYPE)
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
                message = (
                    'An unexpected error occurred querying the license %s. '
                    'Detail: %s' % (dccommon_consts.SYSTEM_CONTROLLER_NAME,
                                    target_error))
                db_api.subcloud_update(
                    self.context, strategy_step.subcloud_id,
                    error_description=message[0:consts.ERROR_DESCRIPTION_LENGTH])
                raise exceptions.LicenseInstallError(
                    subcloud_id=dccommon_consts.SYSTEM_CONTROLLER_NAME,
                    error_message=target_error)

        # retrieve the keystone session for the subcloud and query its license
        subcloud_sysinv_client = \
            self.get_sysinv_client(strategy_step.subcloud.region_name)
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
            # Save error response from sysinv into subcloud error description.
            # Provide exception with sysinv error response to strategy_step details
            message = ('Error installing license on subcloud %s. Detail: %s' %
                       (strategy_step.subcloud.name,
                        install_error))
            db_api.subcloud_update(
                self.context, strategy_step.subcloud_id,
                error_description=message[0:consts.ERROR_DESCRIPTION_LENGTH])
            raise exceptions.LicenseInstallError(
                subcloud_id=strategy_step.subcloud_id,
                error_message=install_error)

        # The license has been successfully installed. Move to the next stage
        self.info_log(strategy_step, "License installed.")
        return self.next_state
