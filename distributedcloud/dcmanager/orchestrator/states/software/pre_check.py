#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dccommon.drivers.openstack import software_v1
from dccommon.drivers.openstack import vim
from dccommon import exceptions as vim_exc
from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.common import utils
from dcmanager.orchestrator.states.base import BaseState
from dcmanager.orchestrator.states.software.cache import cache_specifications

VALID_STRATEGY_STATES = [
    vim.STATE_APPLIED,
    vim.STATE_ABORTED,
    vim.STATE_BUILD_FAILED,
    vim.STATE_BUILD_TIMEOUT,
    vim.STATE_APPLY_FAILED,
    vim.STATE_APPLY_TIMEOUT,
    vim.STATE_ABORT_FAILED,
    vim.STATE_ABORT_TIMEOUT,
]

INVALID_STRATEGY_STATES = [
    vim.STATE_READY_TO_APPLY,
    vim.STATE_BUILDING,
    vim.STATE_APPLYING,
    vim.STATE_ABORTING,
]


class PreCheckState(BaseState):
    """Pre check software orchestration state"""

    def __init__(self, region_name):
        super().__init__(
            next_state=consts.STRATEGY_STATE_SW_INSTALL_LICENSE,
            region_name=region_name,
        )

    def perform_state_action(self, strategy_step):
        """Pre check region status"""

        self.info_log(strategy_step, "Software Orchestration precheck")

        # Get current strategy for the subcloud; check type and state
        subcloud_name = strategy_step.subcloud.name
        try:
            vim_client = self.get_vim_client(self.region_name)
        except Exception as e:
            raise exceptions.SoftwarePreCheckFailedException(
                subcloud=subcloud_name,
                details=f"Failed to get VIM client: {str(e)}",
            )
        try:
            strategy = vim_client.get_current_strategy()
        except vim_exc.VIMClientException as e:
            details = (
                f"Get current strategy failed on subcloud: {subcloud_name}. "
                f"Details: {str(e)}"
            )
            self.error_log(strategy_step, details)
            raise exceptions.SoftwarePreCheckFailedException(
                subcloud=subcloud_name,
                details=details,
            )

        # Strategy format: {strategy_name: strategy_state}
        if strategy and strategy.get(vim.STRATEGY_NAME_SW_USM):
            # Check state and handle accordingly
            self._handle_sw_deploy_strategy(
                vim_client,
                strategy_step,
                strategy.get(vim.STRATEGY_NAME_SW_USM),
            )
        elif strategy:
            details = (
                f"There is an existing strategy {list(strategy.keys())[0]} on "
                f"subcloud {subcloud_name}. Aborting."
            )
            self.error_log(strategy_step, details)
            raise exceptions.SoftwarePreCheckFailedException(
                subcloud=subcloud_name,
                details=details,
            )

        # Check for prestaged data
        extra_args = utils.get_sw_update_strategy_extra_args(self.context)
        release_id = extra_args.get(consts.EXTRA_ARGS_RELEASE_ID)
        try:
            self.info_log(
                strategy_step, f"Check prestaged data for release: {release_id}"
            )
            # Get the release with release_id and state == deployed in
            # RegionOne releases
            regionone_deployed_release = self._read_from_cache(
                cache_specifications.REGION_ONE_RELEASE_USM_CACHE_TYPE,
                release_id=release_id,
                state=software_v1.DEPLOYED,
            )
            self.debug_log(
                strategy_step, f"RegionOne release: {regionone_deployed_release}"
            )
            software_client = self.get_software_client(self.region_name)
            subcloud_releases = software_client.list()
            self.debug_log(strategy_step, f"Subcloud releases: {subcloud_releases}")
        except Exception as exc:
            message = f"Cannot retrieve release list : {exc}."
            self.exception_log(strategy_step, message)
            raise exceptions.SoftwareListFailedException(
                subcloud=subcloud_name,
                details=message,
            )

        # Check if the release is deployed in RegionOne
        if not regionone_deployed_release:
            details = f"Release {release_id} is not deployed in RegionOne. Aborting."
            self.error_log(strategy_step, details)
            raise exceptions.SoftwarePreCheckFailedException(
                subcloud=subcloud_name,
                details=details,
            )

        self._check_prestaged_data(
            strategy_step,
            release_id,
            subcloud_releases,
        )

        return self.next_state

    def _handle_sw_deploy_strategy(self, vim_client, strategy_step, strategy_state):
        if strategy_state in VALID_STRATEGY_STATES:
            # If the strategy is in a valid state, delete it to create a new one
            try:
                details = f"Deleting strategy {vim.STRATEGY_NAME_SW_USM} on subcloud"
                self.info_log(strategy_step, details)
                vim_client.delete_strategy(vim.STRATEGY_NAME_SW_USM)
            except Exception:
                details = (
                    f"Delete strategy {vim.STRATEGY_NAME_SW_USM} failed on "
                    f"subcloud: {strategy_step.subcloud.name}"
                )
                self.error_log(strategy_step, details)
                raise exceptions.SoftwarePreCheckFailedException(
                    subcloud=strategy_step.subcloud.name,
                    details=details,
                )
        elif strategy_state in INVALID_STRATEGY_STATES:
            # If the strategy is in an invalid state, abort orchestration
            details = (
                f"Strategy {vim.STRATEGY_NAME_SW_USM} is in an invalid state: "
                f"{strategy_state}. Aborting."
            )
            self.error_log(strategy_step, details)
            raise exceptions.SoftwarePreCheckFailedException(
                subcloud=strategy_step.subcloud.name,
                details=details,
            )

    def _check_prestaged_data(
        self,
        strategy_step,
        release_id,
        subcloud_releases,
    ):
        # Check if the release with release_id is in subcloud_releases
        is_present_in_subcloud = any(
            release["release_id"] == release_id for release in subcloud_releases
        )
        if not is_present_in_subcloud:
            details = f"Release {release_id} is not prestaged. Aborting."
            self.error_log(strategy_step, details)
            raise exceptions.SoftwarePreCheckFailedException(
                subcloud=strategy_step.subcloud.name,
                details=details,
            )
