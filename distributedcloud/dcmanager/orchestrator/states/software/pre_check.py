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
        try:
            vim_client = self.get_vim_client(self.region_name)
        except Exception as exc:
            details = "Get VIM client failed."
            self.handle_exception(
                strategy_step,
                details,
                exceptions.SoftwarePreCheckFailedException,
                exc=exc,
            )
        try:
            strategy = vim_client.get_current_strategy()
        except vim_exc.VIMClientException as exc:
            details = "Get current strategy failed."
            self.handle_exception(
                strategy_step,
                details,
                exceptions.SoftwarePreCheckFailedException,
                exc=exc,
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
            details = f"Subcloud has an existing {list(strategy.keys())[0]} strategy."
            self.handle_exception(
                strategy_step,
                details,
                exceptions.SoftwarePreCheckFailedException,
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
            details = "Subcloud software list failed."
            self.handle_exception(
                strategy_step,
                details,
                exceptions.SoftwarePreCheckFailedException,
                exc=exc,
            )

        # Check if the release is deployed in RegionOne
        if not regionone_deployed_release:
            details = f"Release {release_id} is not deployed in RegionOne."
            self.handle_exception(
                strategy_step,
                details,
                exceptions.SoftwarePreCheckFailedException,
            )

        # We should skip the install_license state if it's a minor release.
        if strategy_step.subcloud.software_version == utils.extract_version(release_id):
            self.override_next_state(consts.STRATEGY_STATE_SW_CREATE_VIM_STRATEGY)

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
                details = f"Failed to delete {vim.STRATEGY_NAME_SW_USM} strategy."
                self.info_log(strategy_step, details)
                vim_client.delete_strategy(vim.STRATEGY_NAME_SW_USM)
            except Exception:
                details = f"Delete strategy {vim.STRATEGY_NAME_SW_USM} failed."
                self.handle_exception(
                    strategy_step,
                    details,
                    exceptions.SoftwarePreCheckFailedException,
                )
        elif strategy_state in INVALID_STRATEGY_STATES:
            # If the strategy is in an invalid state, abort orchestration
            details = f"{vim.STRATEGY_NAME_SW_USM} strategy is in an invalid state."
            self.handle_exception(
                strategy_step,
                details,
                exceptions.SoftwarePreCheckFailedException,
                state=strategy_state,
            )

    def _check_prestaged_data(
        self,
        strategy_step,
        release_id,
        subcloud_releases,
    ):
        """Check if the release with release_id is prestaged in subcloud_releases"""

        def get_subcloud_release(releases, release_id):
            for release in releases:
                if release["release_id"] == release_id:
                    return release
            return None

        release = get_subcloud_release(subcloud_releases, release_id)
        if not release:
            details = f"Release {release_id} is not prestaged."
            self.handle_exception(
                strategy_step,
                details,
                exceptions.SoftwarePreCheckFailedException,
            )

        # Verify whether the subcloud has already deployed the release or if cleanup
        # of the available releases is still pending.
        self._process_releases_state(
            strategy_step, subcloud_releases, release, release_id
        )

    def _process_releases_state(
        self, strategy_step, subcloud_releases, release, release_id
    ):
        # Filter out releases with state 'unavailable' and sort by 'sw_version'
        filtered_and_sorted_releases = sorted(
            (
                release
                for release in subcloud_releases
                if release["state"] != "unavailable"
            ),
            key=lambda x: x["sw_version"],
        )

        # If the software audit did not run due to an invalid deploy_status,
        # leaving the subcloud out-of-sync, but the highest release in the list is the
        # same as the user specified release and the release state is in 'deployed'
        # state, we can just mark it as complete.
        highest_release = filtered_and_sorted_releases[-1]
        if (
            highest_release["release_id"] == release["release_id"]
            and highest_release["state"] == software_v1.DEPLOYED
        ):
            details = f"Release {release_id} is already deployed in subcloud."
            self.warn_log(strategy_step, details)
            self.override_next_state(consts.STRATEGY_STATE_COMPLETE)
        # If the release is not the highest release in the list, but the latest is in
        # the 'available' state and the current release is in 'deployed,' we should
        # delete the 'available' release in the STRATEGY_STATE_SW_FINISH_STRATEGY
        elif (
            highest_release["release_id"] != release["release_id"]
            and highest_release["state"] == software_v1.AVAILABLE
            and release["state"] == software_v1.DEPLOYED
        ):
            details = f"Release {release_id} is already deployed in subcloud."
            self.warn_log(strategy_step, details)
            self.override_next_state(consts.STRATEGY_STATE_SW_FINISH_STRATEGY)
