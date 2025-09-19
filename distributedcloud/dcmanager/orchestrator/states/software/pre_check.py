#
# Copyright (c) 2023-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dccommon.drivers.openstack import software_v1
from dccommon.drivers.openstack import vim
from dccommon import exceptions as vim_exc
from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.common import utils
from dcmanager.orchestrator.cache import cache_specifications
from dcmanager.orchestrator.states.base import BaseState

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
        self._subcloud_releases = None

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
            self.info_log(
                strategy_step,
                f"Subcloud has an existing {vim.STRATEGY_NAME_SW_USM} strategy.",
            )
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

        extra_args = utils.get_sw_update_strategy_extra_args(self.context)

        if self._validate_extra_args_rollback(extra_args, strategy_step):
            return self.next_state

        if extra_args.get(consts.EXTRA_ARGS_DELETE_ONLY):
            self.info_log(strategy_step, "Delete only requested.")
            self.override_next_state(consts.STRATEGY_STATE_SW_FINISH_STRATEGY)
            return self.next_state

        release_id = extra_args.get(consts.EXTRA_ARGS_RELEASE_ID)

        major_release = utils.get_major_release(release_id)

        # Remove state restriction for N-1 release
        state_filter = (
            None if major_release < utils.tsc.SW_VERSION else software_v1.DEPLOYED
        )

        # Get the release with release_id in RegionOne releases
        regionone_releases = self._read_from_cache(
            cache_specifications.REGION_ONE_RELEASE_USM_CACHE_TYPE,
            release_id=release_id,
            state=state_filter,
        )

        self.debug_log(strategy_step, f"RegionOne release: {regionone_releases}")

        # Check if the release is in RegionOne
        if not regionone_releases:
            details = f"Release {release_id} not found or not deployed in RegionOne"
            self.handle_exception(
                strategy_step,
                details,
                exceptions.SoftwarePreCheckFailedException,
            )

        # We should skip the install_license state if it's a minor release.
        if strategy_step.subcloud.software_version == utils.extract_version(release_id):
            self.override_next_state(consts.STRATEGY_STATE_SW_CREATE_VIM_STRATEGY)

        self.info_log(strategy_step, f"Check prestaged data for release: {release_id}")
        self._check_prestaged_data(
            strategy_step,
            release_id,
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
            details = (
                f"{vim.STRATEGY_NAME_SW_USM} strategy is currently executing and "
                "a new strategy cannot be created."
            )
            self.handle_exception(
                strategy_step,
                details,
                exceptions.SoftwarePreCheckFailedException,
                state=strategy_state,
            )

    def _get_subcloud_releases(self, strategy_step) -> list:
        """Retrieve the list of subcloud software releases.

        If the releases have already been fetched and cached, returns the cached list.
        Otherwise, fetches the list from the software client associated with the current
        region, logs the retrieved releases, and caches the result.

        Args:
            strategy_step: The current strategy step, used for logging and exception.

        Returns:
            list: A list of subcloud software releases.

        Raises:
            SoftwarePreCheckFailedException: If subcloud software list fails.
        """
        if self._subcloud_releases is not None:
            return self._subcloud_releases
        try:
            software_client = self.get_software_client(self.region_name)
            self._subcloud_releases = software_client.list()
            self.debug_log(
                strategy_step, f"Subcloud releases: {self._subcloud_releases}"
            )
            return self._subcloud_releases
        except Exception as exc:
            self.handle_exception(
                strategy_step,
                "Subcloud software list failed.",
                exceptions.SoftwarePreCheckFailedException,
                exc=exc,
            )

    def _check_prestaged_data(
        self,
        strategy_step,
        release_id,
    ):
        """Check if the release with release_id is prestaged in subcloud_releases"""

        def get_subcloud_release(releases, release_id):
            for release in releases:
                if release["release_id"] == release_id:
                    return release
            return None

        subcloud_releases = self._get_subcloud_releases(strategy_step)
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
        highest_release = max(
            (
                release
                for release in subcloud_releases
                if release["state"] != software_v1.UNAVAILABLE
            ),
            key=lambda release: release["sw_version"],
        )
        highest_deployed_release = max(
            (
                release
                for release in subcloud_releases
                if release["state"] == software_v1.DEPLOYED
            ),
            key=lambda release: release["sw_version"],
        )

        # If the software audit did not run due to an invalid deploy_status,
        # leaving the subcloud out-of-sync, but the highest release in the list is the
        # same as the user specified release and the release state is in 'deployed'
        # state, we can just mark it as complete.
        if highest_deployed_release["release_id"] == release["release_id"]:
            details = f"Release {release_id} is already deployed in subcloud."
            self.warn_log(strategy_step, details)
            # If the highest release is in the 'available' state we should delete
            # in the STRATEGY_STATE_SW_FINISH_STRATEGY
            if highest_release["state"] == software_v1.AVAILABLE:
                self.override_next_state(consts.STRATEGY_STATE_SW_FINISH_STRATEGY)
            else:
                self.override_next_state(consts.STRATEGY_STATE_COMPLETE)

    def _validate_extra_args_rollback(
        self, extra_args: dict, strategy_step: str
    ) -> bool:
        """Validate the rollback from extra args and decide next state.

        If rollback requested:
          - If ANY subcloud release is in DEPLOYING, proceed to create VIM strategy.
          - Otherwise, there is no release to rollback
        Returns True if rollback was requested and handled.
        """
        if not extra_args.get(consts.EXTRA_ARGS_ROLLBACK):
            return False
        try:
            sysinv_client = self.get_sysinv_client(self.region_name)
        except Exception as exc:
            self.handle_exception(
                strategy_step,
                "Get sysinv client failed",
                exceptions.SoftwarePreCheckFailedException,
                exc=exc,
            )
        if sysinv_client.get_system().system_mode != consts.SYSTEM_MODE_SIMPLEX:
            self.handle_exception(
                strategy_step,
                "Rollback is only allowed for simplex systems",
                exceptions.SoftwarePreCheckFailedException,
            )

        subcloud_releases = self._get_subcloud_releases(strategy_step)

        # VIM strategy can only rollback to a release in DEPLOYING state with a deploy
        # status of 'start-failed', 'host-failed', or 'active-failed'.
        # Note: the release state comes from 'software release show',
        # and the deploy state comes from 'software deploy show'.
        # The VIM strategy will check the deploy state when deciding if rollback is
        # possible.
        has_deploying = any(
            release.get("state") == software_v1.DEPLOYING
            for release in subcloud_releases
        )

        if has_deploying:
            self.info_log(
                strategy_step,
                "Rollback requested: creating VIM rollback strategy.",
            )
            self.override_next_state(consts.STRATEGY_STATE_SW_CREATE_VIM_STRATEGY)
        else:
            self.info_log(
                strategy_step,
                "Rollback requested but no release available to rollback to.",
            )
            self.override_next_state(consts.STRATEGY_STATE_COMPLETE)
        return True
