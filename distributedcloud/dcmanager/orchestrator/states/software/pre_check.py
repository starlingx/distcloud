#
# Copyright (c) 2023-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import re
import time

from dccommon.drivers.openstack import software_v1
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
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

# TODO(nicodemos): Remove these constants once upgrades can be started from either
# controller (currently only works when controller-0 is active).
# When a swact occurs, services become unavailable and API calls may fail.
# The max time allowed here is 5 minutes (ie: 30 queries with 10 secs sleep)
DEFAULT_MAX_FAILED_QUERIES = 30
# After a swact, there is a sleep before proceeding to the next state
# Added another minute to ensure controller is stable
DEFAULT_SWACT_SLEEP = 60
DEFAULT_SLEEP_DURATION = 10


class PreCheckState(BaseState):
    """Pre check software orchestration state"""

    def __init__(self, region_name, strategy):
        super().__init__(
            next_state=consts.STRATEGY_STATE_SW_INSTALL_LICENSE,
            region_name=region_name,
            strategy=strategy,
        )
        self._subcloud_releases = None
        # max time to wait (in seconds) is: sleep_duration * max_queries
        self.sleep_duration = DEFAULT_SLEEP_DURATION
        self.max_failed_queries = DEFAULT_MAX_FAILED_QUERIES

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

        extra_args = self.strategy.extra_args

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
        if strategy_step.subcloud.software_version == major_release:
            self.override_next_state(consts.STRATEGY_STATE_SW_CREATE_VIM_STRATEGY)
        else:
            # TODO(nicodemos): Remove this once upgrades can be started from either
            # controller (currently only works when controller-0 is active).
            self._check_active_controller(strategy_step)

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
        """Check if the release with release_id is prestaged in subcloud_releases.

        Args:
            strategy_step: The current strategy step.
            release_id (str): The release ID to deploy.

        Raises:
            SoftwarePreCheckFailedException: If prestaged data is required but not
                                             found.
        """

        def get_subcloud_release(releases, release_id):
            for release in releases:
                if release["release_id"] == release_id:
                    return release
            return None

        subcloud_releases = self._get_subcloud_releases(strategy_step)
        release = get_subcloud_release(subcloud_releases, release_id)
        if release:
            # Verify whether the subcloud has already deployed the release or if cleanup
            # of the available releases is still pending.
            next_state = self._process_releases_state(
                strategy_step, subcloud_releases, release, release_id
            )
            if next_state:
                self.override_next_state(next_state)
        else:
            details = f"Release {release_id} is not prestaged."
            if not self.strategy.extra_args.get(consts.EXTRA_ARGS_WITH_PRESTAGE):
                self.handle_exception(
                    strategy_step,
                    details,
                    exceptions.SoftwarePreCheckFailedException,
                )
            self.info_log(strategy_step, details)
            self.override_next_state(consts.STRATEGY_STATE_PRESTAGE_PRE_CHECK)

    def _process_releases_state(
        self, strategy_step, subcloud_releases, release, release_id
    ):
        """Processes the state of software releases for a subcloud.

        Determines the highest available and deployed releases from the provided
        subcloud releases. If the highest deployed release matches the strategy
        release, marks the strategy step as complete. Depending on the state of the
        highest release, overrides the next strategy state accordingly.
        If the subcloud is already prestaged but the with_prestage option is enabled,
        runs the prestage playbook to check for new prestage images.

        Args:
            strategy_step: The current strategy step object.
            subcloud_releases (list): List of releases for the subcloud.
            release (dict): The release prestaged.
            release_id (str): The identifier of the release.

        Side Effects:
            Logs a warning if the release is already deployed.
            Overrides the next strategy state based on release states.

        Returns:
            Next sw-deploy-strategy state
        """

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
                return consts.STRATEGY_STATE_SW_FINISH_STRATEGY
            return consts.STRATEGY_STATE_COMPLETE

        # If the subcloud is already prestaged but the with_prestage option is enabled,
        # we still need to run the prestage playbook to check whether new prestage
        # images are required.
        if self.strategy.extra_args.get(consts.EXTRA_ARGS_WITH_PRESTAGE):
            details = (
                f"Release {release_id} is already prestaged in subcloud. "
                "Prestage playbook will be executed again to check the images."
            )
            self.warn_log(strategy_step, details)
            return consts.STRATEGY_STATE_PRESTAGE_PRE_CHECK

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

    def _check_active_controller(self, strategy_step):
        """Ensure controller-0 is the active controller, performing swact if needed.

        Checks if controller-0 is the active controller. If not, initiates a swact
        operation and waits for it to complete before proceeding.

        Args:
            strategy_step: The current strategy step.

        Raises:
            SoftwarePreCheckFailedException: If client creation, swact initiation,
                                             or swact completion fails.
            StrategyStoppedException: If the strategy is stopped during execution.
        """
        try:
            sysinv_client = self.get_sysinv_client(self.get_region_name(strategy_step))
            controller_0_host = sysinv_client.get_host("controller-0")
        except Exception as exc:
            self.handle_exception(
                strategy_step,
                "Get subcloud sysinv client failed",
                exceptions.SoftwarePreCheckFailedException,
                exc=exc,
            )

        if utils.is_active_controller(controller_0_host):
            return

        self.warn_log(
            strategy_step,
            "Controller-0 is not the active controller; proceeding with swact.",
        )
        self._check_health(strategy_step, sysinv_client)

        try:
            controller_1_host = sysinv_client.get_host("controller-1")
            response = sysinv_client.swact_host(controller_1_host.id)
            if response.task != "Swacting":
                self.handle_exception(
                    strategy_step,
                    "Unable to swact to host controller-0",
                    exceptions.SoftwarePreCheckFailedException,
                )
        except Exception as exc:
            self.handle_exception(
                strategy_step,
                "Failed to initiate swact",
                exceptions.SoftwarePreCheckFailedException,
                exc=exc,
            )

        swact_fail_count = 0
        while True:
            fail_exception = None
            if self.stopped():
                raise exceptions.StrategyStoppedException()

            try:
                host = sysinv_client.get_host("controller-0")
                if utils.is_active_controller(host):
                    self.info_log(
                        strategy_step,
                        "Host: controller-0 is now the active controller.",
                    )
                    break
                swact_fail_count += 1
            except Exception as exc:
                swact_fail_count += 1
                fail_exception = exc

            if swact_fail_count >= self.max_failed_queries:
                self.handle_exception(
                    strategy_step,
                    "Timeout waiting for swact to complete. Please check "
                    "sysinv.log on the subcloud for details.",
                    exceptions.SoftwarePreCheckFailedException,
                    exc=fail_exception,
                )
            time.sleep(self.sleep_duration)

        self.info_log(
            strategy_step,
            f"Waiting {DEFAULT_SWACT_SLEEP} seconds before proceeding",
        )
        time.sleep(DEFAULT_SWACT_SLEEP)

        # Final verification that controller-0 is still active after sleep
        try:
            host = sysinv_client.get_host("controller-0")
            if not utils.is_active_controller(host):
                self.handle_exception(
                    strategy_step,
                    "Controller-0 is no longer active after swact completion",
                    exceptions.SoftwarePreCheckFailedException,
                )
        except Exception as exc:
            self.handle_exception(
                strategy_step,
                "Failed to verify controller-0 status after swact",
                exceptions.SoftwarePreCheckFailedException,
                exc=exc,
            )

    def _check_health(self, strategy_step, sysinv_client: SysinvClient):
        """Check subcloud system health before proceeding with software operations.

        Validates system health by checking for failed components and management
        affecting alarms. Acceptable conditions are:
        - Completely healthy system (no failed checks)
        - Only non-management affecting alarms
        - Single alarm check failure with non-management affecting alarms only

        Args:
            strategy_step: The current strategy step.
            sysinv_client: System inventory client for health queries.

        Raises:
            SoftwarePreCheckFailedException: If system health check fails due to
                                             management affecting issues.
        """

        self.info_log(
            strategy_step, f"Checking {strategy_step.subcloud.name} system health"
        )
        system_health = sysinv_client.get_system_health()
        fails = re.findall(r"\[Fail\]", system_health)
        failed_alarm_check = re.findall(r"No alarms: \[Fail\]", system_health)
        no_mgmt_alarms = re.findall(
            r"\[0\] of which are management affecting", system_health
        )

        # The health conditions acceptable for upgrade are:
        # a) subcloud is completely healthy (i.e. no failed checks)
        # b) subcloud only fails alarm check and it only has non-management
        #    affecting alarm(s)
        if (len(fails) == 0) or (
            len(fails) == 1 and failed_alarm_check and no_mgmt_alarms
        ):
            self.info_log(strategy_step, "Health check passed.")
            return

        if not failed_alarm_check:
            # Health check failure: no alarms involved
            #
            # These could be Kubernetes or other related failure(s) which has not been
            # been converted into an alarm condition.
            details = (
                "System health check failed. Please run 'system health-query' command "
                f"on the subcloud or {consts.ERROR_DESC_CMD} on central for details"
            )
            self.handle_exception(
                strategy_step,
                details,
                exceptions.SoftwarePreCheckFailedException,
            )
        else:
            if len(fails) == 1:
                try:
                    fm_client = self.get_fm_client(strategy_step.subcloud.name)
                except Exception:
                    # if getting the token times out, the orchestrator may have
                    # restarted and subcloud may be offline; so will attempt
                    # to use the persisted values
                    message = (
                        f"Subcloud {strategy_step.subcloud.name} failed to get "
                        "FM client"
                    )
                    self.handle_exception(
                        strategy_step,
                        message,
                        exceptions.SoftwarePreCheckFailedException,
                    )
                # Healthy check failure: exclusively alarms related
                alarms = fm_client.get_alarms()
                for alarm in alarms:
                    if alarm.mgmt_affecting == "True":
                        details = (
                            f"System health check failed due to alarm {alarm.alarm_id}."
                            " Please run 'system health-query' command on the subcloud "
                            f"or {consts.ERROR_DESC_CMD} on central for details."
                        )
                        self.handle_exception(
                            strategy_step,
                            details,
                            exceptions.SoftwarePreCheckFailedException,
                        )
            else:
                # Multiple failures
                details = (
                    "System health check failed due to multiple failures. "
                    "Please run 'system health-query' command on the "
                    f"subcloud or {consts.ERROR_DESC_CMD} on central for details."
                )
                self.handle_exception(
                    strategy_step,
                    details,
                    exceptions.SoftwarePreCheckFailedException,
                )
