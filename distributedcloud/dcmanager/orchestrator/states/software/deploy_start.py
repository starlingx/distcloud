#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dccommon.drivers.openstack import software_v1
from dcmanager.common import consts
from dcmanager.orchestrator.states.base import BaseState
from dcmanager.orchestrator.states.software.cache.cache_specifications import \
    REGION_ONE_RELEASE_USM_CACHE_TYPE

# Max time: 1 minute = 6 queries x 10 seconds between
DEFAULT_MAX_QUERIES = 6
DEFAULT_SLEEP_DURATION = 10


class DeployStartState(BaseState):
    """Software orchestration state for deploy start releases"""

    def __init__(self, region_name):
        super(DeployStartState, self).__init__(
            next_state=consts.STRATEGY_STATE_SW_DEPLOY_HOST,
            region_name=region_name)
        self.max_queries = DEFAULT_MAX_QUERIES
        self.sleep_duration = DEFAULT_SLEEP_DURATION

    def _get_deployed_controller_patches(self):
        regionone_releases = self._read_from_cache(REGION_ONE_RELEASE_USM_CACHE_TYPE)
        deployed_releases = {}
        for release_id, release_info in regionone_releases.items():
            if release_info['state'] == software_v1.DEPLOYED:
                deployed_releases[release_id] = release_info
        return deployed_releases

    def perform_state_action(self, strategy_step):
        """Deploy start releases in this subcloud"""
        self.info_log(strategy_step, "Applying releases")
        deployed_releases = self._get_deployed_controller_patches()
        self.debug_log(strategy_step,
                       f"SystemController deployed releases: {deployed_releases}")

        # Find the max version deployed on the SystemController
        max_version = None
        for deployed_releases_values in deployed_releases.values():
            release_sw_version = deployed_releases_values['sw_version']
            if max_version is None or release_sw_version > max_version:
                max_version = release_sw_version

        # Retrieve all subcloud releases
        try:
            subcloud_releases = self.get_software_client(self.region_name).query()
            self.debug_log(strategy_step,
                           f"Subcloud releases: {subcloud_releases}")
        except Exception:
            message = ("Cannot retrieve subcloud releases. Please see logs for "
                       "details.")
            self.exception_log(strategy_step, message)
            raise Exception(message)

        deploy_start_release = None

        for release_id in subcloud_releases:
            is_reboot_required = subcloud_releases[release_id][
                'reboot_required'] == "Y"
            is_available = subcloud_releases[release_id]['state'] == (
                software_v1.AVAILABLE)
            is_deployed = subcloud_releases[release_id]['state'] == (
                software_v1.DEPLOYED)
            release_sw_version = subcloud_releases[release_id]['sw_version']

            # Check if any release is reboot required
            if deployed_releases.get(
                    release_id) and is_available and is_reboot_required:
                self.override_next_state(consts.STRATEGY_STATE_SW_LOCK_CONTROLLER)

            # Get the only release needed to be deployed
            if (is_deployed and release_sw_version == max_version) or (
                    is_available and release_sw_version == max_version):
                deploy_start_release = release_id

        if deploy_start_release:
            self.info_log(strategy_step,
                          f"Deploy start release {deploy_start_release} to subcloud")
            try:
                self.get_software_client(self.region_name).deploy_start(
                    deploy_start_release)
            except Exception:
                message = (
                    "Cannot deploy start releases to subcloud. Please see logs "
                    "for details.")
                self.exception_log(strategy_step, message)
                raise Exception(message)
        return self.next_state
