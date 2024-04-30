#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dccommon.drivers.openstack import software_v1
from dcmanager.common import consts
from dcmanager.common.exceptions import StrategyStoppedException
from dcmanager.orchestrator.states.base import BaseState
from dcmanager.orchestrator.states.software.cache.cache_specifications import \
    REGION_ONE_RELEASE_USM_CACHE_TYPE


class FinishStrategyState(BaseState):
    """Finish Software Strategy software orchestration state"""

    def __init__(self, region_name):
        super().__init__(
            next_state=consts.STRATEGY_STATE_COMPLETE,
            region_name=region_name,
        )

    def perform_state_action(self, strategy_step):
        """Finish Software Strategy"""

        self.info_log(strategy_step, "Finishing software strategy")

        regionone_committed_releases = self._read_from_cache(
            REGION_ONE_RELEASE_USM_CACHE_TYPE,
            state=software_v1.COMMITTED
        )

        self.debug_log(
            strategy_step,
            f"regionone_committed_releases: {regionone_committed_releases}"
        )

        try:
            software_client = self.get_software_client(self.region_name)
            subcloud_releases = software_client.list()
        except Exception:
            message = ("Cannot retrieve subcloud releases. Please see logs for "
                       "details.")
            self.exception_log(strategy_step, message)
            raise Exception(message)

        self.debug_log(strategy_step,
                       f"Releases for subcloud: {subcloud_releases}")

        releases_to_commit = list()
        releases_to_delete = list()

        # For this subcloud, determine which releases should be committed and
        # which should be deleted.
        releases_to_delete = [
            release["release_id"] for release in subcloud_releases
            if release["state"] in (software_v1.AVAILABLE, software_v1.UNAVAILABLE)
        ]
        releases_to_commit = [
            release["release_id"] for release in subcloud_releases
            if release["state"] == software_v1.DEPLOYED
            and any(
                release["release_id"] == release_regionone["release_id"]
                for release_regionone in regionone_committed_releases
            )
        ]

        if releases_to_delete:
            self.info_log(strategy_step, f"Deleting releases {releases_to_delete}")
            try:
                software_client.delete(releases_to_delete)
            except Exception:
                message = ("Cannot delete releases from subcloud. Please see "
                           "logs for details.")
                self.exception_log(strategy_step, message)
                raise Exception(message)

        if self.stopped():
            raise StrategyStoppedException()

        if releases_to_commit:
            self.info_log(strategy_step,
                          f"Committing releases {releases_to_commit} to subcloud")
            try:
                software_client.commit_patch(releases_to_commit)
            except Exception:
                message = ("Cannot commit releases to subcloud. Please see logs for "
                           "details.")
                self.exception_log(strategy_step, message)
                raise Exception(message)

        return self.next_state
