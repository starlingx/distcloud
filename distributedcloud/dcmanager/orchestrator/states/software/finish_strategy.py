#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dccommon.drivers.openstack import software_v1
from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.orchestrator.states.base import BaseState
from dcmanager.orchestrator.states.software.cache.cache_specifications import (
    REGION_ONE_RELEASE_USM_CACHE_TYPE,
)


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

        regionone_deployed_releases = self._read_from_cache(
            REGION_ONE_RELEASE_USM_CACHE_TYPE, state=software_v1.DEPLOYED
        )

        self.debug_log(
            strategy_step,
            f"regionone_deployed_releases: {regionone_deployed_releases}",
        )

        try:
            software_client = self.get_software_client(self.region_name)
            subcloud_releases = software_client.list()
        except Exception:
            message = "Cannot retrieve subcloud releases. Please see logs for details."
            self.exception_log(strategy_step, message)
            raise exceptions.SoftwareListFailedException(
                subcloud=strategy_step.subcloud.name,
                details=message,
            )

        self.debug_log(strategy_step, f"Releases for subcloud: {subcloud_releases}")

        # For this subcloud, determine which releases should be committed,
        # which should be deleted and which should finish the deploy.
        releases_to_delete = [
            release["release_id"]
            for release in subcloud_releases
            if release["state"] in (software_v1.AVAILABLE, software_v1.UNAVAILABLE)
        ]

        # TODO(nicodemos): Update releases_to_commit and handle it after
        # `software commit` is implemented
        releases_to_commit = []

        releases_to_deploy_delete = [
            release["release_id"]
            for release in subcloud_releases
            if release["state"] == software_v1.DEPLOYING
        ]

        if releases_to_delete:
            self._handle_release_delete(
                strategy_step, software_client, releases_to_delete
            )

        if self.stopped():
            raise exceptions.StrategyStoppedException()

        if releases_to_commit:
            self._handle_deploy_commit(
                strategy_step, software_client, releases_to_commit
            )

        if releases_to_deploy_delete:
            self._handle_deploy_delete(
                strategy_step,
                software_client,
                releases_to_deploy_delete,
                regionone_deployed_releases,
            )

        return self.next_state

    def _handle_release_delete(
        self, strategy_step, software_client, releases_to_delete
    ):
        self.info_log(strategy_step, f"Deleting releases {releases_to_delete}")
        try:
            software_client.delete(releases_to_delete)
        except Exception:
            message = (
                "Cannot delete releases from subcloud. Please see logs for details."
            )
            self.exception_log(strategy_step, message)
            raise exceptions.SoftwareDeleteFailedException(
                subcloud=strategy_step.subcloud.name,
                details=message,
            )

    def _handle_deploy_commit(self, strategy_step, software_client, releases_to_commit):
        raise NotImplementedError()

    # If there are releases in deploying state and it's deployed in the regionone,
    # they should be finished executing the deploy delete operation.
    def _handle_deploy_delete(
        self,
        strategy_step,
        software_client,
        releases_to_deploy_delete,
        regionone_deployed_releases,
    ):
        if not any(
            release_id == release_regionone["release_id"]
            for release_id in releases_to_deploy_delete
            for release_regionone in regionone_deployed_releases
        ):
            message = (
                f"Deploying release found on subcloud {strategy_step.subcloud.name} "
                "and is not deployed in System Controller. Aborting."
            )
            self.error_log(strategy_step, message)
            raise exceptions.SoftwareDeployDeleteFailedException(
                subcloud=strategy_step.subcloud.name,
                details=message,
            )
        self.info_log(
            strategy_step,
            f"Finishing releases {releases_to_deploy_delete} to subcloud",
        )
        try:
            software_client.deploy_delete()
        except Exception:
            message = (
                "Cannot finish deploy delete on subcloud. Please see logs for details."
            )
            self.exception_log(strategy_step, message)
            raise exceptions.SoftwareDeployDeleteFailedException(
                subcloud=strategy_step.subcloud.name,
                details=message,
            )
