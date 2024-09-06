#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dccommon.drivers.openstack import software_v1
from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.common import utils
from dcmanager.db import api as db_api
from dcmanager.orchestrator.states.base import BaseState
from dcmanager.orchestrator.states.software.cache.cache_specifications import (
    REGION_ONE_RELEASE_USM_CACHE_TYPE,
)
from dcorch.rpc import client as dcorch_rpc_client


class FinishStrategyState(BaseState):
    """Finish Software Strategy software orchestration state"""

    def __init__(self, region_name):
        super().__init__(
            next_state=consts.STRATEGY_STATE_COMPLETE,
            region_name=region_name,
        )

    @staticmethod
    def _get_software_version(subcloud_releases: list):
        for release in subcloud_releases:
            if release["state"] == "deployed":
                return utils.get_major_release(release["sw_version"])

    def _finalize_upgrade(self, strategy_step, subcloud_releases: list):
        software_version = self._get_software_version(subcloud_releases)

        if not software_version:
            details = "Unable to find a deployed release after deployment"
            self.handle_exception(
                strategy_step, details, exceptions.SoftwareFinishStrategyException
            )

        if strategy_step.subcloud.software_version != software_version:
            dcorch_rpc = dcorch_rpc_client.EngineWorkerClient()
            dcorch_rpc.update_subcloud_version(
                self.context, self.region_name, software_version
            )

        # Update the database with the software version and deploy status to complete
        db_api.subcloud_update(
            self.context,
            strategy_step.subcloud_id,
            software_version=software_version,
            deploy_status=consts.DEPLOY_STATE_DONE,
        )

        return self.next_state

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
        except Exception as exc:
            details = "Cannot retrieve subcloud releases."
            self.handle_exception(
                strategy_step,
                details,
                exceptions.SoftwareFinishStrategyException,
                exc=exc,
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

        return self._finalize_upgrade(strategy_step, subcloud_releases)

    def _handle_release_delete(
        self, strategy_step, software_client, releases_to_delete
    ):
        self.info_log(strategy_step, f"Deleting releases {releases_to_delete}")
        try:
            software_client.delete(releases_to_delete)
        except Exception as exc:
            details = "Cannot delete releases from subcloud."
            self.handle_exception(
                strategy_step,
                details,
                exceptions.SoftwareFinishStrategyException,
                exc=exc,
            )

    def _handle_deploy_commit(self, strategy_step, software_client, releases_to_commit):
        raise NotImplementedError()

    # If there are releases in deploying state and it's deployed in the regionone,
    # they should be finished executing the deploy delete operation.
    # TODO(nicodemos): This will be removed after VIM Deploy Orchestration handles
    # the software deploy delete operation.
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
            raise exceptions.SoftwareFinishStrategyException(
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
            raise exceptions.SoftwareFinishStrategyException(
                subcloud=strategy_step.subcloud.name,
                details=message,
            )
