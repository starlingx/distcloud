#
# Copyright (c) 2023-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dccommon.drivers.openstack import software_v1
from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.common import utils
from dcmanager.db import api as db_api
from dcmanager.orchestrator.cache.cache_specifications import (
    REGION_ONE_RELEASE_USM_CACHE_TYPE,
)
from dcmanager.orchestrator.states.base import BaseState
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
