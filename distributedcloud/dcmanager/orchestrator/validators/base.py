#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Base class for dcmanager orchestrator's strategy validations.
"""

from oslo_log import log as logging

from dccommon import consts as dccommon_consts
from dcmanager.common import exceptions
from dcmanager.db import api as db_api

LOG = logging.getLogger(__name__)


class StrategyValidationBase(object):
    """Base class for strategy validation"""

    def __init__(self):
        self.accepts_force = False
        self.endpoint_type = None

    def validate_strategy_requirements(
        self, context, subcloud_id, subcloud_name, force=False
    ):
        """Validates the requirements for a strategy

        :param context: request context object
        :param subcloud_id: subcloud's id
        :param subcloud_name: subcloud's name
        :param force: if the strategy should be forced to execute
        :raises BadRequest: if the requirements for the strategy are not met
        """

        if self.accepts_force and force:
            return

        subcloud_status = db_api.subcloud_status_get(
            context, subcloud_id, self.endpoint_type
        )

        if subcloud_status.sync_status == dccommon_consts.SYNC_STATUS_IN_SYNC:
            msg = (
                f"Subcloud {subcloud_name} does not require {self.endpoint_type} update"
            )
            LOG.error(
                "Failed creating software update strategy of type "
                f"{self.endpoint_type}. {msg}"
            )
            raise exceptions.BadRequest(resource="strategy", msg=msg)

    def build_extra_args(self, payload):
        """Builds the extra args for a strategy

        In case the strategy does not accept extra args, None is returned.

        :param payload: strategy request payload
        """

        return None

    def build_availability_status_filter(self):
        """Builds the availability status filter for valid subclouds

        :return: availability status to filter
        :rtype: str
        """

        return dccommon_consts.AVAILABILITY_ONLINE

    def build_sync_status_filter(self, force):
        """Builds the sync status filter for valid subclouds

        :param force: if the strategy should be forced to execute
        :return: sync status to filter
        :rtype: list
        """

        return [dccommon_consts.SYNC_STATUS_OUT_OF_SYNC]
