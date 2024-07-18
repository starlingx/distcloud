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
            raise exceptions.BadRequest(
                resource='strategy', msg=(
                    f'Subcloud {subcloud_name} does not require '
                    f'{self.endpoint_type} update'
                )
            )
