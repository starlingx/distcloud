#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Class for kube rootca strategy validations

It defines methods used in dcmanager orchestrator's to handle the strategy
by its type.
"""

from oslo_log import log as logging

from dccommon import consts as dccommon_consts
from dcmanager.common import consts
from dcmanager.orchestrator.validators.base import StrategyValidationBase

LOG = logging.getLogger(__name__)


class KubeRootCaStrategyValidator(StrategyValidationBase):
    """Class for kube rootca strategy validations"""

    def __init__(self):
        super().__init__()

        self.endpoint_type = dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA
        self.accepts_force = True

    def build_extra_args(self, payload):
        """Builds the extra args for a strategy

        In case the strategy does not accept extra args, None is returned.

        :param payload: strategy request payload
        """

        return {
            consts.EXTRA_ARGS_EXPIRY_DATE: payload.get(consts.EXTRA_ARGS_EXPIRY_DATE),
            consts.EXTRA_ARGS_SUBJECT: payload.get(consts.EXTRA_ARGS_SUBJECT),
            consts.EXTRA_ARGS_CERT_FILE: payload.get(consts.EXTRA_ARGS_CERT_FILE),
        }

    def build_sync_status_filter(self, force):
        """Builds the sync status filter for valid subclouds

        :param force: if the strategy should be forced to execute
        :return: sync status to filter
        :rtype: list
        """

        if force:
            return [
                dccommon_consts.SYNC_STATUS_IN_SYNC,
                dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
            ]
        return [dccommon_consts.SYNC_STATUS_OUT_OF_SYNC]
