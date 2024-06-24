#
# Copyright (c) 2021-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import abc

from dccommon import consts as dccommon_consts


class Auditor(object, metaclass=abc.ABCMeta):
    """Abstract class that manages tasks related to types of audits."""

    def __init__(self, context, dcmanager_state_rpc_client, endpoint_type):
        self.context = context
        self.state_rpc_client = dcmanager_state_rpc_client
        self.endpoint_type = endpoint_type

    def _set_subcloud_sync_status(self, sc_name, sc_region, sc_sync_status):
        """Update the sync status for endpoint."""
        self.state_rpc_client.update_subcloud_endpoint_status(
            self.context,
            subcloud_name=sc_name,
            subcloud_region=sc_region,
            endpoint_type=self.endpoint_type,
            sync_status=sc_sync_status)

    def set_subcloud_endpoint_in_sync(self, sc_name, sc_region):
        """Set the endpoint sync status of this subcloud to be in sync"""
        self._set_subcloud_sync_status(
            sc_name, sc_region, dccommon_consts.SYNC_STATUS_IN_SYNC
        )

    def set_subcloud_endpoint_out_of_sync(self, sc_name, sc_region):
        """Set the endpoint sync status of this subcloud to be out of sync"""
        self._set_subcloud_sync_status(sc_name, sc_region,
                                       dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)

    @abc.abstractmethod
    def get_regionone_audit_data(self):
        """Query RegionOne for audit information to compare against."""
