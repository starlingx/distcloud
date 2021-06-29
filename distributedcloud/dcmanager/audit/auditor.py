#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import abc
import six

from dcmanager.common import consts


class Auditor(object):
    """Abstract class that manages tasks related to types of audits."""

    # todo(abailey): determine if add_metaclass is still required
    six.add_metaclass(abc.ABCMeta)

    def __init__(self, context, dcmanager_rpc_client, endpoint_type):
        self.context = context
        self.dcmanager_rpc_client = dcmanager_rpc_client
        self.endpoint_type = endpoint_type

    def _set_subcloud_sync_status(self, sc_name, sc_sync_status):
        """Update the sync status for endpoint."""
        self.dcmanager_rpc_client.update_subcloud_endpoint_status(
            self.context,
            subcloud_name=sc_name,
            endpoint_type=self.endpoint_type,
            sync_status=sc_sync_status)

    def set_subcloud_endpoint_in_sync(self, sc_name):
        """Set the endpoint sync status of this subcloud to be in sync"""
        self._set_subcloud_sync_status(sc_name, consts.SYNC_STATUS_IN_SYNC)

    def set_subcloud_endpoint_out_of_sync(self, sc_name):
        """Set the endpoint sync status of this subcloud to be out of sync"""
        self._set_subcloud_sync_status(sc_name, consts.SYNC_STATUS_OUT_OF_SYNC)

    @abc.abstractmethod
    def get_regionone_audit_data(self):
        """Query RegionOne for audit information to compare against."""

    @abc.abstractmethod
    def subcloud_audit(self, subcloud_name, region_one_audit_data):
        """Query Subcloud audit information and compare with regionone data

        This method is responsible for calling:
          - set_sc_endpoint_in_sync
          - set_sc_endpoint_out_of_sync
        """
