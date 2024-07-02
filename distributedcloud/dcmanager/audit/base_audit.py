#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_log import log as logging

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.fm import FmClient
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon.utils import log_subcloud_msg
from dcmanager.audit import alarm_aggregation
from dcmanager.common import consts

LOG = logging.getLogger(__name__)


def get_subcloud_base_audit(
    sysinv_client: SysinvClient = None,
    fm_client: FmClient = None,
    subcloud_name: str = None,
):
    avail_to_set = None
    inactive_sg = None
    alarm_updates = None
    if sysinv_client:
        avail_to_set, inactive_sg = get_subcloud_availability_status(
            sysinv_client, subcloud_name
        )
    if fm_client:
        alarm_updates = alarm_aggregation.AlarmAggregation.get_alarm_summary(
            fm_client, subcloud_name
        )
    return avail_to_set, inactive_sg, alarm_updates


def get_subcloud_availability_status(
    sysinv_client: SysinvClient, subcloud_name: str = None
):
    """Check if the subcloud is online or offline.

    For each subcloud, if at least one service is active in each
    service of servicegroup-list then declare the subcloud online.

    Note: It returns the inactive service groups for logging on system
    controller purposes only, as the function runs on the subcloud.

    :param sysinv_client: The subcloud sysinv client.
    :param subcloud_name: The subcloud name.
    :returns: availability status, list of inactive service groups
    """
    avail_to_set = dccommon_consts.AVAILABILITY_OFFLINE
    svc_groups = None
    inactive_only = None

    # get a list of service groups in the subcloud
    try:
        svc_groups = sysinv_client.get_service_groups()
    except Exception as e:
        msg = f"Cannot retrieve service groups. Error: {e}"
        log_subcloud_msg(LOG.warn, msg, subcloud_name)

    if svc_groups:
        active_sgs = []
        inactive_sgs = []

        # Build 2 lists, 1 of active service groups,
        # one with non-active.
        for sg in svc_groups:
            if sg.state != consts.SERVICE_GROUP_STATUS_ACTIVE:
                inactive_sgs.append(sg.service_group_name)
            else:
                active_sgs.append(sg.service_group_name)

        # Create a list of service groups that are only present
        # in non-active list
        inactive_only = [sg for sg in inactive_sgs if sg not in active_sgs]

        # An empty inactive only list and a non-empty active list
        # means we're good to go.
        if not inactive_only and active_sgs:
            avail_to_set = dccommon_consts.AVAILABILITY_ONLINE
        else:
            msg = f"Non-active service groups: {inactive_only}"
            log_subcloud_msg(LOG.info, msg, subcloud_name)
    return avail_to_set, inactive_only
