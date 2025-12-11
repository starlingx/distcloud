#
# Copyright (c) 2021-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from fm_api.constants import FM_ALARM_ID_CERT_EXPIRED
from fm_api.constants import FM_ALARM_ID_CERT_EXPIRING_SOON
from oslo_config import cfg
from oslo_log import log as logging

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.fm import FmClient
from dccommon import utils as cutils

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

KUBE_ROOTCA_ALARM_LIST = [
    FM_ALARM_ID_CERT_EXPIRED,
    FM_ALARM_ID_CERT_EXPIRING_SOON,
]
MONITORED_ALARM_ENTITIES = [
    "system.certificate.kubernetes-root-ca",
]

AUDIT_TYPE = "kube rootca update"
ALARM_BASED = "alarm_based"


class KubeRootcaUpdateAudit(object):
    """Manages tasks related to kube rootca update audits."""

    def __init__(self):
        LOG.debug(f"{AUDIT_TYPE} audit initialized")

    def get_regionone_audit_data(self):
        """Query RegionOne to determine kube rootca update information."""
        # No need to get cert data to compare, alarm based approach will be used
        # in the subcloud audit to assess the validity of cert
        return True

    @classmethod
    def get_subcloud_audit_data(
        cls,
        fm_client: FmClient,
        subcloud_name: str = None,
    ) -> tuple:
        skip_audit = 2 * [dccommon_consts.SKIP_AUDIT]
        try:
            detected_alarms = fm_client.get_alarms_by_ids(KUBE_ROOTCA_ALARM_LIST)
        except Exception:
            msg = f"Failed to get alarms by id, skip {AUDIT_TYPE} audit."
            cutils.log_subcloud_msg(LOG.exception, msg, subcloud_name)
            return skip_audit
        return ALARM_BASED, detected_alarms

    @classmethod
    def get_subcloud_sync_status(
        cls,
        fm_client: FmClient,
        subcloud_name: str = None,
    ):
        """Get the sync status of the subcloud's kube root CA cert."""

        audit_method, subcloud_audit_data = cls.get_subcloud_audit_data(
            fm_client, subcloud_name
        )

        if audit_method == dccommon_consts.SKIP_AUDIT:
            return None

        return cls.subcloud_rootca_audit_alarm_based(subcloud_audit_data)

    @staticmethod
    def subcloud_rootca_audit_alarm_based(detected_alarms):
        """Check alarms of Kubernetes Root CA.

        :param detected_alarms: A list of detected alarms
        """
        if detected_alarms:
            for alarm in detected_alarms:
                if alarm.entity_instance_id in MONITORED_ALARM_ENTITIES:
                    return dccommon_consts.SYNC_STATUS_OUT_OF_SYNC
        return dccommon_consts.SYNC_STATUS_IN_SYNC
