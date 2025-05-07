#
# Copyright (c) 2021-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from fm_api.constants import FM_ALARM_ID_CERT_EXPIRED
from fm_api.constants import FM_ALARM_ID_CERT_EXPIRING_SOON
from oslo_config import cfg
from oslo_log import log as logging

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.fm import FmClient
from dccommon.drivers.openstack.sdk_platform import OpenStackDriver
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon import utils as cutils
from dcmanager.common import utils

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
CERT_BASED = "cert_based"
ALARM_BASED = "alarm_based"


class KubeRootcaUpdateAudit(object):
    """Manages tasks related to kube rootca update audits."""

    def __init__(self):
        LOG.debug(f"{AUDIT_TYPE} audit initialized")

    def get_regionone_audit_data(self):
        """Query RegionOne to determine kube rootca update information.

        Kube rootca audit is based on the root CA cert ID. This identifier will
        consist of a hash from certificate issuer representation and its serial
        number.

        :return: A string of the root CA cert ID
        """
        try:
            m_os_ks_client = OpenStackDriver(
                region_clients=None,
                fetch_subcloud_ips=utils.fetch_subcloud_mgmt_ips,
            ).keystone_client
            endpoint = m_os_ks_client.endpoint_cache.get_endpoint("sysinv")
            sysinv_client = SysinvClient(
                m_os_ks_client.region_name,
                m_os_ks_client.session,
                endpoint=endpoint,
            )
        except Exception:
            LOG.exception("Failed init OS Client, skip Kubernetes root CA audit.")
            return None

        try:
            # Ignore the success flag as the sysinv get_kube_rootca_id is
            # already introduced on system controllers.
            _, cc_cert = sysinv_client.get_kube_rootca_cert_id()
        except Exception:
            # Cannot get the cert ID from central cloud, return None
            LOG.exception(
                "Failed to get Kubernetes root CA from Region One, "
                "skip Kubernetes root CA audit."
            )
            return None

        regionone_rootca_certid = cc_cert.cert_id
        LOG.debug(
            "RegionOne kubernetes rootca update data: " f"{regionone_rootca_certid}."
        )
        return regionone_rootca_certid

    @classmethod
    def get_subcloud_audit_data(
        cls,
        sysinv_client: SysinvClient,
        fm_client: FmClient,
        rehomed: bool = False,
        subcloud_name: str = None,
    ) -> tuple:
        skip_audit = 2 * [dccommon_consts.SKIP_AUDIT]
        if rehomed:
            try:
                success, subcloud_cert_data = sysinv_client.get_kube_rootca_cert_id()
            except Exception:
                msg = (
                    f"Failed to get Kubernetes root CA status, skip {AUDIT_TYPE} audit."
                )
                cutils.log_subcloud_msg(LOG.exception, msg, subcloud_name)
                return skip_audit

            if success:
                return CERT_BASED, subcloud_cert_data

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
        sysinv_client: SysinvClient,
        fm_client: FmClient,
        regionone_rootca_certid: str,
        rehomed: bool = False,
        subcloud_name: str = None,
    ):
        """Get the sync status of the subcloud's kube root CA cert."""

        audit_method, subcloud_audit_data = cls.get_subcloud_audit_data(
            sysinv_client, fm_client, rehomed, subcloud_name
        )

        sync_status = None

        if audit_method == dccommon_consts.SKIP_AUDIT:
            return sync_status
        elif audit_method == ALARM_BASED:
            # If the subcloud doesn't have the sysinv API to get
            # the cert ID, audit based on its alarm.
            sync_status = cls.subcloud_rootca_audit_alarm_based(subcloud_audit_data)
        else:
            sync_status = cls.subcloud_rootca_audit_cert_based(
                subcloud_audit_data, regionone_rootca_certid, subcloud_name
            )
        return sync_status

    @staticmethod
    def subcloud_rootca_audit_alarm_based(detected_alarms):
        """The subcloud doesn't have the method to get Kubernetes root CA

        cert ID, use alarm based audit.
        :param fm_client: the fm client object
        :param subcloud_name: the name of the subcloud
        """

        if detected_alarms:
            for alarm in detected_alarms:
                if alarm.entity_instance_id in MONITORED_ALARM_ENTITIES:
                    return dccommon_consts.SYNC_STATUS_OUT_OF_SYNC
        return dccommon_consts.SYNC_STATUS_IN_SYNC

    @staticmethod
    def subcloud_rootca_audit_cert_based(
        subcloud_cert_data: object,
        regionone_rootca_certid: str,
        subcloud_name: str = None,
    ):
        """Audit if a subcloud's k8s root CA cert is the same as the central

        :param regionone_rootca_certid: the cert ID of the region one
        :param subcloud_cert: subcloud's cert info
        :param subcloud_name: the name of the subcloud
        :return: sync status of the subcloud certificate
        """

        if subcloud_cert_data.error:
            msg = (
                "Failed to get Kubernetes root CA cert id, error: "
                f"{subcloud_cert_data.error}, skip {AUDIT_TYPE} audit."
            )
            cutils.log_subcloud_msg(LOG.error, msg, subcloud_name)
            return None

        out_of_sync = subcloud_cert_data.cert_id != regionone_rootca_certid

        return (
            dccommon_consts.SYNC_STATUS_OUT_OF_SYNC
            if out_of_sync
            else dccommon_consts.SYNC_STATUS_IN_SYNC
        )
