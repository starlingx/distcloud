#
# Copyright (c) 2021-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_config import cfg
from oslo_log import log as logging

from fm_api.constants import FM_ALARM_ID_CERT_EXPIRED
from fm_api.constants import FM_ALARM_ID_CERT_EXPIRING_SOON

from dccommon import consts as dccommon_consts
from dccommon import utils as dccommon_utils

from dccommon.drivers.openstack.sdk_platform import OpenStackDriver
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient

from dcmanager.common import utils

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

KUBE_ROOTCA_ALARM_LIST = [FM_ALARM_ID_CERT_EXPIRED,
                          FM_ALARM_ID_CERT_EXPIRING_SOON, ]
MONITORED_ALARM_ENTITIES = ['system.certificate.kubernetes-root-ca', ]


class KubeRootcaUpdateAudit(object):
    """Manages tasks related to kube rootca update audits."""

    def __init__(self, context):
        self.context = context
        self.audit_type = "kube rootca update"
        LOG.debug("%s audit initialized" % self.audit_type)

    def get_regionone_audit_data(self):
        """Query RegionOne to determine kube rootca update information.

        Kube rootca audit is based on the root CA cert ID. This identifier will
        consist of a hash from certificate issuer representation and its serial
        number.

        :return: A string of the root CA cert ID
        """
        try:
            m_os_ks_client = OpenStackDriver(
                region_name=dccommon_consts.DEFAULT_REGION_NAME,
                region_clients=None,
                fetch_subcloud_ips=utils.fetch_subcloud_mgmt_ips,
            ).keystone_client
            endpoint = m_os_ks_client.endpoint_cache.get_endpoint('sysinv')
            sysinv_client = SysinvClient(
                dccommon_consts.DEFAULT_REGION_NAME, m_os_ks_client.session,
                endpoint=endpoint)
        except Exception:
            LOG.exception("Failed init OS Client, skip Kubernetes root CA "
                          "audit.")
            return None

        try:
            # Ignore the success flag as the sysinv get_kube_rootca_id is
            # already introduced on system controllers.
            _, cc_cert = sysinv_client.get_kube_rootca_cert_id()
        except Exception:
            # Cannot get the cert ID from central cloud, return None
            LOG.exception("Failed to get Kubernetes root CA from Region One, "
                          "skip Kubernetes root CA audit.")
            return None

        regionone_rootca_certid = cc_cert.cert_id
        LOG.debug("RegionOne kubernetes rootca update data: "
                  f"{regionone_rootca_certid}.")
        return regionone_rootca_certid

    def subcloud_kube_rootca_audit(
        self, sysinv_client, fm_client, subcloud, regionone_rootca_certid
    ):
        """Perform an audit of kube root CA update info in a subcloud.

        The audit logic is as follow:
            CentOS subclouds -> alarm based
            Debian subclouds:
              not rehomed(initially deployed or re-deployed) -> alarm based
              rehomed subclouds:
                Not region one cert ID -> skip audit
                subcloud doesn't have the API to get cert ID -> alarm based
                region one cert ID -> cert based

        :param sysinv_client: the sysinv client object
        :param fm_client: the fm client object
        :param subcloud: subcloud object
        :param region_one_audit_data: the audit data of the region one
        """

        LOG.info("Triggered %s audit for: %s" % (self.audit_type, subcloud.name))

        # Firstly, apply alarm based audit against the subclouds deployed in
        # the distributed cloud and the subcloud running on old software
        # version that cannot search for the k8s root CA cert id.
        if (
            dccommon_utils.is_centos(subcloud.software_version)
            or not subcloud.rehomed
        ):
            return self.subcloud_audit_alarm_based(fm_client, subcloud.name)

        sync_status = dccommon_consts.SYNC_STATUS_IN_SYNC

        # Skip the audit if cannot get the region one cert ID.
        if not regionone_rootca_certid:
            LOG.debug(f"No region one audit data, skip {self.audit_type} "
                      f"audit for subcloud: {subcloud.name}.")
            return sync_status

        try:
            success, subcloud_cert_data = sysinv_client.get_kube_rootca_cert_id()
        except Exception:
            LOG.exception("Failed to get Kubernetes root CA cert ID of "
                          f"subcloud: {subcloud.name}, skip "
                          f"{self.audit_type} audit.")
            return None

        if not success:
            # if not success, the subcloud is a Debian based subcloud without
            # the sysinv API to get the cert ID, audit the subcloud based on
            # its alarm.
            return self.subcloud_audit_alarm_based(fm_client, subcloud.name)
        return self.subcloud_audit_cert_based(
            subcloud.name, subcloud_cert_data, regionone_rootca_certid
        )

    def subcloud_audit_alarm_based(self, fm_client, subcloud_name):
        """The subcloud doesn't have the method to get Kubernetes root CA

        cert ID, use alarm based audit.
        :param fm_client: the fm client object
        :param subcloud_name: the name of the subcloud
        """

        sync_status = dccommon_consts.SYNC_STATUS_IN_SYNC
        detected_alarms = fm_client.get_alarms_by_ids(KUBE_ROOTCA_ALARM_LIST)

        if detected_alarms:
            for alarm in detected_alarms:
                if alarm.entity_instance_id in MONITORED_ALARM_ENTITIES:
                    sync_status = dccommon_consts.SYNC_STATUS_OUT_OF_SYNC
                    break

        LOG.info(
            f'{self.audit_type} audit completed for: {subcloud_name}, requesting '
            f'sync_status update to {sync_status}'
        )
        return sync_status

    def subcloud_audit_cert_based(self, subcloud_name,
                                  subcloud_cert_data, regionone_rootca_certid):
        """Audit if a subcloud's k8s root CA cert is the same as the central

        :param subcloud_name: the name of the subcloud
        :param regionone_rootca_certid: the cert ID of the region one
        :param subcloud_cert: subcloud's cert info

        """

        sync_status = dccommon_consts.SYNC_STATUS_IN_SYNC
        if subcloud_cert_data.error:
            LOG.exception("Failed to get Kubernetes root CA cert id for "
                          f"subcloud:{subcloud_name}, error: "
                          f"{subcloud_cert_data.error}, skip {self.audit_type} "
                          "audit.")
            return None

        elif subcloud_cert_data.cert_id != regionone_rootca_certid:
            sync_status = dccommon_consts.SYNC_STATUS_OUT_OF_SYNC

        LOG.info(
            f'{self.audit_type} audit completed for: {subcloud_name}, requesting '
            f'sync_status update to {sync_status}'
        )
        return sync_status
