#
# Copyright (c) 2021-2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from keystoneauth1 import exceptions as keystone_exceptions
from oslo_config import cfg
from oslo_log import log as logging

from fm_api.constants import FM_ALARM_ID_CERT_EXPIRED
from fm_api.constants import FM_ALARM_ID_CERT_EXPIRING_SOON

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.fm import FmClient
from dccommon.drivers.openstack.sdk_platform import OpenStackDriver

from dcmanager.audit.auditor import Auditor

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

KUBE_ROOTCA_ALARM_LIST = [FM_ALARM_ID_CERT_EXPIRED,
                          FM_ALARM_ID_CERT_EXPIRING_SOON, ]
MONITORED_ALARM_ENTITIES = ['system.certificate.kubernetes-root-ca', ]


class KubeRootcaUpdateAudit(Auditor):
    """Manages tasks related to kube rootca update audits."""

    def __init__(self, context, dcmanager_state_rpc_client):
        super(KubeRootcaUpdateAudit, self).__init__(
            context,
            dcmanager_state_rpc_client,
            dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA
        )
        self.audit_type = "kube rootca update"
        LOG.debug("%s audit initialized" % self.audit_type)

    def get_regionone_audit_data(self):
        """Query RegionOne to determine kube rootca update information.

        Kubernetes Root CA updates are considered out of sync based on
        alarms in the subcloud, and not based on region one data.

        :return: An empty list
        """
        return []

    def subcloud_audit(self, subcloud_name, region_one_audit_data):
        """Perform an audit of kube root CA update info in a subcloud.

        :param subcloud_name: the name of the subcloud
        :param region_one_audit_data: ignored. Always an empty list
        """
        LOG.info("Triggered %s audit for: %s" % (self.audit_type,
                                                 subcloud_name))
        # check for a particular alarm in the subcloud
        try:
            sc_os_client = OpenStackDriver(region_name=subcloud_name,
                                           region_clients=None)
            session = sc_os_client.keystone_client.session
            fm_client = FmClient(subcloud_name, session)
        except (keystone_exceptions.EndpointNotFound,
                keystone_exceptions.ConnectFailure,
                keystone_exceptions.ConnectTimeout,
                IndexError):
            LOG.exception("Endpoint for online subcloud:(%s) not found, skip "
                          "%s audit." % (subcloud_name, self.audit_type))
            return
        out_of_sync = False
        detected_alarms = fm_client.get_alarms_by_ids(KUBE_ROOTCA_ALARM_LIST)
        if detected_alarms:
            for alarm in detected_alarms:
                if alarm.entity_instance_id in MONITORED_ALARM_ENTITIES:
                    out_of_sync = True
                    break
        if out_of_sync:
            self.set_subcloud_endpoint_out_of_sync(subcloud_name)
        else:
            self.set_subcloud_endpoint_in_sync(subcloud_name)
        LOG.info("%s audit completed for: %s" % (self.audit_type,
                                                 subcloud_name))
