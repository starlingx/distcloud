#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import eventlet
from eventlet.greenpool import GreenPool
from oslo_config import cfg
from oslo_log import log as logging

from dcagent.common.exceptions import UnsupportedAudit
from dcagent.common.utils import BaseAuditManager
from dccommon import consts as dccommon_consts
from dcmanager.audit.base_audit import get_subcloud_base_audit
from dcmanager.audit.firmware_audit import FirmwareAudit
from dcmanager.audit.kube_rootca_update_audit import KubeRootcaUpdateAudit
from dcmanager.audit.kubernetes_audit import KubernetesAudit
from dcmanager.audit.software_audit import SoftwareAudit
from dcorch.common import consts as dcorch_consts

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

SYSINV_REQUEST_MAP = {
    dcorch_consts.RESOURCE_TYPE_SYSINV_CERTIFICATE: "get_certificates",
    dcorch_consts.RESOURCE_TYPE_SYSINV_USER: "get_user",
    dcorch_consts.RESOURCE_TYPE_SYSINV_FERNET_REPO: "get_fernet_keys",
}


class PeriodicAudit(BaseAuditManager):
    def __init__(self):
        super().__init__()
        self.periodic_audit_loop()

    def periodic_audit_loop(self):
        while True:
            try:
                self.initialize_clients(use_cache=False)
                self._run_periodic_audit_loop()
                eventlet.greenthread.sleep(CONF.scheduler.dcagent_audit_interval)
            except eventlet.greenlet.GreenletExit:
                # We have been told to exit
                return
            except Exception:
                LOG.exception("Error in periodic audit loop")

    def _run_periodic_audit_loop(self):
        # NOTE: We don't care about the return value of the audit functions
        # as the execution here is only used as a way to refresh the cache
        get_subcloud_base_audit(
            sysinv_client=self.sysinv_client, fm_client=self.fm_client
        )
        FirmwareAudit.get_subcloud_audit_data(self.sysinv_client)
        KubernetesAudit.get_subcloud_audit_data(self.sysinv_client)
        KubeRootcaUpdateAudit.get_subcloud_audit_data(
            self.sysinv_client, self.fm_client
        )
        SoftwareAudit.get_subcloud_audit_data(self.software_client)


class RequestedAudit(BaseAuditManager):
    def __init__(self, use_cache: bool = True):
        super().__init__()
        self.use_cache = use_cache

    def get_single_audit_status(self, audit_type, regionone_audit_data):
        # Since this run in parallel, we need to initialize the clients
        # here to not use the same socket in every call
        sysinv_client, fm_client, software_client = self.initialize_clients(
            use_cache=self.use_cache
        )
        if audit_type == dccommon_consts.BASE_AUDIT:
            (availability, inactive_sg, alarms) = get_subcloud_base_audit(
                sysinv_client=sysinv_client, fm_client=fm_client
            )
            resp = {
                "availability": availability,
                "inactive_sg": inactive_sg,
                "alarms": alarms,
            }
        elif audit_type == dccommon_consts.FIRMWARE_AUDIT:
            resp = FirmwareAudit.get_subcloud_sync_status(
                sysinv_client, regionone_audit_data
            )
        elif audit_type == dccommon_consts.KUBE_ROOTCA_AUDIT:
            resp = KubeRootcaUpdateAudit.get_subcloud_sync_status(
                sysinv_client, fm_client, regionone_audit_data
            )
        elif audit_type == dccommon_consts.KUBERNETES_AUDIT:
            resp = KubernetesAudit.get_subcloud_sync_status(
                sysinv_client, regionone_audit_data
            )
        elif audit_type == dccommon_consts.SOFTWARE_AUDIT:
            resp = SoftwareAudit.get_subcloud_sync_status(
                software_client, regionone_audit_data
            )
        elif audit_type in SYSINV_REQUEST_MAP:
            resp = getattr(sysinv_client, SYSINV_REQUEST_MAP[audit_type])()
        else:
            raise UnsupportedAudit(audit=audit_type)
        # If the response is an object or a list of object, convert it
        # to a dictionary before returning
        if "to_dict" in dir(resp):
            resp = resp.to_dict()
        elif isinstance(resp, list):
            resp = [r.to_dict() for r in resp if "to_dict" in dir(r)]
        return audit_type, resp

    def get_sync_status(self, payload):
        sync_resp = {}
        pool = GreenPool(size=10)
        jobs = [
            pool.spawn(self.get_single_audit_status, audit_type, regionone_audit_data)
            for audit_type, regionone_audit_data in payload.items()
        ]

        for job in jobs:
            audit_type, resp = job.wait()
            sync_resp[audit_type] = resp

        return sync_resp
