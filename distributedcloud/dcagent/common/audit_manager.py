#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from cgtsclient.exc import HTTPUnauthorized
import eventlet
from eventlet.greenpool import GreenPool
from oslo_config import cfg
from oslo_log import log as logging

from dcagent.common import exceptions
from dcagent.common import utils
from dccommon import consts as dccommon_consts
from dccommon import utils as dccommon_utils
from dcmanager.audit.base_audit import get_subcloud_base_audit
from dcmanager.audit.firmware_audit import FirmwareAudit
from dcmanager.audit.kube_rootca_update_audit import KubeRootcaUpdateAudit
from dcmanager.audit.kubernetes_audit import KubernetesAudit
from dcmanager.audit.software_audit import SoftwareAudit
from dcorch.common.consts import RESOURCE_TYPE_SYSINV_CERTIFICATE
from dcorch.common.consts import RESOURCE_TYPE_SYSINV_FERNET_REPO
from dcorch.common.consts import RESOURCE_TYPE_SYSINV_USER
from dcorch.engine.sync_services.sysinv import SysinvSyncThread

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

SYSINV_REQUEST_MAP = {
    RESOURCE_TYPE_SYSINV_CERTIFICATE: "get_certificates",
    RESOURCE_TYPE_SYSINV_USER: "get_user",
    RESOURCE_TYPE_SYSINV_FERNET_REPO: "get_fernet_keys",
}

COMPARE_PLATFORM_RESOURCES = {
    RESOURCE_TYPE_SYSINV_CERTIFICATE: SysinvSyncThread.compare_certificate,
    RESOURCE_TYPE_SYSINV_USER: SysinvSyncThread.compare_user,
    RESOURCE_TYPE_SYSINV_FERNET_REPO: SysinvSyncThread.compare_fernet_key,
}


class PeriodicAudit(utils.BaseAuditManager):
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
                eventlet.greenthread.sleep(2)

    def _run_with_retry_if_unauthorized(self, func, arg_getter, **kwargs):
        # If any exception is raised, we just ignore them and wait
        # for the next audit cycle to get fresh data. The only exception
        # we don't ignore is unauthorized by keystone, and we'll try
        # to get a new token and retry the function once in this case
        try:
            return func(*arg_getter(), **kwargs)
        except Exception as ex:
            # Since FM doesn't have a specific exception for unauthorized like
            # cgtsclient (raising only a generic HTTPClientError), we also handle
            # the exception here by the message returned by keystone itself
            if isinstance(
                ex, HTTPUnauthorized
            ) or "The request you have made requires authentication" in str(ex):
                try:
                    LOG.warn(
                        "Getting new keystone token and retrying "
                        f"call to {func.__name__}"
                    )
                    self.initialize_clients(use_cache=False)

                    return func(*arg_getter(), **kwargs)
                except Exception:
                    pass
            # The exception was previouslly logged by the called function,
            # so we don't need to log it again here

    def _run_periodic_audit_loop(self):
        # We call dcorch resources first because, differently from dcmanager resources,
        # they'll raise an exception if an error occurs, which is a way of checking if
        # current keystone token is valid
        # The args are lambda functions so we can refresh them when changing keystone
        # token upon unauthorized exception
        # NOTE: We don't care about the return value of the audit functions
        # as the execution here is only used as a way to refresh the cache
        functions = [
            (SysinvSyncThread.get_certificates_resources, lambda: [self.sysinv_client]),
            (SysinvSyncThread.get_user_resource, lambda: [self.sysinv_client]),
            (SysinvSyncThread.get_fernet_resources, lambda: [self.sysinv_client]),
            (get_subcloud_base_audit, lambda: [self.sysinv_client, self.fm_client]),
            (FirmwareAudit.get_subcloud_audit_data, lambda: [self.sysinv_client]),
            (KubernetesAudit.get_subcloud_audit_data, lambda: [self.sysinv_client]),
            # Need to call kube rootca function two times as it has a different
            # response if the subcloud was rehomed or not and we want to cache both
            # results
            (
                KubeRootcaUpdateAudit.get_subcloud_audit_data,
                lambda: [self.sysinv_client, self.fm_client, False],
            ),
            (
                KubeRootcaUpdateAudit.get_subcloud_audit_data,
                lambda: [self.sysinv_client, self.fm_client, True],
            ),
            (SoftwareAudit.get_subcloud_audit_data, lambda: [self.software_client]),
        ]

        for func, arg_getter in functions:
            self._run_with_retry_if_unauthorized(func, arg_getter)


class RequestedAudit(utils.BaseAuditManager):
    def __init__(self, request_token: str, use_cache: bool = True):
        super().__init__()
        self.request_token = request_token
        self.use_cache = use_cache

    def get_single_audit_status(self, audit_type, regionone_audit_data, extra_args):
        # Since this run in parallel, we need to initialize the clients
        # here to not use the same socket in every call
        sysinv_client, fm_client, software_client = self.initialize_clients(
            use_cache=self.use_cache, request_token=self.request_token
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
            rehomed = extra_args.get("rehomed", False)
            resp = KubeRootcaUpdateAudit.get_subcloud_sync_status(
                sysinv_client, fm_client, regionone_audit_data, rehomed
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
            resp = self.get_sysinv_sync_status(
                sysinv_client, audit_type, regionone_audit_data
            )
        else:
            raise exceptions.UnsupportedAudit(audit=audit_type)
        if resp is None:
            # resp is None when the audit fails to get the data internally
            raise exceptions.AuditStatusFailure(audit=audit_type)
        return audit_type, resp

    def get_sync_status(self, payload, extra_args):
        sync_resp = {}
        pool = GreenPool(size=10)
        jobs = [
            pool.spawn(
                self.get_single_audit_status,
                audit_type,
                regionone_audit_data,
                extra_args,
            )
            for audit_type, regionone_audit_data in payload.items()
        ]

        for job in jobs:
            audit_type, resp = job.wait()
            sync_resp[audit_type] = resp

        LOG.debug(f"Audit response: {sync_resp}")

        return sync_resp

    @staticmethod
    def get_sysinv_sync_status(sysinv_client, audit_type, regionone_audit_data):
        if not regionone_audit_data:
            raise exceptions.MissingRegionOneData(audit=audit_type)
        resp = getattr(sysinv_client, SYSINV_REQUEST_MAP[audit_type])()
        # Filter the certificate list to only include the desired ones
        # This need to be done before converting the object to a dictionary
        if audit_type == RESOURCE_TYPE_SYSINV_CERTIFICATE:
            resp = SysinvSyncThread.filter_cert_list(resp)
        resp = dccommon_utils.convert_resource_to_dict(resp)
        if not isinstance(resp, list):
            resp = [resp]
        if not isinstance(regionone_audit_data, list):
            regionone_audit_data = [regionone_audit_data]
        if audit_type == RESOURCE_TYPE_SYSINV_FERNET_REPO:
            # Combine the list of dictionaries into a list with a
            # single dictionary to match RegionOne response
            resp = [{str(d["id"]): d["key"] for d in resp}]
        LOG.debug(
            f"Auditing {audit_type}: sc_resources: {resp}; "
            f"master_resources: {regionone_audit_data}"
        )

        sync_status = dccommon_consts.SYNC_STATUS_OUT_OF_SYNC
        if audit_type != RESOURCE_TYPE_SYSINV_CERTIFICATE:
            # If the resource is not a certificate, the response will be
            # just "in-sync" or "out-of-sync"
            for m_resource in regionone_audit_data:
                for sc_resource in resp:
                    if COMPARE_PLATFORM_RESOURCES[audit_type](m_resource, sc_resource):
                        sync_status = dccommon_consts.SYNC_STATUS_IN_SYNC
                        break
                # If a master resource is out-of-sync after checking all subcloud
                # resources, flag the audit as out-of-sync
                if sync_status == dccommon_consts.SYNC_STATUS_OUT_OF_SYNC:
                    return sync_status

            # Return in-sync as no audit was flag as out-of-sync above
            return dccommon_consts.SYNC_STATUS_IN_SYNC

        # If the resource is a certificate, the response will be a dictionary
        # with the certificate signature as the key and the sync status as the value
        sync_status_dict = {}
        for m_resource in regionone_audit_data:
            cert_signature = m_resource["signature"]
            for sc_resource in resp:
                if COMPARE_PLATFORM_RESOURCES[audit_type](m_resource, sc_resource):
                    sync_status_dict[cert_signature] = (
                        dccommon_consts.SYNC_STATUS_IN_SYNC
                    )
                    break
            else:
                # If a master resource is out-of-sync after checking all subcloud
                # resources, flag the audit as out-of-sync
                sync_status_dict[cert_signature] = (
                    dccommon_consts.SYNC_STATUS_OUT_OF_SYNC
                )
        return sync_status_dict
