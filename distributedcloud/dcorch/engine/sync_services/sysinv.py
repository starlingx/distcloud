# Copyright (c) 2017-2022, 2024 Wind River Systems, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import threading

from keystoneauth1 import exceptions as keystone_exceptions
from requests_toolbelt import MultipartDecoder

from oslo_log import log as logging
from oslo_serialization import jsonutils
from oslo_utils import timeutils

from cgtsclient.exc import CommunicationError

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.dcagent_v1 import DcagentClient
from dccommon.drivers.openstack.sdk_platform import OpenStackDriver
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon import exceptions as dccommon_exceptions
from dccommon import utils as dccommon_utils
from dcorch.common import consts
from dcorch.common import exceptions
from dcorch.engine.fernet_key_manager import FERNET_REPO_MASTER_ID
from dcorch.engine.fernet_key_manager import FernetKeyManager
from dcorch.engine.sync_thread import AUDIT_RESOURCE_EXTRA
from dcorch.engine.sync_thread import AUDIT_RESOURCE_MISSING
from dcorch.engine.sync_thread import get_master_os_client
from dcorch.engine.sync_thread import SyncThread

LOG = logging.getLogger(__name__)

SYNC_CERTIFICATES = ["ssl_ca", "openstack_ca"]
CERTIFICATE_SIG_NULL = "NoCertificate"


class SysinvSyncThread(SyncThread):
    """Manages tasks related to distributed cloud orchestration for sysinv."""

    SYSINV_MODIFY_RESOURCES = [
        consts.RESOURCE_TYPE_SYSINV_USER,
        consts.RESOURCE_TYPE_SYSINV_FERNET_REPO,
    ]

    SYSINV_CREATE_RESOURCES = [
        consts.RESOURCE_TYPE_SYSINV_CERTIFICATE,
        consts.RESOURCE_TYPE_SYSINV_FERNET_REPO,
    ]

    RESOURCE_UUID_NULL = "NoResourceUUID"

    def __init__(
        self,
        subcloud_name,
        endpoint_type=None,
        management_ip=None,
        software_version=None,
        engine_id=None,
    ):
        super(SysinvSyncThread, self).__init__(
            subcloud_name,
            endpoint_type=endpoint_type,
            management_ip=management_ip,
            software_version=software_version,
            engine_id=engine_id,
        )
        if not self.endpoint_type:
            self.endpoint_type = dccommon_consts.ENDPOINT_TYPE_PLATFORM
        self.sync_handler_map = {
            consts.RESOURCE_TYPE_SYSINV_CERTIFICATE: self.sync_platform_resource,
            consts.RESOURCE_TYPE_SYSINV_USER: self.sync_platform_resource,
            consts.RESOURCE_TYPE_SYSINV_FERNET_REPO: self.sync_platform_resource,
        }
        self.region_name = subcloud_name
        self.log_extra = {
            "instance": "{}/{}: ".format(self.region_name, self.endpoint_type)
        }

        self.audit_resources = [
            consts.RESOURCE_TYPE_SYSINV_CERTIFICATE,
            consts.RESOURCE_TYPE_SYSINV_USER,
            consts.RESOURCE_TYPE_SYSINV_FERNET_REPO,
        ]
        # TODO(ecandotti): remove has_dcagent check in the next StarlingX release
        self.has_dcagent = dccommon_utils.subcloud_has_dcagent(self.software_version)
        self.sc_dcagent_client = None

        self.sc_sysinv_client = None

        LOG.info("SysinvSyncThread initialized", extra=self.log_extra)

    def initialize_sc_clients(self):
        super().initialize_sc_clients()

        sc_sysinv_url = dccommon_utils.build_subcloud_endpoint(
            self.management_ip, "sysinv"
        )
        LOG.debug(
            f"Built sc_sysinv_url {sc_sysinv_url} for subcloud {self.subcloud_name}"
        )

        if self.has_dcagent:
            self.sc_dcagent_client = DcagentClient(
                self.region_name,
                self.sc_admin_session,
                endpoint=dccommon_utils.build_subcloud_endpoint(
                    self.management_ip, "dcagent"
                ),
            )
        self.sc_sysinv_client = SysinvClient(
            region=self.subcloud_name,
            session=self.sc_admin_session,
            endpoint=sc_sysinv_url,
        )

    def get_master_sysinv_client(self):
        return get_master_os_client(["sysinv"]).sysinv_client

    def get_sc_sysinv_client(self):
        if self.sc_sysinv_client is None:
            self.initialize_sc_clients()
        return self.sc_sysinv_client

    def get_sc_dcagent_client(self):
        if self.sc_dcagent_client is None:
            self.initialize_sc_clients()
        return self.sc_dcagent_client

    def sync_platform_resource(self, request, rsrc):
        try:
            # invoke the sync method for the requested resource_type
            # I.e. sync_iuser
            s_func_name = "sync_" + rsrc.resource_type
            LOG.info("Obj:%s, func:%s" % (type(self), s_func_name))
            getattr(self, s_func_name)(self.get_sc_sysinv_client(), request, rsrc)
        except AttributeError:
            LOG.error(
                "{} not implemented for {}".format(
                    request.orch_job.operation_type, rsrc.resource_type
                )
            )
            raise exceptions.SyncRequestFailed
        except exceptions.CertificateExpiredException as e:
            LOG.info(
                "{} {} aborted: {}".format(
                    request.orch_job.operation_type, rsrc.resource_type, str(e)
                ),
                extra=self.log_extra,
            )
            raise exceptions.SyncRequestAbortedBySystem
        except (
            exceptions.ConnectionRefused,
            exceptions.TimeOut,
            keystone_exceptions.connection.ConnectTimeout,
            keystone_exceptions.ConnectFailure,
            CommunicationError,
        ) as e:
            LOG.info(
                "{} {} region_name {} exception {}".format(
                    request.orch_job.operation_type,
                    rsrc.resource_type,
                    self.region_name,
                    str(e),
                ),
                extra=self.log_extra,
            )
            raise exceptions.SyncRequestTimeout
        except exceptions.NotAuthorized:
            LOG.info(
                "{} {} region_name {} not authorized".format(
                    request.orch_job.operation_type,
                    rsrc.resource_type,
                    self.region_name,
                ),
                extra=self.log_extra,
            )
            OpenStackDriver.delete_region_clients(self.region_name)
            raise exceptions.SyncRequestFailedRetry
        except Exception as e:
            LOG.exception(e)
            raise exceptions.SyncRequestFailedRetry

    def update_certificate(self, sysinv_client, signature, certificate=None, data=None):

        try:
            icertificate = sysinv_client.update_certificate(
                signature, certificate=certificate, data=data
            )
            return icertificate
        except (AttributeError, TypeError) as e:
            LOG.info(
                "update_certificate error {} region_name".format(e),
                extra=self.log_extra,
            )
            raise exceptions.SyncRequestFailedRetry

    @staticmethod
    def _decode_certificate_payload(certificate_dict):
        """Decode certificate from payload.

        params: certificate_dict
        returns: certificate, metadata
        """
        certificate = None
        metadata = {}
        content_disposition = "Content-Disposition"
        try:
            content_type = certificate_dict.get("content_type")
            payload = certificate_dict.get("payload")
            multipart_data = MultipartDecoder(payload, content_type)
            for part in multipart_data.parts:
                if 'name="passphrase"' in part.headers.get(content_disposition):
                    metadata.update({"passphrase": part.content})
                elif 'name="mode"' in part.headers.get(content_disposition):
                    metadata.update({"mode": part.content})
                elif 'name="file"' in part.headers.get(content_disposition):
                    certificate = part.content
        except Exception as e:
            LOG.warn("No certificate decode e={}".format(e))

        LOG.info("_decode_certificate_payload metadata={}".format(metadata))
        return certificate, metadata

    def create_certificate(self, sysinv_client, request, rsrc):
        LOG.info(
            "create_certificate resource_info={}".format(
                request.orch_job.resource_info
            ),
            extra=self.log_extra,
        )
        certificate_dict = jsonutils.loads(request.orch_job.resource_info)
        payload = certificate_dict.get("payload")

        if payload and "expiry_date" in payload:
            expiry_datetime = timeutils.normalize_time(
                timeutils.parse_isotime(payload["expiry_date"])
            )

            if timeutils.utcnow() > expiry_datetime:
                LOG.info(
                    "create_certificate Certificate %s has expired at %s"
                    % (payload["signature"], str(expiry_datetime))
                )
                raise exceptions.CertificateExpiredException
        else:
            LOG.info(
                "create_certificate No payload found in resource_info"
                "{}".format(request.orch_job.resource_info),
                extra=self.log_extra,
            )
            return

        certificate, metadata = self._decode_certificate_payload(certificate_dict)

        if isinstance(payload, dict):
            if payload.get("certtype") not in SYNC_CERTIFICATES:
                return
            signature = payload.get("signature")
            LOG.info("signature from dict={}".format(signature))
        else:
            if metadata.get("mode") not in SYNC_CERTIFICATES:
                return
            signature = rsrc.master_id
            LOG.info("signature from master_id={}".format(signature))

        icertificate = None
        signature = rsrc.master_id
        if signature and signature != CERTIFICATE_SIG_NULL:
            icertificate = self.update_certificate(
                sysinv_client, signature, certificate=certificate, data=metadata
            )
        else:
            LOG.info("skipping signature={}".format(signature))

        # Ensure subcloud resource is persisted to the DB for later
        subcloud_rsrc_id = self.persist_db_subcloud_resource(rsrc.id, signature)

        cert_bodys = icertificate.get("certificates")
        sub_certs_updated = [
            str(cert_body.get("signature")) for cert_body in cert_bodys
        ]

        LOG.info(
            "certificate {} {} [{}] updated with subcloud certificates: {}".format(
                rsrc.id, subcloud_rsrc_id, signature, sub_certs_updated
            ),
            extra=self.log_extra,
        )

    def delete_certificate(self, sysinv_client, request, rsrc):
        subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if not subcloud_rsrc:
            return

        try:
            certificates = self.get_certificates_resources(sysinv_client)
            cert_to_delete = None
            for certificate in certificates:
                if certificate.signature == subcloud_rsrc.subcloud_resource_id:
                    cert_to_delete = certificate
                    break
            if not cert_to_delete:
                raise dccommon_exceptions.CertificateNotFound(
                    region_name=self.region_name,
                    signature=subcloud_rsrc.subcloud_resource_id,
                )
            sysinv_client.delete_certificate(cert_to_delete)
        except dccommon_exceptions.CertificateNotFound:
            # Certificate already deleted in subcloud, carry on.
            LOG.info(
                "Certificate not in subcloud, may be already deleted",
                extra=self.log_extra,
            )
        except (AttributeError, TypeError) as e:
            LOG.info("delete_certificate error {}".format(e), extra=self.log_extra)
            raise exceptions.SyncRequestFailedRetry

        subcloud_rsrc.delete()
        # Master Resource can be deleted only when all subcloud resources
        # are deleted along with corresponding orch_job and orch_requests.
        LOG.info(
            "Certificate {}:{} [{}] deleted".format(
                rsrc.id, subcloud_rsrc.id, subcloud_rsrc.subcloud_resource_id
            ),
            extra=self.log_extra,
        )

    def sync_certificates(self, sysinv_client, request, rsrc):
        switcher = {
            consts.OPERATION_TYPE_POST: self.create_certificate,
            consts.OPERATION_TYPE_CREATE: self.create_certificate,
            consts.OPERATION_TYPE_DELETE: self.delete_certificate,
        }

        func = switcher[request.orch_job.operation_type]
        try:
            func(sysinv_client, request, rsrc)
        except (
            keystone_exceptions.connection.ConnectTimeout,
            keystone_exceptions.ConnectFailure,
        ) as e:
            LOG.info(
                "sync_certificates: subcloud {} is not reachable [{}]".format(
                    self.region_name, str(e)
                ),
                extra=self.log_extra,
            )
            raise exceptions.SyncRequestTimeout
        except exceptions.CertificateExpiredException as e:
            LOG.exception(e)
            raise exceptions.CertificateExpiredException
        except Exception as e:
            LOG.exception(e)
            raise exceptions.SyncRequestFailedRetry

    def update_user(self, sysinv_client, passwd_hash, root_sig, passwd_expiry_days):
        LOG.info(
            "update_user={} {} {}".format(passwd_hash, root_sig, passwd_expiry_days),
            extra=self.log_extra,
        )

        try:
            iuser = sysinv_client.update_user(passwd_hash, root_sig, passwd_expiry_days)
            return iuser
        except (AttributeError, TypeError) as e:
            LOG.info("update_user error {} region_name".format(e), extra=self.log_extra)
            raise exceptions.SyncRequestFailedRetry

    def sync_iuser(self, sysinv_client, request, rsrc):
        # The system is populated with user entry for sysadmin.
        LOG.info(
            "sync_user resource_info={}".format(request.orch_job.resource_info),
            extra=self.log_extra,
        )
        user_dict = jsonutils.loads(request.orch_job.resource_info)
        payload = user_dict.get("payload")

        passwd_hash = None
        if isinstance(payload, list):
            for ipayload in payload:
                if ipayload.get("path") == "/passwd_hash":
                    passwd_hash = ipayload.get("value")
                elif ipayload.get("path") == "/root_sig":
                    root_sig = ipayload.get("value")
                elif ipayload.get("path") == "/passwd_expiry_days":
                    passwd_expiry_days = ipayload.get("value")
        else:
            passwd_hash = payload.get("passwd_hash")
            root_sig = payload.get("root_sig")
            passwd_expiry_days = payload.get("passwd_expiry_days")

        LOG.info(
            "sync_user from dict passwd_hash={} root_sig={} "
            "passwd_expiry_days={}".format(passwd_hash, root_sig, passwd_expiry_days),
            extra=self.log_extra,
        )

        if not passwd_hash:
            LOG.info(
                "sync_user no user update found in resource_info {}".format(
                    request.orch_job.resource_info
                ),
                extra=self.log_extra,
            )
            return

        iuser = self.update_user(
            sysinv_client, passwd_hash, root_sig, passwd_expiry_days
        )

        # Ensure subcloud resource is persisted to the DB for later
        subcloud_rsrc_id = self.persist_db_subcloud_resource(rsrc.id, iuser.uuid)
        LOG.info(
            "User sysadmin {}:{} [{}] updated".format(
                rsrc.id, subcloud_rsrc_id, passwd_hash
            ),
            extra=self.log_extra,
        )

    def sync_fernet_repo(self, sysinv_client, request, rsrc):
        switcher = {
            consts.OPERATION_TYPE_PUT: self.update_fernet_repo,
            consts.OPERATION_TYPE_PATCH: self.update_fernet_repo,
            consts.OPERATION_TYPE_CREATE: self.create_fernet_repo,
        }

        func = switcher[request.orch_job.operation_type]
        try:
            func(sysinv_client, request, rsrc)
        except (
            keystone_exceptions.connection.ConnectTimeout,
            keystone_exceptions.ConnectFailure,
        ) as e:
            LOG.info(
                "sync_fernet_resources: subcloud {} is not reachable [{}]".format(
                    self.region_name, str(e)
                ),
                extra=self.log_extra,
            )
            raise exceptions.SyncRequestTimeout
        except Exception as e:
            LOG.exception(e)
            raise exceptions.SyncRequestFailedRetry

    def create_fernet_repo(self, sysinv_client, request, rsrc):
        LOG.info(
            "create_fernet_repo region {} resource_info={}".format(
                self.region_name, request.orch_job.resource_info
            ),
            extra=self.log_extra,
        )
        resource_info = jsonutils.loads(request.orch_job.resource_info)

        try:
            sysinv_client.post_fernet_repo(
                FernetKeyManager.from_resource_info(resource_info)
            )
            # Ensure subcloud resource is persisted to the DB for later
            subcloud_rsrc_id = self.persist_db_subcloud_resource(
                rsrc.id, rsrc.master_id
            )
        except (AttributeError, TypeError) as e:
            LOG.info("create_fernet_repo error {}".format(e), extra=self.log_extra)
            raise exceptions.SyncRequestFailedRetry

        LOG.info(
            "fernet_repo {} {} {} created".format(
                rsrc.id, subcloud_rsrc_id, resource_info
            ),
            extra=self.log_extra,
        )

    def update_fernet_repo(self, sysinv_client, request, rsrc):
        LOG.info(
            "update_fernet_repo region {} resource_info={}".format(
                self.region_name, request.orch_job.resource_info
            ),
            extra=self.log_extra,
        )
        resource_info = jsonutils.loads(request.orch_job.resource_info)

        try:
            sysinv_client.put_fernet_repo(
                FernetKeyManager.from_resource_info(resource_info)
            )
            # Ensure subcloud resource is persisted to the DB for later
            subcloud_rsrc_id = self.persist_db_subcloud_resource(
                rsrc.id, rsrc.master_id
            )
        except (AttributeError, TypeError) as e:
            LOG.info("update_fernet_repo error {}".format(e), extra=self.log_extra)
            raise exceptions.SyncRequestFailedRetry

        LOG.info(
            "fernet_repo {} {} {} update".format(
                rsrc.id, subcloud_rsrc_id, resource_info
            ),
            extra=self.log_extra,
        )

    # SysInv Audit Related
    def get_master_resources(self, resource_type):
        LOG.debug(
            "get_master_resources thread:{}".format(
                threading.currentThread().getName()
            ),
            extra=self.log_extra,
        )
        try:
            if resource_type == consts.RESOURCE_TYPE_SYSINV_CERTIFICATE:
                return self.get_certificates_resources(self.get_master_sysinv_client())
            elif resource_type == consts.RESOURCE_TYPE_SYSINV_USER:
                return [self.get_user_resource(self.get_master_sysinv_client())]
            elif resource_type == consts.RESOURCE_TYPE_SYSINV_FERNET_REPO:
                return [self.get_fernet_resources(self.get_master_sysinv_client())]
            else:
                LOG.error(
                    "Wrong resource type {}".format(resource_type), extra=self.log_extra
                )
                return None
        except Exception as e:
            LOG.exception(e)
            return None

    def get_subcloud_resources(self, resource_type):
        LOG.debug(
            "get_subcloud_resources thread:{}".format(
                threading.currentThread().getName()
            ),
            extra=self.log_extra,
        )
        try:
            if resource_type == consts.RESOURCE_TYPE_SYSINV_CERTIFICATE:
                return self.get_certificates_resources(self.get_sc_sysinv_client())
            elif resource_type == consts.RESOURCE_TYPE_SYSINV_USER:
                return [self.get_user_resource(self.get_sc_sysinv_client())]
            elif resource_type == consts.RESOURCE_TYPE_SYSINV_FERNET_REPO:
                return [self.get_fernet_resources(self.get_sc_sysinv_client())]
            else:
                LOG.error(
                    "Wrong resource type {}".format(resource_type), extra=self.log_extra
                )
                return None
        except (
            exceptions.ConnectionRefused,
            exceptions.TimeOut,
            keystone_exceptions.connection.ConnectTimeout,
            keystone_exceptions.ConnectFailure,
            CommunicationError,
        ) as e:
            LOG.info(
                "get subcloud_resources {}: subcloud {} is not reachable [{}]".format(
                    resource_type, self.region_name, str(e)
                ),
                extra=self.log_extra,
            )
            # None will force skip of audit
            return None
        except exceptions.NotAuthorized as e:
            LOG.info(
                "get subcloud_resources {}: subcloud {} not authorized [{}]".format(
                    resource_type, self.region_name, str(e)
                ),
                extra=self.log_extra,
            )
            OpenStackDriver.delete_region_clients(self.region_name)
            return None
        except (AttributeError, TypeError) as e:
            LOG.info(
                "get subcloud_resources {} error {}".format(resource_type, e),
                extra=self.log_extra,
            )
            return None
        except Exception as e:
            LOG.exception(e)
            return None

    def post_audit(self):
        super().post_audit()
        OpenStackDriver.delete_region_clients_for_thread(self.region_name, "audit")
        OpenStackDriver.delete_region_clients_for_thread(
            dccommon_consts.CLOUD_0, "audit"
        )

    @classmethod
    def get_certificates_resources(cls, sysinv_client: SysinvClient):
        certificate_list = sysinv_client.get_certificates()
        return cls.filter_cert_list(certificate_list)

    @staticmethod
    def filter_cert_list(certificate_list):
        # Only sync the specified certificates to subclouds
        filtered_list = [
            certificate
            for certificate in certificate_list
            if certificate.certtype in SYNC_CERTIFICATES
        ]
        return filtered_list

    @staticmethod
    def get_user_resource(sysinv_client: SysinvClient):
        return sysinv_client.get_user()

    @staticmethod
    def get_fernet_resources(sysinv_client: SysinvClient):
        keys = sysinv_client.get_fernet_keys()
        return FernetKeyManager.to_resource_info(keys)

    def get_resource_id(self, resource_type, resource):
        if resource_type == consts.RESOURCE_TYPE_SYSINV_CERTIFICATE:
            if hasattr(resource, "signature"):
                LOG.debug("get_resource_id signature={}".format(resource.signature))
                if resource.signature is None:
                    return CERTIFICATE_SIG_NULL
                return resource.signature
            elif hasattr(resource, "master_id"):
                LOG.debug(
                    "get_resource_id master_id signature={}".format(resource.master_id)
                )
                if resource.master_id is None:
                    # master_id cannot be None
                    return CERTIFICATE_SIG_NULL
                return resource.master_id
            else:
                LOG.error("no get_resource_id for certificate")
                return CERTIFICATE_SIG_NULL
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_FERNET_REPO:
            LOG.debug("get_resource_id {} resource={}".format(resource_type, resource))
            return FERNET_REPO_MASTER_ID
        else:
            resource_uuid = self.RESOURCE_UUID_NULL
            if isinstance(resource, dict):
                # master_id cannot be None
                resource_uuid = resource.get("uuid", self.RESOURCE_UUID_NULL)
            elif hasattr(resource, "uuid"):
                resource_uuid = resource.uuid
            if resource_uuid != self.RESOURCE_UUID_NULL:
                LOG.debug(f"get_resource_id {resource_type} uuid={resource_uuid}")
            else:
                LOG.debug(f"get_resource_id NO uuid resource_type={resource_type}")
            return resource_uuid

    @staticmethod
    def filter_certificate_resource(certs):
        return [
            {
                "uuid": cert.uuid,
                "signature": cert.signature,
                "expiry_date": cert.expiry_date,
                "start_date": cert.start_date,
            }
            for cert in certs
        ]

    @staticmethod
    def compare_certificate(i1, i2):
        i1 = dccommon_utils.convert_resource_to_dict(i1)
        i2 = dccommon_utils.convert_resource_to_dict(i2)
        if i1.get("signature") and (i1.get("signature") != i2.get("signature")):
            if i1.get("signature") == CERTIFICATE_SIG_NULL:
                return True
            return False
        if (
            i1.get("expiry_date") and i1.get("expiry_date") != i2.get("expiry_date")
        ) or (i1.get("start_date") and i1.get("start_date") != i2.get("start_date")):
            return False
        return True

    def same_certificate(self, i1, i2):
        LOG.debug("same_certificate i1={}, i2={}".format(i1, i2), extra=self.log_extra)
        same = self.compare_certificate(i1, i2)
        if not same:
            LOG.info(
                "same_certificate differs i1={}, i2={}".format(i1, i2),
                extra=self.log_extra,
            )
        return same

    @staticmethod
    def filter_user_resource(user):
        # The user is inside a list to be iterable, so we get
        # the first and only element
        return (
            {
                "uuid": user[0].uuid,
                "passwd_hash": user[0].passwd_hash,
                "passwd_expiry_days": user[0].passwd_expiry_days,
            }
            if user
            else {}
        )

    @staticmethod
    def compare_user(i1, i2):
        i1 = dccommon_utils.convert_resource_to_dict(i1)
        i2 = dccommon_utils.convert_resource_to_dict(i2)
        if i1.get("passwd_hash") != i2.get("passwd_hash") or i1.get(
            "passwd_expiry_days"
        ) != i2.get("passwd_expiry_days"):
            return False
        return True

    def same_user(self, i1, i2):
        LOG.debug("same_user i1={}, i2={}".format(i1, i2), extra=self.log_extra)
        same_user = self.compare_user(i1, i2)
        if not same_user:
            LOG.debug(
                "same_user differs i1={}, i2={}".format(i1, i2), extra=self.log_extra
            )
        return same_user

    @staticmethod
    def compare_fernet_key(i1, i2):
        i1 = dccommon_utils.convert_resource_to_dict(i1)
        i2 = dccommon_utils.convert_resource_to_dict(i2)
        if FernetKeyManager.get_resource_hash(i1) != FernetKeyManager.get_resource_hash(
            i2
        ):
            return False
        return True

    def same_fernet_key(self, i1, i2):
        LOG.debug("same_fernet_repo i1={}, i2={}".format(i1, i2), extra=self.log_extra)
        same_fernet = self.compare_fernet_key(i1, i2)
        if not same_fernet:
            LOG.debug(
                "same_fernet_repo differs i1={}, i2={}".format(i1, i2),
                extra=self.log_extra,
            )
        return same_fernet

    def same_resource(self, resource_type, m_resource, sc_resource):
        if resource_type == consts.RESOURCE_TYPE_SYSINV_CERTIFICATE:
            return self.same_certificate(m_resource, sc_resource)
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_USER:
            return self.same_user(m_resource, sc_resource)
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_FERNET_REPO:
            return self.same_fernet_key(m_resource, sc_resource)
        else:
            LOG.warn(
                "same_resource() unexpected resource_type {}".format(resource_type),
                extra=self.log_extra,
            )

    def audit_discrepancy(self, resource_type, m_resource, sc_resources):
        # Return true to try the audit_action
        if (
            resource_type in self.SYSINV_MODIFY_RESOURCES
            or resource_type in self.SYSINV_CREATE_RESOURCES
        ):
            # The resource differs, signal to perform the audit_action
            return True

        LOG.info(
            "audit_discrepancy resource_type {} default action".format(resource_type),
            extra=self.log_extra,
        )
        return False

    def audit_action(self, resource_type, finding, resource, sc_source=None):
        if resource_type in self.SYSINV_MODIFY_RESOURCES:
            LOG.info(
                "audit_action: {}/{}".format(finding, resource_type),
                extra=self.log_extra,
            )
            num_of_audit_jobs = 0
            if finding == AUDIT_RESOURCE_MISSING:
                # The missing resource should be created by underlying subcloud
                # thus action is to update for a 'missing' resource
                # should not get here since audit discrepancy will handle this
                resource_id = self.get_resource_id(resource_type, resource)
                self.schedule_work(
                    self.endpoint_type,
                    resource_type,
                    resource_id,
                    consts.OPERATION_TYPE_PATCH,
                    self.get_resource_info(resource_type, resource),
                )
                num_of_audit_jobs += 1
            else:
                LOG.warn(
                    "unexpected finding {} resource_type {}".format(
                        finding, resource_type
                    ),
                    extra=self.log_extra,
                )
            return num_of_audit_jobs
        elif resource_type in self.SYSINV_CREATE_RESOURCES:
            LOG.info(
                "audit_action: {}/{}".format(finding, resource_type),
                extra=self.log_extra,
            )
            # Default actions are create & delete. Can be overridden
            # in resource implementation
            num_of_audit_jobs = 0
            # resource can be either from dcorch DB or
            # fetched by OpenStack query
            resource_id = self.get_resource_id(resource_type, resource)
            if resource_id == CERTIFICATE_SIG_NULL:
                LOG.info("No certificate resource to sync")
                return num_of_audit_jobs
            elif resource_id == self.RESOURCE_UUID_NULL:
                LOG.info("No resource to sync")
                return num_of_audit_jobs

            if finding == AUDIT_RESOURCE_MISSING:
                # default action is create for a 'missing' resource
                self.schedule_work(
                    self.endpoint_type,
                    resource_type,
                    resource_id,
                    consts.OPERATION_TYPE_CREATE,
                    self.get_resource_info(
                        resource_type, resource, consts.OPERATION_TYPE_CREATE
                    ),
                )
                num_of_audit_jobs += 1
            elif finding == AUDIT_RESOURCE_EXTRA:
                # default action is delete for a 'extra' resource
                self.schedule_work(
                    self.endpoint_type,
                    resource_type,
                    resource_id,
                    consts.OPERATION_TYPE_DELETE,
                )
                num_of_audit_jobs += 1
            return num_of_audit_jobs
        else:  # use default audit_action
            return super(SysinvSyncThread, self).audit_action(
                resource_type, finding, resource
            )

    def get_resource_info(self, resource_type, resource, operation_type=None):
        payload_resources = [
            consts.RESOURCE_TYPE_SYSINV_CERTIFICATE,
            consts.RESOURCE_TYPE_SYSINV_USER,
        ]
        if resource_type in payload_resources:
            if "payload" not in resource._info:
                dumps = jsonutils.dumps({"payload": resource._info})
            else:
                dumps = jsonutils.dumps(resource._info)
            LOG.info(
                "get_resource_info resource_type={} dumps={}".format(
                    resource_type, dumps
                ),
                extra=self.log_extra,
            )
            return dumps
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_FERNET_REPO:
            LOG.info(
                "get_resource_info resource_type={} resource={}".format(
                    resource_type, resource
                ),
                extra=self.log_extra,
            )
            return jsonutils.dumps(resource)
        else:
            LOG.warn(
                "get_resource_info unsupported resource {}".format(resource_type),
                extra=self.log_extra,
            )
            return super(SysinvSyncThread, self).get_resource_info(
                resource_type, resource, operation_type
            )

    def get_dcagent_resources(self, resource_types: list, master_resources: dict):
        try:
            audit_payload = dict()
            for resource_type in resource_types:
                if resource_type == consts.RESOURCE_TYPE_SYSINV_CERTIFICATE:
                    audit_payload[resource_type] = self.filter_certificate_resource(
                        master_resources.get(resource_type, [])
                    )
                elif resource_type == consts.RESOURCE_TYPE_SYSINV_USER:
                    audit_payload[resource_type] = self.filter_user_resource(
                        master_resources.get(resource_type, "")
                    )
                elif resource_type == consts.RESOURCE_TYPE_SYSINV_FERNET_REPO:
                    audit_payload[resource_type] = master_resources.get(
                        resource_type, ""
                    )
            # audit_payload["use_cache"] = False
            resources = self.get_sc_dcagent_client().audit(audit_payload)
            LOG.debug(
                f"dcagent response: {resources=}",
                extra=self.log_extra,
            )
            return resources

        except Exception:
            failmsg = "Audit failure subcloud: %s, endpoint: %s"
            LOG.exception(failmsg % (self.subcloud_name, "dcagent"))
            return None

    def is_dcagent_managed_resource(self, resource_type):
        return True

    def is_resource_present_in_subcloud(self, resource_type, master_id, sc_resources):
        if sc_resources == dccommon_consts.SYNC_STATUS_IN_SYNC:
            LOG.debug(
                "Resource type {} {} is in-sync".format(resource_type, master_id),
                extra=self.log_extra,
            )
            return True
        elif sc_resources == dccommon_consts.SYNC_STATUS_OUT_OF_SYNC:
            # The information will be logged in the sync_thread
            return False
        elif isinstance(sc_resources, dict):
            # The returned value for certificates is a dictionary with the
            # signature as key and the sync status as value.
            # We want to check if the specific cert is in-sync
            return sc_resources.get(master_id) == dccommon_consts.SYNC_STATUS_IN_SYNC
        # If the response is not what we expected, we considered to not be present
        LOG.warn(f"Unnexpected subcloud resource for {resource_type}: {sc_resources}")
        return False
