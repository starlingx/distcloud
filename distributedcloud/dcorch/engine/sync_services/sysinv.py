# Copyright 2017-2020 Wind River
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

from keystoneauth1 import exceptions as keystone_exceptions
from requests_toolbelt import MultipartDecoder

from oslo_log import log as logging
from oslo_serialization import jsonutils

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack import sdk_platform as sdk
from dccommon import exceptions as dccommon_exceptions
from dcorch.common import consts
from dcorch.common import exceptions

from dcorch.engine.fernet_key_manager import FERNET_REPO_MASTER_ID
from dcorch.engine.fernet_key_manager import FernetKeyManager
from dcorch.engine.sync_thread import AUDIT_RESOURCE_EXTRA
from dcorch.engine.sync_thread import AUDIT_RESOURCE_MISSING
from dcorch.engine.sync_thread import SyncThread

LOG = logging.getLogger(__name__)


class SysinvSyncThread(SyncThread):
    """Manages tasks related to distributed cloud orchestration for sysinv."""

    SYSINV_MODIFY_RESOURCES = [consts.RESOURCE_TYPE_SYSINV_DNS,
                               consts.RESOURCE_TYPE_SYSINV_USER,
                               consts.RESOURCE_TYPE_SYSINV_FERNET_REPO
                               ]

    SYSINV_ADD_DELETE_RESOURCES = [consts.RESOURCE_TYPE_SYSINV_SNMP_COMM,
                                   consts.RESOURCE_TYPE_SYSINV_SNMP_TRAPDEST]

    SYSINV_CREATE_RESOURCES = [consts.RESOURCE_TYPE_SYSINV_CERTIFICATE,
                               consts.RESOURCE_TYPE_SYSINV_FERNET_REPO]

    CERTIFICATE_SIG_NULL = 'NoCertificate'
    RESOURCE_UUID_NULL = 'NoResourceUUID'

    AVOID_SYNC_CERTIFICATES = ["ssl"]

    def __init__(self, subcloud_engine):
        super(SysinvSyncThread, self).__init__(subcloud_engine)

        self.endpoint_type = consts.ENDPOINT_TYPE_PLATFORM
        self.sync_handler_map = {
            consts.RESOURCE_TYPE_SYSINV_DNS:
                self.sync_platform_resource,
            consts.RESOURCE_TYPE_SYSINV_SNMP_COMM:
                self.sync_platform_resource,
            consts.RESOURCE_TYPE_SYSINV_SNMP_TRAPDEST:
                self.sync_platform_resource,
            consts.RESOURCE_TYPE_SYSINV_CERTIFICATE:
                self.sync_platform_resource,
            consts.RESOURCE_TYPE_SYSINV_USER:
                self.sync_platform_resource,
            consts.RESOURCE_TYPE_SYSINV_FERNET_REPO:
                self.sync_platform_resource
        }
        self.region_name = self.subcloud_engine.subcloud.region_name
        self.log_extra = {"instance": "{}/{}: ".format(
            self.subcloud_engine.subcloud.region_name, self.endpoint_type)}

        self.audit_resources = [
            consts.RESOURCE_TYPE_SYSINV_CERTIFICATE,
            consts.RESOURCE_TYPE_SYSINV_DNS,
            consts.RESOURCE_TYPE_SYSINV_SNMP_COMM,
            consts.RESOURCE_TYPE_SYSINV_SNMP_TRAPDEST,
            consts.RESOURCE_TYPE_SYSINV_USER,
            consts.RESOURCE_TYPE_SYSINV_FERNET_REPO,
        ]

        # initialize the master clients
        super(SysinvSyncThread, self).initialize()
        LOG.info("SysinvSyncThread initialized", extra=self.log_extra)

    def sync_platform_resource(self, request, rsrc):
        try:
            s_os_client = sdk.OpenStackDriver(region_name=self.region_name,
                                              thread_name=self.thread.name)
            # invoke the sync method for the requested resource_type
            # I.e. sync_idns
            s_func_name = "sync_" + rsrc.resource_type
            getattr(self, s_func_name)(s_os_client, request, rsrc)
        except AttributeError:
            LOG.error("{} not implemented for {}"
                      .format(request.orch_job.operation_type,
                              rsrc.resource_type))
            raise exceptions.SyncRequestFailed
        except (exceptions.ConnectionRefused, exceptions.TimeOut,
                keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.info("{} {} region_name {} exception {}".format(
                request.orch_job.operation_type, rsrc.resource_type,
                self.region_name, str(e)), extra=self.log_extra)
            raise exceptions.SyncRequestTimeout
        except exceptions.NotAuthorized:
            LOG.info("{} {} region_name {} not authorized".format(
                request.orch_job.operation_type, rsrc.resource_type,
                self.region_name), extra=self.log_extra)
            sdk.OpenStackDriver.delete_region_clients(self.region_name)
            raise exceptions.SyncRequestFailedRetry
        except Exception as e:
            LOG.exception(e)
            raise exceptions.SyncRequestFailedRetry

    def update_dns(self, s_os_client, nameservers):
        try:
            idns = s_os_client.sysinv_client.update_dns(nameservers)
            return idns
        except (AttributeError, TypeError) as e:
            LOG.info("update_dns error {}".format(e),
                     extra=self.log_extra)
            raise exceptions.SyncRequestFailedRetry

    def sync_idns(self, s_os_client, request, rsrc):
        # The system is created with default dns; thus there
        # is a prepopulated dns entry.
        LOG.info("sync_idns resource_info={}".format(
                 request.orch_job.resource_info),
                 extra=self.log_extra)
        dns_dict = jsonutils.loads(request.orch_job.resource_info)
        payload = dns_dict.get('payload')

        nameservers = None
        if type(payload) is list:
            for ipayload in payload:
                if ipayload.get('path') == '/nameservers':
                    nameservers = ipayload.get('value')
                    LOG.debug("sync_idns nameservers = {}".format(nameservers),
                              extra=self.log_extra)
                    break
        else:
            nameservers = payload.get('nameservers')
            LOG.debug("sync_idns nameservers from dict={}".format(nameservers),
                      extra=self.log_extra)

        if nameservers is None:
            LOG.info("sync_idns No nameservers update found in resource_info"
                     "{}".format(request.orch_job.resource_info),
                     extra=self.log_extra)
            nameservers = ""

        idns = self.update_dns(s_os_client, nameservers)

        # Ensure subcloud resource is persisted to the DB for later
        subcloud_rsrc_id = self.persist_db_subcloud_resource(
            rsrc.id, idns.uuid)
        LOG.info("DNS {}:{} [{}] updated"
                 .format(rsrc.id, subcloud_rsrc_id, nameservers),
                 extra=self.log_extra)

    def sync_itrapdest(self, s_os_client, request, rsrc):
        switcher = {
            consts.OPERATION_TYPE_POST: self.snmp_trapdest_create,
            consts.OPERATION_TYPE_CREATE: self.snmp_trapdest_create,
            consts.OPERATION_TYPE_DELETE: self.snmp_trapdest_delete,
        }

        func = switcher[request.orch_job.operation_type]
        try:
            func(s_os_client, request, rsrc)
        except Exception as e:
            LOG.exception(e)
            raise e

    def snmp_trapdest_create(self, s_os_client, request, rsrc):
        LOG.info("snmp_trapdest_create region {} resource_info={}".format(
                 self.subcloud_engine.subcloud.region_name,
                 request.orch_job.resource_info),
                 extra=self.log_extra)
        resource_info_dict = jsonutils.loads(request.orch_job.resource_info)
        payload = resource_info_dict.get('payload')
        if not payload:
            payload = resource_info_dict

        try:
            itrapdest = s_os_client.sysinv_client.snmp_trapdest_create(
                payload)
            itrapdest_id = itrapdest.uuid
            ip_address = itrapdest.ip_address
        except (AttributeError, TypeError) as e:
            LOG.info("snmp_trapdest_create error {}".format(e),
                     extra=self.log_extra)
            raise exceptions.SyncRequestFailedRetry

        # Now persist the subcloud resource to the DB for later
        subcloud_rsrc_id = self.persist_db_subcloud_resource(
            rsrc.id, ip_address)

        LOG.info("SNMP trapdest {}:{} [{}/{}] created".format(rsrc.id,
                 subcloud_rsrc_id, ip_address, itrapdest_id),
                 extra=self.log_extra)
        return itrapdest

    def snmp_trapdest_delete(self, s_os_client, request, rsrc):
        subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if not subcloud_rsrc:
            return

        try:
            s_os_client.sysinv_client.snmp_trapdest_delete(
                subcloud_rsrc.subcloud_resource_id)
        except dccommon_exceptions.TrapDestNotFound:
            # SNMP trapdest already deleted in subcloud, carry on.
            LOG.info("SNMP trapdest not in subcloud, may be already deleted",
                     extra=self.log_extra)
        except (AttributeError, TypeError) as e:
            LOG.info("snmp_trapdest_delete error {}".format(e),
                     extra=self.log_extra)
            raise exceptions.SyncRequestFailedRetry

        subcloud_rsrc.delete()
        # Master Resource can be deleted only when all subcloud resources
        # are deleted along with corresponding orch_job and orch_requests.
        LOG.info("SNMP trapdest {}:{} [{}] deleted".format(
                 rsrc.id, subcloud_rsrc.id,
                 subcloud_rsrc.subcloud_resource_id),
                 extra=self.log_extra)

    def sync_icommunity(self, s_os_client, request, rsrc):
        switcher = {
            consts.OPERATION_TYPE_POST: self.snmp_community_create,
            consts.OPERATION_TYPE_CREATE: self.snmp_community_create,
            consts.OPERATION_TYPE_DELETE: self.snmp_community_delete,
        }

        func = switcher[request.orch_job.operation_type]
        try:
            func(s_os_client, request, rsrc)
        except Exception as e:
            LOG.exception(e)
            raise exceptions.SyncRequestFailedRetry

    def snmp_community_create(self, s_os_client, request, rsrc):
        LOG.info("snmp_community_create region {} resource_info={}".format(
                 self.subcloud_engine.subcloud.region_name,
                 request.orch_job.resource_info),
                 extra=self.log_extra)
        resource_info_dict = jsonutils.loads(request.orch_job.resource_info)
        payload = resource_info_dict.get('payload')
        if not payload:
            payload = resource_info_dict

        try:
            icommunity = s_os_client.sysinv_client.snmp_community_create(
                payload)
            icommunity_id = icommunity.uuid
            community = icommunity.community
        except (AttributeError, TypeError) as e:
            LOG.info("snmp_community_create error {}".format(e),
                     extra=self.log_extra)
            raise exceptions.SyncRequestFailedRetry

        # Now persist the subcloud resource to the DB for later
        subcloud_rsrc_id = self.persist_db_subcloud_resource(
            rsrc.id, community)

        LOG.info("SNMP community {}:{} [{}/{}] created".format(rsrc.id,
                 subcloud_rsrc_id, community, icommunity_id),
                 extra=self.log_extra)
        return icommunity

    def snmp_community_delete(self, s_os_client, request, rsrc):
        subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if not subcloud_rsrc:
            return
        try:
            s_os_client.sysinv_client.snmp_community_delete(
                subcloud_rsrc.subcloud_resource_id)
        except dccommon_exceptions.CommunityNotFound:
            # Community already deleted in subcloud, carry on.
            LOG.info("SNMP community not in subcloud, may be already deleted",
                     extra=self.log_extra)
        except (AttributeError, TypeError) as e:
            LOG.info("snmp_community_delete error {}".format(e),
                     extra=self.log_extra)
            raise exceptions.SyncRequestFailedRetry

        subcloud_rsrc.delete()
        # Master Resource can be deleted only when all subcloud resources
        # are deleted along with corresponding orch_job and orch_requests.
        LOG.info("SNMP community {}:{} [{}] deleted".format(
                 rsrc.id, subcloud_rsrc.id,
                 subcloud_rsrc.subcloud_resource_id),
                 extra=self.log_extra)

    def update_certificate(self, s_os_client, signature,
                           certificate=None, data=None):

        try:
            icertificate = s_os_client.sysinv_client.update_certificate(
                signature, certificate=certificate, data=data)
            return icertificate
        except (AttributeError, TypeError) as e:
            LOG.info("update_certificate error {} region_name".format(e),
                     extra=self.log_extra)
            raise exceptions.SyncRequestFailedRetry

    @staticmethod
    def _decode_certificate_payload(certificate_dict):
        """Decode certificate from payload.

           params: certificate_dict
           returns: certificate, metadata
        """
        certificate = None
        metadata = {}
        content_disposition = 'Content-Disposition'
        try:
            content_type = certificate_dict.get('content_type')
            payload = certificate_dict.get('payload')
            multipart_data = MultipartDecoder(payload, content_type)
            for part in multipart_data.parts:
                if ('name="passphrase"' in part.headers.get(
                        content_disposition)):
                    metadata.update({'passphrase': part.content})
                elif ('name="mode"' in part.headers.get(
                        content_disposition)):
                    metadata.update({'mode': part.content})
                elif ('name="file"' in part.headers.get(
                        content_disposition)):
                    certificate = part.content
        except Exception as e:
            LOG.warn("No certificate decode e={}".format(e))

        LOG.info("_decode_certificate_payload metadata={}".format(
            metadata))
        return certificate, metadata

    def create_certificate(self, s_os_client, request, rsrc):
        LOG.info("create_certificate resource_info={}".format(
                 request.orch_job.resource_info),
                 extra=self.log_extra)
        certificate_dict = jsonutils.loads(request.orch_job.resource_info)
        payload = certificate_dict.get('payload')

        if not payload:
            LOG.info("create_certificate No payload found in resource_info"
                     "{}".format(request.orch_job.resource_info),
                     extra=self.log_extra)
            return

        if payload.get('certtype') in self.AVOID_SYNC_CERTIFICATES:
            return

        if isinstance(payload, dict):
            signature = payload.get('signature')
            LOG.info("signature from dict={}".format(signature))
        else:
            signature = rsrc.master_id
            LOG.info("signature from master_id={}".format(signature))

        certificate, metadata = self._decode_certificate_payload(
            certificate_dict)

        icertificate = None
        signature = rsrc.master_id
        if signature and signature != self.CERTIFICATE_SIG_NULL:
            icertificate = self.update_certificate(
                s_os_client,
                signature,
                certificate=certificate,
                data=metadata)
        else:
            LOG.info("skipping signature={}".format(signature))

        # Ensure subcloud resource is persisted to the DB for later
        subcloud_rsrc_id = self.persist_db_subcloud_resource(
            rsrc.id, signature)

        cert_bodys = icertificate.get('certificates')
        sub_certs_updated = [str(cert_body.get('signature'))
                             for cert_body in cert_bodys]

        LOG.info("certificate {} {} [{}] updated with subcloud certificates:"
                 " {}".format(rsrc.id, subcloud_rsrc_id, signature,
                              sub_certs_updated),
                 extra=self.log_extra)

    def delete_certificate(self, s_os_client, request, rsrc):
        subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if not subcloud_rsrc:
            return

        try:
            certificates = self.get_certificates_resources(s_os_client)
            cert_to_delete = None
            for certificate in certificates:
                if certificate.signature == subcloud_rsrc.subcloud_resource_id:
                    cert_to_delete = certificate
                    break
            if not cert_to_delete:
                raise dccommon_exceptions.CertificateNotFound(
                    region_name=self.subcloud_engine.subcloud.region_name,
                    signature=subcloud_rsrc.subcloud_resource_id)
            s_os_client.sysinv_client.delete_certificate(cert_to_delete)
        except dccommon_exceptions.CertificateNotFound:
            # Certificate already deleted in subcloud, carry on.
            LOG.info("Certificate not in subcloud, may be already deleted",
                     extra=self.log_extra)
        except (AttributeError, TypeError) as e:
            LOG.info("delete_certificate error {}".format(e),
                     extra=self.log_extra)
            raise exceptions.SyncRequestFailedRetry

        subcloud_rsrc.delete()
        # Master Resource can be deleted only when all subcloud resources
        # are deleted along with corresponding orch_job and orch_requests.
        LOG.info("Certificate {}:{} [{}] deleted".format(
                 rsrc.id, subcloud_rsrc.id,
                 subcloud_rsrc.subcloud_resource_id),
                 extra=self.log_extra)

    def sync_certificates(self, s_os_client, request, rsrc):
        switcher = {
            consts.OPERATION_TYPE_POST: self.create_certificate,
            consts.OPERATION_TYPE_CREATE: self.create_certificate,
            consts.OPERATION_TYPE_DELETE: self.delete_certificate,
        }

        func = switcher[request.orch_job.operation_type]
        try:
            func(s_os_client, request, rsrc)
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.info("sync_certificates: subcloud {} is not reachable [{}]"
                     .format(self.subcloud_engine.subcloud.region_name,
                             str(e)), extra=self.log_extra)
            raise exceptions.SyncRequestTimeout
        except Exception as e:
            LOG.exception(e)
            raise exceptions.SyncRequestFailedRetry

    def update_user(self, s_os_client, passwd_hash,
                    root_sig, passwd_expiry_days):
        LOG.info("update_user={} {} {}".format(
                 passwd_hash, root_sig, passwd_expiry_days),
                 extra=self.log_extra)

        try:
            iuser = s_os_client.sysinv_client.update_user(passwd_hash,
                                                          root_sig,
                                                          passwd_expiry_days)
            return iuser
        except (AttributeError, TypeError) as e:
            LOG.info("update_user error {} region_name".format(e),
                     extra=self.log_extra)
            raise exceptions.SyncRequestFailedRetry

    def sync_iuser(self, s_os_client, request, rsrc):
        # The system is populated with user entry for wrsroot.
        LOG.info("sync_user resource_info={}".format(
                 request.orch_job.resource_info),
                 extra=self.log_extra)
        user_dict = jsonutils.loads(request.orch_job.resource_info)
        payload = user_dict.get('payload')

        passwd_hash = None
        if type(payload) is list:
            for ipayload in payload:
                if ipayload.get('path') == '/passwd_hash':
                    passwd_hash = ipayload.get('value')
                elif ipayload.get('path') == '/root_sig':
                    root_sig = ipayload.get('value')
                elif ipayload.get('path') == '/passwd_expiry_days':
                    passwd_expiry_days = ipayload.get('value')
        else:
            passwd_hash = payload.get('passwd_hash')
            root_sig = payload.get('root_sig')
            passwd_expiry_days = payload.get('passwd_expiry_days')

        LOG.info("sync_user from dict passwd_hash={} root_sig={} "
                 "passwd_expiry_days={}".format(
                     passwd_hash, root_sig, passwd_expiry_days),
                 extra=self.log_extra)

        if not passwd_hash:
            LOG.info("sync_user no user update found in resource_info"
                     "{}".format(request.orch_job.resource_info),
                     extra=self.log_extra)
            return

        iuser = self.update_user(s_os_client, passwd_hash, root_sig,
                                 passwd_expiry_days)

        # Ensure subcloud resource is persisted to the DB for later
        subcloud_rsrc_id = self.persist_db_subcloud_resource(
            rsrc.id, iuser.uuid)
        LOG.info("User wrsroot {}:{} [{}] updated"
                 .format(rsrc.id, subcloud_rsrc_id, passwd_hash),
                 extra=self.log_extra)

    def sync_fernet_repo(self, s_os_client, request, rsrc):
        switcher = {
            consts.OPERATION_TYPE_PUT: self.update_fernet_repo,
            consts.OPERATION_TYPE_PATCH: self.update_fernet_repo,
            consts.OPERATION_TYPE_CREATE: self.create_fernet_repo,
        }

        func = switcher[request.orch_job.operation_type]
        try:
            func(s_os_client, request, rsrc)
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.info("sync_fernet_resources: subcloud {} is not reachable [{}]"
                     .format(self.subcloud_engine.subcloud.region_name,
                             str(e)), extra=self.log_extra)
            raise exceptions.SyncRequestTimeout
        except Exception as e:
            LOG.exception(e)
            raise exceptions.SyncRequestFailedRetry

    def create_fernet_repo(self, s_os_client, request, rsrc):
        LOG.info("create_fernet_repo region {} resource_info={}".format(
            self.subcloud_engine.subcloud.region_name,
            request.orch_job.resource_info),
            extra=self.log_extra)
        resource_info = jsonutils.loads(request.orch_job.resource_info)

        try:
            s_os_client.sysinv_client.post_fernet_repo(
                FernetKeyManager.from_resource_info(resource_info))
            # Ensure subcloud resource is persisted to the DB for later
            subcloud_rsrc_id = self.persist_db_subcloud_resource(
                rsrc.id, rsrc.master_id)
        except (AttributeError, TypeError) as e:
            LOG.info("create_fernet_repo error {}".format(e),
                     extra=self.log_extra)
            raise exceptions.SyncRequestFailedRetry

        LOG.info("fernet_repo {} {} {} created".format(rsrc.id,
                 subcloud_rsrc_id, resource_info),
                 extra=self.log_extra)

    def update_fernet_repo(self, s_os_client, request, rsrc):
        LOG.info("update_fernet_repo region {} resource_info={}".format(
            self.subcloud_engine.subcloud.region_name,
            request.orch_job.resource_info),
            extra=self.log_extra)
        resource_info = jsonutils.loads(request.orch_job.resource_info)

        try:
            s_os_client.sysinv_client.put_fernet_repo(
                FernetKeyManager.from_resource_info(resource_info))
            # Ensure subcloud resource is persisted to the DB for later
            subcloud_rsrc_id = self.persist_db_subcloud_resource(
                rsrc.id, rsrc.master_id)
        except (AttributeError, TypeError) as e:
            LOG.info("update_fernet_repo error {}".format(e),
                     extra=self.log_extra)
            raise exceptions.SyncRequestFailedRetry

        LOG.info("fernet_repo {} {} {} update".format(rsrc.id,
                 subcloud_rsrc_id, resource_info),
                 extra=self.log_extra)

    # SysInv Audit Related
    def get_master_resources(self, resource_type):
        try:
            os_client = sdk.OpenStackDriver(
                region_name=dccommon_consts.CLOUD_0,
                thread_name=self.audit_thread.name)
            if resource_type == consts.RESOURCE_TYPE_SYSINV_DNS:
                return [self.get_dns_resource(os_client)]
            elif resource_type == consts.RESOURCE_TYPE_SYSINV_SNMP_COMM:
                return self.get_snmp_community_resources(os_client)
            elif resource_type == consts.RESOURCE_TYPE_SYSINV_SNMP_TRAPDEST:
                return self.get_snmp_trapdest_resources(os_client)
            elif resource_type == consts.RESOURCE_TYPE_SYSINV_CERTIFICATE:
                return self.get_certificates_resources(os_client)
            elif resource_type == consts.RESOURCE_TYPE_SYSINV_USER:
                return [self.get_user_resource(os_client)]
            elif resource_type == consts.RESOURCE_TYPE_SYSINV_FERNET_REPO:
                return [self.get_fernet_resources(os_client)]
            else:
                LOG.error("Wrong resource type {}".format(resource_type),
                          extra=self.log_extra)
                return None
        except Exception as e:
            LOG.exception(e)
            return None

    def get_subcloud_resources(self, resource_type):
        try:
            os_client = sdk.OpenStackDriver(region_name=self.region_name,
                                            thread_name=self.audit_thread.name)
            if resource_type == consts.RESOURCE_TYPE_SYSINV_DNS:
                return [self.get_dns_resource(os_client)]
            elif resource_type == consts.RESOURCE_TYPE_SYSINV_SNMP_COMM:
                return self.get_snmp_community_resources(os_client)
            elif resource_type == consts.RESOURCE_TYPE_SYSINV_SNMP_TRAPDEST:
                return self.get_snmp_trapdest_resources(os_client)
            elif resource_type == consts.RESOURCE_TYPE_SYSINV_CERTIFICATE:
                return self.get_certificates_resources(os_client)
            elif resource_type == consts.RESOURCE_TYPE_SYSINV_USER:
                return [self.get_user_resource(os_client)]
            elif resource_type == consts.RESOURCE_TYPE_SYSINV_FERNET_REPO:
                return [self.get_fernet_resources(os_client)]
            else:
                LOG.error("Wrong resource type {}".format(resource_type),
                          extra=self.log_extra)
                return None
        except (exceptions.ConnectionRefused, exceptions.TimeOut,
                keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.info("get subcloud_resources {}: subcloud {} is not reachable"
                     "[{}]".format(resource_type,
                                   self.subcloud_engine.subcloud.region_name,
                                   str(e)), extra=self.log_extra)
            # None will force skip of audit
            return None
        except exceptions.NotAuthorized as e:
            LOG.info("get subcloud_resources {}: subcloud {} not authorized"
                     "[{}]".format(resource_type,
                                   self.subcloud_engine.subcloud.region_name,
                                   str(e)), extra=self.log_extra)
            sdk.OpenStackDriver.delete_region_clients(self.region_name)
            return None
        except (AttributeError, TypeError) as e:
            LOG.info("get subcloud_resources {} error {}".format(
                resource_type, e), extra=self.log_extra)
            return None
        except Exception as e:
            LOG.exception(e)
            return None

    def post_audit(self):
        super(SysinvSyncThread, self).post_audit()
        sdk.OpenStackDriver.delete_region_clients_for_thread(
            self.region_name, self.audit_thread.name)
        sdk.OpenStackDriver.delete_region_clients_for_thread(
            dccommon_consts.CLOUD_0, self.audit_thread.name)

    def get_dns_resource(self, os_client):
        return os_client.sysinv_client.get_dns()

    def get_snmp_trapdest_resources(self, os_client):
        return os_client.sysinv_client.snmp_trapdest_list()

    def get_snmp_community_resources(self, os_client):
        return os_client.sysinv_client.snmp_community_list()

    def get_certificates_resources(self, os_client):
        certificate_list = os_client.sysinv_client.get_certificates()
        # Filter SSL certificates to avoid sync
        filtered_list = [certificate
                         for certificate in certificate_list
                         if certificate.certtype not in
                         self.AVOID_SYNC_CERTIFICATES]
        return filtered_list

    def get_user_resource(self, os_client):
        return os_client.sysinv_client.get_user()

    def get_fernet_resources(self, os_client):
        keys = os_client.sysinv_client.get_fernet_keys()
        return FernetKeyManager.to_resource_info(keys)

    def get_resource_id(self, resource_type, resource):
        if resource_type == consts.RESOURCE_TYPE_SYSINV_SNMP_COMM:
            LOG.debug("get_resource_id for community {}".format(resource))
            return resource.community
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_SNMP_TRAPDEST:
            if hasattr(resource, 'ip_address') and \
               hasattr(resource, 'community'):
                LOG.debug("get_resource_id resource={} has ip_address and "
                          "community".format(resource),
                          extra=self.log_extra)
                return resource.ip_address
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_CERTIFICATE:
            if hasattr(resource, 'signature'):
                LOG.debug("get_resource_id signature={}".format(
                    resource.signature))
                if resource.signature is None:
                    return self.CERTIFICATE_SIG_NULL
                return resource.signature
            elif hasattr(resource, 'master_id'):
                LOG.debug("get_resource_id master_id signature={}".format(
                    resource.master_id))
                if resource.master_id is None:
                    # master_id cannot be None
                    return self.CERTIFICATE_SIG_NULL
                return resource.master_id
            else:
                LOG.error("no get_resource_id for certificate")
                return self.CERTIFICATE_SIG_NULL
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_FERNET_REPO:
            LOG.debug("get_resource_id {} resource={}".format(
                resource_type, resource))
            return FERNET_REPO_MASTER_ID
        else:
            if hasattr(resource, 'uuid'):
                LOG.debug("get_resource_id {} uuid={}".format(
                    resource_type, resource.uuid))
                return resource.uuid
            else:
                LOG.debug("get_resource_id NO uuid resource_type={}".format(
                    resource_type))
                return self.RESOURCE_UUID_NULL  # master_id cannot be None

    def same_dns(self, i1, i2):
        LOG.debug("same_dns i1={}, i2={}".format(i1, i2),
                  extra=self.log_extra)
        same_nameservers = True
        if i1.nameservers != i2.nameservers:
            if not i1.nameservers and not i2.nameservers:
                # To catch equivalent nameservers None vs ""
                same_nameservers = True
            else:
                same_nameservers = False
        return same_nameservers

    def same_snmp_trapdest(self, i1, i2):
        LOG.debug("same_snmp_trapdest i1={}, i2={}".format(i1, i2),
                  extra=self.log_extra)
        return (i1.ip_address == i2.ip_address and
                i1.community == i2.community)

    def same_snmp_community(self, i1, i2):
        LOG.debug("same_snmp_community i1={}, i2={}".format(i1, i2),
                  extra=self.log_extra)
        if i1.community and (i1.community != i2.community):
            if i1.signature == self.RESOURCE_UUID_NULL:
                LOG.info("Master Resource SNMP Community NULL UUID")
                return True
            return False
        return True

    def same_certificate(self, i1, i2):
        LOG.debug("same_certificate i1={}, i2={}".format(i1, i2),
                  extra=self.log_extra)
        same = True
        if i1.signature and (i1.signature != i2.signature):
            if i1.signature == self.CERTIFICATE_SIG_NULL:
                return True
            same = False
        if ((i1.expiry_date and i1.expiry_date != i2.expiry_date) or
           (i1.start_date and i1.start_date != i2.start_date)):
            same = False

        if not same:
            LOG.info("same_certificate differs i1={}, i2={}".format(i1, i2),
                     extra=self.log_extra)

        return same

    def same_user(self, i1, i2):
        LOG.debug("same_user i1={}, i2={}".format(i1, i2),
                  extra=self.log_extra)
        same_user = True
        if (i1.passwd_hash != i2.passwd_hash or
           i1.passwd_expiry_days != i2.passwd_expiry_days):
            same_user = False
        return same_user

    def same_fernet_key(self, i1, i2):
        LOG.debug("same_fernet_repo i1={}, i2={}".format(i1, i2),
                  extra=self.log_extra)
        same_fernet = True
        if (FernetKeyManager.get_resource_hash(i1) !=
                FernetKeyManager.get_resource_hash(i2)):
            same_fernet = False
        return same_fernet

    def same_resource(self, resource_type, m_resource, sc_resource):
        if resource_type == consts.RESOURCE_TYPE_SYSINV_DNS:
            return self.same_dns(m_resource, sc_resource)
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_SNMP_COMM:
            return self.same_snmp_community(m_resource, sc_resource)
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_SNMP_TRAPDEST:
            return self.same_snmp_trapdest(m_resource, sc_resource)
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_CERTIFICATE:
            return self.same_certificate(m_resource, sc_resource)
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_USER:
            return self.same_user(m_resource, sc_resource)
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_FERNET_REPO:
            return self.same_fernet_key(m_resource, sc_resource)
        else:
            LOG.warn("same_resource() unexpected resource_type {}".format(
                resource_type),
                extra=self.log_extra)

    def audit_discrepancy(self, resource_type, m_resource, sc_resources):
        # Return true to try the audit_action
        if resource_type in self.SYSINV_ADD_DELETE_RESOURCES:
            # It could be that the details are different
            # between master cloud and subcloud now.
            # Thus, delete the resource before creating it again.
            master_id = self.get_resource_id(resource_type, m_resource)
            self.schedule_work(self.endpoint_type, resource_type,
                               master_id,
                               consts.OPERATION_TYPE_DELETE)
            return True
        elif (resource_type in self.SYSINV_MODIFY_RESOURCES or
              resource_type in self.SYSINV_CREATE_RESOURCES):
            # The resource differs, signal to perform the audit_action
            return True

        LOG.info("audit_discrepancy resource_type {} default action".format(
            resource_type), extra=self.log_extra)
        return False

    def audit_action(self, resource_type, finding, resource, sc_source=None):
        if resource_type in self.SYSINV_MODIFY_RESOURCES:
            LOG.info("audit_action: {}/{}"
                     .format(finding, resource_type),
                     extra=self.log_extra)
            num_of_audit_jobs = 0
            if finding == AUDIT_RESOURCE_MISSING:
                # The missing resource should be created by underlying subcloud
                # thus action is to update for a 'missing' resource
                # should not get here since audit discrepency will handle this
                resource_id = self.get_resource_id(resource_type, resource)
                self.schedule_work(self.endpoint_type, resource_type,
                                   resource_id,
                                   consts.OPERATION_TYPE_PATCH,
                                   self.get_resource_info(
                                       resource_type, resource))
                num_of_audit_jobs += 1
            else:
                LOG.warn("unexpected finding {} resource_type {}".format(
                         finding, resource_type),
                         extra=self.log_extra)
            return num_of_audit_jobs
        elif resource_type in self.SYSINV_CREATE_RESOURCES:
            LOG.info("audit_action: {}/{}"
                     .format(finding, resource_type),
                     extra=self.log_extra)
            # Default actions are create & delete. Can be overridden
            # in resource implementation
            num_of_audit_jobs = 0
            # resource can be either from dcorch DB or
            # fetched by OpenStack query
            resource_id = self.get_resource_id(resource_type, resource)
            if resource_id == self.CERTIFICATE_SIG_NULL:
                LOG.info("No certificate resource to sync")
                return num_of_audit_jobs
            elif resource_id == self.RESOURCE_UUID_NULL:
                LOG.info("No resource to sync")
                return num_of_audit_jobs

            if finding == AUDIT_RESOURCE_MISSING:
                # default action is create for a 'missing' resource
                self.schedule_work(
                    self.endpoint_type, resource_type,
                    resource_id,
                    consts.OPERATION_TYPE_CREATE,
                    self.get_resource_info(
                        resource_type, resource,
                        consts.OPERATION_TYPE_CREATE))
                num_of_audit_jobs += 1
            elif finding == AUDIT_RESOURCE_EXTRA:
                # default action is delete for a 'extra' resource
                self.schedule_work(self.endpoint_type, resource_type,
                                   resource_id,
                                   consts.OPERATION_TYPE_DELETE)
                num_of_audit_jobs += 1
            return num_of_audit_jobs
        else:  # use default audit_action
            return super(SysinvSyncThread, self).audit_action(
                resource_type,
                finding,
                resource)

    def get_resource_info(self, resource_type,
                          resource, operation_type=None):
        payload_resources = [consts.RESOURCE_TYPE_SYSINV_DNS,
                             consts.RESOURCE_TYPE_SYSINV_SNMP_COMM,
                             consts.RESOURCE_TYPE_SYSINV_SNMP_TRAPDEST,
                             consts.RESOURCE_TYPE_SYSINV_CERTIFICATE,
                             consts.RESOURCE_TYPE_SYSINV_USER,
                             ]
        if resource_type in payload_resources:
            if 'payload' not in resource._info:
                dumps = jsonutils.dumps({"payload": resource._info})
            else:
                dumps = jsonutils.dumps(resource._info)
            LOG.info("get_resource_info resource_type={} dumps={}".format(
                resource_type, dumps),
                extra=self.log_extra)
            return dumps
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_FERNET_REPO:
            LOG.info("get_resource_info resource_type={} resource={}".format(
                resource_type, resource), extra=self.log_extra)
            return jsonutils.dumps(resource)
        else:
            LOG.warn("get_resource_info unsupported resource {}".format(
                resource_type),
                extra=self.log_extra)
            return super(SysinvSyncThread, self).get_resource_info(
                resource_type, resource, operation_type)
