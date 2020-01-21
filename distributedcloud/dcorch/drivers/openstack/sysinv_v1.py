# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import hashlib
import six

from cgtsclient import client as cgts_client
from cgtsclient.exc import HTTPConflict
from cgtsclient.exc import HTTPNotFound
from cgtsclient.v1.icommunity import CREATION_ATTRIBUTES \
    as SNMP_COMMUNITY_CREATION_ATTRIBUTES
from cgtsclient.v1.itrapdest import CREATION_ATTRIBUTES \
    as SNMP_TRAPDEST_CREATION_ATTRIBUTES
from oslo_log import log
from sysinv.common import constants as sysinv_constants

from dcorch.common import consts
from dcorch.common import exceptions
from dcorch.drivers import base

LOG = log.getLogger(__name__)

API_VERSION = '1'


def make_sysinv_patch(update_dict):
    patch = []
    for k, v in update_dict.items():
        key = k
        if not k.startswith('/'):
            key = '/' + key

        p = {'path': key, 'value': v, 'op': 'replace'}
        patch.append(dict(p))

    LOG.debug("make_sysinv_patch patch={}".format(patch))

    return patch


class SysinvClient(base.DriverBase):
    """Sysinv V1 driver."""

    # TODO(John): This could go into cgtsclient/v1/remotelogging.py
    REMOTELOGGING_PATCH_ATTRS = ['ip_address', 'enabled', 'transport', 'port',
                                 'action']

    def __init__(self, region_name, session):
        self._expired = False
        self.api_version = API_VERSION
        self.region_name = region_name
        self.session = session

        self.client = self.update_client(
            self.api_version, self.region_name, self.session)

    def update_client(self, api_version, region_name, session):
        try:
            endpoint = self.session.get_endpoint(
                service_type=consts.ENDPOINT_TYPE_PLATFORM,
                interface=consts.KS_ENDPOINT_INTERNAL,
                region_name=region_name)
            token = session.get_token()
            client = cgts_client.Client(
                api_version,
                username=session.auth._username,
                password=session.auth._password,
                tenant_name=session.auth._project_name,
                auth_url=session.auth.auth_url,
                endpoint=endpoint,
                token=token)
        except exceptions.ServiceUnavailable:
            raise

        self._expired = False

        return client

    def get_dns(self):
        """Get the dns nameservers for this region

           :return: dns
        """
        idnss = self.client.idns.list()
        if not idnss:
            LOG.info("dns is None for region: %s" % self.region_name)
            return None
        idns = idnss[0]

        LOG.debug("get_dns uuid=%s nameservers=%s" %
                  (idns.uuid, idns.nameservers))

        return idns

    def update_dns(self, nameservers):
        """Update the dns nameservers for this region

           :param: nameservers  csv string
           :return: Nothing
        """
        try:
            idns = self.get_dns()
            if not idns:
                LOG.warn("idns not found %s" % self.region_name)
                return idns

            if idns.nameservers != nameservers:
                if nameservers == "":
                    nameservers = "NC"
                patch = make_sysinv_patch({'nameservers': nameservers,
                                           'action': 'apply'})
                LOG.info("region={} dns update uuid={} patch={}".format(
                         self.region_name, idns.uuid, patch))
                idns = self.client.idns.update(idns.uuid, patch)
            else:
                LOG.info("update_dns no changes, skip dns region={} "
                         "update uuid={} nameservers={}".format(
                             self.region_name, idns.uuid, nameservers))
        except Exception as e:
            LOG.error("update_dns exception={}".format(e))
            raise exceptions.SyncRequestFailedRetry()

        return idns

    def snmp_trapdest_list(self):
        """Get the trapdest list for this region

           :return: itrapdests list of itrapdest
        """
        itrapdests = self.client.itrapdest.list()
        return itrapdests

    def snmp_trapdest_create(self, trapdest_dict):
        """Add the trapdest for this region

           :param: trapdest_payload dictionary
           :return: itrapdest
        """

        # Example trapdest_dict:
        #     {"ip_address": "10.10.10.12", "community": "cgcs"}
        itrapdest = None
        trapdest_create_dict = {}
        for k, v in trapdest_dict.items():
            if k in SNMP_TRAPDEST_CREATION_ATTRIBUTES:
                trapdest_create_dict[str(k)] = v

        LOG.info("snmp_trapdest_create driver region={}"
                 "trapdest_create_dict={}".format(
                     self.region_name, trapdest_create_dict))
        try:
            itrapdest = self.client.itrapdest.create(**trapdest_create_dict)
        except HTTPConflict:
            LOG.info("snmp_trapdest_create exists region={}"
                     "trapdest_dict={}".format(
                         self.region_name, trapdest_dict))
            # Retrieve the existing itrapdest
            trapdests = self.snmp_trapdest_list()
            for trapdest in trapdests:
                if trapdest.ip_address == trapdest_dict.get('ip_address'):
                    LOG.info("snmp_trapdest_create found existing {}"
                             "for region: {}".format(
                                 trapdest, self.region_name))
                    itrapdest = trapdest
                    break
        except Exception as e:
            LOG.error("snmp_trapdest_create exception={}".format(e))
            raise exceptions.SyncRequestFailedRetry()

        return itrapdest

    def snmp_trapdest_delete(self, trapdest_ip_address):
        """Delete the trapdest for this region

           :param: trapdest_ip_address
        """
        try:
            LOG.info("snmp_trapdest_delete region {} ip_address: {}".format(
                     self.region_name, trapdest_ip_address))
            self.client.itrapdest.delete(trapdest_ip_address)
        except HTTPNotFound:
            LOG.info("snmp_trapdest_delete NotFound {} for region: {}".format(
                     trapdest_ip_address, self.region_name))
            raise exceptions.TrapDestNotFound(region_name=self.region_name,
                                              ip_address=trapdest_ip_address)
        except Exception as e:
            LOG.error("snmp_trapdest_delete exception={}".format(e))
            raise exceptions.SyncRequestFailedRetry()

    def snmp_community_list(self):
        """Get the community list for this region

           :return: icommunitys list of icommunity
        """
        icommunitys = self.client.icommunity.list()
        return icommunitys

    def snmp_community_create(self, community_dict):
        """Add the community for this region

           :param: community_payload dictionary
           :return: icommunity
        """

        # Example community_dict: {"community": "cgcs"}
        icommunity = None
        community_create_dict = {}
        for k, v in community_dict.items():
            if k in SNMP_COMMUNITY_CREATION_ATTRIBUTES:
                community_create_dict[str(k)] = v

        LOG.info("snmp_community_create driver region={}"
                 "community_create_dict={}".format(
                     self.region_name, community_create_dict))
        try:
            icommunity = self.client.icommunity.create(**community_create_dict)
        except HTTPConflict:
            LOG.info("snmp_community_create exists region={}"
                     "community_dict={}".format(
                         self.region_name, community_dict))
            # Retrieve the existing icommunity
            communitys = self.snmp_community_list()
            for community in communitys:
                if community.community == community_dict.get('community'):
                    LOG.info("snmp_community_create found existing {}"
                             "for region: {}".format(
                                 community, self.region_name))
                    icommunity = community
                    break
        except Exception as e:
            LOG.error("snmp_community_create exception={}".format(e))
            raise exceptions.SyncRequestFailedRetry()

        return icommunity

    def snmp_community_delete(self, community):
        """Delete the community for this region

           :param: community
        """
        try:
            LOG.info("snmp_community_delete region {} community: {}".format(
                     self.region_name, community))
            self.client.icommunity.delete(community)
        except HTTPNotFound:
            LOG.info("snmp_community_delete NotFound {} for region: {}".format(
                     community, self.region_name))
            raise exceptions.CommunityNotFound(region_name=self.region_name,
                                               community=community)
        except Exception as e:
            LOG.error("snmp_community_delete exception={}".format(e))
            raise exceptions.SyncRequestFailedRetry()

    def get_remotelogging(self):
        """Get the remotelogging for this region

           :return: remotelogging
        """
        try:
            remoteloggings = self.client.remotelogging.list()
            remotelogging = remoteloggings[0]
        except Exception as e:
            LOG.error("get_remotelogging exception={}".format(e))
            raise exceptions.SyncRequestFailedRetry()

        if not remotelogging:
            LOG.info("remotelogging is None for region: %s" % self.region_name)

        else:
            LOG.debug("get_remotelogging uuid=%s ip_address=%s" %
                      (remotelogging.uuid, remotelogging.ip_address))

        return remotelogging

    def create_remote_logging_patch_from_dict(self, values):
        patch = {}
        action_found = False
        for k, v in values.items():
            if k in self.REMOTELOGGING_PATCH_ATTRS:
                if k == 'action':
                    action_found = True
                elif k == 'enabled' and not isinstance(v, six.string_types):
                    # api requires a string for enabled
                    if not v:
                        patch[k] = 'false'
                    else:
                        patch[k] = 'true'
                elif k == 'ip_address' and not v:
                    # api requires a non None/empty value
                    continue
                else:
                    patch[k] = v

        if not action_found:
            patch['action'] = 'apply'

        patch = make_sysinv_patch(patch)
        LOG.debug("create_remote_logging_patch_from_dict=%s" % patch)
        return patch

    @staticmethod
    def ip_address_in_patch(patch):
        for p in patch:
            if p['path'] == '/ip_address':
                if p['value']:
                    return True
        LOG.info("No valid ip_address_in_patch: %s" % patch)
        return False

    def update_remotelogging(self, values):
        """Update the remotelogging values for this region

           :param: values  dictionary or payload
           :return: remotelogging
        """
        try:
            remotelogging = self.get_remotelogging()
            if not remotelogging:
                LOG.warn("remotelogging not found %s" % self.region_name)
                return remotelogging

            if isinstance(values, dict):
                patch = self.create_remote_logging_patch_from_dict(values)
            else:
                patch = values

            if (not self.ip_address_in_patch(patch) and
               not remotelogging.ip_address):
                # This region does not have an ip_address set yet
                LOG.info("region={} remotelogging ip_address not set "
                         "uuid={} patch={}. Skip patch operation.".format(
                             self.region_name, remotelogging.uuid, patch))
                return remotelogging

            LOG.info("region={} remotelogging update uuid={} patch={}".format(
                     self.region_name, remotelogging.uuid, patch))
            remotelogging = self.client.remotelogging.update(
                remotelogging.uuid, patch)
        except Exception as e:
            LOG.error("update_remotelogging exception={}".format(e))
            raise exceptions.SyncRequestFailedRetry()

        return remotelogging

    def get_certificates(self):
        """Get the certificates for this region

           :return: certificates
        """

        try:
            certificates = self.client.certificate.list()
        except Exception as e:
            LOG.error("get_certificates region={} "
                      "exception={}".format(self.region_name, e))
            raise exceptions.SyncRequestFailedRetry()

        if not certificates:
            LOG.info("No certificates in region: {}".format(
                self.region_name))

        return certificates

    def _validate_certificate(self, signature, certificate):
        # JKUNG need to look at the crypto public serial id
        certificate_sig = hashlib.md5(certificate).hexdigest()

        if certificate_sig == signature:
            return True

        LOG.info("_validate_certificate region={} sig={} mismatch "
                 "reference signature={}".format(
                     self.region_name, certificate_sig, signature))
        return False

    def update_certificate(self,
                           signature,
                           certificate=None,
                           data=None):
        """Update the certificate for this region

           :param: signature of the public certificate
           :param: certificate
           :param: data
           :return: icertificate
        """

        LOG.info("update_certificate signature {} data {}".format(
            signature, data))
        if not certificate:
            if data:
                data['passphrase'] = None
                mode = data.get('mode', sysinv_constants.CERT_MODE_SSL)
                if mode == sysinv_constants.CERT_MODE_SSL_CA:
                    certificate_files = [sysinv_constants.SSL_CERT_CA_FILE]
                elif mode == sysinv_constants.CERT_MODE_SSL:
                    certificate_files = [sysinv_constants.SSL_PEM_FILE]
                elif mode == sysinv_constants.CERT_MODE_DOCKER_REGISTRY:
                    certificate_files = \
                        [sysinv_constants.DOCKER_REGISTRY_KEY_FILE,
                         sysinv_constants.DOCKER_REGISTRY_CERT_FILE]
                else:
                    LOG.warn("update_certificate mode {} not supported".format(
                        mode))
                    return
            elif signature and signature.startswith(
                    sysinv_constants.CERT_MODE_SSL_CA):
                data['mode'] = sysinv_constants.CERT_MODE_SSL_CA
                certificate_files = [sysinv_constants.SSL_CERT_CA_FILE]
            elif signature and signature.startswith(
                    sysinv_constants.CERT_MODE_SSL):
                data['mode'] = sysinv_constants.CERT_MODE_SSL
                certificate_files = [sysinv_constants.SSL_PEM_FILE]
            elif signature and signature.startswith(
                    sysinv_constants.CERT_MODE_DOCKER_REGISTRY):
                data['mode'] = sysinv_constants.CERT_MODE_DOCKER_REGISTRY
                certificate_files = \
                    [sysinv_constants.DOCKER_REGISTRY_KEY_FILE,
                     sysinv_constants.DOCKER_REGISTRY_CERT_FILE]
            else:
                LOG.warn("update_certificate signature {} "
                         "not supported".format(signature))
                return

            certificate = ""
            for certificate_file in certificate_files:
                with open(certificate_file, 'r') as content_file:
                    certificate += content_file.read()

            LOG.info("update_certificate from shared file {} {}".format(
                signature, certificate_files))

        if (signature and
                (signature.startswith(sysinv_constants.CERT_MODE_SSL) or
                    (signature.startswith(sysinv_constants.CERT_MODE_TPM)))):
            # ensure https is enabled
            isystem = self.client.isystem.list()[0]
            https_enabled = isystem.capabilities.get('https_enabled', False)
            if not https_enabled:
                isystem = self.client.isystem.update(
                    isystem.uuid,
                    [{"path": "/https_enabled",
                      "value": "true",
                      "op": "replace"}])
                LOG.info("region={} enabled https system={}".format(
                         self.region_name, isystem.uuid))

        try:
            icertificate = self.client.certificate.certificate_install(
                certificate, data)
            LOG.info("update_certificate region={} signature={}".format(
                self.region_name,
                signature))
        except Exception as e:
            LOG.error("update_certificate exception={}".format(e))
            raise exceptions.SyncRequestFailedRetry()

        return icertificate

    def get_user(self):
        """Get the user password info for this region

           :return: iuser
        """
        iusers = self.client.iuser.list()
        if not iusers:
            LOG.info("user is None for region: %s" % self.region_name)
            return None
        iuser = iusers[0]

        LOG.debug("get_user uuid=%s passwd_hash=%s" %
                  (iuser.uuid, iuser.passwd_hash))

        return iuser

    def update_user(self, passwd_hash, root_sig, passwd_expiry_days):
        """Update the user passwd for this region

           :param: passwd_hash
           :return: iuser
        """
        try:
            iuser = self.get_user()
            if not iuser:
                LOG.warn("iuser not found %s" % self.region_name)
                return iuser

            if (iuser.passwd_hash != passwd_hash or
               iuser.passwd_expiry_days != passwd_expiry_days):
                patch = make_sysinv_patch(
                    {'passwd_hash': passwd_hash,
                     'passwd_expiry_days': passwd_expiry_days,
                     'root_sig': root_sig,
                     'action': 'apply',
                     })
                LOG.info("region={} user update uuid={} patch={}".format(
                         self.region_name, iuser.uuid, patch))
                iuser = self.client.iuser.update(iuser.uuid, patch)
            else:
                LOG.info("update_user no changes, skip user region={} "
                         "update uuid={} passwd_hash={}".format(
                             self.region_name, iuser.uuid, passwd_hash))
        except Exception as e:
            LOG.error("update_user exception={}".format(e))
            raise exceptions.SyncRequestFailedRetry()

        return iuser

    def post_fernet_repo(self, key_list=None):
        """Add the fernet keys for this region

           :param: key list payload
           :return: Nothing
        """

        # Example key_list:
        # [{"id": 0, "key": "GgDAOfmyr19u0hXdm5r_zMgaMLjglVFpp5qn_N4GBJQ="},
        # {"id": 1, "key": "7WfL_z54p67gWAkOmQhLA9P0ZygsbbJcKgff0uh28O8="},
        # {"id": 2, "key": ""5gsUQeOZ2FzZP58DN32u8pRKRgAludrjmrZFJSOHOw0="}]
        LOG.info("post_fernet_repo driver region={} "
                 "fernet_repo_list={}".format(self.region_name, key_list))
        try:
            self.client.fernet.create(key_list)
        except Exception as e:
            LOG.error("post_fernet_repo exception={}".format(e))
            raise exceptions.SyncRequestFailedRetry()

    def put_fernet_repo(self, key_list):
        """Update the fernet keys for this region

           :param: key list payload
           :return: Nothing
        """
        LOG.info("put_fernet_repo driver region={} "
                 "fernet_repo_list={}".format(self.region_name, key_list))
        try:
            self.client.fernet.put(key_list)
        except Exception as e:
            LOG.error("put_fernet_repo exception={}".format(e))
            raise exceptions.SyncRequestFailedRetry()

    def get_fernet_keys(self):
        """Retrieve the fernet keys for this region

           :return: a list of fernet keys
        """

        try:
            keys = self.client.fernet.list()
        except Exception as e:
            LOG.error("get_fernet_keys exception={}".format(e))
            raise exceptions.SyncRequestFailedRetry()

        return keys
