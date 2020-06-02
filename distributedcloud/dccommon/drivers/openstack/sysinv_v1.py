# Copyright 2016 Ericsson AB

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
#
# Copyright (c) 2017-2020 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

import hashlib
import os

from cgtsclient.exc import HTTPConflict
from cgtsclient.exc import HTTPNotFound
from cgtsclient.v1.icommunity import CREATION_ATTRIBUTES \
    as SNMP_COMMUNITY_CREATION_ATTRIBUTES
from cgtsclient.v1.itrapdest import CREATION_ATTRIBUTES \
    as SNMP_TRAPDEST_CREATION_ATTRIBUTES
from oslo_log import log

from dccommon import consts
from dccommon.drivers import base
from dccommon import exceptions


LOG = log.getLogger(__name__)
API_VERSION = '1'

CERT_CA_FILE = "ca-cert.pem"
CERT_MODE_DOCKER_REGISTRY = 'docker_registry'
CERT_MODE_SSL = 'ssl'
CERT_MODE_SSL_CA = 'ssl_ca'
CERT_MODE_TPM = 'tpm_mode'

CONTROLLER = 'controller'

NETWORK_TYPE_MGMT = 'mgmt'

SSL_CERT_CA_DIR = "/etc/pki/ca-trust/source/anchors/"
SSL_CERT_CA_FILE = os.path.join(SSL_CERT_CA_DIR, CERT_CA_FILE)
SSL_CERT_DIR = "/etc/ssl/private/"
SSL_CERT_FILE = "server-cert.pem"
SSL_PEM_FILE = os.path.join(SSL_CERT_DIR, SSL_CERT_FILE)

DOCKER_REGISTRY_CERT_FILE = os.path.join(SSL_CERT_DIR, "registry-cert.crt")
DOCKER_REGISTRY_KEY_FILE = os.path.join(SSL_CERT_DIR, "registry-cert.key")


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

    def __init__(self, region, session):
        try:
            # TOX cannot import cgts_client and all the dependencies therefore
            # the client is being lazy loaded since TOX doesn't actually
            # require the cgtsclient module.
            from cgtsclient import client

            # The sysinv client doesn't support a session, so we need to
            # get an endpoint and token.
            endpoint = session.get_endpoint(
                service_type='platform',
                region_name=region,
                interface=consts.KS_ENDPOINT_ADMIN)
            token = session.get_token()

            self.sysinv_client = client.Client(API_VERSION,
                                               endpoint=endpoint,
                                               token=token)
            self.region_name = region
        except exceptions.ServiceUnavailable:
            raise

    def get_host(self, hostname_or_id):
        """Get a host by its hostname or id."""
        return self.sysinv_client.ihost.get(hostname_or_id)

    def get_controller_hosts(self):
        """Get a list of controller hosts."""
        return self.sysinv_client.ihost.list_personality(
            CONTROLLER)

    def _do_host_action(self, host_id, action_value):
        """Protected method to invoke an action on a host."""
        patch = [{'op': 'replace',
                  'path': '/action',
                  'value': action_value}, ]
        return self.sysinv_client.ihost.update(host_id, patch)

    def lock_host(self, host_id, force=False):
        """Lock a host"""
        if force:
            action_value = 'force-lock'
        else:
            action_value = 'lock'
        return self._do_host_action(host_id, action_value)

    def unlock_host(self, host_id, force=False):
        """Unlock a host"""
        if force:
            action_value = 'force-unlock'
        else:
            action_value = 'unlock'
        return self._do_host_action(host_id, action_value)

    def get_management_interface(self, hostname):
        """Get the management interface for a host."""
        interfaces = self.sysinv_client.iinterface.list(hostname)
        for interface in interfaces:
            interface_networks = self.sysinv_client.interface_network.\
                list_by_interface(interface.uuid)
            for if_net in interface_networks:
                if if_net.network_type == NETWORK_TYPE_MGMT:
                    return interface

        # This can happen if the host is still being installed and has not
        # yet created its management interface.
        LOG.warning("Management interface on host %s not found" % hostname)
        return None

    def get_management_address_pool(self):
        """Get the management address pool for a host."""
        networks = self.sysinv_client.network.list()
        for network in networks:
            if network.type == NETWORK_TYPE_MGMT:
                address_pool_uuid = network.pool_uuid
                break
        else:
            LOG.error("Management address pool not found")
            raise exceptions.InternalError()

        return self.sysinv_client.address_pool.get(address_pool_uuid)

    def get_oam_addresses(self):
        """Get the oam address pool for a host."""
        iextoam_object = self.sysinv_client.iextoam.list()
        if iextoam_object is not None and len(iextoam_object) != 0:
            return iextoam_object[0]
        else:
            LOG.error("OAM address not found")
            raise exceptions.OAMAddressesNotFound()

    def create_route(self, interface_uuid, network, prefix, gateway, metric):
        """Create a static route on an interface."""

        LOG.info("Creating route: interface: %s dest: %s/%s "
                 "gateway: %s metric %s" % (interface_uuid, network,
                                            prefix, gateway, metric))
        self.sysinv_client.route.create(interface_uuid=interface_uuid,
                                        network=network,
                                        prefix=prefix,
                                        gateway=gateway,
                                        metric=metric)

    def delete_route(self, interface_uuid, network, prefix, gateway, metric):
        """Delete a static route."""

        # Get the routes for this interface
        routes = self.sysinv_client.route.list_by_interface(interface_uuid)
        for route in routes:
            if (route.network == network and route.prefix == prefix and
                    route.gateway == gateway and route.metric == metric):
                LOG.info("Deleting route: interface: %s dest: %s/%s "
                         "gateway: %s metric %s" % (interface_uuid, network,
                                                    prefix, gateway, metric))
                self.sysinv_client.route.delete(route.uuid)
                return

        LOG.warning("Route not found: interface: %s dest: %s/%s gateway: %s "
                    "metric %s" % (interface_uuid, network, prefix, gateway,
                                   metric))

    def get_service_groups(self):
        """Get a list of service groups."""
        return self.sysinv_client.sm_servicegroup.list()

    def get_license(self):
        """Get the license."""
        return self.sysinv_client.license.show()

    def install_license(self, license_file):
        """Install a license."""
        return self.sysinv_client.license.install_license(license_file)

    def get_loads(self):
        """Get a list of loads."""
        return self.sysinv_client.load.list()

    def get_load(self, load_id):
        """Get a particular load."""
        return self.sysinv_client.load.get(load_id)

    def delete_load(self, load_id):
        """Delete a load with the given id

           :param: load id
        """
        try:
            LOG.info("delete_load region {} load_id: {}".format(
                     self.region_name, load_id))
            self.sysinv_client.load.delete(load_id)
        except HTTPNotFound:
            LOG.info("delete_load NotFound {} for region: {}".format(
                     load_id, self.region_name))
            raise exceptions.LoadNotFound(region_name=self.region_name,
                                          load_id=load_id)
        except Exception as e:
            LOG.error("delete_load exception={}".format(e))
            raise e

    def get_hosts(self):
        """Get a list of hosts."""
        return self.sysinv_client.ihost.list()

    def get_upgrades(self):
        """Get a list of upgrades."""
        return self.sysinv_client.upgrade.list()

    def get_applications(self):
        """Get a list of containerized applications"""

        # Get a list of containerized applications the system knows of
        return self.sysinv_client.app.list()

    def get_system(self):
        """Get the system."""
        systems = self.sysinv_client.isystem.list()
        return systems[0]

    def get_service_parameters(self, name, value):
        """Get service parameters for a given name."""
        opts = []
        opt = dict()
        opt['field'] = name
        opt['value'] = value
        opt['op'] = 'eq'
        opt['type'] = ''
        opts.append(opt)
        parameters = self.sysinv_client.service_parameter.list(q=opts)
        return parameters

    def get_registry_image_tags(self, image_name):
        """Get the image tags for an image from the local registry"""
        image_tags = self.sysinv_client.registry_image.tags(image_name)
        return image_tags

    def get_dns(self):
        """Get the dns nameservers for this region

           :return: dns
        """
        idnss = self.sysinv_client.idns.list()
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
                idns = self.sysinv_client.idns.update(idns.uuid, patch)
            else:
                LOG.info("update_dns no changes, skip dns region={} "
                         "update uuid={} nameservers={}".format(
                             self.region_name, idns.uuid, nameservers))
        except Exception as e:
            LOG.error("update_dns exception={}".format(e))
            raise e

        return idns

    def snmp_trapdest_list(self):
        """Get the trapdest list for this region

           :return: itrapdests list of itrapdest
        """
        itrapdests = self.sysinv_client.itrapdest.list()
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
            itrapdest = self.sysinv_client.itrapdest.create(
                **trapdest_create_dict)
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
            raise e

        return itrapdest

    def snmp_trapdest_delete(self, trapdest_ip_address):
        """Delete the trapdest for this region

           :param: trapdest_ip_address
        """
        try:
            LOG.info("snmp_trapdest_delete region {} ip_address: {}".format(
                     self.region_name, trapdest_ip_address))
            self.sysinv_client.itrapdest.delete(trapdest_ip_address)
        except HTTPNotFound:
            LOG.info("snmp_trapdest_delete NotFound {} for region: {}".format(
                     trapdest_ip_address, self.region_name))
            raise exceptions.TrapDestNotFound(region_name=self.region_name,
                                              ip_address=trapdest_ip_address)
        except Exception as e:
            LOG.error("snmp_trapdest_delete exception={}".format(e))
            raise e

    def snmp_community_list(self):
        """Get the community list for this region

           :return: icommunitys list of icommunity
        """
        icommunitys = self.sysinv_client.icommunity.list()
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
            icommunity = self.sysinv_client.icommunity.create(
                **community_create_dict)
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
            raise e

        return icommunity

    def snmp_community_delete(self, community):
        """Delete the community for this region

           :param: community
        """
        try:
            LOG.info("snmp_community_delete region {} community: {}".format(
                     self.region_name, community))
            self.sysinv_client.icommunity.delete(community)
        except HTTPNotFound:
            LOG.info("snmp_community_delete NotFound {} for region: {}".format(
                     community, self.region_name))
            raise exceptions.CommunityNotFound(region_name=self.region_name,
                                               community=community)
        except Exception as e:
            LOG.error("snmp_community_delete exception={}".format(e))
            raise e

    def get_certificates(self):
        """Get the certificates for this region

           :return: certificates
        """

        try:
            certificates = self.sysinv_client.certificate.list()
        except Exception as e:
            LOG.error("get_certificates region={} "
                      "exception={}".format(self.region_name, e))
            raise e

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
                mode = data.get('mode', CERT_MODE_SSL)
                if mode == CERT_MODE_SSL_CA:
                    certificate_files = [SSL_CERT_CA_FILE]
                elif mode == CERT_MODE_SSL:
                    certificate_files = [SSL_PEM_FILE]
                elif mode == CERT_MODE_DOCKER_REGISTRY:
                    certificate_files = \
                        [DOCKER_REGISTRY_KEY_FILE,
                         DOCKER_REGISTRY_CERT_FILE]
                else:
                    LOG.warn("update_certificate mode {} not supported".format(
                        mode))
                    return
            elif signature and signature.startswith(CERT_MODE_SSL_CA):
                data['mode'] = CERT_MODE_SSL_CA
                certificate_files = [SSL_CERT_CA_FILE]
            elif signature and signature.startswith(CERT_MODE_SSL):
                data['mode'] = CERT_MODE_SSL
                certificate_files = [SSL_PEM_FILE]
            elif signature and signature.startswith(CERT_MODE_DOCKER_REGISTRY):
                data['mode'] = CERT_MODE_DOCKER_REGISTRY
                certificate_files = \
                    [DOCKER_REGISTRY_KEY_FILE,
                     DOCKER_REGISTRY_CERT_FILE]
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
                (signature.startswith(CERT_MODE_SSL) or
                    (signature.startswith(CERT_MODE_TPM)))):
            # ensure https is enabled
            isystem = self.sysinv_client.isystem.list()[0]
            https_enabled = isystem.capabilities.get('https_enabled', False)
            if not https_enabled:
                isystem = self.sysinv_client.isystem.update(
                    isystem.uuid,
                    [{"path": "/https_enabled",
                      "value": "true",
                      "op": "replace"}])
                LOG.info("region={} enabled https system={}".format(
                         self.region_name, isystem.uuid))

        try:
            icertificate = self.sysinv_client.certificate.certificate_install(
                certificate, data)
            LOG.info("update_certificate region={} signature={}".format(
                self.region_name,
                signature))
        except Exception as e:
            LOG.error("update_certificate exception={}".format(e))
            raise e

        return icertificate

    def delete_certificate(self, certificate):
        """Delete the certificate for this region

           :param: a CA certificate to delete
        """
        try:
            LOG.info(" delete_certificate region {} certificate: {}".format(
                     self.region_name, certificate.signature))
            self.sysinv_client.certificate.certificate_uninstall(
                certificate.uuid)
        except HTTPNotFound:
            LOG.info("delete_certificate NotFound {} for region: {}".format(
                     certificate.signature, self.region_name))
            raise exceptions.CertificateNotFound(
                region_name=self.region_name, signature=certificate.signature)

    def get_user(self):
        """Get the user password info for this region

           :return: iuser
        """
        iusers = self.sysinv_client.iuser.list()
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
                iuser = self.sysinv_client.iuser.update(iuser.uuid, patch)
            else:
                LOG.info("update_user no changes, skip user region={} "
                         "update uuid={} passwd_hash={}".format(
                             self.region_name, iuser.uuid, passwd_hash))
        except Exception as e:
            LOG.error("update_user exception={}".format(e))
            raise e

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
            self.sysinv_client.fernet.create(key_list)
        except Exception as e:
            LOG.error("post_fernet_repo exception={}".format(e))
            raise e

    def put_fernet_repo(self, key_list):
        """Update the fernet keys for this region

           :param: key list payload
           :return: Nothing
        """
        LOG.info("put_fernet_repo driver region={} "
                 "fernet_repo_list={}".format(self.region_name, key_list))
        try:
            self.sysinv_client.fernet.put(key_list)
        except Exception as e:
            LOG.error("put_fernet_repo exception={}".format(e))
            raise e

    def get_fernet_keys(self):
        """Retrieve the fernet keys for this region

           :return: a list of fernet keys
        """

        try:
            keys = self.sysinv_client.fernet.list()
        except Exception as e:
            LOG.error("get_fernet_keys exception={}".format(e))
            raise e

        return keys
