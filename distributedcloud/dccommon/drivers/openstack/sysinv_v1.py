# Copyright 2016 Ericsson AB
# Copyright (c) 2017-2023 Wind River Systems, Inc.
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

import hashlib
import os

from cgtsclient.exc import HTTPBadRequest
from cgtsclient.exc import HTTPConflict
from cgtsclient.exc import HTTPNotFound
from oslo_log import log
from oslo_utils import encodeutils

from dccommon import consts
from dccommon.drivers import base
from dccommon import exceptions
from dccommon import utils


LOG = log.getLogger(__name__)
API_VERSION = '1'

CERT_MODE_DOCKER_REGISTRY = 'docker_registry'
CERT_MODE_SSL = 'ssl'
CERT_MODE_SSL_CA = 'ssl_ca'

CONTROLLER = 'controller'

NETWORK_TYPE_MGMT = 'mgmt'
NETWORK_TYPE_ADMIN = 'admin'

SSL_CERT_DIR = "/etc/ssl/private/"
SSL_CERT_FILE = "server-cert.pem"
SSL_PEM_FILE = os.path.join(SSL_CERT_DIR, SSL_CERT_FILE)

DOCKER_REGISTRY_CERT_FILE = os.path.join(SSL_CERT_DIR, "registry-cert.crt")
DOCKER_REGISTRY_KEY_FILE = os.path.join(SSL_CERT_DIR, "registry-cert.key")

# The following constants are declared in sysinv/common/kubernetes.py
# Kubernetes upgrade states
KUBE_UPGRADE_STARTED = 'upgrade-started'
KUBE_UPGRADE_DOWNLOADING_IMAGES = 'downloading-images'
KUBE_UPGRADE_DOWNLOADING_IMAGES_FAILED = 'downloading-images-failed'
KUBE_UPGRADE_DOWNLOADED_IMAGES = 'downloaded-images'
KUBE_UPGRADING_FIRST_MASTER = 'upgrading-first-master'
KUBE_UPGRADING_FIRST_MASTER_FAILED = 'upgrading-first-master-failed'
KUBE_UPGRADED_FIRST_MASTER = 'upgraded-first-master'
KUBE_UPGRADING_NETWORKING = 'upgrading-networking'
KUBE_UPGRADING_NETWORKING_FAILED = 'upgrading-networking-failed'
KUBE_UPGRADED_NETWORKING = 'upgraded-networking'
KUBE_UPGRADING_SECOND_MASTER = 'upgrading-second-master'
KUBE_UPGRADING_SECOND_MASTER_FAILED = 'upgrading-second-master-failed'
KUBE_UPGRADED_SECOND_MASTER = 'upgraded-second-master'
KUBE_UPGRADING_KUBELETS = 'upgrading-kubelets'
KUBE_UPGRADE_COMPLETE = 'upgrade-complete'

# Kubernetes host upgrade statuses
KUBE_HOST_UPGRADING_CONTROL_PLANE = 'upgrading-control-plane'
KUBE_HOST_UPGRADING_CONTROL_PLANE_FAILED = 'upgrading-control-plane-failed'
KUBE_HOST_UPGRADING_KUBELET = 'upgrading-kubelet'
KUBE_HOST_UPGRADING_KUBELET_FAILED = 'upgrading-kubelet-failed'

# Kubernetes rootca update states

KUBE_ROOTCA_UPDATE_STARTED = 'update-started'
KUBE_ROOTCA_UPDATE_CERT_UPLOADED = 'update-new-rootca-cert-uploaded'
KUBE_ROOTCA_UPDATE_CERT_GENERATED = 'update-new-rootca-cert-generated'
KUBE_ROOTCA_UPDATING_PODS_TRUSTBOTHCAS = 'updating-pods-trust-both-cas'
KUBE_ROOTCA_UPDATED_PODS_TRUSTBOTHCAS = 'updated-pods-trust-both-cas'
KUBE_ROOTCA_UPDATING_PODS_TRUSTBOTHCAS_FAILED = 'updating-pods-trust-both-cas-failed'
KUBE_ROOTCA_UPDATING_PODS_TRUSTNEWCA = 'updating-pods-trust-new-ca'
KUBE_ROOTCA_UPDATED_PODS_TRUSTNEWCA = 'updated-pods-trust-new-ca'
KUBE_ROOTCA_UPDATING_PODS_TRUSTNEWCA_FAILED = 'updating-pods-trust-new-ca-failed'
KUBE_ROOTCA_UPDATE_COMPLETED = 'update-completed'
KUBE_ROOTCA_UPDATE_ABORTED = 'update-aborted'

# Kubernetes rootca host update states
KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS = 'updating-host-trust-both-cas'
KUBE_ROOTCA_UPDATED_HOST_TRUSTBOTHCAS = 'updated-host-trust-both-cas'
KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS_FAILED = 'updating-host-trust-both-cas-failed'
KUBE_ROOTCA_UPDATING_HOST_UPDATECERTS = 'updating-host-update-certs'
KUBE_ROOTCA_UPDATED_HOST_UPDATECERTS = 'updated-host-update-certs'
KUBE_ROOTCA_UPDATING_HOST_UPDATECERTS_FAILED = 'updating-host-update-certs-failed'
KUBE_ROOTCA_UPDATING_HOST_TRUSTNEWCA = 'updating-host-trust-new-ca'
KUBE_ROOTCA_UPDATED_HOST_TRUSTNEWCA = 'updated-host-trust-new-ca'
KUBE_ROOTCA_UPDATING_HOST_TRUSTNEWCA_FAILED = 'updating-host-trust-new-ca-failed'

# The following is the name of the host filesystem 'scratch' which is used
# by dcmanager upgrade orchestration for the load import operations.
HOST_FS_NAME_SCRATCH = 'scratch'

SYSINV_CLIENT_REST_DEFAULT_TIMEOUT = 600


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

    def __init__(self, region, session,
                 timeout=SYSINV_CLIENT_REST_DEFAULT_TIMEOUT,
                 endpoint_type=consts.KS_ENDPOINT_ADMIN,
                 endpoint=None):
        try:
            # TOX cannot import cgts_client and all the dependencies therefore
            # the client is being lazy loaded since TOX doesn't actually
            # require the cgtsclient module.
            from cgtsclient import client

            # The sysinv client doesn't support a session, so we need to
            # get an endpoint and token.
            if endpoint is None:
                endpoint = session.get_endpoint(
                    service_type='platform',
                    region_name=region,
                    interface=endpoint_type)

            token = session.get_token()
            self.sysinv_client = client.Client(API_VERSION,
                                               endpoint=endpoint,
                                               token=token,
                                               timeout=timeout)
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

    def swact_host(self, host_id, force=False):
        """Perform host swact"""
        if force:
            action_value = 'force-swact'
        else:
            action_value = 'swact'
        return self._do_host_action(host_id, action_value)

    def configure_bmc_host(self,
                           host_id,
                           bm_username,
                           bm_ip,
                           bm_password,
                           bm_type='ipmi'):
        """Configure bmc of a host"""
        patch = [
            {'op': 'replace',
             'path': '/bm_username',
             'value': bm_username},
            {'op': 'replace',
             'path': '/bm_ip',
             'value': bm_ip},
            {'op': 'replace',
             'path': '/bm_password',
             'value': bm_password},
            {'op': 'replace',
             'path': '/bm_type',
             'value': bm_type},
        ]
        return self.sysinv_client.ihost.update(host_id, patch)

    def upgrade_host(self, host_id, force=False):
        """Invoke the API for 'system host-upgrade'"""
        return self.sysinv_client.ihost.upgrade(host_id, force)

    def power_on_host(self, host_id):
        """Power on a host"""
        action_value = 'power-on'
        return self._do_host_action(host_id, action_value)

    def power_off_host(self, host_id):
        """Power off a host"""
        action_value = 'power-off'
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

    def get_admin_interface(self, hostname):
        """Get the admin interface for a host."""
        interfaces = self.sysinv_client.iinterface.list(hostname)
        for interface in interfaces:
            interface_networks = self.sysinv_client.interface_network.\
                list_by_interface(interface.uuid)
            for if_net in interface_networks:
                if if_net.network_type == NETWORK_TYPE_ADMIN:
                    return interface

        # This can happen if the host is still being installed and has not
        # yet created its admin interface.
        LOG.warning("Admin interface on host %s not found" % hostname)
        return None

    def get_admin_address_pool(self):
        """Get the admin address pool for a host."""
        networks = self.sysinv_client.network.list()
        for network in networks:
            if network.type == NETWORK_TYPE_ADMIN:
                address_pool_uuid = network.pool_uuid
                break
        else:
            LOG.error("Admin address pool not found")
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
                 "gateway: %s metric: %s" % (interface_uuid, network,
                                             prefix, gateway, metric))
        try:
            self.sysinv_client.route.create(interface_uuid=interface_uuid,
                                            network=network,
                                            prefix=prefix,
                                            gateway=gateway,
                                            metric=metric)
        except HTTPConflict:
            # The route already exists
            LOG.warning("Failed to create route, route: interface: %s dest: "
                        "%s/%s gateway: %s metric: %s already exists" %
                        (interface_uuid, network, prefix, gateway, metric))
        except Exception as e:
            LOG.error("Failed to create route: route: interface: %s dest: "
                      "%s/%s gateway: %s metric: %s" % (interface_uuid,
                                                        network, prefix,
                                                        gateway, metric))
            raise e

    def delete_route(self, interface_uuid, network, prefix, gateway, metric):
        """Delete a static route."""

        # Get the routes for this interface
        routes = self.sysinv_client.route.list_by_interface(interface_uuid)
        for route in routes:
            if (route.network == network and route.prefix == prefix and
                    route.gateway == gateway and route.metric == metric):
                LOG.info("Deleting route: interface: %s dest: %s/%s "
                         "gateway: %s metric: %s" % (interface_uuid, network,
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

    def import_load(self, path_to_iso, path_to_sig):
        """Import the particular software load."""
        try:
            return self.sysinv_client.load.import_load(path_to_iso=path_to_iso,
                                                       path_to_sig=path_to_sig)
        except HTTPBadRequest as e:
            if "Max number of loads" in str(e):
                raise exceptions.LoadMaxReached(region_name=self.region_name)
            raise

    def import_load_metadata(self, load):
        """Import the software load metadata."""
        return self.sysinv_client.load.import_load_metadata(load=load)

    def get_system_health(self):
        """Get system health."""
        return self.sysinv_client.health.get()

    def get_system_health_upgrade(self):
        """Get platform upgrade health."""
        return self.sysinv_client.health.get_upgrade()

    def get_kube_upgrade_health(self):
        """Get system health for kube upgrade."""
        return self.sysinv_client.health.get_kube_upgrade()

    def get_hosts(self):
        """Get a list of hosts."""
        return self.sysinv_client.ihost.list()

    def get_upgrades(self):
        """Get a list of upgrades."""
        return self.sysinv_client.upgrade.list()

    def get_error_msg(self):
        """Get the upgrade message."""
        return self.sysinv_client.upgrade.get_upgrade_msg()

    def upgrade_activate(self):
        """Invoke the API for 'system upgrade-activate', which is an update """
        patch = [{'op': 'replace',
                  'path': '/state',
                  'value': 'activation-requested'}, ]
        return self.sysinv_client.upgrade.update(patch)

    def upgrade_complete(self):
        """Invoke the API for 'system upgrade-complete', which is a delete"""
        return self.sysinv_client.upgrade.delete()

    def upgrade_start(self, force=False):
        """Invoke the API for 'system upgrade-start', which is a create"""
        return self.sysinv_client.upgrade.create(force)

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
        certificate_sig = hashlib.md5(
            encodeutils.safe_encode(certificate)).hexdigest()

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
            ssl_cert_ca_file = utils.get_ssl_cert_ca_file()
            if data:
                data['passphrase'] = None
                mode = data.get('mode', CERT_MODE_SSL)
                if mode == CERT_MODE_SSL_CA:
                    certificate_files = [ssl_cert_ca_file]
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
                certificate_files = [ssl_cert_ca_file]
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

        if (signature and signature.startswith(CERT_MODE_SSL) and
                not signature.startswith(CERT_MODE_SSL_CA)):
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

    def get_host_filesystems(self, host_uuid):
        """Get the host filesystems for a host"""

        return self.sysinv_client.host_fs.list(host_uuid)

    def get_host_filesystem(self, host_uuid, name):
        """Get the named filesystem for a host

           :return: host_fs or None
        """

        host_fs = None
        host_fs_list = self.get_host_filesystems(host_uuid)

        for host_fs in host_fs_list or []:
            if host_fs.name == name:
                break

        return host_fs

    def get_host_device_list(self, host_name):
        """Get a list of devices for a given host"""
        return self.sysinv_client.pci_device.list(host_name)

    def get_device_label_list(self):
        """Get a list of device labels"""
        return self.sysinv_client.device_label.list()

    def get_device_images(self):
        """Get a list of device images."""
        return self.sysinv_client.device_image.list()

    def get_device_image(self, image_uuid):
        """Get device image from uuid."""
        return self.sysinv_client.device_image.get(image_uuid)

    def get_device_image_states(self):
        """Get a list of device image states."""
        return self.sysinv_client.device_image_state.list()

    def kube_rootca_update_start(self, force=False, alarm_ignore_list=None):
        """Ask System Inventory to start a kube rootca update

        :param force: boolean to force the start
        :alarm_ignore_list: a list of alarms to ignore
        """
        # todo(abailey): sysinv client endpoint needs to add alarm_ignore_list
        return self.sysinv_client.kube_rootca_update.create(force)

    def kube_rootca_update_upload_cert(self, pem_file):
        """Ask System Inventory to upload a cert.

        :param pem_file: a file handle to a pem file containing key and cert
        """
        return self.sysinv_client.kube_rootca_update.rootCA_upload(pem_file)

    def get_kube_rootca_update(self, update_uuid):
        """Retrieve the details of a given kubernetes rootca update

        :param update_uuid: kube rootca update uuid
        If the update is not found, returns None
        """
        return self.sysinv_client.kube_rootca_update.get(update_uuid)

    def get_kube_rootca_updates(self):
        """Retrieve the kubernetes rootca updates if one is present."""
        return self.sysinv_client.kube_rootca_update.get_list()

    def get_kube_upgrade(self, kube_upgrade_uuid):
        """Retrieve the details of a given kubernetes upgrade

        :param kube_upgrade_uuid: kube upgrade uuid
        If the upgrade is not found, returns None
        """
        return self.sysinv_client.kube_upgrade.get(kube_upgrade_uuid)

    def get_kube_upgrades(self):
        """Retrieve the kubernetes upgrade if one is present."""
        return self.sysinv_client.kube_upgrade.list()

    def get_kube_version(self, version):
        """Retrieve the details of a given kubernetes version

        :param version: kubernetes version
        If the version is not found, returns None
        """
        return self.sysinv_client.kube_version.get(version)

    def get_kube_versions(self):
        """Retrieve the list of kubernetes versions known to the system."""
        return self.sysinv_client.kube_version.list()

    def get_kube_rootca_cert_id(self):
        """Retrieve the ID of kubernetes rootca cert"""
        try:
            cert_id = self.sysinv_client.kube_rootca_update.get_cert_id()
        except HTTPBadRequest as e:
            # The get_cert_id may not implemented in the subcloud.
            if "Expected a uuid" in str(e):
                return False, None
            LOG.error("get Kube root CA ID exception {}".format(e))
            raise e
        except Exception as e:
            LOG.error("get Kube root CA ID exception {}".format(e))
            raise e

        return True, cert_id

    def apply_device_image(self, device_image_id, labels=None):
        """Apply a device image.

           :param: device_image_id the image to apply
           :param: labels the labels to pass as part of the apply
        """
        return self.sysinv_client.device_image.apply(device_image_id,
                                                     labels=labels)

    def remove_device_image(self, device_image_id, labels=None):
        """Remove a device image.

           :param: device_image_id the image to remove
           :param: labels the labels to pass as part of the remove
        """
        return self.sysinv_client.device_image.remove(device_image_id,
                                                      labels=labels)

    def upload_device_image(self, device_image_file, fields):
        """Upload a device image.

           :param: device_image_file the file to upload
           :param: fields can be: 'bitstream_type', 'pci_vendor', 'pci_device',
           'bitstream_id', 'key_signature', 'revoke_key_id', 'name',
           'description', 'image_version', 'bmc', 'retimer_included', 'uuid'
        """
        return self.sysinv_client.device_image.upload(device_image_file,
                                                      **fields)
