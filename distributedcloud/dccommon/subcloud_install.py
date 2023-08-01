# Copyright (c) 2021-2023 Wind River Systems, Inc.
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
#

import json
import os
import shutil
import socket
import ssl
import tempfile
import time

from eventlet.green import subprocess
import netaddr
from oslo_log import log as logging
from six.moves.urllib import error as urllib_error
from six.moves.urllib import parse
from six.moves.urllib import request
import yaml

from dccommon import consts
from dccommon.drivers.openstack.keystone_v3 import KeystoneClient
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon import exceptions
from dccommon import utils as dccommon_utils
from dcmanager.common import consts as dcmanager_consts
from dcmanager.common import utils

LOG = logging.getLogger(__name__)

BOOT_MENU_TIMEOUT = '5'

# The RVMC_IMAGE_NAME:RVMC_IMAGE_TAG must align with the one specified
# in system images in the ansible install/upgrade playbook
RVMC_IMAGE_NAME = 'docker.io/starlingx/rvmc'
RVMC_IMAGE_TAG = 'stx.8.0-v1.0.1'

SUBCLOUD_ISO_PATH = '/opt/platform/iso'
SUBCLOUD_ISO_DOWNLOAD_PATH = '/var/www/pages/iso'
SUBCLOUD_FEED_PATH = '/var/www/pages/feed'
DCVAULT_BOOTIMAGE_PATH = '/opt/dc-vault/loads/'
PACKAGE_LIST_PATH = '/usr/local/share/pkg-list'
GEN_ISO_COMMAND = '/usr/local/bin/gen-bootloader-iso.sh'
GEN_ISO_COMMAND_CENTOS = '/usr/local/bin/gen-bootloader-iso-centos.sh'
NETWORK_SCRIPTS = '/etc/sysconfig/network-scripts'
NETWORK_INTERFACE_PREFIX = 'ifcfg'
NETWORK_ROUTE_PREFIX = 'route'
LOCAL_REGISTRY_PREFIX = 'registry.local:9001/'

# Redfish constants
ACTION_URL = '/Actions/ComputerSystem.Reset'
POWER_OFF_PAYLOAD = {'Action': 'Reset', 'ResetType': 'ForceOff'}
REDFISH_HEADER = {'Content-Type': 'application/json',
                  'Accept': 'application/json'}
REDFISH_SYSTEMS_URL = '/redfish/v1/Systems'
SUCCESSFUL_STATUS_CODES = [200, 202, 204]


class SubcloudShutdown(object):
    """Sends a shutdown signal to a Redfish controlled subcloud

    Approach:

    To shutdown a Redfish controlled subcloud, it's needed to first
    send a GET request to find the @odata.id of the member, and then
    send a POST request with the shutdown signal. Since this is
    intended as a way to turn off the subcloud during the deploy abort
    process, only the ForceOff option is considered.
    """
    def __init__(self, subcloud_name):
        self.target = subcloud_name
        self.rvmc_data = self._get_subcloud_data()

    def _get_subcloud_data(self):
        rvmc_config_file_path = os.path.join(consts.ANSIBLE_OVERRIDES_PATH,
                                             self.target, consts.RVMC_CONFIG_FILE_NAME)
        if not os.path.isfile(rvmc_config_file_path):
            raise Exception('Missing rvmc files for %s' % self.target)
        with open(os.path.abspath(rvmc_config_file_path), 'r') as f:
            rvmc_data = f.read()
        rvmc_config_values = yaml.load(rvmc_data, Loader=yaml.SafeLoader)
        base_url = "https://" + rvmc_config_values['bmc_address']
        bmc_username = rvmc_config_values['bmc_username']
        bmc_password = rvmc_config_values['bmc_password']
        credentials = ("%s:%s" % (bmc_username.rstrip(), bmc_password)).encode("utf-8")
        return {'base_url': base_url, 'credentials': credentials}

    def _make_request(self, url, credentials, method, retry=5):
        if method == 'get':
            payload = None
        else:
            payload = json.dumps(POWER_OFF_PAYLOAD).encode('utf-8')

        try:
            context = ssl._create_unverified_context()
            req = request.Request(url, headers=REDFISH_HEADER, method=method)
            req.add_header('Authorization', 'Basic %s' % credentials)
            response = request.urlopen(req, data=payload, context=context)
            status_code = response.getcode()

            if status_code not in SUCCESSFUL_STATUS_CODES:
                if retry <= 0:
                    raise exceptions.SubcloudShutdownError(
                        subcloud_name=self.target)
                retry -= retry
                time.sleep(2)
                self._make_request(url, credentials, method, retry=retry)
        except urllib_error.URLError:
            # This occurs when the BMC is not available anymore,
            # so we just ignore it.
            return None
        except Exception as ex:
            raise ex

        return response

    def _get_data_id(self):
        base_url = self.rvmc_data['base_url']
        credentials = self.rvmc_data['credentials']
        url = base_url + REDFISH_SYSTEMS_URL
        response = self._make_request(url, credentials, method='GET')
        if not response:
            return None
        r = json.loads(response.read().decode())

        for member in r['Members']:
            if member.get('@odata.id'):
                url_with_id = member['@odata.id']
                break

        return url_with_id

    def send_shutdown_signal(self):
        base_url = self.rvmc_data['base_url']
        credentials = self.rvmc_data['credentials']
        url_with_id = self._get_data_id()
        if not url_with_id:
            return None
        url = base_url + url_with_id + ACTION_URL
        response = self._make_request(url, credentials, method='POST')
        return response


class SubcloudInstall(object):
    """Class to encapsulate the subcloud install operations"""

    def __init__(self, context, subcloud_name):
        ks_client = KeystoneClient(region_name=consts.CLOUD_0)
        session = ks_client.endpoint_cache.get_session_from_token(
            context.auth_token, context.project)
        endpoint = ks_client.endpoint_cache.get_endpoint('sysinv')
        self.sysinv_client = SysinvClient(consts.CLOUD_0,
                                          session, endpoint=endpoint)
        self.name = subcloud_name
        self.input_iso = None
        self.www_root = None
        self.https_enabled = None

    @staticmethod
    def config_device(ks_cfg, interface, vlan=False):
        device_cfg = "%s/%s-%s" % (NETWORK_SCRIPTS, NETWORK_INTERFACE_PREFIX,
                                   interface)
        ks_cfg.write("\tcat << EOF > " + device_cfg + "\n")
        ks_cfg.write("DEVICE=" + interface + "\n")
        ks_cfg.write("BOOTPROTO=none\n")
        ks_cfg.write("ONBOOT=yes\n")
        if vlan:
            ks_cfg.write("VLAN=yes\n")

    @staticmethod
    def config_ip_address(ks_cfg, values):
        ks_cfg.write("IPADDR=" + values['bootstrap_address'] + "\n")
        ks_cfg.write(
            "PREFIX=" + str(values['bootstrap_address_prefix']) + "\n")

    @staticmethod
    def config_default_route(ks_cfg, values, ip_version):
        if ip_version == 4:
            ks_cfg.write("DEFROUTE=yes\n")
            ks_cfg.write("GATEWAY=" + values['nexthop_gateway'] + "\n")
        else:
            ks_cfg.write("IPV6INIT=yes\n")
            ks_cfg.write("IPV6_DEFROUTE=yes\n")
            ks_cfg.write("IPV6_DEFAULTGW=" + values['nexthop_gateway'] + "\n")

    @staticmethod
    def config_static_route(ks_cfg, interface, values, ip_version):
        if ip_version == 4:
            route_cfg = "%s/%s-%s" % (NETWORK_SCRIPTS, NETWORK_ROUTE_PREFIX,
                                      interface)
            ks_cfg.write("\tcat << EOF > " + route_cfg + "\n")
            ks_cfg.write("ADDRESS0=" + values['network_address'] + "\n")
            ks_cfg.write("NETMASK0=" + str(values['network_mask']) + "\n")
            ks_cfg.write("GATEWAY0=" + values['nexthop_gateway'] + "\n")
        else:
            route_cfg = "%s/%s6-%s" % (NETWORK_SCRIPTS, NETWORK_ROUTE_PREFIX,
                                       interface)
            ks_cfg.write("\tcat << EOF > " + route_cfg + "\n")
            route_args = "%s/%s via %s dev %s\n" % (values['network_address'],
                                                    values['network_mask'],
                                                    values['nexthop_gateway'],
                                                    interface)
            ks_cfg.write(route_args)
        ks_cfg.write("EOF\n\n")

    @staticmethod
    def format_address(ip_address):
        try:
            address = netaddr.IPAddress(ip_address)
            if address.version == 6:
                return "[%s]" % address
            else:
                return str(address)
        except netaddr.AddrFormatError as e:
            LOG.error("Failed to format the address: %s", ip_address)
            raise e

    def get_oam_address(self):
        oam_addresses = self.sysinv_client.get_oam_addresses()
        return self.format_address(oam_addresses.oam_floating_ip)

    def get_https_enabled(self):
        if self.https_enabled is None:
            system = self.sysinv_client.get_system()
            self.https_enabled = system.capabilities.get('https_enabled',
                                                         False)
        return self.https_enabled

    def get_image_base_url(self):
        # get the protocol
        protocol = 'https' if self.get_https_enabled() else 'http'

        # get the configured http or https port
        value = 'https_port' if self.get_https_enabled() else 'http_port'
        http_parameters = self.sysinv_client.get_service_parameters('name',
                                                                    value)
        port = getattr(http_parameters[0], 'value')

        return "%s://%s:%s" % (protocol, self.get_oam_address(), port)

    def check_image_exists(self, image_name, image_tag):
        tags = self.sysinv_client.get_registry_image_tags(image_name)
        if tags:
            if any(getattr(tag, 'tag') == image_tag for tag in tags):
                return
        msg = "Error: Image %s:%s not found in the local registry." % (
            image_name, image_tag)
        LOG.error(msg)
        raise exceptions.ImageNotInLocalRegistry(image_name=image_name,
                                                 image_tag=image_tag)

    @staticmethod
    def create_rvmc_config_file(override_path, payload):

        LOG.debug("create rvmc config file, path: %s, payload: %s",
                  override_path, payload)
        rvmc_config_file = os.path.join(override_path, consts.RVMC_CONFIG_FILE_NAME)

        with open(rvmc_config_file, 'w') as f_out_rvmc_config_file:
            for k, v in payload.items():
                if k in consts.BMC_INSTALL_VALUES or k == 'image':
                    f_out_rvmc_config_file.write(k + ': ' + v + '\n')

    def create_install_override_file(self, override_path, payload):

        LOG.debug("create install override file")
        self.check_image_exists(RVMC_IMAGE_NAME, RVMC_IMAGE_TAG)
        rvmc_image = LOCAL_REGISTRY_PREFIX + RVMC_IMAGE_NAME + ':' +\
            RVMC_IMAGE_TAG
        install_override_file = os.path.join(override_path,
                                             'install_values.yml')
        rvmc_name = "%s-%s" % (consts.RVMC_NAME_PREFIX, self.name)
        host_name = socket.gethostname()

        with open(install_override_file, 'w') as f_out_override_file:
            f_out_override_file.write(
                '---'
                '\npassword_change: true'
                '\nrvmc_image: ' + rvmc_image +
                '\nrvmc_name: ' + rvmc_name +
                '\nhost_name: ' + host_name +
                '\nrvmc_config_dir: ' + override_path
                + '\n'
            )
            for k, v in payload.items():
                f_out_override_file.write("%s: %s\n" % (k, v))

    def create_ks_conf_file(self, filename, values):
        try:
            with open(filename, 'w') as f:
                # create ks-addon.cfg
                default_route = False
                static_route = False
                if 'nexthop_gateway' in values:
                    if 'network_address' in values:
                        static_route = True
                    else:
                        default_route = True

                f.write("OAM_DEV=" + str(values['bootstrap_interface']) + "\n")

                vlan_id = None
                if 'bootstrap_vlan' in values:
                    vlan_id = values['bootstrap_vlan']
                    f.write("OAM_VLAN=" + str(vlan_id) + "\n\n")

                interface = "$OAM_DEV"
                self.config_device(f, interface)

                ip_version = netaddr.IPAddress(
                    values['bootstrap_address']).version
                if vlan_id is None:
                    self.config_ip_address(f, values)
                    if default_route:
                        self.config_default_route(f, values, ip_version)
                f.write("EOF\n\n")

                route_interface = interface
                if vlan_id is not None:
                    vlan_interface = "$OAM_DEV.$OAM_VLAN"
                    self.config_device(f, vlan_interface, vlan=True)
                    self.config_ip_address(f, values)
                    if default_route:
                        self.config_default_route(f, values, ip_version)
                    f.write("EOF\n")
                    route_interface = vlan_interface

                if static_route:
                    self.config_static_route(f, route_interface,
                                             values, ip_version)
        except IOError as e:
            LOG.error("Failed to open file: %s", filename)
            LOG.exception(e)
            raise e

    def update_iso(self, override_path, values):
        if not os.path.isdir(self.www_root):
            os.mkdir(self.www_root, 0o755)
        LOG.debug("update_iso: www_root: %s, values: %s, override_path: %s",
                  self.www_root, str(values), override_path)
        path = None
        software_version = str(values['software_version'])
        try:
            if parse.urlparse(values['image']).scheme:
                url = values['image']
            else:
                path = os.path.abspath(values['image'])
                url = parse.urljoin('file:', request.pathname2url(path))
            filename = os.path.join(override_path, 'bootimage.iso')

            if path and path.startswith(consts.LOAD_VAULT_DIR +
                                        '/' + software_version):
                if os.path.exists(path):
                    # Reference known load in vault
                    LOG.info("Setting input_iso to load vault path %s" % path)
                    self.input_iso = path
                else:
                    raise exceptions.LoadNotInVault(path=path)
            else:
                LOG.info("Downloading %s to %s", url, override_path)
                self.input_iso, _ = request.urlretrieve(url, filename)

            LOG.info("Downloaded %s to %s", url, self.input_iso)
        except urllib_error.ContentTooShortError as e:
            msg = "Error: Downloading file %s may be interrupted: %s" % (
                values['image'], e)
            LOG.error(msg)
            raise exceptions.DCCommonException(
                resource=self.name,
                msg=msg)
        except Exception as e:
            msg = "Error: Could not download file %s: %s" % (
                values['image'], e)
            LOG.error(msg)
            raise exceptions.DCCommonException(
                resource=self.name,
                msg=msg)

        is_subcloud_debian = dccommon_utils.is_debian(software_version)

        if is_subcloud_debian:
            update_iso_cmd = [
                GEN_ISO_COMMAND,
                "--input", self.input_iso,
                "--www-root", self.www_root,
                "--id", self.name,
                "--boot-hostname", self.name,
                "--timeout", BOOT_MENU_TIMEOUT,
            ]
        else:
            update_iso_cmd = [
                GEN_ISO_COMMAND_CENTOS,
                "--input", self.input_iso,
                "--www-root", self.www_root,
                "--id", self.name,
                "--boot-hostname", self.name,
                "--timeout", BOOT_MENU_TIMEOUT,
                "--patches-from-iso",
            ]
        for key in consts.GEN_ISO_OPTIONS:
            if key in values:
                LOG.debug("Setting option from key=%s, option=%s, value=%s",
                          key, consts.GEN_ISO_OPTIONS[key], values[key])
                if key in ('bootstrap_address', 'nexthop_gateway'):
                    update_iso_cmd += [consts.GEN_ISO_OPTIONS[key],
                                       self.format_address(values[key])]
                elif key == 'no_check_certificate':
                    if str(values[key]) == 'True' and self.get_https_enabled():
                        update_iso_cmd += [consts.GEN_ISO_OPTIONS[key],
                                           'inst.noverifyssl=True']
                elif key in ('rootfs_device', 'boot_device',
                             'rd.net.timeout.ipv6dad'):
                    update_iso_cmd += [consts.GEN_ISO_OPTIONS[key],
                                       (key + '=' + str(values[key]))]
                elif key == 'bootstrap_vlan':
                    vlan_inteface = "%s.%s:%s" % \
                                    (values['bootstrap_interface'],
                                     values['bootstrap_vlan'],
                                     values['bootstrap_interface'])
                    update_iso_cmd += [consts.GEN_ISO_OPTIONS[key],
                                       ('vlan' + '=' + vlan_inteface)]
                elif (key == 'bootstrap_interface'
                      and 'bootstrap_vlan' in values):
                    boot_interface = "%s.%s" % (values['bootstrap_interface'],
                                                values['bootstrap_vlan'])
                    update_iso_cmd += [consts.GEN_ISO_OPTIONS[key], boot_interface]
                elif key == 'persistent_size':
                    update_iso_cmd += [consts.GEN_ISO_OPTIONS[key],
                                       ('persistent_size=%s'
                                        % str(values[key]))]
                elif key == 'hw_settle':
                    # translate to 'insthwsettle' boot parameter
                    update_iso_cmd += [consts.GEN_ISO_OPTIONS[key],
                                       ('insthwsettle=%s'
                                        % str(values[key]))]
                elif key == 'extra_boot_params':
                    update_iso_cmd += [consts.GEN_ISO_OPTIONS[key],
                                       ('extra_boot_params=%s'
                                        % str(values[key]))]
                else:
                    update_iso_cmd += [consts.GEN_ISO_OPTIONS[key], str(values[key])]

        if is_subcloud_debian:
            # Get the base URL. ostree_repo is located within this path
            base_url = os.path.join(self.get_image_base_url(), 'iso',
                                    software_version)
        else:
            # create ks-addon.cfg
            addon_cfg = os.path.join(override_path, 'ks-addon.cfg')
            self.create_ks_conf_file(addon_cfg, values)

            update_iso_cmd += ['--addon', addon_cfg]

            # Get the base URL
            base_url = os.path.join(self.get_image_base_url(), 'iso',
                                    software_version)

        update_iso_cmd += ['--base-url', base_url]

        str_cmd = ' '.join(x for x in update_iso_cmd)
        LOG.info("Running update_iso_cmd: %s", str_cmd)
        result = subprocess.run(update_iso_cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        if result.returncode != 0:
            msg = f'Failed to update iso: {str_cmd}'
            LOG.error("%s returncode: %s, output: %s",
                      msg,
                      result.returncode,
                      result.stdout.decode('utf-8').replace('\n', ', '))
            raise Exception(msg)

    def cleanup(self, software_version=None):
        # Do not remove the input_iso if it is in the Load Vault
        if (self.input_iso is not None and
                not self.input_iso.startswith(consts.LOAD_VAULT_DIR) and
                os.path.exists(self.input_iso)):
            os.remove(self.input_iso)

        if (self.www_root is not None and os.path.isdir(self.www_root)):
            if dccommon_utils.is_debian(software_version):
                cleanup_cmd = [
                    GEN_ISO_COMMAND,
                    "--id", self.name,
                    "--www-root", self.www_root,
                    "--delete"
                ]
            else:
                cleanup_cmd = [
                    GEN_ISO_COMMAND_CENTOS,
                    "--id", self.name,
                    "--www-root", self.www_root,
                    "--delete"
                ]
            LOG.info("Running install cleanup: %s", self.name)
            result = subprocess.run(cleanup_cmd,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT)
            if result.returncode == 0:
                # Note: watch for non-exit 0 errors in this output as well
                msg = f'Finished install cleanup: {cleanup_cmd}'
                LOG.info("%s returncode: %s, output: %s",
                         msg,
                         result.returncode,
                         result.stdout.decode('utf-8').replace('\n', ', '))
            else:
                msg = f'Failed install cleanup: {cleanup_cmd}'
                LOG.error("%s returncode: %s, output: %s",
                          msg,
                          result.returncode,
                          result.stdout.decode('utf-8').replace('\n', ', '))

    # TODO(kmacleod): utils.synchronized should be moved into dccommon
    @utils.synchronized("packages-list-from-bootimage", external=True)
    def _copy_packages_list_from_bootimage(self, software_version, pkg_file_src):
        # The source file (pkg_file_src) is not available.
        # So create a temporary directory in /mnt, mount the bootimage.iso
        # from /opt/dc-vault/rel-<version>/. Then copy the file from there to
        # the pkg_file_src location.

        if os.path.exists(pkg_file_src):
            LOG.info("Found existing package_checksums file at %s", pkg_file_src)
            return

        temp_bootimage_mnt_dir = tempfile.mkdtemp()
        bootimage_path = os.path.join(DCVAULT_BOOTIMAGE_PATH, software_version,
                                      'bootimage.iso')

        with open(os.devnull, "w") as fnull:
            try:
                subprocess.check_call(['mount', '-r', '-o', 'loop',  # pylint: disable=not-callable
                                      bootimage_path,
                                      temp_bootimage_mnt_dir],
                                      stdout=fnull,
                                      stderr=fnull)
            except Exception:
                os.rmdir(temp_bootimage_mnt_dir)
                raise Exception("Unable to mount bootimage.iso")

        # Now that the bootimage.iso has been mounted, copy package_checksums to
        # pkg_file_src.
        try:
            pkg_file = os.path.join(temp_bootimage_mnt_dir,
                                    'package_checksums')
            LOG.info("Copying %s to %s", pkg_file, pkg_file_src)
            shutil.copy(pkg_file, pkg_file_src)

            # now copy package_checksums to
            # /usr/local/share/pkg-list/<software_version>_packages_list.txt
            # This will only be done once by the first thread to access this code.

            # The directory PACKAGE_LIST_PATH may exist from a previous invocation
            # of this function (artifacts due to a previous failure).
            # Create the directory if it does not exist.

            if not os.path.exists(PACKAGE_LIST_PATH):
                os.mkdir(PACKAGE_LIST_PATH, 0o755)

            package_list_file = os.path.join(PACKAGE_LIST_PATH,
                                             software_version + "_packages_list.txt")
            shutil.copy(pkg_file_src, package_list_file)
        except IOError:
            # bootimage.iso in /opt/dc-vault/<release-id>/ does not have the file.
            # this is an issue in bootimage.iso.
            msg = "Package_checksums not found in bootimage.iso"
            LOG.error(msg)
            raise Exception(msg)
        finally:
            subprocess.check_call(['umount', '-l', temp_bootimage_mnt_dir])  # pylint: disable=not-callable
            os.rmdir(temp_bootimage_mnt_dir)

    def check_ostree_mount(self, source_path):
        """Mount the ostree_repo at ostree_repo_mount_path if necessary.

        Note that ostree_repo is mounted in a location not specific to a
        subcloud. We never unmount this directory once the mount path is
        established.
        """
        ostree_mount_dir = os.path.join(self.www_root, 'ostree_repo')
        LOG.debug("Checking mount: %s", ostree_mount_dir)
        check_path = os.path.join(ostree_mount_dir, 'config')
        if not os.path.exists(check_path):
            self._do_ostree_mount(ostree_mount_dir, check_path, source_path)

    # TODO(kmacleod): utils.synchronized should be moved into dccommon
    @utils.synchronized("ostree-mount-subclouds", external=True)
    def _do_ostree_mount(self, ostree_repo_mount_path,
                         check_path, source_path):
        # check again while locked:
        if not os.path.exists(check_path):
            LOG.info("Mounting ostree_repo at %s", ostree_repo_mount_path)
            if not os.path.exists(ostree_repo_mount_path):
                os.makedirs(ostree_repo_mount_path, mode=0o755)
            subprocess.check_call(  # pylint: disable=not-callable
                ["mount", "--bind",
                 "%s/ostree_repo" % source_path,
                 ostree_repo_mount_path])

    def prep(self, override_path, payload):
        """Update the iso image and create the config files for the subcloud"""
        LOG.info("Prepare for %s remote install" % (self.name))
        iso_values = {}
        for k in consts.MANDATORY_INSTALL_VALUES:
            if k in list(consts.GEN_ISO_OPTIONS.keys()):
                iso_values[k] = payload.get(k)
            if k not in consts.BMC_INSTALL_VALUES:
                iso_values[k] = payload.get(k)

        for k in consts.OPTIONAL_INSTALL_VALUES:
            if k in payload:
                iso_values[k] = payload.get(k)

        software_version = str(payload['software_version'])
        iso_values['software_version'] = payload['software_version']
        iso_values['image'] = payload['image']

        override_path = os.path.join(override_path, self.name)
        if not os.path.isdir(override_path):
            os.mkdir(override_path, 0o755)

        self.www_root = os.path.join(SUBCLOUD_ISO_PATH, software_version)

        feed_path_rel_version = os.path.join(SUBCLOUD_FEED_PATH,
                                             "rel-{version}".format(
                                                 version=software_version))

        if dccommon_utils.is_debian(software_version):
            self.check_ostree_mount(feed_path_rel_version)

        # Clean up iso directory if it already exists
        # This may happen if a previous installation attempt was abruptly
        # terminated
        iso_dir_path = os.path.join(self.www_root, 'nodes', self.name)
        if os.path.isdir(iso_dir_path):
            LOG.info("Found preexisting iso dir for subcloud %s, cleaning up",
                     self.name)
            self.cleanup(software_version)

        # Update the default iso image based on the install values
        # Runs gen-bootloader-iso.sh
        self.update_iso(override_path, iso_values)

        # remove the iso values from the payload
        for k in iso_values:
            if k in payload:
                del payload[k]

        # get the boot image url for bmc
        payload['image'] = os.path.join(self.get_image_base_url(), 'iso',
                                        software_version, 'nodes',
                                        self.name, 'bootimage.iso')

        # create the rvmc config file
        self.create_rvmc_config_file(override_path, payload)

        # remove the bmc values from the payload
        for k in consts.BMC_INSTALL_VALUES:
            if k in payload:
                del payload[k]

        # Only applicable for 22.06:
        if (
            dccommon_utils.is_centos(software_version)
            and software_version == dccommon_utils.LAST_SW_VERSION_IN_CENTOS
        ):
            # when adding a new subcloud, the subcloud will pull
            # the file "packages_list" from the controller.
            # The subcloud pulls from /var/www/pages/iso/<version>/.
            # The file needs to be copied from /var/www/pages/feed to
            # this location, as packages_list.
            pkg_file_dest = os.path.join(
                SUBCLOUD_ISO_DOWNLOAD_PATH,
                software_version,
                'nodes',
                self.name,
                software_version + "_packages_list.txt")

            pkg_file_src = os.path.join(SUBCLOUD_FEED_PATH,
                                        "rel-{version}".format(
                                            version=software_version),
                                        'package_checksums')

            if not os.path.exists(pkg_file_src):
                # the file does not exist. copy it from the bootimage.
                self._copy_packages_list_from_bootimage(software_version,
                                                        pkg_file_src)

            # since we now have package_checksums, copy to destination.
            shutil.copy(pkg_file_src, pkg_file_dest)

        # remove the boot image url from the payload
        if 'image' in payload:
            del payload['image']

        # create the install override file
        self.create_install_override_file(override_path, payload)

    def install(self, log_file_dir, install_command):
        LOG.info("Start remote install %s", self.name)
        log_file = os.path.join(log_file_dir, self.name) + '_playbook_output.log'

        try:
            # Since this is a long-running task we want to register
            # for cleanup on process restart/SWACT.
            ansible = dccommon_utils.AnsiblePlaybook(self.name)
            aborted = ansible.run_playbook(log_file, install_command)
            # Returns True if the playbook was aborted and False otherwise
            return aborted
        except exceptions.PlaybookExecutionFailed:
            msg = ("Failed to install %s, check individual "
                   "log at %s or run %s for details"
                   % (self.name, log_file, dcmanager_consts.ERROR_DESC_CMD))
            raise Exception(msg)
