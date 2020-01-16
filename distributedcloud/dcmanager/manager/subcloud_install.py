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
# Copyright (c) 2020 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

import base64
import datetime
import json
import netaddr
import os
import socket
import subprocess

from six.moves.urllib import error as urllib_error
from six.moves.urllib import parse
from six.moves.urllib import request

from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.common import install_consts
from dcmanager.drivers.openstack.sysinv_v1 import SysinvClient
from dcorch.drivers.openstack.keystone_v3 import KeystoneClient

from oslo_log import log as logging

LOG = logging.getLogger(__name__)

BOOT_MENU_TIMEOUT = '5'
RVMC_NAME_PREFIX = 'rvmc'
RVMC_IMAGE_NAME = 'docker.io/starlingx/rvmc'
SUBCLOUD_ISO_PATH = '/opt/platform/iso'
SUBCLOUD_ISO_DOWNLOAD_PATH = '/www/pages/iso'
UPDATE_ISO_COMMAND = '/usr/local/bin/update-iso.sh'
NETWORK_SCRIPTS = '/etc/sysconfig/network-scripts'
NETWORK_INTERFACE_PREFIX = 'ifcfg'
NETWORK_ROUTE_PREFIX = 'route'


OPTIONAL_INSTALL_VALUES = [
    'nexthop_gateway',
    'network_address',
    'network_mask',
    'console_type',
    'bootstrap_vlan',
    'rootfs_device',
    'boot_device'
]

UPDATE_ISO_OPTIONS = {
    'install_type': '-d',
    'console_type': '-p',
    'rootfs_device': '-p',
    'boot_device': '-p'
}

BMC_OPTIONS = {
    'bmc_address',
    'bmc_username',
    'bmc_password',
}


class SubcloudInstall(object):
    """Class to encapsulate the subcloud install operations"""

    def __init__(self, context, subcloud_name):
        ks_client = KeystoneClient()
        session = ks_client.endpoint_cache.get_session_from_token(
            context.auth_token, context.project)
        self.sysinv_client = SysinvClient(consts.DEFAULT_REGION_NAME, session)
        self.name = subcloud_name
        self.input_iso = None
        self.output_iso = None

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

    def get_oam_address(self):
        oam_pool = self.sysinv_client.get_oam_address_pool()
        try:
            oam_address = netaddr.IPAddress(oam_pool.floating_address)
            if oam_address.version == 6:
                return "[%s]" % oam_address
            else:
                return str(oam_address)
        except netaddr.AddrFormatError:
            return oam_pool.floating_address

    def get_image_base_url(self):
        system = self.sysinv_client.get_system()

        # get the protocol
        https_enabled = system.capabilities.get('https_enabled', False)
        protocol = 'https' if https_enabled else 'http'

        # get the configured http or https port
        value = 'https_port' if https_enabled else 'http_port'
        http_parameters = self.sysinv_client.get_service_parameters('name',
                                                                    value)
        port = getattr(http_parameters[0], 'value')

        return "%s://%s:%s" % (protocol, self.get_oam_address(), port)

    def get_image_tag(self, image_name):
        tags = self.sysinv_client.get_registry_image_tags(image_name)
        if not tags:
            msg = ("Error: Image % not found in the local registry." %
                   image_name)
            LOG.error(msg)
            raise exceptions.NotFound()
        tag = getattr(tags[0], 'tag')
        return tag

    @staticmethod
    def create_rvmc_config_file(override_path, payload):

        LOG.debug("create rvmc config file")
        rvmc_config_file = os.path.join(override_path, 'rvmc-config.yaml')

        with open(rvmc_config_file, 'w') as f_out_rvmc_config_file:
            for k, v in payload.items():
                if k in BMC_OPTIONS or k == 'image':
                    f_out_rvmc_config_file.write(k + ': ' + v + '\n')

    def create_install_override_file(self, override_path, payload):

        LOG.debug("create install override file")
        rvmc_image = RVMC_IMAGE_NAME + ':' + self.get_image_tag(
            RVMC_IMAGE_NAME)
        install_override_file = os.path.join(override_path,
                                             'install_values.yml')
        rvmc_name = "%s-%s" % (RVMC_NAME_PREFIX, self.name)
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
                f_out_override_file.write("%s: %s\n" % (k, json.dumps(v)))

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
        output_iso_dir = os.path.join(SUBCLOUD_ISO_PATH,
                                      str(values['software_version']))
        if not os.path.isdir(output_iso_dir):
            os.mkdir(output_iso_dir, 0o755)

        try:
            if parse.urlparse(values['image']).scheme:
                url = values['image']
            else:
                path = os.path.abspath(values['image'])
                url = parse.urljoin('file:', request.pathname2url(path))
            filename = os.path.join(override_path, 'bootimage.iso')
            LOG.info("Downloading %s to %s", url, override_path)
            self.input_iso, _ = request.urlretrieve(url, filename)
            LOG.info("Downloaded %s to %s", url, self.input_iso)
        except urllib_error.ContentTooShortError as e:
            msg = "Error: Downloading file %s may be interrupted: %s" % (
                values['image'], e)
            LOG.error(msg)
            raise exceptions.DCManagerException(
                resource=self.name,
                msg=msg)
        except Exception as e:
            msg = "Error: Could not download file %s: %s" % (
                values['image'], e)
            LOG.error(msg)
            raise exceptions.DCManagerException(
                resource=self.name,
                msg=msg)

        output_iso_file = os.path.join(output_iso_dir,
                                       self.name + 'bootimage.iso')
        if os.path.exists(output_iso_file):
            os.remove(output_iso_file)

        update_iso_cmd = [
            UPDATE_ISO_COMMAND,
            "-i", self.input_iso,
            "-o", output_iso_file
        ]
        for k in UPDATE_ISO_OPTIONS.keys():
            if k in values:
                if k == 'install_type':
                    update_iso_cmd += [UPDATE_ISO_OPTIONS[k],
                                       str(values[k])]
                else:
                    update_iso_cmd += [UPDATE_ISO_OPTIONS[k],
                                       (k + '=' + values[k])]

        # create ks-addon.cfg
        addon_cfg = os.path.join(override_path, 'ks-addon.cfg')
        self.create_ks_conf_file(addon_cfg, values)

        update_iso_cmd += ['-t', BOOT_MENU_TIMEOUT]
        update_iso_cmd += ['-a', addon_cfg]

        str_cmd = ' '.join(update_iso_cmd)
        LOG.debug("update_iso_cmd:(%s)", str_cmd)
        try:
            with open(os.devnull, "w") as fnull:
                subprocess.check_call(update_iso_cmd, stdout=fnull,
                                      stderr=fnull)
        except subprocess.CalledProcessError as ex:
            msg = "Failed to update iso %s, " % str(update_iso_cmd)
            LOG.error(msg)
            raise ex
        return output_iso_file

    def cleanup(self):
        if (self.input_iso is not None and
                os.path.exists(self.input_iso)):
            os.remove(self.input_iso)
        if (self.output_iso is not None and
                os.path.exists(self.output_iso)):
            os.remove(self.output_iso)

    def prep(self, override_path, payload):
        """Update the iso image and create the config files for the subcloud"""
        LOG.info("Prepare for %s remote install" % (self.name))
        iso_values = {}
        for k in install_consts.MANDATORY_INSTALL_VALUES:
            if k in UPDATE_ISO_OPTIONS.keys():
                iso_values[k] = payload.get(k)
            if k not in BMC_OPTIONS:
                iso_values[k] = payload.get(k)

        for k in OPTIONAL_INSTALL_VALUES:
            if k in payload:
                iso_values[k] = payload.get(k)

        override_path = os.path.join(override_path, self.name)
        if not os.path.isdir(override_path):
            os.mkdir(override_path, 0o755)

        # update the default iso image based on the install values
        self.output_iso = self.update_iso(override_path, iso_values)
        software_version = str(payload['software_version'])

        # remove the iso values from the payload
        for k in iso_values:
            if k in payload:
                del payload[k]

        # get the boot image url for bmc
        payload['image'] = os.path.join(self.get_image_base_url(), 'iso',
                                        software_version,
                                        os.path.basename(self.output_iso))
        # encode the bmc_password
        encoded_password = base64.b64encode(
            payload['bmc_password'].encode("utf-8"))
        payload['bmc_password'] = str(encoded_password)

        # create the rvmc config file
        self.create_rvmc_config_file(override_path, payload)

        # remove the bmc values from the payload
        for k in BMC_OPTIONS:
            if k in payload:
                del payload[k]

        # remove the boot image url from the payload
        if 'image' in payload:
            del payload['image']

        # create the install override file
        self.create_install_override_file(override_path, payload)

    def install(self, log_file_dir, install_command):
        log_file = (log_file_dir + self.name + '_install_' +
                    str(datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S'))
                    + '.log')
        with open(log_file, "w") as f_out_log:
            try:
                subprocess.check_call(install_command,
                                      stdout=f_out_log,
                                      stderr=f_out_log)
            except subprocess.CalledProcessError as e:
                msg = ("Failed to install the subcloud %s, check individual "
                       "log at %s for detailed output."
                       % (self.name, log_file))
                LOG.error(msg)
                raise e
