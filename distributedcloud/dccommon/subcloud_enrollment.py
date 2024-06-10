# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import hashlib
import os
import shutil
import tempfile
import yaml

from eventlet.green import subprocess
from oslo_config import cfg
from oslo_log import log as logging

from dccommon import consts
from dccommon import exceptions
from dccommon.subcloud_install import SubcloudInstall
from dccommon import utils as dccommon_utils
from dcmanager.common import consts as dcmanager_consts

LOG = logging.getLogger(__name__)

CONF = cfg.CONF

SUBCLOUD_ISO_PATH = '/opt/platform/iso'


class SubcloudEnrollmentInit(object):
    """Class to encapsulate the subcloud enrollment init operations.

    These operations are necessary to prepare a standalone node for
    subcloud enrollment. The enrollment initialization is performed
    in the following order:

    1. prep:
        - Creates required directories
        - Initiates cloud-init config files and seed iso generation
        - Creates RVMC config
    2. enroll_init:
        - Invokes the install playbook to run the RVMC script/insert
            the generated ISO and reconfigure the standalone node
    3. cleanup:
        - Removes generated iso
    """

    def __init__(self, subcloud_name):
        self.sysinv_client = SubcloudInstall.get_sysinv_client()
        self.name = subcloud_name
        self.www_root = None
        self.iso_dir_path = None
        self.seed_iso_path = None
        self.https_enabled = None

    def get_https_enabled(self):
        if self.https_enabled is None:
            system = self.sysinv_client.get_system()
            self.https_enabled = system.capabilities.get('https_enabled',
                                                         False)
        return self.https_enabled

    def _build_seed_network_config(self, path, iso_values):
        if not os.path.isdir(path):
            msg = f'No directory exists: {path}'
            raise exceptions.EnrollInitExecutionFailed(reason=msg)

        # TODO(srana): Investigate other bootstrap / install values
        # that would need to be covered here.
        network_cloud_config = [
            {
                'type': 'physical',
                'name': iso_values['install_values']['bootstrap_interface'],
                'subnets': [
                    {
                        'type': 'static',
                        'address': iso_values['external_oam_floating_address'],
                        'netmask': iso_values['install_values']['network_mask'],
                        'gateway': iso_values['external_oam_gateway_address'],
                    }
                ]
            }
        ]

        network_config_file = os.path.join(path, 'network-config')
        with open(network_config_file, 'w') as f_out_network_config_file:
            contents = {'version': 1, 'config': network_cloud_config}
            f_out_network_config_file.write(yaml.dump(contents,
                                                      default_flow_style=False,
                                                      sort_keys=False))

        return True

    def _build_seed_user_config(self, path, iso_values):
        if not os.path.isdir(path):
            msg = f'No directory exists: {path}'
            raise exceptions.EnrollInitExecutionFailed(reason=msg)

        hashed_password = hashlib.sha256(
            iso_values['admin_password'].encode()).hexdigest()

        account_config = {
            'list': [f'sysadmin:{hashed_password}'],
            'expire': 'False'
        }

        user_data_file = os.path.join(path, 'user-data')
        with open(user_data_file, 'w') as f_out_user_data_file:
            contents = {'chpasswd': account_config}
            f_out_user_data_file.writelines('#cloud-config\n')
            f_out_user_data_file.write(yaml.dump(contents,
                                                 default_flow_style=False,
                                                 sort_keys=False))

        return True

    def _generate_seed_iso(self, payload):
        temp_seed_data_dir = tempfile.mkdtemp(prefix='seed_')

        LOG.info(f'Preparing seed iso generation for {self.name}')

        # TODO(srana): After integration, extract required bootstrap and install
        # into iso_values. For now, pass in payload.
        try:
            # Generate seed cloud-config files
            self._build_seed_network_config(temp_seed_data_dir, payload)
            self._build_seed_user_config(temp_seed_data_dir, payload)
        except Exception as e:
            LOG.exception(f'Unable to generate seed config files '
                          f'for {self.name}: {e}')
            shutil.rmtree(temp_seed_data_dir)
            return False

        gen_seed_iso_command = [
            "genisoimage",
            "-o", self.seed_iso_path,
            "-volid", "CIDATA",
            "-untranslated-filenames",
            "-joliet",
            "-rock",
            "-iso-level", "2",
            temp_seed_data_dir
        ]

        LOG.info(f'Running gen_seed_iso_command '
                 f'for {self.name}: {gen_seed_iso_command}')
        result = subprocess.run(gen_seed_iso_command,
                                # capture both streams in stdout:
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)

        shutil.rmtree(temp_seed_data_dir)

        if result.returncode == 0:
            msg = (
                f'Finished generating seed iso for {self.name}: '
                f'{gen_seed_iso_command}'
            )
            LOG.info("%s returncode: %s, output: %s",
                     msg,
                     result.returncode,
                     result.stdout.decode('utf-8').replace('\n', ', '))
        else:
            msg = (
                f'Failed to generate seed iso for {self.name}: '
                f'{gen_seed_iso_command}'
            )
            LOG.error("%s returncode: %s, output: %s",
                      msg,
                      result.returncode,
                      result.stdout.decode('utf-8').replace('\n', ', '))
            raise Exception(msg)

        return True

    def prep(self, override_path, payload):
        LOG.info(f'Prepare config for {self.name} enroll init')

        software_version = str(payload['software_version'])
        self.www_root = os.path.join(SUBCLOUD_ISO_PATH, software_version)
        self.iso_dir_path = os.path.join(self.www_root, 'nodes', self.name)
        self.seed_iso_path = os.path.join(self.iso_dir_path,
                                          consts.ENROLL_INIT_SEED_ISO_NAME)
        override_path = os.path.join(override_path, self.name)

        if not os.path.isdir(override_path):
            os.mkdir(override_path, 0o755)

        if not os.path.isdir(self.www_root):
            os.mkdir(self.www_root, 0o755)

        if not os.path.isdir(self.iso_dir_path):
            os.makedirs(self.iso_dir_path, 0o755, exist_ok=True)
        elif os.path.exists(self.seed_iso_path):
            # Clean up iso file if it already exists
            # This may happen if a previous enroll init attempt was abruptly
            # terminated
            LOG.info(f'Found preexisting seed iso for subcloud {self.name}, '
                     'cleaning up')
            os.remove(self.seed_iso_path)

        self._generate_seed_iso(payload)

        # get the boot image url for bmc
        image_base_url = SubcloudInstall.get_image_base_url(self.get_https_enabled(),
                                                            self.sysinv_client)
        payload['image'] = os.path.join(image_base_url, 'iso',
                                        software_version, 'nodes',
                                        self.name, consts.ENROLL_INIT_SEED_ISO_NAME)

        SubcloudInstall.create_rvmc_config_file(override_path, payload)

        return True

    def enroll_init(self, log_file_dir, enroll_command):
        LOG.info(f'Start enroll init for {self.name}')
        subcloud_log_base_path = os.path.join(log_file_dir, self.name)
        playbook_log_file = f'{subcloud_log_base_path}_playbook_output.log'

        try:
            ansible = dccommon_utils.AnsiblePlaybook(self.name)
            ansible.run_playbook(playbook_log_file, enroll_command)
            return True
        except exceptions.PlaybookExecutionFailed:
            msg = (
                f"Failed to enroll init {self.name}, check individual "
                f"logs at {playbook_log_file}. "
                f"Run {dcmanager_consts.ERROR_DESC_CMD} for details"
            )
            raise Exception(msg)

    def cleanup(self):
        if os.path.exists(self.seed_iso_path):
            os.remove(self.seed_iso_path)
