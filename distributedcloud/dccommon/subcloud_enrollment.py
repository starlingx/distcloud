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

LOG = logging.getLogger(__name__)

CONF = cfg.CONF

SUBCLOUD_ISO_PATH = '/opt/platform/iso'


class SubcloudEnrollmentInit(object):
    """Class to encapsulate the subcloud enrollment init operations.

       These opeartions are necessary to prepare a standalone node for
       subcloud enrollment.
    """

    def __init__(self, subcloud_name):
        self.name = subcloud_name
        self.www_root = None
        self.iso_dir_path = None
        self.seed_iso_path = None

    def build_seed_network_config(self, path, iso_values):
        if not os.path.isdir(path):
            raise Exception(f'No directory exists: {path}')

        # TODO(srana): Investigate other bootstrap / install values
        # that would need to be covered here.
        network_cloud_config = [
            {
                'type': 'physical',
                'name': iso_values['bootstrap_interface'],
                'subnets': [
                    {
                        'type': 'static',
                        'address': iso_values['external_oam_floating_address'],
                        'netmask': iso_values['network_mask'],
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

    def build_seed_user_config(self, path, iso_values):
        if not os.path.isdir(path):
            raise Exception(f'No directory exists: {path}')

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

    def generate_seed_iso(self, payload):
        self.www_root = os.path.join(SUBCLOUD_ISO_PATH, payload['software_version'])
        temp_seed_data_dir = tempfile.mkdtemp(prefix='seed_')
        self.iso_dir_path = os.path.join(self.www_root, 'nodes', self.name)
        self.seed_iso_path = os.path.join(self.iso_dir_path, 'seed.iso')

        LOG.info(f'Preparing seed iso generation for {self.name}')

        if not os.path.isdir(self.iso_dir_path):
            os.makedirs(self.iso_dir_path, 0o755, exist_ok=True)
        elif os.path.exists(self.seed_iso_path):
            LOG.info(f'Found preexisting seed iso for subcloud {self.name}, '
                     f'cleaning up')
            os.remove(self.seed_iso_path)

        # TODO(srana): After integration, extract required bootstrap and install
        # into iso_values. For now, pass in payload.
        try:
            # Generate seed cloud-config files
            self.build_seed_network_config(temp_seed_data_dir, payload)
            self.build_seed_user_config(temp_seed_data_dir, payload)
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
