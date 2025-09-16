# Copyright (c) 2024-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import crypt
import os
import tarfile
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

SUBCLOUD_ISO_PATH = "/opt/platform/iso"


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

    @staticmethod
    def validate_enroll_init_values(payload):
        install_values = payload["install_values"]
        missing_keys = []

        for key in consts.MANDATORY_ENROLL_INIT_VALUES:
            if key not in payload and key not in install_values:
                missing_keys.append(key)

        if missing_keys:
            msg = f"Missing required values: {', '.join(missing_keys)}"
            raise exceptions.EnrollInitExecutionFailed(reason=msg)

    def get_https_enabled(self):
        if self.https_enabled is None:
            system = self.sysinv_client.get_system()
            self.https_enabled = system.capabilities.get("https_enabled", False)
        return self.https_enabled

    def _build_seed_network_config(self, path, iso_values):
        if not os.path.isdir(path):
            msg = f"No directory exists: {path}"
            raise exceptions.EnrollInitExecutionFailed(reason=msg)

        subnet_prefix = iso_values["external_oam_subnet"].split(",")[0].split("/")[1]

        network_element = {
            "type": "physical",
            "name": iso_values["install_values"]["bootstrap_interface"],
            "subnets": [
                {
                    "type": "static",
                    "address": (
                        iso_values["external_oam_floating_address"].split(",")[0]
                        + "/"
                        + subnet_prefix
                    ),
                    "gateway": iso_values["external_oam_gateway_address"].split(",")[0],
                }
            ],
        }

        vlan_id = iso_values["install_values"].get("bootstrap_vlan", None)
        if vlan_id:
            network_element["type"] = "vlan"
            network_element["name"] = f"vlan{vlan_id}"
            network_element["vlan_link"] = iso_values["install_values"][
                "bootstrap_interface"
            ]
            network_element["vlan_id"] = vlan_id

        network_cloud_config = []
        network_cloud_config.append(network_element)

        network_config_file = os.path.join(path, "network-config")
        with open(network_config_file, "w") as f_out_network_config_file:
            contents = {"version": 1, "config": network_cloud_config}
            f_out_network_config_file.write(
                yaml.dump(contents, default_flow_style=False, sort_keys=False)
            )

        return True

    def _build_seed_meta_data(self, path, iso_values):
        if not os.path.isdir(path):
            msg = f"No directory exists: {path}"
            raise exceptions.EnrollInitExecutionFailed(reason=msg)

        meta_data = {"instance-id": self.name, "local-hostname": "controller-0"}

        meta_data_file = os.path.join(path, "meta-data")
        with open(meta_data_file, "w") as f_out_meta_data_file:
            f_out_meta_data_file.write(
                yaml.dump(meta_data, default_flow_style=False, sort_keys=False)
            )

        return True

    def create_enroll_override_file(self, override_path, payload, cloud_init_tarball):
        enroll_override_file = os.path.join(override_path, "enroll_overrides.yml")

        with open(enroll_override_file, "w") as f_out_override_file:
            f_out_override_file.write(
                "---"
                "\nenroll_reconfigured_oam: "
                + payload.get("external_oam_floating_address").split(",")[0]
                + "\n"
            )

            enroll_overrides = payload["install_values"].get("enroll_overrides", {})

            # If no custom cloud-init config is provided, disable IPMI SEL event
            # monitoring by default.
            if (
                cloud_init_tarball is None
                and "ipmi_sel_event_monitoring" not in enroll_overrides
            ):
                f_out_override_file.write("ipmi_sel_event_monitoring: false\n")

            if enroll_overrides:
                for k, v in enroll_overrides.items():
                    # Properly format boolean values with yaml.dump
                    f_out_override_file.write(
                        f"{k}: {yaml.dump(v, default_flow_style=False).strip()}\n"
                    )

    def _build_seed_user_config(self, path, iso_values):
        if not os.path.isdir(path):
            msg = f"No directory exists: {path}"
            raise exceptions.EnrollInitExecutionFailed(reason=msg)

        # Generate /cloud-init-config/scripts directory
        scripts_dir = os.path.join(path, "cloud-init-config", "scripts")
        os.makedirs(scripts_dir, exist_ok=True)

        # Create 10-platform-reconfig script for enroll-init-reconfigure
        hashed_password = crypt.crypt(
            iso_values["sysadmin_password"], crypt.mksalt(crypt.METHOD_SHA512)
        )

        enroll_utils = "/usr/local/bin/"
        reconfig_script = os.path.join(enroll_utils, "enroll-init-reconfigure")
        extern_oam_gw_ip = iso_values["external_oam_gateway_address"].split(",")[0]

        reconfig_command = (
            f"{reconfig_script}"
            f" --oam_subnet {iso_values['external_oam_subnet'].split(',')[0]}"
            f" --oam_gateway_ip {extern_oam_gw_ip}"
            f" --oam_ip {iso_values['external_oam_floating_address'].split(',')[0]}"
            f" --new_password '{hashed_password}'"
        )

        if iso_values["system_mode"] == dcmanager_consts.SYSTEM_MODE_DUPLEX:
            reconfig_command += (
                f" --oam_c0_ip "
                f"{iso_values['external_oam_node_0_address'].split(',')[0]}"
                f" --oam_c1_ip "
                f"{iso_values['external_oam_node_1_address'].split(',')[0]}"
            )

        platform_script = os.path.join(
            scripts_dir,
            consts.PLATFORM_RECONFIGURE_FILE_NAME,
        )
        with open(platform_script, "w") as f:
            f.write("#!/bin/bash\n")
            f.write(f"{reconfig_command}\n")
        os.chmod(platform_script, 0o755)

        # Create a completion event script that runs last. It will send an IPMI SEL
        # event to indicate that all custom scripts executed before it ran successfully.
        # If any of the scripts fail, this one won't be executed and the Ansible
        # monitoring task will time out.
        enroll_overrides = iso_values["install_values"].get("enroll_overrides", {})
        if enroll_overrides.get("ipmi_sel_event_monitoring", True) is not False:
            completion_script = os.path.join(scripts_dir, "99-completion-event")
            with open(completion_script, "w") as f:
                f.write(
                    """#!/bin/bash
        echo "$(date '+%F %H:%M:%S'): INFO: All custom scripts completed successfully"
        tmp_file=$(mktemp /tmp/ipmi_event_XXXXXX.txt)
        echo "0x04 0xF0 0x01 0x6f 0xff 0xff 0xe6 # \"Custom complete\"" > "$tmp_file"
        ipmitool sel add "$tmp_file" 2>/dev/null
        rm -f "$tmp_file"
        """
                )
            os.chmod(completion_script, 0o755)

        # Write user-data with runcmd
        user_data_file = os.path.join(path, "user-data")
        runcmd = [
            ["/bin/bash", "-c", "echo $(date): Initiating enroll-init sequence"],
            "mkdir -p /opt/nocloud",
            "mount LABEL=CIDATA /opt/nocloud",
            "run-parts --verbose --exit-on-error "
            "/opt/nocloud/cloud-init-config/scripts",
            "eject /opt/nocloud",
        ]

        with open(user_data_file, "w") as f:
            # Cloud-init module frequency for runcmd and scripts-user
            # must be set to 'always'. This ensures that the
            # cloud config is applied on an enroll-init retry, since the
            # default frequency for these modules is 'per-instance'.
            # It's necessary to specify both modules, runcmd
            # generates the script, while scripts-user executes it.
            contents = {
                "cloud_config_modules": [["runcmd", "always"]],
                "cloud_final_modules": [["scripts-user", "always"]],
                "runcmd": runcmd,
            }

            f.writelines("#cloud-config\n")
            yaml.dump(
                contents,
                f,
                default_flow_style=None,
                sort_keys=False,
                width=float("inf"),
            )

        return True

    def _get_cloud_init_config(self):
        cloud_init_tarball_name = f"{self.name}_{consts.CLOUD_INIT_CONFIG}.tar"
        cloud_init_tarball = os.path.join(
            consts.ANSIBLE_OVERRIDES_PATH, cloud_init_tarball_name
        )
        if os.path.isfile(cloud_init_tarball):
            LOG.info(f"Detected {cloud_init_tarball} tarball")
            return cloud_init_tarball
        return None

    def _generate_seed_iso(self, payload, cloud_init_tarball):
        LOG.info(f"Preparing seed iso generation for {self.name}")

        with tempfile.TemporaryDirectory(prefix="seed_") as temp_seed_data_dir:
            # TODO(srana): After integration, extract required bootstrap and install
            # into iso_values. For now, pass in payload.
            try:
                # Untar cloud_init_config if present
                if cloud_init_tarball:
                    with tarfile.open(cloud_init_tarball, "r") as tar:
                        tar.extractall(path=temp_seed_data_dir)
                    LOG.info(
                        f"Extracted cloud-init-data for {self.name} "
                        f"to {temp_seed_data_dir}"
                    )
                else:
                    LOG.debug(
                        f"No valid cloud-init-data tarball provided for {self.name}"
                    )

                self._build_seed_network_config(temp_seed_data_dir, payload)
                self._build_seed_meta_data(temp_seed_data_dir, payload)
                self._build_seed_user_config(temp_seed_data_dir, payload)

            except Exception as e:
                LOG.exception(
                    f"Unable to generate seed config files for {self.name}: {e}"
                )
                return False

            gen_seed_iso_command = [
                "genisoimage",
                "-o",
                self.seed_iso_path,
                "-volid",
                "CIDATA",
                "-untranslated-filenames",
                "-joliet",
                "-rock",
                "-iso-level",
                "2",
                temp_seed_data_dir,
            ]

            LOG.info(
                f"Running gen_seed_iso_command for {self.name}: {gen_seed_iso_command}"
            )
            result = subprocess.run(
                gen_seed_iso_command,
                # capture both streams in stdout:
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )

        if result.returncode == 0:
            msg = (
                f"Finished generating seed iso for {self.name}: {gen_seed_iso_command}"
            )
            LOG.info(
                "%s returncode: %s, output: %s",
                msg,
                result.returncode,
                result.stdout.decode("utf-8").replace("\n", ", "),
            )
        else:
            msg = f"Failed to generate seed iso for {self.name}: {gen_seed_iso_command}"
            LOG.error(
                "%s returncode: %s, output: %s",
                msg,
                result.returncode,
                result.stdout.decode("utf-8").replace("\n", ", "),
            )
            raise Exception(msg)

        return True

    def prep(self, override_path, payload, subcloud_primary_oam_ip_family):
        LOG.info(f"Prepare config for {self.name} enroll init")

        SubcloudEnrollmentInit.validate_enroll_init_values(payload)

        software_version = str(payload["software_version"])
        self.www_root = os.path.join(SUBCLOUD_ISO_PATH, software_version)
        self.iso_dir_path = os.path.join(self.www_root, "nodes", self.name)
        self.seed_iso_path = os.path.join(
            self.iso_dir_path, consts.ENROLL_INIT_SEED_ISO_NAME
        )
        override_path = os.path.join(override_path, self.name)

        if not os.path.isdir(override_path):
            os.mkdir(override_path, 0o755)

        if not os.path.isdir(self.www_root):
            os.mkdir(self.www_root, 0o755)

        if not os.path.isdir(self.iso_dir_path):
            os.makedirs(self.iso_dir_path, 0o755, exist_ok=True)
        elif os.path.exists(self.seed_iso_path):
            # Clean up iso file if it already exists.
            # This may happen if a previous enroll init attempt was abruptly terminated.
            LOG.info(
                f"Found preexisting seed iso for subcloud {self.name}, cleaning up"
            )
            os.remove(self.seed_iso_path)

        cloud_init_tarball = self._get_cloud_init_config()

        self._generate_seed_iso(payload, cloud_init_tarball)

        # get the boot image url for bmc
        image_base_url = SubcloudInstall.get_image_base_url(
            self.get_https_enabled(), self.sysinv_client, subcloud_primary_oam_ip_family
        )
        bmc_values = {
            "bmc_username": payload["install_values"]["bmc_username"],
            "bmc_password": payload["bmc_password"],
            "bmc_address": payload["install_values"]["bmc_address"],
        }
        bmc_values["image"] = os.path.join(
            image_base_url,
            "iso",
            software_version,
            "nodes",
            self.name,
            consts.ENROLL_INIT_SEED_ISO_NAME,
        )

        SubcloudInstall.create_rvmc_config_file(override_path, bmc_values)

        self.create_enroll_override_file(override_path, payload, cloud_init_tarball)

        return True

    def enroll_init(self, log_file_dir, enroll_command):
        LOG.info(f"Start enroll init for {self.name}")
        subcloud_log_base_path = os.path.join(log_file_dir, self.name)
        log_file = f"{subcloud_log_base_path}_playbook_output.log"

        try:
            ansible = dccommon_utils.AnsiblePlaybook(self.name)
            ansible.run_playbook(log_file, enroll_command)
            return True
        except exceptions.PlaybookExecutionFailed:
            msg = (
                f"Failed to enroll init {self.name}, check individual logs at "
                f"{log_file}. Run {dcmanager_consts.ERROR_DESC_CMD} for details."
            )
            LOG.error(msg)
            raise

    def cleanup(self):
        if os.path.exists(self.seed_iso_path):
            os.remove(self.seed_iso_path)
