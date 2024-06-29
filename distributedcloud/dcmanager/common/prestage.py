# Copyright (c) 2022-2024 Wind River Systems, Inc.
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
#

"""
Common prestaging operations.

These are shared across dcmanager (SubcloudManager) and orchestration.
"""

import base64
import os
import threading

from oslo_config import cfg
from oslo_log import log as logging

from tsconfig.tsconfig import SW_VERSION

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.sdk_platform import OpenStackDriver
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon.exceptions import PlaybookExecutionFailed
from dccommon.exceptions import PlaybookExecutionTimeout
from dccommon import ostree_mount
from dccommon.utils import AnsiblePlaybook

from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.common import utils
from dcmanager.db import api as db_api

LOG = logging.getLogger(__name__)
CONF = cfg.CONF

DEPLOY_BASE_DIR = dccommon_consts.DEPLOY_DIR
ANSIBLE_PRESTAGE_SUBCLOUD_PACKAGES_PLAYBOOK = (
    "/usr/share/ansible/stx-ansible/playbooks/prestage_sw_packages.yml"
)
ANSIBLE_PRESTAGE_SUBCLOUD_IMAGES_PLAYBOOK = (
    "/usr/share/ansible/stx-ansible/playbooks/prestage_images.yml"
)
ANSIBLE_PRESTAGE_INVENTORY_SUFFIX = "_prestage_inventory.yml"
PRINT_PRESTAGE_VERSIONS_TASK = r"prestage\/prestage-versions : Print prestage versions"
PRESTAGE_VERSIONS_KEY_STR = "prestage_versions:"


def _get_system_controller_upgrades():
    # get a cached keystone client (and token)
    try:
        os_client = OpenStackDriver(
            region_name=dccommon_consts.SYSTEM_CONTROLLER_NAME, region_clients=None
        )
    except Exception:
        LOG.exception(
            "Failed to get keystone client for %s",
            dccommon_consts.SYSTEM_CONTROLLER_NAME,
        )
        raise

    ks_client = os_client.keystone_client
    sysinv_client = SysinvClient(
        dccommon_consts.SYSTEM_CONTROLLER_NAME,
        ks_client.session,
        endpoint=ks_client.endpoint_cache.get_endpoint("sysinv"),
    )

    return sysinv_client.get_upgrades()


def is_system_controller_upgrading():
    return len(_get_system_controller_upgrades()) != 0


def global_prestage_validate(payload):
    """Global prestage validation (not subcloud-specific)"""

    if is_system_controller_upgrading():
        raise exceptions.PrestagePreCheckFailedException(
            subcloud=dccommon_consts.SYSTEM_CONTROLLER_NAME,
            details=(
                "Prestage operations are not allowed while system "
                "controller upgrade is in progress."
            ),
        )

    if (
        "sysadmin_password" not in payload
        or payload["sysadmin_password"] is None
        or payload["sysadmin_password"] == ""
    ):
        raise exceptions.PrestagePreCheckFailedException(
            subcloud=None,
            orch_skip=False,
            details="Missing required parameter 'sysadmin_password'",
        )

    # Ensure we can decode the sysadmin_password
    # (we decode again when running ansible)
    try:
        base64.b64decode(payload["sysadmin_password"]).decode("utf-8")
    except Exception as ex:
        raise exceptions.PrestagePreCheckFailedException(
            subcloud=None,
            orch_skip=False,
            details=(
                "Failed to decode subcloud sysadmin_password, verify the password "
                "is base64 encoded. Details: %s" % ex
            ),
        )


def initial_subcloud_validate(
    subcloud,
    installed_releases,
    software_major_release,  # format: YY.MM
    for_sw_deploy,
):
    """Basic validation a subcloud prestage operation.

    Raises a PrestageCheckFailedException on failure.
    """
    LOG.debug("Validating subcloud prestage '%s'", subcloud.name)

    if subcloud.availability_status != dccommon_consts.AVAILABILITY_ONLINE:
        raise exceptions.PrestagePreCheckFailedException(
            subcloud=subcloud.name, orch_skip=True, details="Subcloud is offline."
        )

    if subcloud.management_state != dccommon_consts.MANAGEMENT_MANAGED:
        raise exceptions.PrestagePreCheckFailedException(
            subcloud=subcloud.name, orch_skip=True, details="Subcloud is not managed."
        )

    if subcloud.backup_status in consts.STATES_FOR_ONGOING_BACKUP:
        raise exceptions.PrestagePreCheckFailedException(
            subcloud=subcloud.name,
            orch_skip=True,
            details="Prestage operation is not allowed while backup is in progress.",
        )

    if subcloud.deploy_status != consts.DEPLOY_STATE_DONE:
        raise exceptions.PrestagePreCheckFailedException(
            subcloud=subcloud.name,
            orch_skip=True,
            details=(
                "Prestage operation is not allowed when subcloud deploy is in progress."
            ),
        )

    allowed_prestage_states = [
        consts.PRESTAGE_STATE_FAILED,
        consts.PRESTAGE_STATE_COMPLETE,
    ]
    if subcloud.prestage_status and (
        subcloud.prestage_status not in allowed_prestage_states
    ):
        raise exceptions.PrestagePreCheckFailedException(
            subcloud=subcloud.name,
            orch_skip=True,
            details=(
                "Prestage operation is only allowed while subcloud prestage "
                "status is one of: %s. The current prestage status is %s."
            )
            % (", ".join(allowed_prestage_states), subcloud.prestage_status),
        )

    # The request software version must be either the same as the software version
    # of the subcloud or any available/deployed release on the system controller
    # (can be checked with "software list" command).
    if (
        not for_sw_deploy
        and software_major_release
        and software_major_release != subcloud.software_version
        and software_major_release not in installed_releases
    ):
        raise exceptions.PrestagePreCheckFailedException(
            subcloud=subcloud.name,
            orch_skip=True,
            details=(
                f"Specified release is not supported. {software_major_release} "
                "version must first be imported"
            ),
        )


def validate_prestage(subcloud, payload):
    """Validate a subcloud prestage operation.

    Prestage conditions validation
      - Subcloud exists
      - Subcloud is an AIO-SX
      - Subcloud is online
      - Subcloud is managed
      - Subcloud backup operation is not in progress
      - Subcloud has no management-affecting alarms (unless force=true)

    Raises a PrestageCheckFailedException on failure.
    """
    LOG.debug("Validating subcloud prestage '%s'", subcloud.name)

    installed_releases = []
    software_version = None
    software_major_release = None
    if payload.get(consts.PRESTAGE_REQUEST_RELEASE):
        software_version = payload.get(consts.PRESTAGE_REQUEST_RELEASE)
        software_major_release = utils.get_major_release(software_version)
        installed_releases = utils.get_systemcontroller_installed_releases()

    for_sw_deploy = is_prestage_for_sw_deploy(payload)

    # re-run the initial validation
    initial_subcloud_validate(
        subcloud,
        installed_releases,
        software_major_release,
        for_sw_deploy,
    )

    subcloud_type, system_health, oam_floating_ip = _get_prestage_subcloud_info(
        subcloud
    )

    if subcloud_type != consts.SYSTEM_MODE_SIMPLEX:
        raise exceptions.PrestagePreCheckFailedException(
            subcloud=subcloud.name,
            orch_skip=True,
            details="Prestage operation is only accepted for a simplex subcloud.",
        )

    if not payload["force"] and not utils.pre_check_management_affected_alarm(
        system_health
    ):
        raise exceptions.PrestagePreCheckFailedException(
            subcloud=subcloud.name,
            orch_skip=False,
            details=(
                "Subcloud has management affecting alarm(s). Please resolve the alarm "
                "condition(s) or use --force option and try again."
            ),
        )

    return oam_floating_ip


def prestage_start(context, subcloud_id):
    subcloud = db_api.subcloud_update(
        context, subcloud_id, prestage_status=consts.PRESTAGE_STATE_PACKAGES
    )
    return subcloud


def prestage_complete(context, subcloud_id, prestage_versions):
    db_api.subcloud_update(
        context,
        subcloud_id,
        prestage_status=consts.PRESTAGE_STATE_COMPLETE,
        prestage_versions=prestage_versions,
    )


def prestage_fail(context, subcloud_id):
    db_api.subcloud_update(
        context, subcloud_id, prestage_status=consts.PRESTAGE_STATE_FAILED
    )


def is_local(subcloud_version, specified_version):
    return subcloud_version == specified_version


def is_prestage_for_sw_deploy(payload):
    # The default is for_install, so we can simply check if the payload is
    # tagged with for_sw_deploy
    for_sw_deploy = payload.get(consts.PRESTAGE_FOR_SW_DEPLOY, False)
    return for_sw_deploy


def prestage_subcloud(context, payload):
    """Subcloud prestaging

    This is the standalone (not orchestrated) prestage implementation.

    3 phases:
    1. Prestage validation (already done by this point)
        - Subcloud exists, is online, is managed, is AIO-SX
        - Subcloud has no management-affecting alarms (unless force is given)
    2. Packages prestaging
        - run prestage_packages.yml ansible playbook
    3. Images prestaging
        - run prestage_images.yml ansible playbook
    """
    subcloud_name = payload["subcloud_name"]
    for_sw_deploy = is_prestage_for_sw_deploy(payload)
    LOG.info(
        f"Prestaging subcloud: {subcloud_name}, "
        f"force={payload['force']}, for_sw_deploy={for_sw_deploy}"
    )
    try:
        subcloud = db_api.subcloud_get_by_name(context, subcloud_name)
    except exceptions.SubcloudNameNotFound:
        LOG.info(
            "Prestage validation failure: subcloud '%s' does not exist",
            subcloud_name,
        )
        raise exceptions.PrestagePreCheckFailedException(
            subcloud=subcloud_name, details="Subcloud does not exist"
        )

    subcloud = prestage_start(context, subcloud.id)
    try:
        apply_thread = threading.Thread(
            target=_prestage_standalone_thread, args=(context, subcloud, payload)
        )

        apply_thread.start()

        return db_api.subcloud_db_model_to_dict(subcloud)

    except Exception:
        LOG.exception("Subcloud prestaging failed %s" % subcloud_name)
        prestage_fail(context, subcloud.id)


def _prestage_standalone_thread(context, subcloud, payload):
    """Run the prestage operations inside a separate thread"""
    log_file = utils.get_subcloud_ansible_log_file(subcloud.name)
    for_sw_deploy = is_prestage_for_sw_deploy(payload)
    try:
        prestage_packages(context, subcloud, payload)
        # Get the prestage versions from the logs generated by
        # the prestage packages playbook
        prestage_versions = utils.get_msg_output_info(
            log_file, PRINT_PRESTAGE_VERSIONS_TASK, PRESTAGE_VERSIONS_KEY_STR
        )

        # TODO(kmacleod) need to invoke this for retagging images
        if not for_sw_deploy:
            prestage_images(context, subcloud, payload)

        prestage_complete(context, subcloud.id, prestage_versions)
        LOG.info("Prestage complete: %s", subcloud.name)

    except Exception:
        LOG.exception(
            f"Subcloud prestaging failed (in standalone thread) {subcloud.name}"
        )
        prestage_fail(context, subcloud.id)
        raise


def _get_prestage_subcloud_info(subcloud):
    """Retrieve prestage data from the subcloud.

    Pull all required data here in order to minimize keystone/sysinv client
    interactions.
    """
    try:
        os_client = OpenStackDriver(
            region_name=subcloud.region_name,
            region_clients=None,
            fetch_subcloud_ips=utils.fetch_subcloud_mgmt_ips,
        )
        keystone_client = os_client.keystone_client
        endpoint = keystone_client.endpoint_cache.get_endpoint("sysinv")
        sysinv_client = SysinvClient(
            subcloud.region_name, keystone_client.session, endpoint=endpoint
        )
        mode = sysinv_client.get_system().system_mode
        health = sysinv_client.get_system_health()
        oam_floating_ip = sysinv_client.get_oam_addresses().oam_floating_ip
        return mode, health, oam_floating_ip

    except Exception as e:
        LOG.exception(e)
        raise exceptions.PrestagePreCheckFailedException(
            subcloud=subcloud.name,
            details="Failed to retrieve subcloud system mode and system health.",
        )


def _run_ansible(
    context,
    prestage_command,
    phase,
    subcloud,
    prestage_status,
    sysadmin_password,
    oam_floating_ip,
    software_version,
    ansible_subcloud_inventory_file,
    timeout_seconds=None,
):
    if not timeout_seconds:
        # We always want to set a timeout in prestaging operations:
        timeout_seconds = CONF.playbook_timeout

    LOG.info(
        "Prestaging %s for subcloud: %s, version: %s, timeout: %ss",
        phase,
        subcloud.name,
        software_version,
        timeout_seconds,
    )

    db_api.subcloud_update(context, subcloud.id, prestage_status=prestage_status)

    # Create the ansible inventory for the new subcloud
    utils.create_subcloud_inventory_with_admin_creds(
        subcloud.name,
        ansible_subcloud_inventory_file,
        oam_floating_ip,
        ansible_pass=utils.decode_and_normalize_passwd(sysadmin_password),
    )

    log_file = utils.get_subcloud_ansible_log_file(subcloud.name)

    try:
        ansible = AnsiblePlaybook(subcloud.name)
        ansible.run_playbook(
            log_file, prestage_command, timeout=timeout_seconds, register_cleanup=True
        )
    except PlaybookExecutionFailed as ex:
        timeout_msg = ""
        if isinstance(ex, PlaybookExecutionTimeout):
            timeout_msg = " (TIMEOUT)"
        msg = (
            "Prestaging %s failed%s for subcloud %s, "
            "check individual log at %s for detailed output."
            % (phase, timeout_msg, subcloud.name, log_file)
        )
        LOG.exception("%s: %s", msg, ex)
        raise Exception(msg)
    finally:
        utils.delete_subcloud_inventory(ansible_subcloud_inventory_file)

    LOG.info("Prestage %s successful for subcloud %s", phase, subcloud.name)


def prestage_packages(context, subcloud, payload):
    """Run the prestage packages ansible script."""

    # Ansible inventory filename for the specified subcloud
    ansible_subcloud_inventory_file = utils.get_ansible_filename(
        subcloud.name, ANSIBLE_PRESTAGE_INVENTORY_SUFFIX
    )

    prestage_software_version = payload.get(consts.PRESTAGE_REQUEST_RELEASE, SW_VERSION)
    prestage_major_release = utils.get_major_release(prestage_software_version)
    extra_vars_str = f"software_version={prestage_software_version} "
    extra_vars_str += f"software_major_release={prestage_major_release}"

    if is_prestage_for_sw_deploy(payload):
        extra_vars_str += f" prestage_install={consts.PRESTAGE_FOR_SW_DEPLOY}"
    else:
        # default
        extra_vars_str += f" prestage_install={consts.PRESTAGE_FOR_INSTALL}"

    ostree_mount.validate_ostree_iso_mount(prestage_major_release)

    _run_ansible(
        context,
        [
            "ansible-playbook",
            ANSIBLE_PRESTAGE_SUBCLOUD_PACKAGES_PLAYBOOK,
            "--inventory",
            ansible_subcloud_inventory_file,
            "--extra-vars",
            extra_vars_str,
        ],
        "packages",
        subcloud,
        consts.PRESTAGE_STATE_PACKAGES,
        payload["sysadmin_password"],
        payload["oam_floating_ip"],
        prestage_software_version,
        ansible_subcloud_inventory_file,
    )


def prestage_images(context, subcloud, payload):
    """Run the prestage images ansible script.

    If the prestage images file has been uploaded, include the fully
    qualified path name in the extra vars before invoking the prestage_images.yml
    playbook.

    If the prestage images file has not been uploaded, only proceed
    with images prestage if the prestage source is local.

    Ensure the final state is either prestage-failed or prestage-complete
    regardless of whether prestage_images.yml playbook is executed or skipped.

    """
    prestage_software_version = payload.get(consts.PRESTAGE_REQUEST_RELEASE, SW_VERSION)
    prestage_major_release = utils.get_major_release(prestage_software_version)
    extra_vars_str = f"software_version={prestage_software_version} "
    extra_vars_str += f"software_major_release={prestage_major_release}"

    # TODO(kmacleod) we may not need these if images are not prestaged
    # if for_sw_deploy
    if consts.PRESTAGE_FOR_INSTALL in payload:
        extra_vars_str += f" for_install={payload[consts.PRESTAGE_FOR_INSTALL]}"
    elif consts.PRESTAGE_FOR_SW_DEPLOY in payload:
        extra_vars_str += f" for_sw_deploy={payload[consts.PRESTAGE_FOR_SW_DEPLOY]}"

    image_list_filename = None
    deploy_dir = os.path.join(DEPLOY_BASE_DIR, prestage_major_release)
    if os.path.isdir(deploy_dir):
        image_list_filename = utils.get_filename_by_prefix(
            deploy_dir, "prestage_images"
        )
    if image_list_filename:
        image_list_file = os.path.join(deploy_dir, image_list_filename)
        # include this file in the ansible args:
        extra_vars_str += " image_list_file=%s" % image_list_file
        LOG.debug("prestage images list file: %s", image_list_file)
    else:
        LOG.debug("prestage images list file does not exist")
        if prestage_major_release != subcloud.software_version:
            # Prestage source is remote but there is no images list file so
            # skip the images prestage.
            LOG.info(
                "Images prestage is skipped for %s as the prestage images "
                "list for release %s has not been uploaded and the "
                "subcloud is running a different load than %s."
                % (subcloud.name, prestage_major_release, prestage_major_release)
            )
            return

    # Ansible inventory filename for the specified subcloud
    ansible_subcloud_inventory_file = utils.get_ansible_filename(
        subcloud.name, ANSIBLE_PRESTAGE_INVENTORY_SUFFIX
    )
    _run_ansible(
        context,
        [
            "ansible-playbook",
            ANSIBLE_PRESTAGE_SUBCLOUD_IMAGES_PLAYBOOK,
            "--inventory",
            ansible_subcloud_inventory_file,
            "--extra-vars",
            extra_vars_str,
        ],
        "images",
        subcloud,
        consts.PRESTAGE_STATE_IMAGES,
        payload["sysadmin_password"],
        payload["oam_floating_ip"],
        prestage_software_version,
        ansible_subcloud_inventory_file,
        timeout_seconds=CONF.playbook_timeout * 2,
    )
