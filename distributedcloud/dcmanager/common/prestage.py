# Copyright (c) 2022-2025 Wind River Systems, Inc.
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
import json
import os
import threading

from oslo_config import cfg
from oslo_log import log as logging

from tsconfig.tsconfig import SW_VERSION

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon.endpoint_cache import EndpointCache
from dccommon.exceptions import PlaybookExecutionFailed
from dccommon import ostree_mount
from dccommon import utils as cutils

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
PRINT_PRESTAGE_VERSIONS_TASK = (
    r"prestage\/get-prestage-versions : Print prestage versions"
)
PRESTAGE_VERSIONS_KEY_STR = "prestage_versions:"


def initial_subcloud_validate(subcloud):
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

    # The sw-deploy-apply-strategy-failed state could be due to a missing
    # prestage operation
    if subcloud.deploy_status not in [
        consts.DEPLOY_STATE_DONE,
        consts.DEPLOY_STATE_SW_DEPLOY_APPLY_STRATEGY_FAILED,
    ]:
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


def validate_prestage_subcloud(subcloud, payload, system_controller_sw_list=None):
    """Validate a subcloud prestage operation.

    Prestage conditions validation
      - Subcloud exists
      - Subcloud is online
      - Subcloud is managed
      - Subcloud backup operation is not in progress
      - Subcloud has no management-affecting alarms (unless force=true)

    Raises a PrestageCheckFailedException on failure.
    """
    LOG.debug("Validating subcloud prestage '%s'", subcloud.name)

    # Do software version validation. If the version is not validated correctly,
    # it implies that there is an error. Therefore the prestage cannot be continued.
    software_version, message = utils.get_validated_sw_version_for_prestage(
        payload, subcloud, system_controller_sw_list
    )
    if not software_version:
        raise exceptions.PrestagePreCheckFailedException(
            subcloud=subcloud.name,
            orch_skip=False,
            details=message,
        )
    # Configure the release parameter to the appropriate software version
    payload.update({consts.PRESTAGE_REQUEST_RELEASE: software_version})

    # re-run the initial validation
    initial_subcloud_validate(subcloud)

    subcloud_type, system_health, oam_floating_ip, controller_0_is_active = (
        _get_prestage_subcloud_info(subcloud)
    )
    prestage_reason = utils.get_prestage_reason(payload)

    if (
        subcloud_type == consts.SYSTEM_MODE_DUPLEX
        and prestage_reason == consts.PRESTAGE_FOR_INSTALL
        and not controller_0_is_active
    ):
        raise exceptions.PrestagePreCheckFailedException(
            subcloud=subcloud.name,
            orch_skip=True,
            details=(
                "Prestage for install on duplex subclouds "
                "is only allowed when controller-0 is active."
            ),
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
    return db_api.subcloud_update(
        context, subcloud_id, prestage_status=consts.PRESTAGE_STATE_PRESTAGING
    )


def prestage_complete(context, subcloud_id, prestage_versions):
    db_api.subcloud_update(
        context,
        subcloud_id,
        prestage_status=consts.PRESTAGE_STATE_COMPLETE,
        prestage_versions=prestage_versions,
        error_description=consts.ERROR_DESC_EMPTY,
    )


def prestage_fail(context, subcloud_id):
    db_api.subcloud_update(
        context, subcloud_id, prestage_status=consts.PRESTAGE_STATE_FAILED
    )


def is_local(subcloud_version, specified_version):
    return subcloud_version == specified_version


def prestage_subcloud(context, payload):
    """Subcloud prestaging

    This is the standalone (not orchestrated) prestage implementation.

    3 phases:
    1. Prestage validation (already done by this point)
        - Subcloud exists, is online, is managed
        - Subcloud has no management-affecting alarms (unless force is given)
    2. Packages prestaging
        - run prestage_packages.yml ansible playbook
    3. Images prestaging
        - run prestage_images.yml ansible playbook
    """
    subcloud_name = payload["subcloud_name"]
    prestage_reason = utils.get_prestage_reason(payload)
    LOG.info(
        f"Prestaging subcloud: {subcloud_name}, "
        f"force={payload['force']}, prestage_reason={prestage_reason}"
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

    prestage_reason = utils.get_prestage_reason(payload)

    try:
        prestage_packages(context, subcloud, payload, prestage_reason)
        # Get the prestage versions from the logs generated by
        # the prestage packages playbook
        prestage_versions = get_prestage_versions(subcloud.name)
        prestage_images(context, subcloud, payload, prestage_reason)
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
        keystone_endpoint = cutils.build_subcloud_endpoint(
            subcloud.management_start_ip, dccommon_consts.ENDPOINT_NAME_KEYSTONE
        )
        admin_session = EndpointCache.get_admin_session(keystone_endpoint)
        sysinv_client = SysinvClient(
            region=subcloud.region_name,
            session=admin_session,
            endpoint=cutils.build_subcloud_endpoint(
                subcloud.management_start_ip, dccommon_consts.ENDPOINT_NAME_SYSINV
            ),
        )
        mode = sysinv_client.get_system().system_mode
        health = sysinv_client.get_system_health()
        # Interested only in primary OAM address of subcloud
        oam_floating_ip = utils.get_oam_floating_ip_primary(subcloud, admin_session)
        controller_active_info = sysinv_client.get_host("controller-0")
        controller_0_is_active = (
            controller_active_info.capabilities["Personality"]
            == consts.PERSONALITY_CONTROLLER_ACTIVE
        )

        return mode, health, oam_floating_ip, controller_0_is_active

    except Exception as e:
        LOG.exception(e)
        raise exceptions.PrestagePreCheckFailedException(
            subcloud=subcloud.name,
            details="Failed to retrieve subcloud system mode and system health.",
        )


def get_subcloud_oam_ip(subcloud):
    """Retrieve the subcloud's oam ip"""

    try:
        keystone_endpoint = cutils.build_subcloud_endpoint(
            subcloud.management_start_ip, dccommon_consts.ENDPOINT_NAME_KEYSTONE
        )
        admin_session = EndpointCache.get_admin_session(keystone_endpoint)
        # Interested only in primary OAM address of subcloud
        return utils.get_oam_floating_ip_primary(subcloud, admin_session)
    except Exception as e:
        LOG.exception(e)
        raise exceptions.PrestagePreCheckFailedException(
            subcloud=subcloud.name,
            details="Failed to retrieve the subcloud's oam ip.",
        )


def get_prestage_versions(subcloud_name):
    log_file = utils.get_subcloud_ansible_log_file(subcloud_name)
    # Get the prestage versions from the ansible playbook logs
    # generated by the previous step - prestage packages.
    return utils.get_msg_output_info(
        log_file,
        PRINT_PRESTAGE_VERSIONS_TASK,
        PRESTAGE_VERSIONS_KEY_STR,
    )


def _run_ansible(
    context,
    prestage_command,
    phase,
    subcloud,
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
        f"Prestaging {phase} for subcloud: {subcloud.name}, "
        f"version: {software_version}, floating_ip: {oam_floating_ip}, "
        f"timeout: {timeout_seconds}",
    )

    # Create the ansible inventory for the new subcloud
    utils.create_subcloud_inventory_with_admin_creds(
        subcloud.name,
        ansible_subcloud_inventory_file,
        oam_floating_ip,
        ansible_pass=json.dumps(
            base64.b64decode(sysadmin_password, validate=True).decode("utf-8")
        ),
    )

    log_file = utils.get_subcloud_ansible_log_file(subcloud.name)

    try:
        ansible = cutils.AnsiblePlaybook(subcloud.name)
        ansible.run_playbook(
            log_file, prestage_command, timeout=timeout_seconds, register_cleanup=True
        )
    except PlaybookExecutionFailed as ex:
        msg = (
            "Prestaging %s failed for subcloud %s, "
            "check individual log at %s for detailed output."
            % (phase, subcloud.name, log_file)
        )
        LOG.error("%s: %s", msg, ex)
        utils.find_and_save_ansible_error_msg(
            context,
            subcloud,
            log_file,
            exception=ex,
            stage=consts.PRESTAGE_STATE_PRESTAGING,
            prestage_status=consts.PRESTAGE_STATE_FAILED,
        )
        raise Exception(msg)
    finally:
        utils.delete_subcloud_inventory(ansible_subcloud_inventory_file)

    LOG.info("Prestage %s successful for subcloud %s", phase, subcloud.name)


def prestage_packages(context, subcloud, payload, reason):
    """Run the prestage packages ansible script."""

    # Ansible inventory filename for the specified subcloud
    ansible_subcloud_inventory_file = utils.get_ansible_filename(
        subcloud.name, ANSIBLE_PRESTAGE_INVENTORY_SUFFIX
    )

    software_version = payload.get(consts.PRESTAGE_REQUEST_RELEASE, SW_VERSION)
    software_list = payload.get(consts.PRESTAGE_SYSTEM_CONTROLLER_SW_LIST)
    extra_vars_str = f"software_version={software_version} "
    extra_vars_str += f"prestage_reason={reason}"

    # This only applies if the list was populated in prestage pre-check.
    if software_list:
        extra_vars_str += (
            f" {consts.PRESTAGE_SYSTEM_CONTROLLER_SW_LIST}='{software_list}'"
        )

    ostree_mount.validate_ostree_iso_mount(software_version)

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
        payload["sysadmin_password"],
        payload["oam_floating_ip"],
        software_version,
        ansible_subcloud_inventory_file,
    )


def prestage_images(context, subcloud, payload, reason):
    """Run the prestage images ansible script.

    If the prestage images file has been uploaded, include the fully
    qualified path name in the extra vars before invoking the prestage_images.yml
    playbook.

    If the prestage images file has not been uploaded, only proceed
    with images prestage if the prestage source is local.

    Ensure the final state is either prestage-failed or prestage-complete
    regardless of whether prestage_images.yml playbook is executed or skipped.

    """
    software_version = payload.get(consts.PRESTAGE_REQUEST_RELEASE, SW_VERSION)
    extra_vars_str = f"software_version={software_version} "
    extra_vars_str += f"prestage_reason={reason}"

    image_list_filename = None
    deploy_dir = os.path.join(DEPLOY_BASE_DIR, software_version)
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
        if reason == consts.PRESTAGE_FOR_SW_DEPLOY:
            LOG.info(
                f"Images prestage is skipped for {subcloud.name} as "
                f"the prestage images list for release {software_version} "
                f"has not been uploaded for {reason}."
            )
            return
        elif software_version != subcloud.software_version:
            # Prestage source is remote but there is no images list file for
            # for-install scenario so skip the images prestage.
            LOG.info(
                f"Images prestage is skipped for {subcloud.name}. The prestage "
                f"images list for release {software_version} has not "
                f"been uploaded for {reason} and the subcloud is "
                f"running a different load than {software_version}."
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
        payload["sysadmin_password"],
        payload["oam_floating_ip"],
        software_version,
        ansible_subcloud_inventory_file,
        timeout_seconds=CONF.playbook_timeout * 2,
    )
