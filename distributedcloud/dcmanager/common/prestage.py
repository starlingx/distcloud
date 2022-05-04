# Copyright (c) 2022 Wind River Systems, Inc.
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

from dccommon.consts import DEPLOY_DIR
from dccommon.drivers.openstack.sdk_platform import OpenStackDriver
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon.exceptions import PlaybookExecutionFailed
from dccommon.exceptions import PlaybookExecutionTimeout
from dccommon.utils import run_playbook_with_timeout

from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.common import utils
from dcmanager.db import api as db_api

LOG = logging.getLogger(__name__)
CONF = cfg.CONF

DEPLOY_BASE_DIR = DEPLOY_DIR + '/' + SW_VERSION
PREPARE_PRESTAGE_PACKAGES_OUTPUT_PATH = DEPLOY_BASE_DIR + '/prestage/shared'
PRESTAGE_PREPARATION_COMPLETED_FILE = os.path.join(
    PREPARE_PRESTAGE_PACKAGES_OUTPUT_PATH, '.prestage_preparation_completed')
PRESTAGE_PREPARATION_FAILED_FILE = os.path.join(
    DEPLOY_BASE_DIR, '.prestage_preparation_failed')
ANSIBLE_PREPARE_PRESTAGE_PACKAGES_PLAYBOOK = \
    "/usr/share/ansible/stx-ansible/playbooks/prepare_prestage_packages.yml"
ANSIBLE_PRESTAGE_SUBCLOUD_PACKAGES_PLAYBOOK = \
    "/usr/share/ansible/stx-ansible/playbooks/prestage_sw_packages.yml"
ANSIBLE_PRESTAGE_SUBCLOUD_IMAGES_PLAYBOOK = \
    "/usr/share/ansible/stx-ansible/playbooks/prestage_images.yml"
ANSIBLE_PRESTAGE_INVENTORY_SUFFIX = '_prestage_inventory.yml'


def is_deploy_status_prestage(deploy_status):
    return deploy_status in (consts.PRESTAGE_STATE_PREPARE,
                             consts.PRESTAGE_STATE_PACKAGES,
                             consts.PRESTAGE_STATE_IMAGES,
                             consts.PRESTAGE_STATE_FAILED,
                             consts.PRESTAGE_STATE_COMPLETE)


def _get_system_controller_upgrades():
    # get a cached keystone client (and token)
    try:
        os_client = OpenStackDriver(
            region_name=consts.SYSTEM_CONTROLLER_NAME,
            region_clients=None)
    except Exception:
        LOG.exception("Failed to get keystone client for %s",
                      consts.SYSTEM_CONTROLLER_NAME)
        raise

    ks_client = os_client.keystone_client
    sysinv_client = SysinvClient(
        consts.SYSTEM_CONTROLLER_NAME, ks_client.session,
        endpoint=ks_client.endpoint_cache.get_endpoint('sysinv'))

    return sysinv_client.get_upgrades()


def is_system_controller_upgrading():
    return len(_get_system_controller_upgrades()) != 0


def global_prestage_validate(payload):
    """Global prestage validation (not subcloud-specific)"""

    if is_system_controller_upgrading():
        raise exceptions.PrestagePreCheckFailedException(
            subcloud=consts.SYSTEM_CONTROLLER_NAME,
            details='Prestage operations not allowed while system'
                    ' controller upgrade is in progress.')

    if ('sysadmin_password' not in payload
            or payload['sysadmin_password'] is None
            or payload['sysadmin_password'] == ''):
        raise exceptions.PrestagePreCheckFailedException(
            subcloud=None,
            orch_skip=False,
            details="Missing required parameter 'sysadmin_password'")

    # Ensure we can decode the sysadmin_password
    # (we decode again when running ansible)
    try:
        base64.b64decode(payload['sysadmin_password']).decode('utf-8')
    except Exception as ex:
        raise exceptions.PrestagePreCheckFailedException(
            subcloud=None,
            orch_skip=False,
            details="Failed to decode subcloud sysadmin_password,"
                    " verify the password is base64 encoded."
                    " Details: %s" % ex)


def initial_subcloud_validate(subcloud):
    """Basic validation a subcloud prestage operation.

    Raises a PrestageCheckFailedException on failure.
    """
    LOG.debug("Validating subcloud prestage '%s'", subcloud.name)

    if subcloud.availability_status != consts.AVAILABILITY_ONLINE:
        raise exceptions.PrestagePreCheckFailedException(
            subcloud=subcloud.name,
            orch_skip=True,
            details="Subcloud is offline.")

    if subcloud.management_state != consts.MANAGEMENT_MANAGED:
        raise exceptions.PrestagePreCheckFailedException(
            subcloud=subcloud.name,
            orch_skip=True,
            details="Subcloud is not managed.")

    allowed_deploy_states = [consts.DEPLOY_STATE_DONE,
                             consts.PRESTAGE_STATE_FAILED,
                             consts.PRESTAGE_STATE_COMPLETE]
    if subcloud.deploy_status not in allowed_deploy_states:
        raise exceptions.PrestagePreCheckFailedException(
            subcloud=subcloud.name,
            orch_skip=True,
            details="Prestage operation is only allowed while"
                    " subcloud deploy status is one of: %s."
                    " The current deploy status is %s."
            % (', '.join(allowed_deploy_states), subcloud.deploy_status))


def validate_prestage(subcloud, payload):
    """Validate a subcloud prestage operation.

    Prestage conditions validation
      - Subcloud exists
      - Subcloud is an AIO-SX
      - Subcloud is online
      - Subcloud is managed
      - Subcloud has no management-affecting alarms (unless force=true)

    Raises a PrestageCheckFailedException on failure.
    """
    LOG.debug("Validating subcloud prestage '%s'", subcloud.name)

    # re-run the initial validation
    initial_subcloud_validate(subcloud)

    subcloud_type, system_health, oam_floating_ip = \
        _get_prestage_subcloud_info(subcloud.name)

    if subcloud_type != consts.SYSTEM_MODE_SIMPLEX:
        raise exceptions.PrestagePreCheckFailedException(
            subcloud=subcloud.name,
            orch_skip=True,
            details="Prestage operation is only accepted for a simplex"
                    " subcloud.")

    if (not payload['force']
            and not utils.pre_check_management_affected_alarm(system_health)):
        raise exceptions.PrestagePreCheckFailedException(
            subcloud=subcloud.name,
            orch_skip=False,
            details="Subcloud has management affecting alarm(s)."
                    " Please resolve the alarm condition(s)"
                    " or use --force option and try again.")

    return oam_floating_ip


@utils.synchronized('prestage-prepare-cleanup', external=True)
def cleanup_failed_preparation():
    """Remove the preparation failed file if it exists from a previous run"""
    if os.path.exists(PRESTAGE_PREPARATION_FAILED_FILE):
        LOG.debug("Cleanup: removing %s", PRESTAGE_PREPARATION_FAILED_FILE)
        os.remove(PRESTAGE_PREPARATION_FAILED_FILE)


def prestage_start(context, subcloud_id):
    subcloud = db_api.subcloud_update(
        context, subcloud_id,
        deploy_status=consts.PRESTAGE_STATE_PREPARE)
    return subcloud


def prestage_complete(context, subcloud_id):
    db_api.subcloud_update(
        context, subcloud_id,
        deploy_status=consts.PRESTAGE_STATE_COMPLETE)


def prestage_fail(context, subcloud_id):
    db_api.subcloud_update(
        context, subcloud_id,
        deploy_status=consts.PRESTAGE_STATE_FAILED)


def is_upgrade(subcloud_version):
    return SW_VERSION != subcloud_version


def prestage_subcloud(context, payload):
    """Subcloud prestaging

    This is the standalone (not orchestrated) prestage implementation.

    4 phases:
    1. Prestage validation (already done by this point)
        - Subcloud exists, is online, is managed, is AIO-SX
        - Subcloud has no management-affecting alarms (unless force is given)
    2. Packages preparation
        - prestage-prepare-packages.sh
    3. Packages prestaging
        - run prestage_packages.yml ansible playbook
    4. Images prestaging
        - run prestage_images.yml ansible playbook
    """
    subcloud_name = payload['subcloud_name']
    LOG.info("Prestaging subcloud: %s, force=%s" % (subcloud_name,
                                                    payload['force']))
    try:
        subcloud = db_api.subcloud_get_by_name(context, subcloud_name)
    except exceptions.SubcloudNameNotFound:
        LOG.info("Prestage validation failure: "
                 "subcloud '%s' does not exist", subcloud_name)
        raise exceptions.PrestagePreCheckFailedException(
            subcloud=subcloud_name,
            details="Subcloud does not exist")

    cleanup_failed_preparation()
    subcloud = prestage_start(context, subcloud.id)
    try:
        apply_thread = threading.Thread(
            target=_prestage_standalone_thread,
            args=(context, subcloud, payload))

        apply_thread.start()

        return db_api.subcloud_db_model_to_dict(subcloud)

    except Exception:
        LOG.exception("Subcloud prestaging failed %s" % subcloud_name)
        prestage_fail(context, subcloud.id)


def _sync_run_prestage_prepare_packages(context, subcloud, payload):
    """Run prepare prestage packages ansible script."""

    if os.path.exists(PRESTAGE_PREPARATION_FAILED_FILE):
        LOG.warn("Subcloud %s prestage preparation aborted due to "
                 "previous %s failure", subcloud.name,
                 consts.PRESTAGE_STATE_PREPARE)
        raise Exception("Aborted due to previous %s failure"
                        % consts.PRESTAGE_STATE_PREPARE)

    LOG.info("Running prepare prestage ansible script, version=%s "
             "(subcloud_id=%s)", SW_VERSION, subcloud.id)
    db_api.subcloud_update(context,
                           subcloud.id,
                           deploy_status=consts.PRESTAGE_STATE_PREPARE)

    # Ansible inventory filename for the specified subcloud
    ansible_subcloud_inventory_file = \
        utils.get_ansible_filename(subcloud.name,
                                   ANSIBLE_PRESTAGE_INVENTORY_SUFFIX)

    extra_vars_str = "current_software_version=%s previous_software_version=%s" \
        % (SW_VERSION, subcloud.software_version)

    try:
        _run_ansible(context,
                     ["ansible-playbook",
                      ANSIBLE_PREPARE_PRESTAGE_PACKAGES_PLAYBOOK,
                      "--inventory", ansible_subcloud_inventory_file,
                      "--extra-vars", extra_vars_str],
                     "prepare",
                     subcloud,
                     consts.PRESTAGE_STATE_PREPARE,
                     payload['sysadmin_password'],
                     payload['oam_floating_ip'],
                     ansible_subcloud_inventory_file,
                     consts.PRESTAGE_PREPARE_TIMEOUT)
    except Exception:
        # Flag the failure on file system so that other orchestrated
        # strategy steps in this run fail immediately. This file is
        # removed at the start of each orchestrated/standalone run.
        # This creates the file if it doesn't exist:
        with open(PRESTAGE_PREPARATION_FAILED_FILE, 'a'):
            pass
        raise

    LOG.info("Prepare prestage ansible successful")


@utils.synchronized('prestage-prepare-packages', external=True)
def prestage_prepare(context, subcloud, payload):
    """Run the prepare prestage packages playbook if required."""
    if is_upgrade(subcloud.software_version):
        if not os.path.exists(PRESTAGE_PREPARATION_COMPLETED_FILE):
            _sync_run_prestage_prepare_packages(context, subcloud, payload)
        else:
            LOG.info(
                "Skipping prestage package preparation (not required)")
    else:
        LOG.info("Skipping prestage package preparation (reinstall)")


def _prestage_standalone_thread(context, subcloud, payload):
    """Run the prestage operations inside a separate thread"""
    try:
        prestage_prepare(context, subcloud, payload)
        prestage_packages(context, subcloud, payload)
        prestage_images(context, subcloud, payload)

        prestage_complete(context, subcloud.id)
        LOG.info("Prestage complete: %s", subcloud.name)

    except Exception:
        prestage_fail(context, subcloud.id)
        raise


def _get_prestage_subcloud_info(subcloud_name):
    """Retrieve prestage data from the subcloud.

    Pull all required data here in order to minimize keystone/sysinv client
    interactions.
    """
    try:
        os_client = OpenStackDriver(region_name=subcloud_name,
                                    region_clients=None)
        keystone_client = os_client.keystone_client
        endpoint = keystone_client.endpoint_cache.get_endpoint('sysinv')
        sysinv_client = SysinvClient(subcloud_name,
                                     keystone_client.session,
                                     endpoint=endpoint)
        mode = sysinv_client.get_system().system_mode
        health = sysinv_client.get_system_health()
        oam_floating_ip = sysinv_client.get_oam_addresses().oam_floating_ip
        return mode, health, oam_floating_ip

    except Exception as e:
        LOG.exception(e)
        raise exceptions.PrestagePreCheckFailedException(
            subcloud=subcloud_name,
            details="Failed to retrieve subcloud system mode and system health.")


def _run_ansible(context, prestage_command, phase,
                 subcloud, deploy_status,
                 sysadmin_password, oam_floating_ip,
                 ansible_subcloud_inventory_file,
                 timeout_seconds=None):
    if not timeout_seconds:
        # We always want to set a timeout in prestaging operations. Use default:
        timeout_seconds = CONF.playbook_timeout

    if deploy_status == consts.PRESTAGE_STATE_PREPARE:
        LOG.info(("Preparing prestage shared packages for subcloud: %s, "
                  "version: %s, timeout: %ss"),
                 subcloud.name, SW_VERSION, timeout_seconds)
    else:
        LOG.info("Prestaging %s for subcloud: %s, version: %s, timeout: %ss",
                 phase, subcloud.name, SW_VERSION, timeout_seconds)

    db_api.subcloud_update(context,
                           subcloud.id,
                           deploy_status=deploy_status)
    log_file = os.path.join(consts.DC_ANSIBLE_LOG_DIR, subcloud.name) + \
        '_playbook_output.log'

    # Create the ansible inventory for the new subcloud
    utils.create_subcloud_inventory_with_admin_creds(
        subcloud.name,
        ansible_subcloud_inventory_file,
        oam_floating_ip,
        ansible_pass=base64.b64decode(sysadmin_password).decode('utf-8'))
    try:
        run_playbook_with_timeout(log_file,
                                  prestage_command,
                                  timeout=timeout_seconds)
    except PlaybookExecutionFailed as ex:
        timeout_msg = ''
        if isinstance(ex, PlaybookExecutionTimeout):
            timeout_msg = ' (TIMEOUT)'
        msg = ("Prestaging %s failed%s for subcloud %s,"
               " check individual log at %s for detailed output."
               % (phase, timeout_msg, subcloud.name, log_file))
        LOG.exception("%s: %s", msg, ex)
        raise Exception(msg)
    finally:
        utils.delete_subcloud_inventory(ansible_subcloud_inventory_file)

    LOG.info("Prestage %s successful for subcloud %s",
             phase, subcloud.name)


def prestage_packages(context, subcloud, payload):
    """Run the prestage packages ansible script."""

    # Ansible inventory filename for the specified subcloud
    ansible_subcloud_inventory_file = \
        utils.get_ansible_filename(subcloud.name,
                                   ANSIBLE_PRESTAGE_INVENTORY_SUFFIX)

    extra_vars_str = "software_version=%s" % SW_VERSION
    _run_ansible(context,
                 ["ansible-playbook",
                  ANSIBLE_PRESTAGE_SUBCLOUD_PACKAGES_PLAYBOOK,
                  "--inventory", ansible_subcloud_inventory_file,
                  "--extra-vars", extra_vars_str],
                 "packages",
                 subcloud,
                 consts.PRESTAGE_STATE_PACKAGES,
                 payload['sysadmin_password'],
                 payload['oam_floating_ip'],
                 ansible_subcloud_inventory_file)


def prestage_images(context, subcloud, payload):
    """Run the prestage images ansible script.

    Approach:

    If the prestage images file has been uploaded for the target software
    version then pass the image_list_file to the prestage_images.yml playbook
    If the images file does not exist and the prestage is for upgrade,
    skip calling prestage_images.yml playbook.

    Ensure the final state is either prestage-failed or prestage-complete
    regardless of whether prestage_images.yml playbook is executed or skipped.
    """
    upgrade = is_upgrade(subcloud.software_version)
    extra_vars_str = "software_version=%s" % SW_VERSION

    image_list_file = None
    if upgrade:
        image_list_filename = utils.get_filename_by_prefix(DEPLOY_BASE_DIR,
                                                           'prestage_images')
        if image_list_filename:
            image_list_file = os.path.join(DEPLOY_BASE_DIR, image_list_filename)
            # include this file in the ansible args:
            extra_vars_str += (" image_list_file=%s" % image_list_file)
            LOG.debug("prestage images list file: %s", image_list_file)
        else:
            LOG.debug("prestage images list file does not exist")

    # There are only two scenarios where we want to run ansible
    # for prestaging images:
    # 1. reinstall
    # 2. upgrade, with supplied image list
    if not upgrade or (upgrade and image_list_file):
        # Ansible inventory filename for the specified subcloud
        ansible_subcloud_inventory_file = \
            utils.get_ansible_filename(subcloud.name,
                                       ANSIBLE_PRESTAGE_INVENTORY_SUFFIX)
        _run_ansible(context,
                     ["ansible-playbook",
                      ANSIBLE_PRESTAGE_SUBCLOUD_IMAGES_PLAYBOOK,
                      "--inventory", ansible_subcloud_inventory_file,
                      "--extra-vars", extra_vars_str],
                     "images",
                     subcloud,
                     consts.PRESTAGE_STATE_IMAGES,
                     payload['sysadmin_password'],
                     payload['oam_floating_ip'],
                     ansible_subcloud_inventory_file)
    else:
        LOG.info("Skipping ansible prestage images step, upgrade: %s,"
                 " image_list_file: %s", upgrade, image_list_file)
