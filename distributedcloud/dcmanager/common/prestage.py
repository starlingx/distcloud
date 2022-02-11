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

import os
import subprocess
import threading

from oslo_log import log as logging

from tsconfig.tsconfig import SW_VERSION

from dccommon.consts import DEPLOY_DIR
from dccommon.drivers.openstack.sdk_platform import OpenStackDriver
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon.exceptions import PlaybookExecutionFailed
from dccommon.utils import run_playbook

from dcmanager.common import consts
from dcmanager.common.consts import PRESTAGE_FILE_POSTFIX
from dcmanager.common import exceptions
from dcmanager.common import utils
from dcmanager.db import api as db_api

LOG = logging.getLogger(__name__)

PREPARE_PRESTAGE_PACKAGES_SCRIPT = \
    '/usr/local/bin/prepare-prestage-packages.sh'
DEPLOY_BASE_DIR = DEPLOY_DIR + '/' + SW_VERSION
PREPARE_PRESTAGE_PACKAGES_OUTPUT_PATH = DEPLOY_BASE_DIR + '/prestage/shared'
PREPARE_PRESTAGE_PACKAGES_IMAGES_LIST \
    = DEPLOY_BASE_DIR + '/prestage_images_image_list.txt'
ANSIBLE_PRESTAGE_SUBCLOUD_PACKAGES_PLAYBOOK = \
    "/usr/share/ansible/stx-ansible/playbooks/prestage_sw_packages.yml"
ANSIBLE_PRESTAGE_SUBCLOUD_IMAGES_PLAYBOOK = \
    "/usr/share/ansible/stx-ansible/playbooks/prestage_images.yml"


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


def validate_prestage_subcloud(subcloud, payload):
    """Validate a subcloud prestage operation.

    Prestage conditions validation
      - Subcloud exists
      - Subcloud is an AIO-SX
      - Subcloud is online
      - Subcloud is managed
      - Subcloud has no management-affecting alarms (unless force=true)

    Raises a PrestageCheckFailedException on failure.

    Returns the oam_floating_ip for subsequent use by ansible.
    """
    force = payload['force']
    LOG.debug("Validating subcloud prestage '%s', force=%s",
              subcloud.name, force)

    if subcloud.availability_status != consts.AVAILABILITY_ONLINE:
        raise exceptions.PrestagePreCheckFailedException(
            subcloud=subcloud.name, details="Subcloud is offline")

    subcloud_type, system_health, oam_floating_ip = \
        _get_prestage_subcloud_info(subcloud.name)

    # TODO(kmacleod) for orchestration, make sure we check this
    # as part of strategy create
    if is_system_controller_upgrading():
        raise exceptions.PrestagePreCheckFailedException(
            subcloud=subcloud.name,
            details='Prestage operations not allowed while system'
                    ' controller upgrade is in progress.')

    if (subcloud_type != consts.SYSTEM_MODE_SIMPLEX or
            subcloud.management_state != consts.MANAGEMENT_MANAGED):
        raise exceptions.PrestagePreCheckFailedException(
            subcloud=subcloud.name,
            details='Prestage operation is only accepted for a simplex'
                    ' subcloud that is currently online and managed.')

    if (not force
            and not utils.pre_check_management_affected_alarm(system_health)):
        raise exceptions.PrestagePreCheckFailedException(
            subcloud=subcloud.name,
            details='There is management affecting alarm(s) in the'
                    ' subcloud. Please resolve the alarm condition(s)'
                    ' or use --force option and try again.')

    allowed_deploy_states = [consts.DEPLOY_STATE_DONE,
                             consts.PRESTAGE_STATE_FAILED,
                             consts.PRESTAGE_STATE_COMPLETE]
    if subcloud.deploy_status not in allowed_deploy_states:
        raise exceptions.PrestagePreCheckFailedException(
            subcloud=subcloud.name,
            details='Prestage operation is only allowed while'
                    ' subcloud deploy status is one of: %s.'
                    ' The current deploy status is %s.'
            % (', '.join(allowed_deploy_states), subcloud.deploy_status))

    return oam_floating_ip


def prestage_subcloud(context, payload):
    """Subcloud prestaging

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

    # TODO(kmacleod) fail if prestaging orchestration in progress

    subcloud = db_api.subcloud_update(
        context, subcloud.id,
        deploy_status=consts.PRESTAGE_STATE_PREPARE)
    try:
        apply_thread = threading.Thread(
            target=run_prestage_thread, args=(context, subcloud, payload))

        apply_thread.start()

        return db_api.subcloud_db_model_to_dict(subcloud)

    except Exception:
        LOG.exception("Subcloud prestaging failed %s" % subcloud_name)
        db_api.subcloud_update(
            context, subcloud_name,
            deploy_status=consts.PRESTAGE_STATE_FAILED)


def run_prestage_thread(context, subcloud, payload):
    """Run the prestage operations inside a separate thread"""
    try:
        is_upgrade = SW_VERSION != subcloud.software_version

        if is_upgrade:
            # TODO(kmacleod): check for '.prestage_prepation_completed' file instead
            # of Packages directory (not in place yet)
            if not os.path.exists(
                    os.path.join(PREPARE_PRESTAGE_PACKAGES_OUTPUT_PATH,
                                 'Packages')):
                if not _run_prestage_prepare_packages(
                        context, subcloud.id):
                    db_api.subcloud_update(
                        context, subcloud.id,
                        deploy_status=consts.PRESTAGE_STATE_FAILED)
                    return
            else:
                LOG.info(
                    "Skipping prestage package preparation (not required)")
        else:
            LOG.info("Skipping prestage package preparation (reinstall)")

        if _run_prestage_ansible(
                context, subcloud, payload['oam_floating_ip'],
                payload['sysadmin_password'], is_upgrade):
            db_api.subcloud_update(
                context, subcloud.id,
                deploy_status=consts.PRESTAGE_STATE_COMPLETE)
            LOG.info("Prestage complete: %s", subcloud.name)
        else:
            db_api.subcloud_update(
                context, subcloud.id,
                deploy_status=consts.PRESTAGE_STATE_FAILED)

    except Exception:
        LOG.exception("Unexpected exception")
        db_api.subcloud_update(context, subcloud.id,
                               deploy_status=consts.PRESTAGE_STATE_FAILED)


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
            details='Failed to retrieve subcloud system mode and system health.')


@utils.synchronized('prestage-prepare-packages', external=True)
def _run_prestage_prepare_packages(context, subcloud_id):

    LOG.info("Running prestage prepare packages script, version=%s "
             "(subcloud_id=%s)", SW_VERSION, subcloud_id)
    db_api.subcloud_update(context,
                           subcloud_id,
                           deploy_status=consts.PRESTAGE_STATE_PREPARE)

    if not os.path.exists(PREPARE_PRESTAGE_PACKAGES_SCRIPT):
        LOG.error("Prepare prestage packages script does not exist: %s",
                  PREPARE_PRESTAGE_PACKAGES_SCRIPT)
        return False

    LOG.info("Executing script: %s --release-id %s",
             PREPARE_PRESTAGE_PACKAGES_SCRIPT, SW_VERSION)
    try:
        output = subprocess.check_output(
            [PREPARE_PRESTAGE_PACKAGES_SCRIPT, "--release-id", SW_VERSION],
            stderr=subprocess.STDOUT)
        LOG.info("%s output:\n%s", PREPARE_PRESTAGE_PACKAGES_SCRIPT, output)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to prepare prestage packages for  %s", SW_VERSION)
        return False

    LOG.info("Prestage prepare packages successful")
    return True


def _run_prestage_ansible(context, subcloud, oam_floating_ip,
                          sysadmin_password, is_upgrade):

    log_file = os.path.join(consts.DC_ANSIBLE_LOG_DIR, subcloud.name) + \
        '_prestage_playbook_output.log'

    # Ansible inventory filename for the specified subcloud
    ansible_subcloud_inventory_file = \
        utils.get_ansible_filename(subcloud.name, PRESTAGE_FILE_POSTFIX)

    # Create the ansible inventory for the new subcloud
    utils.create_subcloud_inventory_with_admin_creds(
        subcloud.name,
        ansible_subcloud_inventory_file,
        oam_floating_ip,
        ansible_pass=sysadmin_password)

    def _run_ansible(prestage_command, phase, deploy_status):
        LOG.info("Prestaging %s for subcloud: %s, version: %s",
                 phase, subcloud.name, SW_VERSION)
        db_api.subcloud_update(context,
                               subcloud.id,
                               deploy_status=deploy_status)
        try:
            run_playbook(log_file, prestage_command)
        except PlaybookExecutionFailed:
            LOG.error("Failed to run the prestage %s playbook"
                      " for subcloud %s, check individual log at "
                      "%s for detailed output.",
                      phase, subcloud.name, log_file)
            return False

        LOG.info("Prestage %s successful for subcloud %s",
                 phase, subcloud.name)
        return True

    # Always run prestage_packages.yml playbook.
    #
    # Pass the image_list_file to the prestage_images.yml playbook if the
    # prestage images file has been uploaded for the target software
    # version. If this file does not exist and the prestage is for upgrade,
    # skip calling prestage_images.yml playbook.
    #
    # Ensure the final state is either prestage-failed or prestage-complete
    # regardless whether prestage_images.yml playbook is skipped or not.
    #
    try:
        extra_vars_str = "software_version=%s" % SW_VERSION
        if not _run_ansible(["ansible-playbook",
                             ANSIBLE_PRESTAGE_SUBCLOUD_PACKAGES_PLAYBOOK,
                             "--inventory", ansible_subcloud_inventory_file,
                             "--extra-vars", extra_vars_str],
                            "packages",
                            consts.PRESTAGE_STATE_PACKAGES):
            return False

        image_list_exists = \
            os.path.exists(PREPARE_PRESTAGE_PACKAGES_IMAGES_LIST)
        LOG.debug("prestage images list: %s, exists: %s",
                  PREPARE_PRESTAGE_PACKAGES_IMAGES_LIST, image_list_exists)
        if is_upgrade and image_list_exists:
            extra_vars_str += (" image_list_file=%s" %
                               PREPARE_PRESTAGE_PACKAGES_IMAGES_LIST)

        if not is_upgrade or (is_upgrade and image_list_exists):
            if not _run_ansible(["ansible-playbook",
                                 ANSIBLE_PRESTAGE_SUBCLOUD_IMAGES_PLAYBOOK,
                                 "--inventory",
                                 ansible_subcloud_inventory_file,
                                 "--extra-vars", extra_vars_str],
                                "images",
                                consts.PRESTAGE_STATE_IMAGES):
                return False
        else:
            LOG.info("Skipping ansible prestage images step, upgrade: %s,"
                     " image_list_exists: %s",
                     is_upgrade, image_list_exists)
        return True

    finally:
        utils.delete_subcloud_inventory(ansible_subcloud_inventory_file)
