# Copyright 2017 Ericsson AB.
# Copyright (c) 2017-2025 Wind River Systems, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

from __future__ import division

import base64
import collections
from contextlib import nullcontext
import copy
import datetime
import filecmp
import functools
import json
import os
from pathlib import Path
import random
import shutil
import tempfile
import threading
import time
from typing import Optional

from eventlet.green import subprocess
from eventlet import greenpool
from fm_api import constants as fm_const
from fm_api import fm_api
import keyring
import netaddr
from oslo_config import cfg
from oslo_log import log as logging
from oslo_messaging import RemoteError
from oslo_messaging import rpc as oslo_message_rpc
from oslo_utils import timeutils
from tsconfig.tsconfig import CONFIG_PATH
from tsconfig.tsconfig import SW_VERSION
import yaml

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.keystone_v3 import KeystoneClient
from dccommon.drivers.openstack.sdk_platform import OpenStackDriver
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon import endpoint_cache
from dccommon.exceptions import PlaybookExecutionFailed
from dccommon.exceptions import SubcloudNotFound
from dccommon import kubeoperator
from dccommon.subcloud_enrollment import SubcloudEnrollmentInit
from dccommon.subcloud_install import SubcloudInstall
from dccommon import utils as dccommon_utils
from dcmanager.audit import rpcapi as dcmanager_audit_rpc_client
from dcmanager.common import consts
from dcmanager.common.consts import INVENTORY_FILE_POSTFIX
from dcmanager.common import context as dcmanager_context
from dcmanager.common import exceptions
from dcmanager.common.exceptions import DCManagerException
from dcmanager.common.i18n import _
from dcmanager.common import manager
from dcmanager.common import phased_subcloud_deploy as psd_common
from dcmanager.common import prestage
from dcmanager.common import utils
from dcmanager.db import api as db_api
from dcmanager.db.sqlalchemy.models import Subcloud
from dcmanager.manager.peer_group_audit_manager import PeerGroupAuditManager
from dcmanager.manager.system_peer_manager import SystemPeerManager
from dcmanager.rpc import client as dcmanager_rpc_client
from dcorch.rpc import client as dcorch_rpc_client

LOG = logging.getLogger(__name__)
CONF = cfg.CONF

# Name of our distributed cloud addn_hosts file for dnsmasq
# to read.  This file is referenced in dnsmasq.conf
ADDN_HOSTS_DC = "dnsmasq.addn_hosts_dc"

# Subcloud configuration paths
ANSIBLE_SUBCLOUD_BACKUP_CREATE_PLAYBOOK = (
    "/usr/share/ansible/stx-ansible/playbooks/create_subcloud_backup.yml"
)
ANSIBLE_SUBCLOUD_BACKUP_DELETE_PLAYBOOK = (
    "/usr/share/ansible/stx-ansible/playbooks/delete_subcloud_backup.yml"
)
ANSIBLE_SUBCLOUD_BACKUP_RESTORE_PLAYBOOK = (
    "/usr/share/ansible/stx-ansible/playbooks/restore_subcloud_backup.yml"
)
ANSIBLE_SUBCLOUD_PLAYBOOK = "/usr/share/ansible/stx-ansible/playbooks/bootstrap.yml"
ANSIBLE_SUBCLOUD_REHOME_PLAYBOOK = (
    "/usr/share/ansible/stx-ansible/playbooks/rehome_subcloud.yml"
)
ANSIBLE_SUBCLOUD_UPDATE_PLAYBOOK = (
    "/usr/share/ansible/stx-ansible/playbooks/update_subcloud.yml"
)

# TODO(yuxing) Remove the ANSIBLE_VALIDATE_KEYSTONE_PASSWORD_SCRIPT when end
# the support of rehoming a subcloud with a software version below 22.12
ANSIBLE_VALIDATE_KEYSTONE_PASSWORD_SCRIPT = (
    consts.ANSIBLE_CURRENT_VERSION_BASE_PATH
    + "/roles/rehome-subcloud/update-keystone-data/files/"
    + "validate_keystone_passwords.sh"
)

USERS_TO_REPLICATE = [
    "sysinv",
    "usm",
    "vim",
    "mtce",
    "fm",
    "barbican",
    "dcmanager",
]

# The timeout of the rehome playbook is set to 180 seconds as it takes a
# long time for privilege escalation before resetting the host route and
# LDAP server address in a subcloud.
REHOME_PLAYBOOK_TIMEOUT = "180"  # 180 seconds
UPDATE_PLAYBOOK_TIMEOUT = "180"
SC_INTERMEDIATE_CERT_DURATION = "8760h"  # 1 year = 24 hours x 365
SC_INTERMEDIATE_CERT_RENEW_BEFORE = "720h"  # 30 days
CERT_NAMESPACE = "dc-cert"

TRANSITORY_STATES = {
    consts.DEPLOY_STATE_NONE: consts.DEPLOY_STATE_CREATE_FAILED,
    consts.DEPLOY_STATE_CREATING: consts.DEPLOY_STATE_CREATE_FAILED,
    consts.DEPLOY_STATE_PRE_INSTALL: consts.DEPLOY_STATE_PRE_INSTALL_FAILED,
    consts.DEPLOY_STATE_INSTALLING: consts.DEPLOY_STATE_INSTALL_FAILED,
    consts.DEPLOY_STATE_PRE_BOOTSTRAP: consts.DEPLOY_STATE_PRE_BOOTSTRAP_FAILED,
    consts.DEPLOY_STATE_BOOTSTRAPPING: consts.DEPLOY_STATE_BOOTSTRAP_FAILED,
    consts.DEPLOY_STATE_PRE_CONFIG: consts.DEPLOY_STATE_PRE_CONFIG_FAILED,
    consts.DEPLOY_STATE_CONFIGURING: consts.DEPLOY_STATE_CONFIG_FAILED,
    consts.DEPLOY_STATE_ABORTING_INSTALL: consts.DEPLOY_STATE_INSTALL_FAILED,
    consts.DEPLOY_STATE_ABORTING_BOOTSTRAP: consts.DEPLOY_STATE_BOOTSTRAP_FAILED,
    consts.DEPLOY_STATE_ABORTING_CONFIG: consts.DEPLOY_STATE_CONFIG_FAILED,
    consts.DEPLOY_STATE_PRE_RESTORE: consts.DEPLOY_STATE_RESTORE_PREP_FAILED,
    consts.DEPLOY_STATE_RESTORING: consts.DEPLOY_STATE_RESTORE_FAILED,
    consts.DEPLOY_STATE_PRE_REHOME: consts.DEPLOY_STATE_REHOME_PREP_FAILED,
    consts.DEPLOY_STATE_REHOMING: consts.DEPLOY_STATE_REHOME_FAILED,
    # The next two states are needed due to upgrade scenario:
    # TODO(gherzman): remove states when they are no longer needed
    consts.DEPLOY_STATE_PRE_DEPLOY: consts.DEPLOY_STATE_PRE_CONFIG_FAILED,
    consts.DEPLOY_STATE_DEPLOYING: consts.DEPLOY_STATE_CONFIG_FAILED,
    consts.DEPLOY_STATE_PRE_ENROLL: consts.DEPLOY_STATE_PRE_ENROLL_FAILED,
    consts.DEPLOY_STATE_ENROLLING: consts.DEPLOY_STATE_ENROLL_FAILED,
    consts.DEPLOY_STATE_PRE_INIT_ENROLL: consts.DEPLOY_STATE_PRE_INIT_ENROLL_FAILED,
    consts.DEPLOY_STATE_INITIATING_ENROLL: consts.DEPLOY_STATE_INIT_ENROLL_FAILED,
}

TRANSITORY_BACKUP_STATES = {
    consts.BACKUP_STATE_VALIDATING: consts.BACKUP_STATE_VALIDATE_FAILED,
    consts.BACKUP_STATE_PRE_BACKUP: consts.BACKUP_STATE_PREP_FAILED,
    consts.BACKUP_STATE_IN_PROGRESS: consts.BACKUP_STATE_FAILED,
}

TRANSITORY_PRESTAGE_STATES = {
    consts.PRESTAGE_STATE_PRESTAGING: consts.PRESTAGE_STATE_FAILED,
}

MAX_PARALLEL_SUBCLOUD_BACKUP_CREATE = 250
MAX_PARALLEL_SUBCLOUD_BACKUP_DELETE = 250
MAX_PARALLEL_SUBCLOUD_BACKUP_RESTORE = 100

# Values for the exponential backoff retry to get subcloud's
# certificate secret.
MAX_ATTEMPTS_TO_GET_INTERMEDIATE_CA_CERT = 15
MIN_WAIT_BEFORE_RETRY_KUBE_REQUEST = 1

# Values present on the overrides file generated during
# subcloud_deploy_create. They should not be deleted from
# the overrides if it's needed to recreate the file.
GENERATED_OVERRIDES_VALUES = [
    "region_config",
    "distributed_cloud_role",
    "system_controller_subnet",
    "system_controller_floating_address",
    "system_controller_oam_subnet",
    "system_controller_oam_floating_address",
    "system_controller_keystone_admin_user_id",
    "system_controller_keystone_admin_project_id",
    "system_controller_keystone_services_project_id",
    "system_controller_keystone_sysinv_user_id",
    "system_controller_keystone_dcmanager_user_id",
    "users",
    "dc_root_ca_cert",
    "sc_ca_cert",
    "sc_ca_key",
]

VALUES_TO_DELETE_OVERRIDES = [
    "deploy_playbook",
    "deploy_values",
    "deploy_config",
    "deploy_chart",
    "deploy_overrides",
    "install_values",
    "sysadmin_password",
]


class SubcloudManager(manager.Manager):
    """Manages tasks related to subclouds."""

    regionone_data = collections.defaultdict(dict)

    def __init__(self, *args, **kwargs):
        LOG.debug(_("SubcloudManager initialization..."))

        super(SubcloudManager, self).__init__(
            service_name="subcloud_manager", *args, **kwargs
        )
        self.context = dcmanager_context.get_admin_context()
        self.dcorch_rpc_client = dcorch_rpc_client.EngineWorkerClient()
        self.fm_api = fm_api.FaultAPIs()
        self.audit_rpc_client = dcmanager_audit_rpc_client.ManagerAuditClient()
        self.state_rpc_client = dcmanager_rpc_client.SubcloudStateClient()
        self.batch_rehome_lock = threading.Lock()

    @staticmethod
    def _get_subcloud_cert_name(subcloud_name):
        cert_name = "%s-adminep-ca-certificate" % subcloud_name
        return cert_name

    @staticmethod
    def _get_subcloud_cert_secret_name(subcloud_name):
        secret_name = "%s-adminep-ca-certificate" % subcloud_name
        return secret_name

    @staticmethod
    def _create_intermediate_ca_cert(payload):
        subcloud_region = payload["region_name"]
        cert_name = SubcloudManager._get_subcloud_cert_name(subcloud_region)
        secret_name = SubcloudManager._get_subcloud_cert_secret_name(subcloud_region)

        cert = {
            "apiVersion": (
                "%s/%s"
                % (kubeoperator.CERT_MANAGER_GROUP, kubeoperator.CERT_MANAGER_VERSION)
            ),
            "kind": "Certificate",
            "metadata": {"namespace": CERT_NAMESPACE, "name": cert_name},
            "spec": {
                "secretName": secret_name,
                "duration": SC_INTERMEDIATE_CERT_DURATION,
                "renewBefore": SC_INTERMEDIATE_CERT_RENEW_BEFORE,
                "issuerRef": {"kind": "Issuer", "name": "dc-adminep-root-ca-issuer"},
                "commonName": cert_name,
                "isCA": True,
            },
        }

        kube = kubeoperator.KubeOperator()
        # Time delay is set to prevent the aggravation of stress scenarios in
        # the system while performing the parallel addition of many subclouds.
        delay = random.uniform(0, 10)
        time.sleep(delay)
        kube.apply_cert_manager_certificate(CERT_NAMESPACE, cert_name, cert)

        # May wait from ~2s to ~3min30s for the certificate secret to be ready.
        # Exponential backoff retry is implemented to define the wait time
        # between each attempt to request the certificate secret object.
        # wait_per_request = min_wait*2**retry_times + random_number between
        # 0-min_wait with a total maximum wait time of 210s, e.g:
        #    1st retry: 1*2**(0*0.3 + 1) + 1, max wait time 3s,
        #    2nd retry: 1*2**(1*0.3 + 1) + 1, max wait time ~3.46s,
        #    ...
        #    10th retry: 1*2**(9*0.3 + 1) + 1, max wait time ~13.99s,
        #    ...
        #    15th retry: 1*2**(14*0.3 + 1) + 1, max wait time ~37.76s.
        for count in range(MAX_ATTEMPTS_TO_GET_INTERMEDIATE_CA_CERT):
            secret = kube.kube_get_secret(secret_name, CERT_NAMESPACE)
            wait_per_request = MIN_WAIT_BEFORE_RETRY_KUBE_REQUEST * 2 ** (
                count * 0.3 + 1
            ) + random.uniform(0, MIN_WAIT_BEFORE_RETRY_KUBE_REQUEST)
            if not hasattr(secret, "data"):
                time.sleep(wait_per_request)
                LOG.debug("Wait for %s ... %s" % (secret_name, count))
                continue

            data = secret.data
            if (
                "ca.crt" not in data or "tls.crt" not in data or "tls.key" not in data
            ) or not (data["ca.crt"] and data["tls.crt"] and data["tls.key"]):
                # ca cert, certificate and key pair are needed and must exist
                # for creating an intermediate ca. If not, certificate is not
                # ready yet.
                time.sleep(wait_per_request)
                LOG.debug("Wait for %s ... %s" % (secret_name, count))
                continue

            payload["dc_root_ca_cert"] = data["ca.crt"]
            payload["sc_ca_cert"] = data["tls.crt"]
            payload["sc_ca_key"] = data["tls.key"]
            return
        raise Exception("Secret for certificate %s is not ready." % cert_name)

    # TODO(kmacleod) switch to using utils.get_ansible_filename
    @staticmethod
    def _get_ansible_filename(subcloud_name, postfix=".yml"):
        ansible_filename = os.path.join(
            dccommon_consts.ANSIBLE_OVERRIDES_PATH, subcloud_name + postfix
        )
        return ansible_filename

    def compose_install_command(
        self,
        subcloud_name,
        ansible_subcloud_inventory_file,
        software_version=None,
        bmc_access_only=None,
    ):
        install_command = [
            "ansible-playbook",
            dccommon_consts.ANSIBLE_SUBCLOUD_INSTALL_PLAYBOOK,
            "-i",
            ansible_subcloud_inventory_file,
            "--limit",
            subcloud_name,
            "-e",
            "@%s" % dccommon_consts.ANSIBLE_OVERRIDES_PATH
            + "/"
            + subcloud_name
            + "/"
            + "install_values.yml",
            "-e",
            (
                "install_release_version=%s" % software_version
                if software_version
                else SW_VERSION
            ),
            "-e",
            "rvmc_config_file=%s"
            % os.path.join(
                dccommon_consts.ANSIBLE_OVERRIDES_PATH,
                subcloud_name,
                dccommon_consts.RVMC_CONFIG_FILE_NAME,
            ),
        ]

        if bmc_access_only:
            install_command += ["-e", f"bmc_access_only={bmc_access_only}"]

        return install_command

    def compose_enroll_command(
        self,
        subcloud_name,
        subcloud_region,
        ansible_subcloud_inventory_file,
        software_version,
        state,
    ):

        if state == "init":
            enroll_command = [
                "ansible-playbook",
                dccommon_consts.ANSIBLE_SUBCLOUD_ENROLL_INIT_PLAYBOOK,
                "-i",
                ansible_subcloud_inventory_file,
                "--limit",
                subcloud_name,
                "-e",
                "@%s" % dccommon_consts.ANSIBLE_OVERRIDES_PATH
                + "/"
                + subcloud_name
                + "/"
                + "enroll_overrides.yml",
                "-e",
                (
                    "install_release_version=%s" % software_version
                    if software_version
                    else SW_VERSION
                ),
                "-e",
                "rvmc_config_file=%s"
                % os.path.join(
                    dccommon_consts.ANSIBLE_OVERRIDES_PATH,
                    subcloud_name,
                    dccommon_consts.RVMC_CONFIG_FILE_NAME,
                ),
            ]

            return enroll_command
        elif state == "enroll":
            extra_vars = "override_files_dir='%s' region_name=%s" % (
                dccommon_consts.ANSIBLE_OVERRIDES_PATH,
                subcloud_region,
            )

            enroll_command = [
                "ansible-playbook",
                dccommon_consts.ANSIBLE_SUBCLOUD_ENROLL_PLAYBOOK,
                "-i",
                ansible_subcloud_inventory_file,
                "--limit",
                subcloud_name,
                "-e",
                extra_vars,
                "-e",
                (
                    "install_release_version=%s" % software_version
                    if software_version
                    else SW_VERSION
                ),
            ]

            return enroll_command
        else:
            raise exceptions.InvalidInputError

    def compose_bootstrap_command(
        self,
        subcloud_name,
        subcloud_region,
        ansible_subcloud_inventory_file,
        software_version=None,
    ):
        bootstrap_command = [
            "ansible-playbook",
            utils.get_playbook_for_software_version(
                ANSIBLE_SUBCLOUD_PLAYBOOK, software_version
            ),
            "-i",
            ansible_subcloud_inventory_file,
            "--limit",
            subcloud_name,
        ]
        # Add the overrides dir and region_name so the playbook knows
        # which overrides to load
        bootstrap_command += [
            "-e",
            str("override_files_dir='%s' region_name=%s")
            % (dccommon_consts.ANSIBLE_OVERRIDES_PATH, subcloud_region),
            "-e",
            (
                "install_release_version=%s" % software_version
                if software_version
                else SW_VERSION
            ),
        ]
        return bootstrap_command

    def compose_config_command(
        self, subcloud_name, ansible_subcloud_inventory_file, payload
    ):
        config_command = [
            "ansible-playbook",
            payload[consts.DEPLOY_PLAYBOOK],
            "-e",
            "@%s" % dccommon_consts.ANSIBLE_OVERRIDES_PATH
            + "/"
            + subcloud_name
            + "_deploy_values.yml",
            "-i",
            ansible_subcloud_inventory_file,
            "--limit",
            subcloud_name,
        ]
        return config_command

    def compose_backup_command(self, subcloud_name, ansible_subcloud_inventory_file):
        backup_command = [
            "ansible-playbook",
            ANSIBLE_SUBCLOUD_BACKUP_CREATE_PLAYBOOK,
            "-i",
            ansible_subcloud_inventory_file,
            "--limit",
            subcloud_name,
            "-e",
            "subcloud_bnr_overrides=%s"
            % (
                dccommon_consts.ANSIBLE_OVERRIDES_PATH
                + "/"
                + subcloud_name
                + "_backup_create_values.yml"
            ),
        ]
        return backup_command

    def compose_backup_delete_command(
        self, subcloud_name, ansible_subcloud_inventory_file=None
    ):
        backup_command = [
            "ansible-playbook",
            ANSIBLE_SUBCLOUD_BACKUP_DELETE_PLAYBOOK,
            "-e",
            "subcloud_bnr_overrides=%s" % dccommon_consts.ANSIBLE_OVERRIDES_PATH
            + "/"
            + subcloud_name
            + "_backup_delete_values.yml",
        ]
        if ansible_subcloud_inventory_file:
            # Backup stored in subcloud storage
            backup_command.extend(
                ("-i", ansible_subcloud_inventory_file, "--limit", subcloud_name)
            )
        else:
            # Backup stored in central storage
            backup_command.extend(("-e", "inventory_hostname=%s" % subcloud_name))
        return backup_command

    def compose_backup_restore_command(
        self,
        subcloud_name,
        ansible_subcloud_inventory_file,
        auto_restore_mode=None,
        with_install=False,
    ):
        backup_command = [
            "ansible-playbook",
            ANSIBLE_SUBCLOUD_BACKUP_RESTORE_PLAYBOOK,
            "-i",
            ansible_subcloud_inventory_file,
            "--limit",
            subcloud_name,
            "-e",
            "subcloud_bnr_overrides=%s"
            % (
                dccommon_consts.ANSIBLE_OVERRIDES_PATH
                + "/"
                + subcloud_name
                + "_backup_restore_values.yml"
            ),
        ]

        if auto_restore_mode:
            backup_command += ["-e", f"auto_restore_mode={auto_restore_mode}"]
            backup_command += [
                "-e",
                "rvmc_config_file=%s"
                % os.path.join(
                    dccommon_consts.ANSIBLE_OVERRIDES_PATH,
                    subcloud_name,
                    dccommon_consts.RVMC_CONFIG_FILE_NAME,
                ),
            ]

            # When auto-restoring on pre-installed subclouds, we need to use a
            # seed iso to transfer the central backup and overrides to the subcloud
            if auto_restore_mode == "auto" and not with_install:
                backup_command += ["-e", "mount_seed_iso=true"]

        return backup_command

    def compose_update_command(
        self, subcloud_name, ansible_subcloud_inventory_file, software_version=None
    ):
        subcloud_update_command = [
            "ansible-playbook",
            ANSIBLE_SUBCLOUD_UPDATE_PLAYBOOK,
            "-i",
            ansible_subcloud_inventory_file,
            "--limit",
            subcloud_name,
            "--timeout",
            UPDATE_PLAYBOOK_TIMEOUT,
            "-e",
            (
                "install_release_version=%s" % software_version
                if software_version
                else SW_VERSION
            ),
            "-e",
            "subcloud_update_overrides=%s"
            % (
                dccommon_consts.ANSIBLE_OVERRIDES_PATH
                + "/"
                + subcloud_name
                + "_update_values.yml"
            ),
        ]
        return subcloud_update_command

    def compose_rehome_command(
        self,
        subcloud_name,
        subcloud_region,
        ansible_subcloud_inventory_file,
        software_version,
    ):
        extra_vars = "override_files_dir='%s' region_name=%s" % (
            dccommon_consts.ANSIBLE_OVERRIDES_PATH,
            subcloud_region,
        )

        rehome_command = [
            "ansible-playbook",
            ANSIBLE_SUBCLOUD_REHOME_PLAYBOOK,
            "-i",
            ansible_subcloud_inventory_file,
            "--limit",
            subcloud_name,
            "--timeout",
            REHOME_PLAYBOOK_TIMEOUT,
            "-e",
            (
                "install_release_version=%s" % software_version
                if software_version
                else SW_VERSION
            ),
            "-e",
            extra_vars,
        ]
        return rehome_command

    def _migrate_manage_subcloud(
        self, context, payload, available_system_peers, subcloud
    ):
        success = True
        # Try to unmanage the subcloud on peer system
        if available_system_peers:
            if self._unmanage_system_peer_subcloud(available_system_peers, subcloud):
                success = False
                LOG.warning(
                    "Unmanged subcloud: %s error on peer system, exit migration"
                    % subcloud.name
                )
                return subcloud, success

        # migrate and set managed for
        # online and complete subclouds.
        self.migrate_subcloud(context, subcloud.id, payload)
        subcloud = db_api.subcloud_get(context, subcloud.id)

        if subcloud.deploy_status != consts.DEPLOY_STATE_DONE:
            success = False
        else:
            # Wait online to set managed
            # Until BATCH_REHOME_MGMT_STATES_TIMEOUT reached
            job_done_ts = time.monotonic()
            while True:
                offline_seconds = time.monotonic() - job_done_ts
                if subcloud.availability_status == dccommon_consts.AVAILABILITY_OFFLINE:
                    if offline_seconds >= consts.BATCH_REHOME_MGMT_STATES_TIMEOUT:
                        LOG.warning(
                            "Skip trying to manage subcloud: %s, "
                            "wait online timeout [%d]"
                            % (subcloud.name, offline_seconds)
                        )
                        success = False
                        break
                    time.sleep(20)
                else:
                    try:
                        self.update_subcloud(
                            context, subcloud.id, dccommon_consts.MANAGEMENT_MANAGED
                        )
                    except Exception:
                        LOG.exception(
                            "Unable to manage subcloud %s after migration operation"
                            % subcloud.name
                        )
                        success = False
                        return subcloud, success
                    LOG.info("Set manage of subcloud: %s success" % subcloud.name)
                    break
                subcloud = db_api.subcloud_get(context, subcloud.id)

        return subcloud, success

    def _get_peer_system_list(self, peer_group):
        system_peers = list()
        # Get associations by peer group
        associations = db_api.peer_group_association_get_by_peer_group_id(
            self.context, peer_group.id
        )
        if not associations:
            LOG.info(
                "No association found for peer group %s" % peer_group.peer_group_name
            )
            return system_peers
        for association in associations:
            system_peer = db_api.system_peer_get(
                self.context, association.system_peer_id
            )
            # Get 'available' system peer
            if (
                system_peer.availability_state
                != consts.SYSTEM_PEER_AVAILABILITY_STATE_AVAILABLE
            ):
                LOG.warning(
                    "Peer system %s offline, skip checking" % system_peer.peer_name
                )
                continue
            else:
                system_peers.append(system_peer)

        return system_peers

    def _unmanage_system_peer_subcloud(self, system_peers, subcloud):
        unmanaged_error = False
        for system_peer in system_peers:
            LOG.debug(
                "Get subcloud: %s from system_peer: %s"
                % (subcloud.name, system_peer.peer_name)
            )
            for attempt in range(3):
                try:
                    dc_client = SystemPeerManager.get_peer_dc_client(system_peer)
                    # Get remote subcloud by region_name from system peer
                    remote_subcloud = dc_client.get_subcloud(
                        subcloud.region_name, is_region_name=True
                    )
                    is_unmanaged = (
                        remote_subcloud.get("management-state")
                        == dccommon_consts.MANAGEMENT_UNMANAGED
                    )
                    is_rehome_pending = (
                        remote_subcloud.get("deploy-status")
                        == consts.DEPLOY_STATE_REHOME_PENDING
                    )

                    # Check if it's already in the correct state
                    if is_unmanaged and is_rehome_pending:
                        LOG.info(
                            f"Remote subcloud {remote_subcloud.get('name')} from "
                            f"system peer {system_peer.peer_name} is already "
                            "unmanaged and rehome-pending, skipping unmanage attempt"
                        )
                        break

                    try:
                        UNMANAGED = dccommon_consts.MANAGEMENT_UNMANAGED
                        if not is_unmanaged:
                            # Unmanage and update the deploy-status
                            payload = {
                                "management-state": UNMANAGED,
                                "migrate": "true",
                            }
                            remote_subcloud = dc_client.update_subcloud(
                                subcloud.region_name,
                                files=None,
                                data=payload,
                                is_region_name=True,
                            )
                            LOG.info(
                                "Successfully updated subcloud: "
                                f"{remote_subcloud.get('name')} on peer "
                                f"system {system_peer.peer_name} to "
                                f"{dccommon_consts.MANAGEMENT_UNMANAGED} "
                                f"and {consts.DEPLOY_STATE_REHOME_PENDING} state."
                            )
                        else:
                            # Already unmanaged, just update the deploy-status
                            payload = {"migrate": "true"}
                            remote_subcloud = dc_client.update_subcloud(
                                subcloud.region_name,
                                files=None,
                                data=payload,
                                is_region_name=True,
                            )
                            LOG.info(
                                "Successfully updated subcloud: "
                                f"{remote_subcloud.get('name')} on peer "
                                f"system {system_peer.peer_name} to "
                                f"{consts.DEPLOY_STATE_REHOME_PENDING} state."
                            )
                        return unmanaged_error
                    except Exception as e:
                        raise exceptions.SubcloudNotUnmanaged() from e

                except SubcloudNotFound:
                    LOG.info(
                        "No identical subcloud: %s found on peer system: %s"
                        % (subcloud.region_name, system_peer.peer_name)
                    )
                    break
                except exceptions.SubcloudNotUnmanaged:
                    LOG.exception(
                        "Unmanaged error on subcloud: %s on system %s"
                        % (subcloud.region_name, system_peer.peer_name)
                    )
                    unmanaged_error = True
                except Exception:
                    LOG.exception(
                        "Failed to set unmanged for subcloud: %s on system %s attempt: "
                        "%d" % (subcloud.region_name, system_peer.peer_name, attempt)
                    )
                    time.sleep(1)
        return unmanaged_error

    def _clear_alarm_for_peer_group(self, peer_group):
        # Get alarms related to peer group
        faults = self.fm_api.get_faults_by_id(
            fm_const.FM_ALARM_ID_DC_SUBCLOUD_PEER_GROUP_NOT_MANAGED
        )
        if not faults:
            return
        for fault in faults:
            entity_instance_id_str = "peer_group=%s,peer=" % (
                peer_group.peer_group_name
            )
            if entity_instance_id_str in fault.entity_instance_id:
                LOG.info("Clear alarm for peer group %s" % peer_group.peer_group_name)
                self.fm_api.clear_fault(
                    fm_const.FM_ALARM_ID_DC_SUBCLOUD_PEER_GROUP_NOT_MANAGED,
                    fault.entity_instance_id,
                )

    def migrate_subcloud(self, context, subcloud_ref, payload):
        """migrate_subcloud function is for day-2's rehome purpose.

        This is called by 'dcmanager subcloud migrate <subcloud>'.
        This function is used to migrate those 'secondary' subcloud.

        :param context: request context object
        :param subcloud_ref: id or name of the subcloud
        :param payload: subcloud configuration
        """
        subcloud = None
        try:
            # subcloud_ref could be int type id.
            subcloud = utils.subcloud_get_by_ref(context, str(subcloud_ref))
            if not subcloud:
                LOG.error("Failed to migrate, non-existent subcloud %s" % subcloud_ref)
                return
            if "sysadmin_password" not in payload:
                LOG.error(
                    "Failed to migrate subcloud: %s, must provide sysadmin_password"
                    % subcloud.name
                )
                return

            if subcloud.deploy_status not in [
                consts.DEPLOY_STATE_SECONDARY,
                consts.DEPLOY_STATE_REHOME_FAILED,
                consts.DEPLOY_STATE_REHOME_PREP_FAILED,
            ]:
                LOG.error(
                    "Failed to migrate subcloud: %s, "
                    "must be in secondary or rehome failure state" % subcloud.name
                )
                return

            db_api.subcloud_update(
                context,
                subcloud.id,
                deploy_status=consts.DEPLOY_STATE_PRE_REHOME,
                error_description=consts.ERROR_DESC_EMPTY,
            )
            rehome_data = json.loads(subcloud.rehome_data)
            saved_payload = rehome_data["saved_payload"]
            # Update sysadmin_password
            sysadmin_password = base64.b64decode(payload["sysadmin_password"]).decode(
                "utf-8"
            )
            saved_payload["sysadmin_password"] = sysadmin_password
            # Decode admin_password
            if "admin_password" in saved_payload:
                saved_payload["admin_password"] = base64.b64decode(
                    saved_payload["admin_password"]
                ).decode("utf-8")

            # Re-generate ansible config based on latest rehome_data
            subcloud = self.generate_subcloud_ansible_config(subcloud, saved_payload)
            self.rehome_subcloud(context, subcloud)
        except Exception:
            # If we failed to migrate the subcloud, update the
            # deployment status
            if subcloud:
                LOG.exception("Failed to migrate subcloud %s" % subcloud.name)
                db_api.subcloud_update(
                    context,
                    subcloud.id,
                    deploy_status=consts.DEPLOY_STATE_REHOME_PREP_FAILED,
                )
            return

    def batch_migrate_subcloud(self, context, payload):
        if "peer_group" not in payload:
            LOG.error("Failed to migrate subcloud peer group, missing peer_group")
            return
        if "sysadmin_password" not in payload:
            LOG.error(
                "Failed to migrate subcloud peer group, missing sysadmin_password"
            )
            return
        if self.batch_rehome_lock.locked():
            LOG.warning("Batch migrate is already running.")
            return
        with self.batch_rehome_lock:
            try:
                peer_group = utils.subcloud_peer_group_get_by_ref(
                    context, payload["peer_group"]
                )

                self.run_batch_migrate(
                    context, peer_group, payload["sysadmin_password"]
                )
            except Exception as e:
                LOG.exception(
                    "Failed to batch migrate subcloud peer group: %s error: %s"
                    % (payload["peer_group"], e)
                )

    def run_batch_migrate(self, context, peer_group, sysadmin_password):
        subclouds = db_api.subcloud_get_for_peer_group(context, peer_group.id)
        subclouds_ready_to_migrate = []
        for tmp_subcloud in subclouds:
            # Check subcloud is ready for rehome
            # Verify rehome data
            rehome_data_json_str = tmp_subcloud.rehome_data
            if not rehome_data_json_str:
                LOG.error(
                    "Unable to migrate subcloud: %s no rehome data" % tmp_subcloud.name
                )
                db_api.subcloud_update(
                    context,
                    tmp_subcloud.id,
                    deploy_status=consts.DEPLOY_STATE_REHOME_PREP_FAILED,
                )
                continue
            tmp_rehome_data = json.loads(rehome_data_json_str)
            # Verify saved_payload in _rehome_data
            if "saved_payload" not in tmp_rehome_data:
                LOG.error(
                    "Unable to migrate subcloud: %s no saved_payload"
                    % tmp_subcloud.name
                )
                db_api.subcloud_update(
                    context,
                    tmp_subcloud.id,
                    deploy_status=consts.DEPLOY_STATE_REHOME_PREP_FAILED,
                )
                continue
            if tmp_subcloud.deploy_status in [
                consts.DEPLOY_STATE_SECONDARY,
                consts.DEPLOY_STATE_REHOME_FAILED,
                consts.DEPLOY_STATE_REHOME_PREP_FAILED,
            ]:
                subclouds_ready_to_migrate.append(tmp_subcloud)
            else:
                LOG.info(
                    "Skipping subcloud %s from batch migration: subcloud deploy_status "
                    "is not in secondary, rehome-failed or rehome-prep-failed"
                    % tmp_subcloud.name
                )

        # If no subcloud need to rehome, exit
        if not subclouds_ready_to_migrate:
            LOG.info(
                "No subclouds to be migrated in peer group: %s "
                "ending migration attempt" % str(peer_group.peer_group_name)
            )
            return

        # Set migration_status to migrating
        db_api.subcloud_peer_group_update(
            self.context, peer_group.id, migration_status=consts.PEER_GROUP_MIGRATING
        )

        # Try to get peer system by peer group
        system_peers = self._get_peer_system_list(peer_group)

        # Use thread pool to limit number of operations in parallel
        migrate_pool = greenpool.GreenPool(size=peer_group.max_subcloud_rehoming)
        # Spawn threads to migrate each applicable subcloud
        tmp_payload = {"sysadmin_password": sysadmin_password}
        migrate_function = functools.partial(
            self._migrate_manage_subcloud, context, tmp_payload, system_peers
        )

        self._run_parallel_group_operation(
            "migrate", migrate_function, migrate_pool, subclouds_ready_to_migrate
        )

        # Set migration_status to complete,
        # Update system leader id and name
        local_system = utils.get_local_system()
        peer_group = db_api.subcloud_peer_group_update(
            self.context,
            peer_group.id,
            system_leader_id=local_system.uuid,
            system_leader_name=local_system.name,
            migration_status=consts.PEER_GROUP_MIGRATION_COMPLETE,
        )

        # Try to send audit request to system peer
        resp = PeerGroupAuditManager.send_audit_peer_group(system_peers, peer_group)
        if resp:
            LOG.warning(
                "Audit peer group %s response: %s" % (peer_group.peer_group_name, resp)
            )

        # Try to clear existing alarm if we rehomed a '0' priority peer group
        if peer_group.group_priority == 0:
            self._clear_alarm_for_peer_group(peer_group)

        LOG.info("Batch migrate operation finished")

    def rehome_subcloud(self, context, subcloud):
        # Ansible inventory filename for the specified subcloud
        ansible_subcloud_inventory_file = self._get_ansible_filename(
            subcloud.name, INVENTORY_FILE_POSTFIX
        )

        log_file = (
            os.path.join(consts.DC_ANSIBLE_LOG_DIR, subcloud.name)
            + "_playbook_output.log"
        )

        rehome_command = self.compose_rehome_command(
            subcloud.name,
            subcloud.region_name,
            ansible_subcloud_inventory_file,
            subcloud.software_version,
        )

        # Update the deploy status to rehoming
        db_api.subcloud_update(
            context,
            subcloud.id,
            deploy_status=consts.DEPLOY_STATE_REHOMING,
            error_description=consts.ERROR_DESC_EMPTY,
        )

        # Run the rehome-subcloud playbook
        try:
            ansible = dccommon_utils.AnsiblePlaybook(subcloud.name)
            ansible.run_playbook(log_file, rehome_command)
        except PlaybookExecutionFailed as e:
            msg = (
                "Failed to run the subcloud rehome playbook for subcloud "
                f"{subcloud.name}, check individual log at {log_file} "
                "for detailed output."
            )
            LOG.error(msg)

            utils.find_and_save_ansible_error_msg(
                context,
                subcloud,
                log_file,
                exception=e,
                stage=consts.DEPLOY_STATE_REHOMING,
                deploy_status=consts.DEPLOY_STATE_REHOME_FAILED,
            )
            return
        # Update the deploy status to complete and rehomed flag to true only
        # after playbook execution succeeded.
        db_api.subcloud_update(
            context, subcloud.id, deploy_status=consts.DEPLOY_STATE_DONE, rehomed=True
        )
        LOG.info("Successfully rehomed subcloud %s" % subcloud.name)

    def add_subcloud(self, context, subcloud_id, payload):
        """Add subcloud and notify orchestrators.

        :param context: request context object
        :param subcloud_id: id of the subcloud
        :param payload: subcloud configuration
        """
        LOG.info(
            f"Adding subcloud {payload['name']} with region {payload['region_name']}."
        )

        rehoming = payload.get("migrate", "").lower() == "true"
        secondary = payload.get("secondary", "").lower() == "true"
        enroll = payload.get("enroll", "").lower() == "true"
        initial_deployment = True if not (rehoming or enroll) else False

        # Create the subcloud
        subcloud = self.subcloud_deploy_create(
            context,
            subcloud_id,
            payload,
            rehoming,
            initial_deployment,
            return_as_dict=False,
            enroll=enroll,
        )

        # return if 'secondary' subcloud
        if secondary:
            return

        # Return if create failed
        if rehoming:
            success_state = consts.DEPLOY_STATE_PRE_REHOME
        else:
            success_state = consts.DEPLOY_STATE_CREATED
        if subcloud.deploy_status != success_state:
            return

        # Rehome subcloud
        if rehoming:
            self.rehome_subcloud(context, subcloud)
            return

        # Define which deploy phases should be run
        phases_to_run = []
        if consts.INSTALL_VALUES in payload and not enroll:
            phases_to_run.append(consts.DEPLOY_PHASE_INSTALL)
        if enroll and consts.INSTALL_VALUES in payload:
            phases_to_run.append(consts.DEPLOY_PHASE_ENROLL)
        else:
            phases_to_run.append(consts.DEPLOY_PHASE_BOOTSTRAP)
        if consts.DEPLOY_CONFIG in payload:
            phases_to_run.append(consts.DEPLOY_PHASE_CONFIG)
        else:
            phases_to_run.append(consts.DEPLOY_PHASE_COMPLETE)

        # Finish adding the subcloud by running the deploy phases
        succeeded = self.run_deploy_phases(
            context,
            subcloud_id,
            payload,
            phases_to_run,
            initial_deployment=initial_deployment,
        )

        if succeeded:
            LOG.info(f"Finished adding subcloud {subcloud['name']}.")

    def redeploy_subcloud(self, context, subcloud_id, payload, previous_version):
        """Redeploy subcloud

        :param context: request context object
        :param subcloud_id: subcloud id from db
        :param payload: subcloud redeploy parameters
        :param previous_version: the previous subcloud software version
        """

        LOG.info(f"Redeploying subcloud {payload['name']}.")

        # Define which deploy phases to run
        phases_to_run = [consts.DEPLOY_PHASE_INSTALL, consts.DEPLOY_PHASE_BOOTSTRAP]
        if consts.DEPLOY_CONFIG in payload:
            phases_to_run.append(consts.DEPLOY_PHASE_CONFIG)
        else:
            phases_to_run.append(consts.DEPLOY_PHASE_COMPLETE)

        succeeded = self.run_deploy_phases(
            context,
            subcloud_id,
            payload,
            phases_to_run,
            initial_deployment=True,
            previous_version=previous_version,
        )

        if succeeded:
            LOG.info(f"Finished redeploying subcloud {payload['name']}.")

    def create_subcloud_backups(self, context, payload):
        """Backup subcloud or group of subclouds

        :param context: request context object
        :param payload: subcloud backup create detail
        """

        subcloud_id = payload.get("subcloud")
        group_id = payload.get("group")

        # Retrieve either a single subcloud or all subclouds in a group
        subclouds = (
            [db_api.subcloud_get(context, subcloud_id)]
            if subcloud_id
            else db_api.subcloud_get_for_group(context, group_id)
        )

        self._filter_subclouds_with_ongoing_backup(subclouds)
        self._update_backup_status(context, subclouds, consts.BACKUP_STATE_INITIAL)

        # Validate the subclouds and filter the ones applicable for backup
        self._update_backup_status(context, subclouds, consts.BACKUP_STATE_VALIDATING)

        subclouds_to_backup, invalid_subclouds = self._validate_subclouds_for_backup(
            subclouds, "create"
        )

        self._mark_invalid_subclouds_for_backup(context, invalid_subclouds)

        # Use thread pool to limit number of operations in parallel
        backup_pool = greenpool.GreenPool(size=MAX_PARALLEL_SUBCLOUD_BACKUP_CREATE)

        # Spawn threads to back up each applicable subcloud
        backup_function = functools.partial(self._backup_subcloud, context, payload)

        self._run_parallel_group_operation(
            "backup create", backup_function, backup_pool, subclouds_to_backup
        )

        LOG.info("Subcloud backup operation finished")

    def delete_subcloud_backups(self, context, release_version, payload):
        """Delete backups for subcloud or group of subclouds for a given release

        :param context: request context object
        :param release_version Backup release version to be deleted
        :param payload: subcloud backup delete detail
        """

        local_delete = payload.get("local_only")

        subclouds_to_delete_backup, invalid_subclouds = (
            self._filter_subclouds_for_backup_delete(context, payload, local_delete)
        )

        # Spawn threads to back up each applicable subcloud
        backup_delete_function = functools.partial(
            self._delete_subcloud_backup, context, payload, release_version
        )

        # Use thread pool to limit number of operations in parallel
        max_parallel_operations = MAX_PARALLEL_SUBCLOUD_BACKUP_DELETE
        backup_delete_pool = greenpool.GreenPool(size=max_parallel_operations)

        failed_subclouds = self._run_parallel_group_operation(
            "backup delete",
            backup_delete_function,
            backup_delete_pool,
            subclouds_to_delete_backup,
        )

        LOG.info("Subcloud backup delete operation finished")

        return self._subcloud_operation_notice(
            "delete", subclouds_to_delete_backup, failed_subclouds, invalid_subclouds
        )

    def restore_subcloud_backups(self, context, payload):
        """Restore a subcloud or group of subclouds from backup data

        :param context: request context object
        :param payload: restore backup subcloud detail
        """

        subcloud_id = payload.get("subcloud")
        group_id = payload.get("group")

        # Initialize subclouds lists
        restore_subclouds, invalid_subclouds, failed_subclouds = (
            list(),
            list(),
            list(),
        )

        # Retrieve either a single subcloud or all subclouds in a group
        subclouds = (
            [db_api.subcloud_get(context, subcloud_id)]
            if subcloud_id
            else db_api.subcloud_get_for_group(context, group_id)
        )

        bootstrap_address_dict = payload.get("restore_values", {}).get(
            "bootstrap_address", {}
        )

        restore_subclouds, invalid_subclouds = self._validate_subclouds_for_backup(
            subclouds, "restore", bootstrap_address_dict
        )

        if restore_subclouds:
            # Use thread pool to limit number of operations in parallel
            restore_pool = greenpool.GreenPool(
                size=MAX_PARALLEL_SUBCLOUD_BACKUP_RESTORE
            )

            # Spawn threads to back up each applicable subcloud
            restore_function = functools.partial(
                self._restore_subcloud_backup, context, payload
            )

            failed_subclouds = self._run_parallel_group_operation(
                "backup restore", restore_function, restore_pool, restore_subclouds
            )

        restored_subclouds = len(restore_subclouds) - len(failed_subclouds)
        LOG.info(
            "Subcloud restore backup operation finished.\nRestored subclouds: %s. "
            "Invalid subclouds: %s. Failed subclouds: %s."
            % (restored_subclouds, len(invalid_subclouds), len(failed_subclouds))
        )

        return self._subcloud_operation_notice(
            "restore", restore_subclouds, failed_subclouds, invalid_subclouds
        )

    def _deploy_bootstrap_prep(
        self,
        context,
        subcloud,
        payload: dict,
        initial_deployment=False,
    ):
        """Run the preparation steps needed to run the bootstrap operation

        :param context: target request context object
        :param subcloud: subcloud model object
        :param payload: bootstrap request parameters
        :param initial_deployment: initial_deployment flag from subcloud inventory
        :return: ansible command needed to run the bootstrap playbook
        """

        self._deploy_bootstrap_enroll_prep(
            "bootstrap",
            context,
            payload,
            subcloud,
            initial_deployment=initial_deployment,
        )

        ansible_subcloud_inventory_file = self._get_ansible_filename(
            subcloud.name, INVENTORY_FILE_POSTFIX
        )

        bootstrap_command = self.compose_bootstrap_command(
            subcloud.name,
            subcloud.region_name,
            ansible_subcloud_inventory_file,
            subcloud.software_version,
        )
        return bootstrap_command

    def _deploy_bootstrap_enroll_prep(
        self, operation, context, payload, subcloud, initial_deployment=False
    ):

        network_reconfig = utils.has_network_reconfig(payload, subcloud)
        if network_reconfig:
            self._configure_system_controller_network(
                context, payload, subcloud, update_db=False
            )
            # Regenerate the addn_hosts_dc file
            self._create_addn_hosts_dc(context)

        if operation == "bootstrap":
            _deploy_status = consts.DEPLOY_STATE_PRE_BOOTSTRAP
        elif operation == "enroll":
            _deploy_status = consts.DEPLOY_STATE_PRE_ENROLL
        else:
            raise exceptions.InvalidParameterValue

        if subcloud.deploy_status != _deploy_status or network_reconfig:

            # Update subcloud
            subcloud = db_api.subcloud_update(
                context,
                subcloud.id,
                description=payload.get("description"),
                management_subnet=utils.get_primary_management_subnet(payload),
                management_gateway_ip=utils.get_primary_management_gateway_address(
                    payload
                ),
                management_start_ip=utils.get_primary_management_start_address(payload),
                management_end_ip=utils.get_primary_management_end_address(payload),
                systemcontroller_gateway_ip=(
                    utils.get_primary_systemcontroller_gateway_address(payload)
                ),
                location=payload.get("location"),
                deploy_status=_deploy_status,
            )

        # Populate payload with passwords
        payload["ansible_become_pass"] = payload["sysadmin_password"]
        payload["ansible_ssh_pass"] = payload["sysadmin_password"]
        payload["admin_password"] = str(keyring.get_password("CGCS", "admin"))

        payload_for_overrides_file = payload.copy()
        for key in VALUES_TO_DELETE_OVERRIDES:
            if key in payload_for_overrides_file:
                del payload_for_overrides_file[key]

        # Update the ansible overrides file
        overrides_file = os.path.join(
            dccommon_consts.ANSIBLE_OVERRIDES_PATH, subcloud.name + ".yml"
        )
        overrides_file_exists = utils.update_values_on_yaml_file(
            overrides_file,
            payload_for_overrides_file,
            values_to_keep=GENERATED_OVERRIDES_VALUES,
        )

        if not overrides_file_exists:
            generate_ca_certs = operation.lower() != "enroll"
            # Overrides file doesn't exist, so we generate a new one
            self.generate_subcloud_ansible_config(
                subcloud,
                payload,
                initial_deployment=initial_deployment,
                create_ca_cert=generate_ca_certs,
            )

        # Only creates inventory for bootstrap, for enroll
        # is created inside the enroll function
        elif operation.lower() == "bootstrap":
            ansible_subcloud_inventory_file = self._get_ansible_filename(
                subcloud.name, INVENTORY_FILE_POSTFIX
            )
            # Since we generate an inventory already when generating the
            # new Ansible overrides, only create the inventory here when
            # the overrides already existed
            utils.create_subcloud_inventory(
                payload, ansible_subcloud_inventory_file, initial_deployment
            )

        utils.update_install_values_with_new_bootstrap_address(
            context, payload, subcloud
        )

    def _deploy_config_prep(
        self,
        subcloud,
        payload: dict,
        ansible_subcloud_inventory_file,
        initial_deployment=False,
    ):
        """Run the preparation steps needed to run the config operation

        :param subcloud: target subcloud model object
        :param payload: config request parameters
        :param ansible_subcloud_inventory_file: the ansible inventory file path
        :param initial_deployment: initial_deployment flag from subcloud inventory
        :return: ansible command needed to run the config playbook
        """
        self._prepare_for_deployment(payload, subcloud.name)

        # Update the ansible inventory for the subcloud
        bootstrap_address = payload[consts.BOOTSTRAP_ADDRESS]
        subcloud_params = {
            "name": subcloud.name,
            consts.BOOTSTRAP_ADDRESS: bootstrap_address,
        }
        utils.create_subcloud_inventory(
            subcloud_params, ansible_subcloud_inventory_file, initial_deployment
        )

        config_command = self.compose_config_command(
            subcloud.name, ansible_subcloud_inventory_file, payload
        )
        return config_command

    def _deploy_install_prep(
        self,
        subcloud,
        payload: dict,
        ansible_subcloud_inventory_file,
        initial_deployment=False,
        init_enroll=False,
    ):
        """Run preparation steps for install or init enroll operations

        :param subcloud: target subcloud model object
        :param payload: install request parameters
        :param ansible_subcloud_inventory_file: the ansible inventory file path
        :param initial_deployment: initial_deployment flag from subcloud inventory
        :param init_enroll: which operation should be run, install or init-enroll
        :return: ansible command needed to run the install playbook

        """
        payload["install_values"]["ansible_ssh_pass"] = payload["sysadmin_password"]
        payload["install_values"]["ansible_become_pass"] = payload["sysadmin_password"]

        # If all update_values already exists on override file or are
        # the same as the existing ones, the update won't happen
        # and the file will remain untouched
        bootstrap_file = psd_common.get_config_file_path(
            subcloud.name, consts.BOOTSTRAP_VALUES
        )
        update_values = {
            "software_version": payload["software_version"],
            "bmc_password": payload["bmc_password"],
            "ansible_ssh_pass": payload["sysadmin_password"],
            "ansible_become_pass": payload["sysadmin_password"],
        }
        utils.update_values_on_yaml_file(bootstrap_file, update_values)

        # Update the ansible inventory for the subcloud
        bootstrap_address = payload["install_values"]["bootstrap_address"]
        subcloud_params = {
            "name": subcloud.name,
            consts.BOOTSTRAP_ADDRESS: bootstrap_address,
        }

        if init_enroll:
            utils.create_subcloud_inventory_with_admin_creds(
                subcloud.name,
                ansible_subcloud_inventory_file,
                payload[consts.BOOTSTRAP_ADDRESS],
                ansible_pass=json.dumps(payload["sysadmin_password"]),
            )
            init_enroll_command = self.compose_enroll_command(
                subcloud.name,
                subcloud.region_name,
                ansible_subcloud_inventory_file,
                subcloud.software_version,
                state="init",
            )
            return init_enroll_command

        utils.create_subcloud_inventory(
            subcloud_params, ansible_subcloud_inventory_file, initial_deployment
        )

        install_command = self.compose_install_command(
            subcloud.name, ansible_subcloud_inventory_file, payload["software_version"]
        )
        return install_command

    def subcloud_deploy_abort(self, context, subcloud_id, deploy_status):
        """Abort the subcloud deploy

        :param context: request context object
        :param subcloud_id: subcloud id from db
        :param deploy_status: subcloud deploy status from db
        """

        LOG.info("Aborting deployment of subcloud %s." % subcloud_id)
        subcloud = utils.update_abort_status(context, subcloud_id, deploy_status)

        try:
            ansible = dccommon_utils.AnsiblePlaybook(subcloud.name)
            aborted = ansible.run_abort()
            if not aborted:
                LOG.warning(
                    "Ansible deploy phase subprocess of %s "
                    "was terminated before it could be aborted" % subcloud.name
                )
                # let the main phase thread handle the state update
                return

            if subcloud.deploy_status == consts.DEPLOY_STATE_ABORTING_INSTALL:
                LOG.info(f"Sending shutdown signal to subcloud {subcloud.name}")
                dccommon_utils.send_subcloud_shutdown_signal(subcloud.name)
                LOG.info(f"Shutdown signal sent to subcloud {subcloud.name}")
            LOG.info(f"Successfully aborted deployment of {subcloud.name}")
        except TimeoutError:
            LOG.warning(f"Subcloud deploy abort timed out for subcloud {subcloud.name}")
        except Exception as ex:
            LOG.error(
                "Subcloud deploy abort failed for subcloud %s: %s"
                % (subcloud.name, str(ex))
            )
            utils.update_abort_status(
                context, subcloud.id, subcloud.deploy_status, abort_failed=True
            )
            # exception is logged above
            raise ex
        utils.update_abort_status(context, subcloud.id, subcloud.deploy_status)

    def subcloud_deploy_resume(
        self,
        context,
        subcloud_id,
        subcloud_name,
        payload: dict,
        deploy_states_to_run,
        previous_version=None,
    ):
        """Resume the subcloud deployment

        :param context: request context object
        :param subcloud_id: subcloud id from db
        :param subcloud_name: name of the subcloud
        :param payload: subcloud resume payload
        :param deploy_states_to_run: deploy phases pending execution
        :param previous_version: the previous subcloud software version
        """
        LOG.info(
            "Resuming deployment of subcloud %s. Deploy phases to be executed: %s"
            % (subcloud_name, ", ".join(deploy_states_to_run))
        )

        self.run_deploy_phases(
            context,
            subcloud_id,
            payload,
            deploy_states_to_run,
            initial_deployment=True,
            previous_version=previous_version,
        )

    def generate_subcloud_ansible_config(
        self, subcloud, payload, initial_deployment=False, create_ca_cert=True
    ):
        """Generate latest ansible config based on given payload.

        :param subcloud: subcloud object
        :param payload: subcloud configuration
        :param initial_deployment: if being called during initial deployment
        :param create_ca_cert: if should create ca certs
        :return: resulting subcloud DB object
        """
        if initial_deployment:
            LOG.debug(
                f"Overrides file not found for {payload['name']}. "
                "Generating new overrides file."
            )
        else:
            LOG.info("Generate subcloud %s ansible config." % payload["name"])

        try:
            # Write ansible based on rehome_data
            m_ks_client = OpenStackDriver(
                region_clients=None,
                fetch_subcloud_ips=utils.fetch_subcloud_mgmt_ips,
            ).keystone_client
            endpoint = m_ks_client.endpoint_cache.get_endpoint("sysinv")
            sysinv_client = SysinvClient(
                m_ks_client.region_name,
                m_ks_client.session,
                endpoint=endpoint,
            )
            LOG.debug("Getting cached regionone data for %s" % subcloud.name)
            cached_regionone_data = self._get_cached_regionone_data(
                m_ks_client, sysinv_client
            )

            self._populate_payload_with_cached_keystone_data(
                cached_regionone_data, payload, populate_passwords=True
            )

            payload["users"] = {}
            for user in USERS_TO_REPLICATE:
                payload["users"][user] = str(
                    keyring.get_password(user, dccommon_consts.SERVICES_USER_NAME)
                )

            if "region_name" not in payload:
                payload["region_name"] = subcloud.region_name

            # Ansible inventory filename for the specified subcloud
            ansible_subcloud_inventory_file = utils.get_ansible_filename(
                subcloud.name, INVENTORY_FILE_POSTFIX
            )

            # Create the ansible inventory for the new subcloud
            utils.create_subcloud_inventory(
                payload,
                ansible_subcloud_inventory_file,
                initial_deployment=initial_deployment,
            )

            # Create subcloud intermediate certificate and pass in keys
            # On initial deployment, this was already created by subcloud
            # deploy create, so we just get the existing secret
            if initial_deployment:
                self._populate_payload_with_dc_intermediate_ca_cert(payload)
            elif create_ca_cert:
                self._create_intermediate_ca_cert(payload)

            # Write this subclouds overrides to file
            # NOTE: This file should not be deleted if subcloud operation fails
            # as it is used for debugging
            self._write_subcloud_ansible_config(cached_regionone_data, payload)

            return subcloud

        except Exception:
            LOG.exception("Failed to generate subcloud %s config" % payload["name"])
            raise

    def subcloud_deploy_create(
        self,
        context,
        subcloud_id,
        payload,
        rehoming=False,
        initial_deployment=True,
        return_as_dict=True,
        enroll=False,
    ):
        """Create subcloud and notify orchestrators.

        :param context: request context object
        :param subcloud_id: subcloud_id from db
        :param payload: subcloud configuration
        :param rehoming: flag indicating if this is part of a rehoming operation
        :param initial_deployment: initial_deployment flag from subcloud inventory
        :param return_as_dict: converts the subcloud DB object to a dict before
        :param enroll: define steps to run when running enroll operation
        returning
        :return: resulting subcloud DB object or dictionary
        """
        LOG.info("Creating subcloud %s." % payload["name"])

        # cache original payload data for day-2's rehome usage
        original_payload = copy.deepcopy(payload)

        # Check the secondary option from payload
        secondary_str = payload.get("secondary", "")
        secondary = secondary_str.lower() == "true"

        if rehoming:
            deploy_state = consts.DEPLOY_STATE_PRE_REHOME
        elif secondary:
            deploy_state = consts.DEPLOY_STATE_SECONDARY
        else:
            deploy_state = consts.DEPLOY_STATE_CREATING

        subcloud = db_api.subcloud_update(
            context,
            subcloud_id,
            deploy_status=deploy_state,
            error_description=consts.ERROR_DESC_EMPTY,
        )

        rehome_data = None
        try:
            # Create a new route to this subcloud on the management interface
            # on both controllers.
            m_ks_client = OpenStackDriver(
                region_clients=None,
                fetch_subcloud_ips=utils.fetch_subcloud_mgmt_ips,
            ).keystone_client
            # system-controller and subcloud communication is through
            # single-stack/primary (of subcloud) only.
            subcloud_subnet = netaddr.IPNetwork(
                utils.get_primary_management_subnet(payload)
            )
            endpoint = m_ks_client.endpoint_cache.get_endpoint("sysinv")
            sysinv_client = SysinvClient(
                m_ks_client.region_name,
                m_ks_client.session,
                endpoint=endpoint,
            )
            LOG.debug("Getting cached regionone data for %s" % subcloud.name)
            cached_regionone_data = self._get_cached_regionone_data(
                m_ks_client, sysinv_client
            )
            for mgmt_if_uuid in cached_regionone_data["mgmt_interface_uuids"]:
                sysinv_client.create_route(
                    mgmt_if_uuid,
                    str(subcloud_subnet.ip),
                    subcloud_subnet.prefixlen,
                    utils.get_primary_systemcontroller_gateway_address(payload),
                    1,
                )

            if not enroll:
                # Inform orchestrator that subcloud has been added
                self.dcorch_rpc_client.add_subcloud(
                    context,
                    subcloud.region_name,
                    subcloud.software_version,
                    subcloud.management_start_ip,
                )
            # create entry into alarm summary table, will get real values later
            alarm_updates = {
                "critical_alarms": -1,
                "major_alarms": -1,
                "minor_alarms": -1,
                "warnings": -1,
                "cloud_status": consts.ALARMS_DISABLED,
            }
            db_api.subcloud_alarms_create(context, subcloud.name, alarm_updates)

            # Regenerate the addn_hosts_dc file
            self._create_addn_hosts_dc(context)

            # Passwords need to be populated when rehoming
            self._populate_payload_with_cached_keystone_data(
                cached_regionone_data, payload, populate_passwords=rehoming
            )

            if "deploy_playbook" in payload:
                self._prepare_for_deployment(
                    payload, subcloud.name, populate_passwords=False
                )

            payload["users"] = {}
            for user in USERS_TO_REPLICATE:
                payload["users"][user] = str(
                    keyring.get_password(user, dccommon_consts.SERVICES_USER_NAME)
                )

            # Ansible inventory filename for the specified subcloud
            ansible_subcloud_inventory_file = utils.get_ansible_filename(
                subcloud.name, INVENTORY_FILE_POSTFIX
            )

            # Create the ansible inventory for the new subcloud
            utils.create_subcloud_inventory(
                payload, ansible_subcloud_inventory_file, initial_deployment
            )

            if not enroll:
                # create subcloud intermediate certificate and pass in keys
                self._create_intermediate_ca_cert(payload)

            # Write this subclouds overrides to file
            # NOTE: This file should not be deleted if subcloud add fails
            # as it is used for debugging
            self._write_subcloud_ansible_config(cached_regionone_data, payload)

            # To add a 'secondary' subcloud, save payload into DB
            # for day-2's migrate purpose.
            if secondary:
                # remove unused parameters
                if "secondary" in original_payload:
                    del original_payload["secondary"]
                if "ansible_ssh_pass" in original_payload:
                    del original_payload["ansible_ssh_pass"]
                if "sysadmin_password" in original_payload:
                    del original_payload["sysadmin_password"]
                if "ansible_become_pass" in original_payload:
                    del original_payload["ansible_become_pass"]
                if "admin_password" in original_payload:
                    # Encode admin_password
                    original_payload["admin_password"] = base64.b64encode(
                        original_payload["admin_password"].encode("utf-8")
                    ).decode("utf-8")
                bootstrap_info = utils.create_subcloud_rehome_data_template()
                bootstrap_info["saved_payload"] = original_payload
                rehome_data = json.dumps(bootstrap_info)
                deploy_state = consts.DEPLOY_STATE_SECONDARY

            if not rehoming and not secondary:
                deploy_state = consts.DEPLOY_STATE_CREATED

            LOG.info(f"Successfully created subcloud {payload['name']}")

        except Exception:
            LOG.exception("Failed to create subcloud %s" % payload["name"])
            # If we failed to create the subcloud, update the deployment status

            if rehoming:
                deploy_state = consts.DEPLOY_STATE_REHOME_PREP_FAILED
            elif secondary:
                deploy_state = consts.DEPLOY_STATE_SECONDARY_FAILED
            else:
                deploy_state = consts.DEPLOY_STATE_CREATE_FAILED

        subcloud = db_api.subcloud_update(
            context, subcloud.id, deploy_status=deploy_state, rehome_data=rehome_data
        )

        # The RPC call must return the subcloud as a dictionary, otherwise it
        # should return the DB object for dcmanager internal use (subcloud add)
        if return_as_dict:
            subcloud = db_api.subcloud_db_model_to_dict(subcloud)

        return subcloud

    def subcloud_deploy_install(
        self,
        context,
        subcloud_id,
        payload: dict,
        initial_deployment=False,
        previous_version=None,
    ) -> bool:
        """Install subcloud

        :param context: request context object
        :param subcloud_id: subcloud id from db
        :param payload: subcloud Install
        :param initial_deployment: initial_deployment flag from subcloud inventory
        :param previous_version: previous subcloud software version
        :return: success status
        """

        # Retrieve the subcloud details from the database
        software_version = payload["software_version"]
        subcloud = db_api.subcloud_update(
            context,
            subcloud_id,
            software_version=software_version,
            deploy_status=consts.DEPLOY_STATE_PRE_INSTALL,
            data_install=json.dumps(payload["install_values"]),
            error_description=consts.ERROR_DESC_EMPTY,
        )

        # Notify dcorch of the software version update
        if previous_version and previous_version != software_version:
            self.dcorch_rpc_client.update_subcloud_version(
                self.context, subcloud.region_name, software_version
            )

        LOG.info(f"Installing subcloud {subcloud.name}.")

        try:
            log_file = (
                os.path.join(consts.DC_ANSIBLE_LOG_DIR, subcloud.name)
                + "_playbook_output.log"
            )
            ansible_subcloud_inventory_file = self._get_ansible_filename(
                subcloud.name, INVENTORY_FILE_POSTFIX
            )

            install_command = self._deploy_install_prep(
                subcloud, payload, ansible_subcloud_inventory_file, initial_deployment
            )
            install_success = self._run_subcloud_install(
                context, subcloud, install_command, log_file, payload["install_values"]
            )
            if install_success:
                db_api.subcloud_update(
                    context,
                    subcloud.id,
                    deploy_status=consts.DEPLOY_STATE_INSTALLED,
                    error_description=consts.ERROR_DESC_EMPTY,
                )
            return install_success

        except Exception:
            LOG.exception(f"Failed to install subcloud {subcloud.name}")
            # If we failed to install the subcloud,
            # update the deployment status
            db_api.subcloud_update(
                context,
                subcloud_id,
                deploy_status=consts.DEPLOY_STATE_PRE_INSTALL_FAILED,
            )
            return False

    def subcloud_deploy_enroll(self, context, subcloud_id, payload: dict):

        db_api.subcloud_update(
            context, subcloud_id, deploy_status=consts.DEPLOY_STATE_PRE_INIT_ENROLL
        )

        subcloud = db_api.subcloud_get(context, subcloud_id)

        if self.subcloud_init_enroll(context, subcloud.id, payload):
            try:
                # based upon primary IP of oam dual-stack
                endpoint = (
                    "https://"
                    + utils.format_address(
                        payload.get("external_oam_floating_address").split(",")[0]
                    )
                    + ":6385"
                )
                subcloud_region_name = utils.get_region_name(endpoint)

                # The region name in the payload was randomly generated, need to
                # update to the correct one get from the subcloud
                payload["region_name"] = subcloud_region_name

                subcloud = db_api.subcloud_update(
                    context,
                    subcloud_id,
                    region_name=subcloud_region_name,
                    deploy_status=consts.DEPLOY_STATE_PRE_ENROLL,
                )

                # TODO(glyraper): Use the RPC Transport allow_remote_exmods
                #  parameter to re-raise serialized remote exceptions.
                # Subcloud may already be created in dcorch db
                # in a previous process, if so, we should ignore
                # the creation.
                try:
                    # Inform orchestrator that subcloud has been added
                    self.dcorch_rpc_client.add_subcloud(
                        context,
                        subcloud.region_name,
                        subcloud.software_version,
                        subcloud.management_start_ip,
                    )

                except oslo_message_rpc.client.RemoteError as ex:
                    if "duplicate key value violates unique constraint" in str(ex):
                        pass

                self._create_intermediate_ca_cert(payload=payload)

                self._deploy_bootstrap_enroll_prep("enroll", context, payload, subcloud)

                log_file = (
                    os.path.join(consts.DC_ANSIBLE_LOG_DIR, subcloud.name)
                    + "_playbook_output.log"
                )
                ansible_subcloud_inventory_file = self._get_ansible_filename(
                    subcloud.name, INVENTORY_FILE_POSTFIX
                )
                utils.create_subcloud_inventory_with_admin_creds(
                    subcloud.name,
                    ansible_subcloud_inventory_file,
                    payload[consts.BOOTSTRAP_ADDRESS],
                    ansible_pass=json.dumps(payload["sysadmin_password"]),
                )

                enroll_playbook_command = self.compose_enroll_command(
                    subcloud.name,
                    subcloud.region_name,
                    ansible_subcloud_inventory_file,
                    subcloud.software_version,
                    state="enroll",
                )
                return self._run_subcloud_enroll(
                    context,
                    subcloud,
                    enroll_playbook_command,
                    log_file,
                    region_name=subcloud_region_name,
                )

            except Exception:
                LOG.exception(f"Failed to enroll subcloud {subcloud.name}")
                db_api.subcloud_update(
                    context,
                    subcloud_id,
                    deploy_status=consts.DEPLOY_STATE_PRE_ENROLL_FAILED,
                )
                return False
        else:
            LOG.error(f"Initial enrollment failed for subcloud {subcloud.name}")
            return False

    def subcloud_deploy_bootstrap(
        self, context, subcloud_id, payload, initial_deployment=False
    ):
        """Bootstrap subcloud

        :param context: request context object
        :param subcloud_id: subcloud_id from db
        :param payload: subcloud bootstrap configuration
        :param initial_deployment: initial_deployment flag from subcloud inventory
        :return: success status
        """
        LOG.info("Bootstrapping subcloud %s." % payload["name"])

        # Retrieve the subcloud details from the database
        subcloud = db_api.subcloud_get(context, subcloud_id)

        try:
            log_file = (
                os.path.join(consts.DC_ANSIBLE_LOG_DIR, subcloud.name)
                + "_playbook_output.log"
            )

            bootstrap_command = self._deploy_bootstrap_prep(
                context,
                subcloud,
                payload,
                initial_deployment,
            )
            bootstrap_success = self._run_subcloud_bootstrap(
                context, subcloud, bootstrap_command, log_file
            )
            return bootstrap_success

        except Exception:
            LOG.exception("Failed to bootstrap subcloud %s" % payload["name"])
            db_api.subcloud_update(
                context,
                subcloud_id,
                deploy_status=consts.DEPLOY_STATE_PRE_BOOTSTRAP_FAILED,
                error_description=consts.ERROR_DESC_EMPTY,
            )
            return False

    def subcloud_deploy_config(
        self, context, subcloud_id, payload: dict, initial_deployment=False
    ) -> bool:
        """Configure subcloud

        :param context: request context object
        :param subcloud_id: subcloud_id from db
        :param payload: subcloud configuration
        :param initial_deployment: initial_deployment flag from subcloud inventory
        :return: success status
        """
        LOG.info("Configuring subcloud %s." % subcloud_id)

        subcloud = db_api.subcloud_update(
            context,
            subcloud_id,
            deploy_status=consts.DEPLOY_STATE_PRE_CONFIG,
            error_description=consts.ERROR_DESC_EMPTY,
        )
        try:
            log_file = (
                os.path.join(consts.DC_ANSIBLE_LOG_DIR, subcloud.name)
                + "_playbook_output.log"
            )
            # Ansible inventory filename for the specified subcloud
            ansible_subcloud_inventory_file = self._get_ansible_filename(
                subcloud.name, INVENTORY_FILE_POSTFIX
            )

            config_command = self._deploy_config_prep(
                subcloud, payload, ansible_subcloud_inventory_file, initial_deployment
            )

            config_success = self._run_subcloud_config(
                subcloud, context, config_command, log_file
            )
            return config_success

        except Exception:
            LOG.exception("Failed to configure %s" % subcloud.name)
            db_api.subcloud_update(
                context,
                subcloud_id,
                deploy_status=consts.DEPLOY_STATE_PRE_CONFIG_FAILED,
            )
            return False

    def subcloud_deploy_complete(self, context, subcloud_id):
        """Completes the subcloud deployment.

        :param context: request context object
        :param subcloud_id: subcloud_id from db
        :return: resulting subcloud dictionary
        """
        LOG.info("Completing subcloud %s deployment." % subcloud_id)

        # Just update the deploy status
        subcloud = db_api.subcloud_update(
            context,
            subcloud_id,
            deploy_status=consts.DEPLOY_STATE_DONE,
            error_description=consts.ERROR_DESC_EMPTY,
        )

        LOG.info(
            "Subcloud %s deploy status set to: %s"
            % (subcloud_id, consts.DEPLOY_STATE_DONE)
        )

        return db_api.subcloud_db_model_to_dict(subcloud)

    def _subcloud_operation_notice(
        self, operation, restore_subclouds, failed_subclouds, invalid_subclouds
    ):
        all_failed = (
            not set(restore_subclouds) - set(failed_subclouds)
        ) and not invalid_subclouds
        if all_failed:
            LOG.error("Backup %s failed for all applied subclouds" % operation)
            raise exceptions.SubcloudBackupOperationFailed(operation=operation)

        if invalid_subclouds:
            self._warn_for_invalid_subclouds_on_backup_operation(invalid_subclouds)
        if failed_subclouds:
            self._warn_for_failed_subclouds_on_backup_operation(
                operation, failed_subclouds
            )

        if invalid_subclouds or failed_subclouds:
            return self._build_subcloud_operation_notice(
                operation, failed_subclouds, invalid_subclouds
            )
        return

    def _filter_subclouds_with_ongoing_backup(self, subclouds):
        i = 0
        while i < len(subclouds):
            subcloud = subclouds[i]
            if subcloud.backup_status in consts.STATES_FOR_ONGOING_BACKUP:
                LOG.info(
                    _(
                        "Subcloud %s already has a backup operation in progress"
                        % subcloud.name
                    )
                )
                subclouds.pop(i)
            else:
                i += 1

    def _validate_subclouds_for_backup(
        self, subclouds, operation, bootstrap_address_dict=None
    ):
        valid_subclouds = []
        invalid_subclouds = []
        for subcloud in subclouds:
            is_valid = False
            try:
                if utils.is_valid_for_backup_operation(
                    operation, subcloud, bootstrap_address_dict
                ):
                    is_valid = True

            except exceptions.ValidateFail:
                is_valid = False

            if is_valid:
                valid_subclouds.append(subcloud)
            else:
                invalid_subclouds.append(subcloud)

        return valid_subclouds, invalid_subclouds

    def subcloud_init_enroll(self, context, subcloud_id, payload: dict) -> bool:
        """Init subcloud enroll

        :param context: request context object
        :param subcloud_id: subcloud id from db
        :param payload: subcloud Install
        :param initial_deployment: initial_deployment flag from subcloud inventory
        :return: success status
        """

        subcloud = db_api.subcloud_get(context, subcloud_id)

        LOG.info("Initiating subcloud %s enrollment." % subcloud.name)

        try:
            enrollment = SubcloudEnrollmentInit(subcloud.name)
            subcloud_primary_oam_ip_family = utils.get_primary_oam_address_ip_family(
                subcloud
            )
            enrollment.prep(
                dccommon_consts.ANSIBLE_OVERRIDES_PATH,
                payload,
                subcloud_primary_oam_ip_family,
            )

            # Retrieve the subcloud details from the database
            subcloud = db_api.subcloud_update(
                context,
                subcloud_id,
                deploy_status=consts.DEPLOY_STATE_INITIATING_ENROLL,
                data_install=json.dumps(payload["install_values"]),
                software_version=payload["software_version"],
            )

            # TODO(glyraper): log_file to be used in the playbook execution
            # log_file = (
            #     os.path.join(consts.DC_ANSIBLE_LOG_DIR, subcloud.name)
            #     + "_playbook_output.log"
            # )
            ansible_subcloud_inventory_file = self._get_ansible_filename(
                subcloud.name, INVENTORY_FILE_POSTFIX
            )
            init_enroll_command = self._deploy_install_prep(
                subcloud, payload, ansible_subcloud_inventory_file, init_enroll=True
            )
            if enrollment.enroll_init(consts.DC_ANSIBLE_LOG_DIR, init_enroll_command):
                LOG.info(
                    "Subcloud enrollment initial phase successful "
                    f"for subcloud {subcloud.name}"
                )

                db_api.subcloud_update(
                    context,
                    subcloud_id,
                    deploy_status=consts.DEPLOY_STATE_INIT_ENROLL_COMPLETE,
                    error_description=consts.ERROR_DESC_EMPTY,
                )
                return True

        except Exception as e:
            # If we failed to initiate the subcloud enroll,
            # save the error message and update the deployment status
            msg = utils.find_and_save_ansible_error_msg(
                context,
                subcloud,
                log_file=(
                    f"{os.path.join(consts.DC_ANSIBLE_LOG_DIR, subcloud.name)}"
                    "_playbook_output.log"
                ),
                exception=e,
                stage=consts.DEPLOY_STATE_ENROLLING,
                deploy_status=consts.DEPLOY_STATE_PRE_INIT_ENROLL_FAILED,
            )
            LOG.error(msg)
            return False

    @staticmethod
    def _mark_invalid_subclouds_for_backup(context, invalid_subclouds):
        try:
            invalid_ids = {subcloud.id for subcloud in invalid_subclouds}
            invalid_names = {subcloud.name for subcloud in invalid_subclouds}

            if invalid_ids:
                # Set state on subclouds that failed validation
                LOG.warn(
                    "The following subclouds are not online and/or managed and/or "
                    "in a valid deploy state, and will not be backed up: %s",
                    ", ".join(list(invalid_names)),
                )
                SubcloudManager._update_backup_status_by_ids(
                    context, invalid_ids, consts.BACKUP_STATE_VALIDATE_FAILED
                )

        except DCManagerException as ex:
            LOG.exception("Subcloud backup validation failed")
            raise ex

    @staticmethod
    def _warn_for_invalid_subclouds_on_backup_operation(invalid_subclouds):
        invalid_names = {subcloud.name for subcloud in invalid_subclouds}
        LOG.warn(
            "The following subclouds were not online and/or in a valid "
            "deploy/management state, and thus were not be reached "
            "for backup operation: %s",
            ", ".join(list(invalid_names)),
        )

    @staticmethod
    def _warn_for_failed_subclouds_on_backup_operation(operation, failed_subclouds):
        failed_names = {subcloud.name for subcloud in failed_subclouds}
        LOG.warn(
            "Backup %s operation failed for some subclouds, "
            "check previous logs for details. Failed subclouds: %s"
            % (operation, ", ".join(list(failed_names)))
        )

    @staticmethod
    def _update_backup_status(context, subclouds, backup_status):
        subcloud_ids = [subcloud.id for subcloud in subclouds]
        return SubcloudManager._update_backup_status_by_ids(
            context, subcloud_ids, backup_status
        )

    @staticmethod
    def _update_backup_status_by_ids(context, subcloud_ids, backup_status):
        validate_state_form = {Subcloud.backup_status.name: backup_status}
        db_api.subcloud_bulk_update_by_ids(context, subcloud_ids, validate_state_form)

    @staticmethod
    def _run_parallel_group_operation(op_type, op_function, thread_pool, subclouds):
        failed_subclouds = []
        processed = 0

        for subcloud, success in thread_pool.imap(op_function, subclouds):
            processed += 1

            if not success:
                failed_subclouds.append(subcloud)

            completion = float(processed) / float(len(subclouds)) * 100
            remaining = len(subclouds) - processed
            LOG.info(
                "Processed subcloud %s for %s (operation %.0f%% "
                "complete, %d subcloud(s) remaining)"
                % (subcloud.name, op_type, completion, remaining)
            )

        return failed_subclouds

    def _backup_subcloud(self, context, payload, subcloud):
        try:
            # Health check validation
            if not utils.is_subcloud_healthy(
                subcloud.region_name, subcloud_ip=subcloud.management_start_ip
            ):
                db_api.subcloud_update(
                    context,
                    subcloud.id,
                    backup_status=consts.BACKUP_STATE_VALIDATE_FAILED,
                )
                LOG.info(
                    ("Subcloud %s is not in good health for subcloud-backup create")
                    % subcloud.name
                )
                return subcloud, False

            db_api.subcloud_update(
                context,
                subcloud.id,
                backup_status=consts.BACKUP_STATE_PRE_BACKUP,
                error_description=consts.ERROR_DESC_EMPTY,
            )

            subcloud_inventory_file = self._create_subcloud_inventory_file(subcloud)

            # Prepare for backup
            overrides_file = self._create_overrides_for_backup_or_restore(
                "create", payload, subcloud.name
            )
            backup_command = self.compose_backup_command(
                subcloud.name, subcloud_inventory_file
            )

            self._clear_subcloud_backup_failure_alarm_if_exists(subcloud)
        except Exception:
            self._fail_subcloud_backup_prep(context, subcloud)
            return subcloud, False

        local_only = payload.get("local_only") or False
        success = self._run_subcloud_backup_create_playbook(
            subcloud, backup_command, context, local_only
        )

        if success:
            utils.delete_subcloud_inventory(overrides_file)

        return subcloud, success

    def _filter_subclouds_for_backup_delete(self, context, payload, local_delete):
        subcloud_id = payload.get("subcloud")
        group_id = payload.get("group")

        # Retrieve either a single subcloud or all subclouds in a group
        subclouds = (
            [db_api.subcloud_get(context, subcloud_id)]
            if subcloud_id
            else db_api.subcloud_get_for_group(context, group_id)
        )
        invalid_subclouds = []

        # Subcloud state validation only required for local delete
        if local_delete:
            # Use same criteria defined for subcloud backup create
            subclouds_to_delete_backup, invalid_subclouds = (
                self._validate_subclouds_for_backup(subclouds, "delete")
            )
        else:
            # Otherwise, validation is unnecessary, since connection is not required
            subclouds_to_delete_backup = subclouds

        return subclouds_to_delete_backup, invalid_subclouds

    def _delete_subcloud_backup(self, context, payload, release_version, subcloud):
        try:
            overrides_file = self._create_overrides_for_backup_delete(
                payload, subcloud.name, release_version
            )
            inventory_file = None
            if payload["override_values"]["local"]:
                inventory_file = self._create_subcloud_inventory_file(subcloud)
            delete_command = self.compose_backup_delete_command(
                subcloud.name, inventory_file
            )
        except Exception:
            LOG.exception(
                "Failed to prepare subcloud %s for backup delete" % subcloud.name
            )
            return subcloud, False

        success = self._run_subcloud_backup_delete_playbook(
            context, subcloud, delete_command
        )

        if success:
            utils.delete_subcloud_inventory(overrides_file)

        return subcloud, success

    @staticmethod
    def _stage_auto_restore_files(
        stage_dir: Path, overrides_file: Path, payload: dict, subcloud: Subcloud
    ) -> str:
        """Stage auto-restore files in a directory for subcloud auto-restore.

        Creates an 'auto-restore' directory and hard links the required files into it.
        Hard links are used instead of symlinks because gen-bootloader-iso.sh uses
        rsync -a, which will properly copy the actual file content during the
        update_iso phase into the miniboot ISO.
        """
        target_path = Path(stage_dir) / "auto-restore"
        target_path.mkdir()

        LOG.info(
            f"Staging auto-restore files for subcloud {subcloud.name} into: "
            f"{target_path}"
        )

        # Stage the restore overrides file
        destination_file = target_path / "backup_restore_values.yml"
        os.link(overrides_file, destination_file)
        os.chmod(destination_file, 0o600)

        # Stage the subcloud backup file
        if not payload["local_only"] and not payload.get("factory"):
            central_backup = utils.find_central_subcloud_backup(
                subcloud.name, payload.get("software_version")
            )
            destination_file = target_path / central_backup.name
            os.link(central_backup, destination_file)

        return os.fspath(target_path)

    @staticmethod
    def _get_auto_restore_temp_dir_location(
        subcloud: Subcloud, payload: dict
    ) -> Optional[Path]:
        """Get the directory where temp folder should be created"""
        if payload.get("local_only") or payload.get("factory"):
            # For local-only or factory auto-retores, we only need to
            # copy the restore overrides file, so we create a temp dir
            # inside ANSIBLE_OVERRIDES_PATH as that will always exist
            return Path(dccommon_consts.ANSIBLE_OVERRIDES_PATH)
        try:
            # For remote auto-restore, we need to copy the backup file
            # and the restore overrides, so we use the following dir:
            # CENTRAL_BACKUP_DIR / subcloud_name / software_version
            central_backup = utils.find_central_subcloud_backup(
                subcloud.name, payload.get("software_version")
            )
            return central_backup.parent
        except FileNotFoundError:
            LOG.exception(
                "Unable to find subcloud backup for remote auto-restore, make "
                "sure a subcloud backup was created without --local-only"
            )
            raise

    def _create_auto_restore_user_data(self, temp_dir: str, subcloud_name: str) -> None:
        """Create cloud-init user-data file for auto-restore

        The seed iso will be mounted into the subcloud and the backup archive and
        restore override values will be copied into the SUBCLOUD_AUTO_RESTORE_DIR.
        Then the dc-auto-restore service is started, triggering the auto-restore
        operation inside the subcloud.
        """
        runcmd = [
            [
                "/bin/bash",
                "-c",
                "echo $(date): Starting auto-restore from seed ISO",
            ],
            ["mkdir", "-p", "/mnt/seed-iso"],
            ["mount", "LABEL=CIDATA", "/mnt/seed-iso"],
            [
                "cp",
                "-r",
                "/mnt/seed-iso/auto-restore",
                f"{consts.SUBCLOUD_AUTO_RESTORE_DIR}",
            ],
            [
                "/bin/bash",
                "-c",
                f"if [ ! -f {consts.SUBCLOUD_AUTO_RESTORE_DIR}/"
                "backup_restore_values.yml ]; then "
                "echo 'ERROR: backup_restore_values.yml not found'; "
                "exit 1; fi",
            ],
            [
                "/bin/bash",
                "-c",
                "echo 'Auto-restore files copied:'; "
                f"ls -la {consts.SUBCLOUD_AUTO_RESTORE_DIR}",
            ],
            ["umount", "/mnt/seed-iso"],
            ["rmdir", "/mnt/seed-iso"],
            [
                "/bin/bash",
                "-c",
                "echo 'Starting auto-restore service'; "
                "systemctl start dc-auto-restore.service",
            ],
            [
                "/bin/bash",
                "-c",
                "echo $(date): Auto-restore seed processing completed successfully",
            ],
        ]
        user_data_content = {
            "network": {"config": "disabled"},
            "runcmd": runcmd,
            "cloud_config_modules": [["runcmd", "always"]],
            "cloud_final_modules": [["scripts-user", "always"]],
        }

        user_data_file = os.path.join(temp_dir, "user-data")
        with open(user_data_file, "w", encoding="utf-8") as f:
            f.write("#cloud-config\n")
            yaml.dump(user_data_content, f, default_flow_style=False, sort_keys=False)

        LOG.info(f"Created user-data for auto-restore seed ISO for {subcloud_name}")

    def _create_auto_restore_meta_data(self, temp_dir: str, subcloud_name: str) -> None:
        meta_data_content = {"instance-id": f"{subcloud_name}"}

        meta_data_file = os.path.join(temp_dir, "meta-data")
        with open(meta_data_file, "w", encoding="utf-8") as f:
            yaml.dump(meta_data_content, f, default_flow_style=False)

        LOG.info(f"Created meta-data for auto-restore seed ISO for {subcloud_name}")

    def _generate_auto_restore_seed_iso(
        self, subcloud: Subcloud, overrides_file: str, payload: dict
    ) -> str:
        try:
            software_version = str(payload.get("software_version"))
            www_root = os.path.join("/opt/platform/iso", software_version)
            iso_dir_path = os.path.join(www_root, "nodes", subcloud.name)
            iso_output_path = os.path.join(
                iso_dir_path, dccommon_consts.AUTO_RESTORE_SEED_ISO_NAME
            )

            if not os.path.isdir(www_root):
                os.mkdir(www_root, 0o755)
            if not os.path.isdir(iso_dir_path):
                os.makedirs(iso_dir_path, 0o755, exist_ok=True)
            elif os.path.exists(iso_output_path):
                # Clean up iso file if it already exists.
                LOG.info(
                    f"Found preexisting seed iso for subcloud {subcloud.name}, "
                    "cleaning up"
                )
                os.remove(iso_output_path)

            LOG.info(
                f"Generating auto-restore seed ISO for {subcloud.name}: "
                f"{iso_output_path}"
            )

            # Create the cloud-init ISO structure in a single temp directory
            with tempfile.TemporaryDirectory(
                prefix=f".{subcloud.name}",
                dir=self._get_auto_restore_temp_dir_location(subcloud, payload),
            ) as temp_iso_dir:
                self._create_auto_restore_user_data(temp_iso_dir, subcloud.name)
                self._create_auto_restore_meta_data(temp_iso_dir, subcloud.name)

                self._stage_auto_restore_files(
                    Path(temp_iso_dir), Path(overrides_file), payload, subcloud
                )

                gen_seed_iso_command = [
                    "genisoimage",
                    "-o",
                    iso_output_path,
                    "-volid",
                    "CIDATA",
                    "-untranslated-filenames",
                    "-joliet",
                    "-rock",
                    "-iso-level",
                    "2",
                    temp_iso_dir,
                ]

                LOG.info(f"Running auto-restore ISO generation: {gen_seed_iso_command}")
                result = subprocess.run(
                    gen_seed_iso_command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                )

                output = result.stdout.decode("utf-8").replace("\n", ", ")

                if result.returncode == 0:
                    LOG.info(
                        "Successfully generated auto-restore seed ISO for %s: "
                        "returncode: %s, output: %s",
                        subcloud.name,
                        result.returncode,
                        output,
                    )
                    return iso_output_path

                LOG.error(
                    "Failed to generate auto-restore seed ISO for %s: "
                    "returncode: %s, output: %s",
                    subcloud.name,
                    result.returncode,
                    output,
                )
                return None

        except Exception as e:
            LOG.exception(
                f"Exception generating auto-restore seed ISO for {subcloud.name}: {e}"
            )
            return None

    def _cleanup_auto_restore_seed_iso(self, iso_path: str) -> None:
        try:
            if iso_path and os.path.exists(iso_path):
                os.remove(iso_path)
                LOG.info(f"Cleaned up auto-restore seed ISO: {iso_path}")
        except Exception as e:
            LOG.warning(f"Failed to cleanup auto-restore seed ISO {iso_path}: {e}")

    def _create_rvmc_config_for_seed_iso(
        self, subcloud: Subcloud, payload: dict
    ) -> str:
        override_path = os.path.join(
            dccommon_consts.ANSIBLE_OVERRIDES_PATH, subcloud.name
        )

        if not os.path.exists(override_path):
            os.makedirs(override_path, 0o755)

        sysinv_client = SysinvClient(
            dccommon_utils.get_region_one_name(),
            endpoint_cache.EndpointCache.get_admin_session(),
        )

        https_enabled = sysinv_client.get_system().capabilities.get(
            "https_enabled", False
        )
        subcloud_primary_oam_ip_family = utils.get_primary_oam_address_ip_family(
            subcloud
        )
        image_base_url = SubcloudInstall.get_image_base_url(
            https_enabled, sysinv_client, subcloud_primary_oam_ip_family
        )

        install_values = payload.get("install_values", {})
        bmc_values = {
            "bmc_username": install_values.get("bmc_username"),
            "bmc_password": install_values.get("bmc_password"),
            "bmc_address": install_values.get("bmc_address"),
            "image": os.path.join(
                image_base_url,
                "iso",
                payload["software_version"],
                "nodes",
                subcloud.name,
                dccommon_consts.AUTO_RESTORE_SEED_ISO_NAME,
            ),
        }

        for value in dccommon_consts.OPTIONAL_BMC_INSTALL_VALUES:
            if value in install_values:
                bmc_values[value] = install_values.get(value)

        SubcloudInstall.create_rvmc_config_file(override_path, bmc_values)

        rvmc_config_path = os.path.join(
            override_path, dccommon_consts.RVMC_CONFIG_FILE_NAME
        )
        LOG.info(
            "Created RVMC config for auto-restore seed ISO for "
            f"subcloud {subcloud.name}: {rvmc_config_path}"
        )
        return rvmc_config_path

    def _restore_subcloud_backup(self, context, payload, subcloud):
        log_file = (
            os.path.join(consts.DC_ANSIBLE_LOG_DIR, subcloud.name)
            + "_playbook_output.log"
        )

        bmc_access_only = True
        seed_iso_path = None

        if payload.get("factory"):
            auto_restore_mode = "factory"
        elif payload.get("auto"):
            auto_restore_mode = "auto"
        else:
            auto_restore_mode = None
            bmc_access_only = False

        # To get the bootstrap_address for the subcloud, we considered
        # the following order:
        # 1) Use the value from restore_values if present
        # 2) Use the value from install_values if present
        # 3) Use the value from the current inventory file if it exist
        # To reach this part of the code, one of the above conditions is True
        bootstrap_address_dict = payload.get("restore_values", {}).get(
            "bootstrap_address", {}
        )
        if bootstrap_address_dict.get(subcloud.name):
            LOG.debug(
                "Using bootstrap_address from restore_values for subcloud %s"
                % subcloud.name
            )
            bootstrap_address = bootstrap_address_dict.get(subcloud.name)
        elif subcloud.data_install:
            LOG.debug(
                "Using bootstrap_address from install_values for subcloud %s"
                % subcloud.name
            )
            data_install = json.loads(subcloud.data_install)
            bootstrap_address = data_install.get("bootstrap_address")
        else:
            LOG.debug(
                "Using bootstrap_address from previous inventory file for subcloud %s"
                % subcloud.name
            )
            bootstrap_address = utils.get_ansible_host_ip_from_inventory(subcloud.name)

        try:
            db_api.subcloud_update(
                context,
                subcloud.id,
                deploy_status=consts.DEPLOY_STATE_PRE_RESTORE,
                error_description=consts.ERROR_DESC_EMPTY,
            )
            subcloud_inventory_file = self._create_subcloud_inventory_file(
                subcloud, bootstrap_address=bootstrap_address
            )

            # Install wipe_osds parameter is required to determine if
            # the OSDs should be wiped during restore when --with-install
            # subcommand is provided.
            install_wipe_osds = False
            if payload.get("with_install"):
                data_install = json.loads(subcloud.data_install)
                install_wipe_osds = data_install.get("wipe_osds", False)

            # Prepare for restore
            overrides_file = self._create_overrides_for_backup_or_restore(
                "restore",
                payload,
                subcloud.name,
                auto_restore_mode,
                install_wipe_osds,
                subcloud_region_name=subcloud.region_name,
            )

            restore_command = self.compose_backup_restore_command(
                subcloud.name,
                subcloud_inventory_file,
                auto_restore_mode,
                payload.get("with_install"),
            )

            # Handle auto-restore without install using seed ISO
            if auto_restore_mode == "auto" and not payload.get("with_install"):
                LOG.info(
                    f"Performing auto-restore without install for {subcloud.name} "
                    f"using seed ISO approach"
                )

                seed_iso_path = self._generate_auto_restore_seed_iso(
                    subcloud, overrides_file, payload
                )

                if not seed_iso_path:
                    raise Exception("Failed to generate auto-restore seed ISO")

                data_install = json.loads(subcloud.data_install)
                if payload.get("install_values"):
                    payload.get("install_values").update(data_install)
                else:
                    payload["install_values"] = data_install

                self._create_rvmc_config_for_seed_iso(subcloud, payload)

        except Exception:
            db_api.subcloud_update(
                context,
                subcloud.id,
                deploy_status=consts.DEPLOY_STATE_RESTORE_PREP_FAILED,
            )
            LOG.exception(
                f"Failed to prepare subcloud {subcloud.name} for backup restore"
            )
            return subcloud, False

        if payload.get("with_install"):
            data_install = json.loads(subcloud.data_install)
            software_version = payload.get("software_version")
            install_command = self.compose_install_command(
                subcloud.name,
                subcloud_inventory_file,
                software_version,
                bmc_access_only,
            )
            # Update data_install with missing data
            matching_iso, _ = utils.get_vault_load_files(software_version)
            data_install["software_version"] = software_version
            data_install["image"] = matching_iso
            data_install["ansible_ssh_pass"] = payload["sysadmin_password"]
            data_install["ansible_become_pass"] = payload["sysadmin_password"]

            # Notify dcorch of the software version update
            if subcloud.software_version != software_version:
                self.dcorch_rpc_client.update_subcloud_version(
                    context, subcloud.region_name, software_version
                )

            auto_restore_context = (
                tempfile.TemporaryDirectory(
                    prefix=f".{subcloud.name}",
                    dir=self._get_auto_restore_temp_dir_location(subcloud, payload),
                )
                if auto_restore_mode
                else nullcontext()
            )

            kickstart_uri = None
            if auto_restore_mode == "factory":
                kickstart_uri = (
                    "partition://platform_backup:factory/"
                    f"{software_version}/miniboot.cfg"
                )

            with auto_restore_context as temp_dir:
                # Stage the auto-restore files so they can be copied to the
                # miniboot ISO during subcloud installation. These files will
                # end up in /opt/platform-backup/auto-restore on the subcloud
                include_paths = None
                if temp_dir:
                    include_paths = [
                        self._stage_auto_restore_files(
                            temp_dir, Path(overrides_file), payload, subcloud
                        )
                    ]

                install_success = self._run_subcloud_install(
                    context,
                    subcloud,
                    install_command,
                    log_file,
                    data_install,
                    include_paths,
                    kickstart_uri,
                )

            if not install_success:
                return subcloud, False

        try:
            success = self._run_subcloud_backup_restore_playbook(
                subcloud, restore_command, context, log_file, auto_restore_mode
            )

            if success:
                utils.delete_subcloud_inventory(overrides_file)

            return subcloud, success

        finally:
            if seed_iso_path:
                self._cleanup_auto_restore_seed_iso(seed_iso_path)

    @staticmethod
    def _build_subcloud_operation_notice(
        operation, failed_subclouds, invalid_subclouds
    ):
        invalid_subcloud_names = [subcloud.name for subcloud in invalid_subclouds]
        failed_subcloud_names = [subcloud.name for subcloud in failed_subclouds]

        notice = "Subcloud backup %s operation completed with warnings:\n" % operation
        if invalid_subclouds:
            notice += (
                "The following subclouds were skipped for local backup "
                "%s operation: %s." % (operation, " ,".join(invalid_subcloud_names))
            )
        if failed_subclouds:
            notice += (
                "The following subclouds failed during backup "
                "%s operation: %s." % (operation, " ,".join(failed_subcloud_names))
            )
        return notice

    def _create_subcloud_inventory_file(
        self, subcloud, bootstrap_address=None, initial_deployment=False
    ):
        # Ansible inventory filename for the specified subcloud
        ansible_subcloud_inventory_file = self._get_ansible_filename(
            subcloud.name, INVENTORY_FILE_POSTFIX
        )

        if not bootstrap_address:
            # Use subcloud floating IP for host reachability
            keystone_endpoint = dccommon_utils.build_subcloud_endpoint(
                subcloud.management_start_ip, dccommon_consts.ENDPOINT_NAME_KEYSTONE
            )
            admin_session = endpoint_cache.EndpointCache.get_admin_session(
                auth_url=keystone_endpoint
            )
            # interested in subcloud's primary OAM address only
            bootstrap_address = utils.get_oam_floating_ip_primary(
                subcloud, admin_session
            )

        # Add parameters used to generate inventory
        subcloud_params = {
            "name": subcloud.name,
            "bootstrap-address": bootstrap_address,
        }

        utils.create_subcloud_inventory(
            subcloud_params, ansible_subcloud_inventory_file, initial_deployment
        )
        return ansible_subcloud_inventory_file

    @staticmethod
    def _get_auto_restore_backup_dir(payload: dict, auto_restore_mode: str) -> str:
        sw_version = payload.get("software_version")
        if auto_restore_mode == "factory":
            return os.path.join(consts.SUBCLOUD_FACTORY_BACKUP_DIR, sw_version)
        elif auto_restore_mode == "auto":
            if payload["local_only"]:
                return os.path.join(consts.SUBCLOUD_LOCAL_BACKUP_DIR, sw_version)
            else:
                return consts.SUBCLOUD_AUTO_RESTORE_DIR
        else:
            raise Exception(f"Invalid auto restore mode: {auto_restore_mode}")

    def _create_overrides_for_backup_or_restore(
        self,
        op,
        payload,
        subcloud_name,
        auto_restore_mode=None,
        install_wipe_osds=None,
        subcloud_region_name=None,
    ):
        # Set override names as expected by the playbook
        if not payload.get("override_values"):
            payload["override_values"] = {}

        payload["override_values"]["local"] = payload["local_only"] or False

        if op == "create":
            payload["override_values"]["backup_registry_images"] = (
                payload["registry_images"] or False
            )
            suffix = "backup_create_values"
        else:
            payload["override_values"]["restore_registry_images"] = (
                payload["registry_images"] or False
            )
            suffix = "backup_restore_values"

            # We need to map the install wipe_osds parameter to the restore
            # wipe_ceph_osds parameter, so that the restore playbook
            # can use it to determine whether to wipe the OSDs or not.
            # This is crucial because if the wipe_osds parameter is set to True
            # in install-values, but not set in restore, by default the restore
            # wipe_ceph_osds parameter will be False, skipping the wipe
            # and causing the restore to fail.
            if install_wipe_osds:
                payload["override_values"]["wipe_ceph_osds"] = install_wipe_osds

        if not payload["local_only"]:
            payload["override_values"]["central_backup_dir"] = consts.CENTRAL_BACKUP_DIR

        payload["override_values"]["ansible_ssh_pass"] = payload["sysadmin_password"]
        payload["override_values"]["ansible_become_pass"] = payload["sysadmin_password"]
        payload["override_values"]["admin_password"] = str(
            keyring.get_password("CGCS", "admin")
        )

        # The factory-installed region name is not expected to match the
        # subclouds's region name stored in the system controller, so we don't
        # add the following override for factory restore.
        if subcloud_region_name and auto_restore_mode != "factory":
            payload["override_values"]["expected_region_name"] = subcloud_region_name

        if payload.get("backup_values"):
            LOG.info(
                "Backup create: Received backup_values for subcloud %s" % subcloud_name
            )
            for key, value in payload.get("backup_values").items():
                payload["override_values"][key] = value
        elif payload.get("restore_values"):
            LOG.info(
                "Backup restore: Received restore_values for subcloud %s"
                % subcloud_name
            )
            for key, value in payload.get("restore_values").items():
                payload["override_values"][key] = value

        if op == "create" and not (
            payload["override_values"].get("max_home_dir_usage")
            or payload["local_only"]
        ):
            # For central backups, if not specified otherwise in the received
            # overrides provided by the user, we must limit the allowed size of the
            # subcloud user's home directory smaller than the default (2000),
            # since it is included in the backup.
            payload["override_values"][
                "max_home_dir_usage"
            ] = consts.DEFAULT_SUBCLOUD_CENTRAL_BACKUP_MAX_HOME_DIR_SIZE_MB

        # auto_restore_mode allows the auto restore script running inside the
        # subcloud to determine which type of restore to run
        if op == "restore" and auto_restore_mode:
            payload["override_values"]["auto_restore_mode"] = auto_restore_mode

            # Do not login into external registries during restore as it's
            # assumed the subcloud has no connectivity. Use the images from the
            # backup archives instead.
            payload["override_values"]["skip_registry_login"] = True

            # For standard restore, the following values would be defined by
            # the playbook running on the system controller. For auto restore
            # the playbook is not executed so we define the values here
            payload["override_values"]["initial_backup_dir"] = (
                self._get_auto_restore_backup_dir(payload, auto_restore_mode)
            )

            # auto-restore only supports simplex subclouds, so we use optimized
            # restore
            payload["override_values"]["restore_mode"] = "optimized"
            payload["override_values"]["skip_patches_restore"] = True
            payload["override_values"]["exclude_sw_deployments"] = True

            if auto_restore_mode == "factory":
                # For factory restore, the prestaged registry images file must
                # be inside SUBCLOUD_FACTORY_BACKUP_DIR/<sw_version>, so we
                # override the images_archive_dir variable
                payload["override_values"]["images_archive_dir"] = payload[
                    "override_values"
                ]["initial_backup_dir"]

        return self._create_backup_overrides_file(payload, subcloud_name, suffix)

    def _create_overrides_for_backup_delete(
        self, payload, subcloud_name, release_version
    ):
        # Set override names as expected by the playbook
        if not payload.get("override_values"):
            payload["override_values"] = {}

        payload["override_values"]["software_version"] = release_version

        payload["override_values"]["local"] = payload["local_only"] or False

        if not payload["local_only"]:
            payload["override_values"]["central_backup_dir"] = consts.CENTRAL_BACKUP_DIR
        else:
            payload["override_values"]["ansible_ssh_pass"] = payload[
                "sysadmin_password"
            ]
            payload["override_values"]["ansible_become_pass"] = payload[
                "sysadmin_password"
            ]

        return self._create_backup_overrides_file(
            payload, subcloud_name, "backup_delete_values"
        )

    def _create_backup_overrides_file(self, payload, subcloud_name, filename_suffix):
        backup_overrides_file = os.path.join(
            dccommon_consts.ANSIBLE_OVERRIDES_PATH,
            subcloud_name + "_" + filename_suffix + ".yml",
        )

        with open(backup_overrides_file, "w") as f_out:
            f_out.write("---\n")
            for k, v in payload["override_values"].items():
                f_out.write("%s: %s\n" % (k, json.dumps(v)))

        return backup_overrides_file

    def _run_subcloud_backup_create_playbook(
        self, subcloud, backup_command, context, local_only
    ):
        log_file = (
            os.path.join(consts.DC_ANSIBLE_LOG_DIR, subcloud.name)
            + "_playbook_output.log"
        )

        db_api.subcloud_update(
            context,
            subcloud.id,
            backup_status=consts.BACKUP_STATE_IN_PROGRESS,
            error_description=consts.ERROR_DESC_EMPTY,
        )

        # Run the subcloud backup playbook
        try:
            ansible = dccommon_utils.AnsiblePlaybook(subcloud.name)
            ansible.run_playbook(log_file, backup_command)

            # Decide between complete-local or complete-central
            if local_only:
                backup_status = consts.BACKUP_STATE_COMPLETE_LOCAL
            else:
                backup_status = consts.BACKUP_STATE_COMPLETE_CENTRAL

            db_api.subcloud_update(
                context,
                subcloud.id,
                backup_status=backup_status,
                backup_datetime=timeutils.utcnow(),
            )

            LOG.info("Successfully backed up subcloud %s" % subcloud.name)
            return True
        except PlaybookExecutionFailed as e:
            msg = utils.find_and_save_ansible_error_msg(
                context,
                subcloud,
                log_file,
                exception=e,
                stage=consts.BACKUP_STATE_IN_PROGRESS,
                backup_status=consts.BACKUP_STATE_FAILED,
            )
            LOG.error(msg)
            self._set_subcloud_backup_failure_alarm(subcloud)
            return False

    @staticmethod
    def _run_subcloud_backup_delete_playbook(context, subcloud, delete_command):
        log_file = (
            os.path.join(consts.DC_ANSIBLE_LOG_DIR, subcloud.name)
            + "_playbook_output.log"
        )

        try:
            # Run the subcloud backup delete playbook
            ansible = dccommon_utils.AnsiblePlaybook(subcloud.name)
            ansible.run_playbook(log_file, delete_command)

            # Set backup status to unknown after delete, since most recent backup may
            # have been deleted
            db_api.subcloud_bulk_update_by_ids(
                context,
                [subcloud.id],
                {
                    Subcloud.backup_status.name: consts.BACKUP_STATE_UNKNOWN,
                    Subcloud.backup_datetime.name: None,
                },
            )

            LOG.info("Successfully deleted backup for subcloud %s" % subcloud.name)
            return True

        except PlaybookExecutionFailed as e:
            LOG.error(
                "Failed to delete backup for subcloud %s, check individual "
                "log at %s for detailed output." % (subcloud.name, log_file)
            )

            msg = utils.find_and_save_ansible_error_msg(
                context,
                subcloud,
                log_file,
                exception=e,
                stage=consts.BACKUP_STATE_FAILED,
                operation="deleting-backup",
            )
            LOG.error(msg)
            return False

    def _run_subcloud_backup_restore_playbook(
        self, subcloud, restore_command, context, log_file, auto_restore_mode=None
    ):
        db_api.subcloud_update(
            context,
            subcloud.id,
            deploy_status=consts.DEPLOY_STATE_RESTORING,
            error_description=consts.ERROR_DESC_EMPTY,
        )
        # Run the subcloud backup restore playbook
        try:
            ansible = dccommon_utils.AnsiblePlaybook(subcloud.name)
            # The restore timeout needs to be increased a half because the default
            # of 1h is not enough to restore a duplex subcloud running rook ceph.
            restore_timeout = CONF.playbook_timeout * 1.5
            ansible.run_playbook(log_file, restore_command, timeout=restore_timeout)

            mode_str = f"{auto_restore_mode} " if auto_restore_mode else ""
            LOG.info(f"Successfully {mode_str}restore subcloud {subcloud.name}")

            complete_state = (
                consts.DEPLOY_STATE_FACTORY_RESTORE_COMPLETE
                if auto_restore_mode == "factory"
                else consts.DEPLOY_STATE_DONE
            )

            db_api.subcloud_update(context, subcloud.id, deploy_status=complete_state)
            return True
        except PlaybookExecutionFailed as e:
            msg = utils.find_and_save_ansible_error_msg(
                context,
                subcloud,
                log_file,
                exception=e,
                stage=consts.DEPLOY_STATE_RESTORING,
                deploy_status=consts.DEPLOY_STATE_RESTORE_FAILED,
            )
            LOG.error(msg)
            return False

    @staticmethod
    def _fail_subcloud_backup_prep(context, subcloud):
        LOG.exception("Failed to prepare subcloud %s for backup" % subcloud.name)

        db_api.subcloud_update(
            context, subcloud.id, backup_status=consts.BACKUP_STATE_PREP_FAILED
        )

    def _clear_subcloud_backup_failure_alarm_if_exists(self, subcloud):
        entity_instance_id = "subcloud=%s" % subcloud.name

        try:
            fault = self.fm_api.get_fault(
                fm_const.FM_ALARM_ID_DC_SUBCLOUD_BACKUP_FAILED, entity_instance_id
            )
            if fault:
                self.fm_api.clear_fault(
                    fm_const.FM_ALARM_ID_DC_SUBCLOUD_BACKUP_FAILED,  # noqa
                    entity_instance_id,
                )
        except Exception as e:
            LOG.exception(e)

    def _set_subcloud_backup_failure_alarm(self, subcloud):
        entity_instance_id = "subcloud=%s" % subcloud.name

        try:
            fault = fm_api.Fault(
                alarm_id=fm_const.FM_ALARM_ID_DC_SUBCLOUD_BACKUP_FAILED,  # noqa
                alarm_state=fm_const.FM_ALARM_STATE_SET,
                entity_type_id=fm_const.FM_ENTITY_TYPE_SUBCLOUD,
                entity_instance_id=entity_instance_id,
                severity=fm_const.FM_ALARM_SEVERITY_MINOR,
                reason_text=("Subcloud Backup Failure (subcloud=%s)" % subcloud.name),
                alarm_type=fm_const.FM_ALARM_TYPE_3,
                probable_cause=fm_const.ALARM_PROBABLE_CAUSE_UNKNOWN,
                proposed_repair_action=(
                    "Retry subcloud backup after checking input file. "
                    "If problem persists, please contact next level of support."
                ),
                service_affecting=False,
            )
            self.fm_api.set_fault(fault)
        except Exception as e:
            LOG.exception(e)

    def run_deploy_phases(
        self,
        context,
        subcloud_id,
        payload,
        deploy_phases_to_run,
        initial_deployment=False,
        previous_version=None,
    ):
        """Run one or more deployment phases, ensuring correct order

        :param context: request context object
        :param subcloud_id: subcloud id from db
        :param payload: deploy phases payload
        :param deploy_phases_to_run: deploy phases that should run
        :param initial_deployment: initial_deployment flag from subcloud inventory
        :param previous_version: previous subcloud software version
        """
        try:
            succeeded = True
            if consts.DEPLOY_PHASE_INSTALL in deploy_phases_to_run:
                succeeded = self.subcloud_deploy_install(
                    context, subcloud_id, payload, initial_deployment, previous_version
                )
            if succeeded and consts.DEPLOY_PHASE_ENROLL in deploy_phases_to_run:
                succeeded = self.subcloud_deploy_enroll(context, subcloud_id, payload)
            if succeeded and consts.DEPLOY_PHASE_BOOTSTRAP in deploy_phases_to_run:
                succeeded = self.subcloud_deploy_bootstrap(
                    context, subcloud_id, payload, initial_deployment
                )
            if succeeded and consts.DEPLOY_PHASE_CONFIG in deploy_phases_to_run:
                succeeded = self.subcloud_deploy_config(
                    context, subcloud_id, payload, initial_deployment
                )
            if succeeded and consts.DEPLOY_PHASE_COMPLETE in deploy_phases_to_run:
                self.subcloud_deploy_complete(context, subcloud_id)
            return succeeded

        except Exception as ex:
            LOG.exception("run_deploy_phases failed")
            raise ex

    def _run_subcloud_config(self, subcloud, context, config_command, log_file):
        # Run the custom deploy playbook
        LOG.info("Starting deploy of %s" % subcloud.name)
        db_api.subcloud_update(
            context,
            subcloud.id,
            deploy_status=consts.DEPLOY_STATE_CONFIGURING,
            error_description=consts.ERROR_DESC_EMPTY,
        )

        try:
            ansible = dccommon_utils.AnsiblePlaybook(subcloud.name)
            aborted = ansible.run_playbook(log_file, config_command)
        except PlaybookExecutionFailed as e:
            msg = utils.find_and_save_ansible_error_msg(
                context,
                subcloud,
                log_file,
                exception=e,
                stage=consts.DEPLOY_STATE_CONFIGURING,
                deploy_status=consts.DEPLOY_STATE_CONFIG_FAILED,
            )
            LOG.error(msg)
            return False
        if aborted:
            return False
        LOG.info("Successfully deployed %s" % subcloud.name)
        db_api.subcloud_update(
            context,
            subcloud.id,
            deploy_status=consts.DEPLOY_STATE_DONE,
            error_description=consts.ERROR_DESC_EMPTY,
        )
        return True

    @staticmethod
    def _run_subcloud_install(
        context,
        subcloud,
        install_command,
        log_file,
        payload,
        include_paths=None,
        kickstart_uri=None,
    ):
        software_version = str(payload["software_version"])
        LOG.info(
            "Preparing remote install of %s, version: %s",
            subcloud.name,
            software_version,
        )
        if (
            subcloud.deploy_status != consts.DEPLOY_STATE_PRE_INSTALL
            or subcloud.software_version != software_version
        ):
            db_api.subcloud_update(
                context,
                subcloud.id,
                deploy_status=consts.DEPLOY_STATE_PRE_INSTALL,
                software_version=software_version,
            )
        try:
            install = SubcloudInstall(subcloud.name)
            subcloud_primary_oam_ip_family = utils.get_primary_oam_address_ip_family(
                subcloud
            )
            install.prep(
                dccommon_consts.ANSIBLE_OVERRIDES_PATH,
                payload,
                subcloud_primary_oam_ip_family,
                include_paths,
                kickstart_uri,
            )
        except Exception as e:
            LOG.exception(e)
            db_api.subcloud_update(
                context,
                subcloud.id,
                deploy_status=consts.DEPLOY_STATE_PRE_INSTALL_FAILED,
            )
            if install:
                install.cleanup(software_version)
            return False

        # Run the remote install playbook
        LOG.info("Starting remote install of %s" % subcloud.name)
        db_api.subcloud_update(
            context,
            subcloud.id,
            deploy_status=consts.DEPLOY_STATE_INSTALLING,
            error_description=consts.ERROR_DESC_EMPTY,
        )
        try:
            aborted = install.install(consts.DC_ANSIBLE_LOG_DIR, install_command)
        except Exception as e:
            msg = utils.find_and_save_ansible_error_msg(
                context,
                subcloud,
                log_file,
                exception=e,
                stage=consts.DEPLOY_STATE_INSTALLING,
                deploy_status=consts.DEPLOY_STATE_INSTALL_FAILED,
            )
            LOG.error(msg)
            install.cleanup(software_version)
            return False
        install.cleanup(software_version)
        if aborted:
            return False
        LOG.info("Successfully installed %s" % subcloud.name)
        return True

    def _run_subcloud_enroll(
        self, context, subcloud, enroll_command, log_file, region_name
    ):

        # Update the subcloud deploy_status to enrolling
        db_api.subcloud_update(
            context,
            subcloud.id,
            deploy_status=consts.DEPLOY_STATE_ENROLLING,
            error_description=consts.ERROR_DESC_EMPTY,
        )

        LOG.info(f"Starting enroll of subcloud {subcloud.name}")
        try:
            ansible = dccommon_utils.AnsiblePlaybook(subcloud.name)
            ansible.run_playbook(log_file, enroll_command)
        except PlaybookExecutionFailed as e:
            msg = utils.find_and_save_ansible_error_msg(
                context,
                subcloud,
                log_file,
                exception=e,
                stage=consts.DEPLOY_STATE_ENROLLING,
                deploy_status=consts.DEPLOY_STATE_ENROLL_FAILED,
            )
            LOG.error(f"Enroll failed for subcloud {subcloud.name}: {msg}")
            return False

        # Ensure rehomed=False after bootstrapped from central cloud, it
        # applies on both initial deployment and re-deployment.
        db_api.subcloud_update(
            context,
            subcloud.id,
            deploy_status=consts.DEPLOY_STATE_ENROLLED,
            error_description=consts.ERROR_DESC_EMPTY,
            region_name=region_name,
            rehomed=False,
        )

        # enrollment finished, the cloud-init files are no longer needed
        self._delete_subcloud_cloud_init_files(subcloud.name)
        LOG.info(f"Successfully enrolled {subcloud.name}")
        return True

    def _run_subcloud_bootstrap(self, context, subcloud, bootstrap_command, log_file):
        # Update the subcloud deploy_status to bootstrapping
        db_api.subcloud_update(
            context,
            subcloud.id,
            deploy_status=consts.DEPLOY_STATE_BOOTSTRAPPING,
            error_description=consts.ERROR_DESC_EMPTY,
        )

        # Run the ansible subcloud bootstrap playbook
        LOG.info("Starting bootstrap of %s" % subcloud.name)
        try:
            ansible = dccommon_utils.AnsiblePlaybook(subcloud.name)
            aborted = ansible.run_playbook(log_file, bootstrap_command)
        except PlaybookExecutionFailed as e:
            msg = utils.find_and_save_ansible_error_msg(
                context,
                subcloud,
                log_file,
                exception=e,
                stage=consts.DEPLOY_STATE_BOOTSTRAPPING,
                deploy_status=consts.DEPLOY_STATE_BOOTSTRAP_FAILED,
            )
            LOG.error(msg)
            return False

        if aborted:
            return False

        # Ensure rehomed=False after bootstrapped from central cloud, it
        # applies on both initial deployment and re-deployment.
        db_api.subcloud_update(
            context,
            subcloud.id,
            deploy_status=consts.DEPLOY_STATE_BOOTSTRAPPED,
            error_description=consts.ERROR_DESC_EMPTY,
            rehomed=False,
        )

        LOG.info("Successfully bootstrapped %s" % subcloud.name)
        return True

    def _create_addn_hosts_dc(self, context):
        """Generate the addn_hosts_dc file for hostname/ip translation"""

        addn_hosts_dc = os.path.join(CONFIG_PATH, ADDN_HOSTS_DC)
        addn_hosts_dc_temp = addn_hosts_dc + ".temp"

        subclouds = db_api.subcloud_get_all(context)
        with open(addn_hosts_dc_temp, "w") as f_out_addn_dc_temp:
            for subcloud in subclouds:
                addn_dc_line = subcloud.management_start_ip + " " + subcloud.name + "\n"
                f_out_addn_dc_temp.write(addn_dc_line)

            # if no more subclouds, create empty file so dnsmasq does not
            # emit an error log.
            if not subclouds:
                f_out_addn_dc_temp.write(" ")

        if not filecmp.cmp(addn_hosts_dc_temp, addn_hosts_dc):
            os.rename(addn_hosts_dc_temp, addn_hosts_dc)
            # restart dnsmasq so it can re-read our addn_hosts file.
            os.system("pkill -HUP dnsmasq")

    def _write_subcloud_ansible_config(self, cached_regionone_data, payload):
        """Create the override file for usage with the specified subcloud"""

        overrides_file = os.path.join(
            dccommon_consts.ANSIBLE_OVERRIDES_PATH, payload["name"] + ".yml"
        )

        # cached_regionone_data supports dual-stack mgmt and oam
        # for systemcontroller.
        # Communication between subcloud and system controller is through primary
        # mgmt and oam of subcloud.
        #
        # Subcloud accesses systemcontroller mgmt subnet (system_controller_subnet)
        # through subcloud's primary mgmt network/gateway. So
        # system_controller_subnet should be populated of same IP family
        # as of subcloud's primary mgmt network. This IP family is not
        # necessarily primary management subnet of system-controller.
        # eg: dual-stack (IPv4 primary, IPv6 secondary) mgmt systemcontroller
        # and IPv6-only management subcloud.
        #
        # Similarly, subcloud accesses systemcontroller oam subnet
        # (system_controller_oam_subnet) through subcloud's primary oam network.
        #
        system_controller_mgmt_pools = cached_regionone_data["mgmt_pools"]
        try:
            mgmt_pool = utils.get_pool_by_ip_family(
                system_controller_mgmt_pools,
                utils.get_primary_management_gateway_address_ip_family(payload),
            )
        except Exception as e:
            raise Exception(
                f"subcloud primary management gateway address IP family does not "
                f"exist on system controller managements: {e}"
            )

        mgmt_floating_ip = mgmt_pool.floating_address
        mgmt_subnet = "%s/%d" % (mgmt_pool.network, mgmt_pool.prefix)

        # choose systemcontroller oam pool based upon IP family
        # of subcloud's primary OAM.
        # system controller OAM pools can be either single-stack or dual-stack,
        # subcloud need to choose right IP family based upon subcloud primary
        # OAM IP family, as OAM communication between subcloud and
        # system controller is single stack only, based upon subcloud primary OAM.
        system_controller_oam_pools = cached_regionone_data["oam_pools"]
        subcloud_primary_oam_ip_family = utils.get_primary_oam_address_ip_family(
            payload
        )
        try:
            oam_pool = utils.get_pool_by_ip_family(
                system_controller_oam_pools, subcloud_primary_oam_ip_family
            )
        except Exception as e:
            raise Exception(
                f"subcloud primary OAM IP family does not"
                f"exist on system controller OAM: {e}"
            )

        oam_floating_ip = oam_pool.floating_address
        oam_subnet = "%s/%d" % (oam_pool.network, oam_pool.prefix)

        with open(overrides_file, "w") as f_out_overrides_file:
            f_out_overrides_file.write(
                "---"
                "\nregion_config: yes"
                "\ndistributed_cloud_role: subcloud"
                "\nsystem_controller_subnet: "
                + mgmt_subnet
                + "\nsystem_controller_floating_address: "
                + mgmt_floating_ip
                + "\nsystem_controller_oam_subnet: "
                + oam_subnet
                + "\nsystem_controller_oam_floating_address: "
                + oam_floating_ip
                + "\n"
            )

            for k, v in payload.items():
                if k not in VALUES_TO_DELETE_OVERRIDES:
                    f_out_overrides_file.write("%s: %s\n" % (k, json.dumps(v)))

    def _write_deploy_files(self, payload, subcloud_name):
        """Create the deploy value files for the subcloud"""

        deploy_values_file = os.path.join(
            dccommon_consts.ANSIBLE_OVERRIDES_PATH, subcloud_name + "_deploy_values.yml"
        )

        with open(deploy_values_file, "w") as f_out_deploy_values_file:
            json.dump(payload["deploy_values"], f_out_deploy_values_file)

    def _prepare_for_deployment(self, payload, subcloud_name, populate_passwords=True):
        payload["deploy_values"] = dict()
        if populate_passwords:
            payload["deploy_values"]["ansible_become_pass"] = payload[
                "sysadmin_password"
            ]
            payload["deploy_values"]["ansible_ssh_pass"] = payload["sysadmin_password"]
            payload["deploy_values"]["admin_password"] = str(
                keyring.get_password("CGCS", "admin")
            )
        payload["deploy_values"]["deployment_config"] = payload[consts.DEPLOY_CONFIG]
        payload["deploy_values"]["deployment_manager_chart"] = payload[
            consts.DEPLOY_CHART
        ]
        if consts.DEPLOY_OVERRIDES in payload:
            payload["deploy_values"]["deployment_manager_overrides"] = payload[
                consts.DEPLOY_OVERRIDES
            ]
        payload["deploy_values"]["user_uploaded_artifacts"] = payload[
            "user_uploaded_artifacts"
        ]
        self._write_deploy_files(payload, subcloud_name)

    def _delete_subcloud_routes(
        self, keystone_client: KeystoneClient, subcloud: Subcloud
    ):
        """Delete the routes to this subcloud"""

        # Delete the route to this subcloud on the management interface on
        # both controllers.
        management_subnet = netaddr.IPNetwork(subcloud.management_subnet)

        subclouds = db_api.subcloud_get_all(self.context)
        for s in subclouds:
            if s.id == subcloud.id:
                continue
            s_management_subnet = netaddr.IPNetwork(s.management_subnet)
            if s_management_subnet == management_subnet:
                LOG.warning(
                    "Subcloud %r shares the same subnet as %r, not deleting route",
                    s.name,
                    subcloud.name,
                )
                return

        endpoint = keystone_client.endpoint_cache.get_endpoint("sysinv")
        sysinv_client = SysinvClient(
            keystone_client.region_name,
            keystone_client.session,
            endpoint=endpoint,
        )
        cached_regionone_data = self._get_cached_regionone_data(
            keystone_client, sysinv_client
        )
        for mgmt_if_uuid in cached_regionone_data["mgmt_interface_uuids"]:
            sysinv_client.delete_route(
                mgmt_if_uuid,
                str(management_subnet.ip),
                management_subnet.prefixlen,
                str(netaddr.IPAddress(subcloud.systemcontroller_gateway_ip)),
                1,
            )

    @staticmethod
    def _delete_subcloud_cert(subcloud_region):
        cert_name = SubcloudManager._get_subcloud_cert_name(subcloud_region)
        secret_name = SubcloudManager._get_subcloud_cert_secret_name(subcloud_region)

        kube = kubeoperator.KubeOperator()
        kube.delete_cert_manager_certificate(CERT_NAMESPACE, cert_name)

        kube.kube_delete_secret(secret_name, CERT_NAMESPACE)
        LOG.info("cert %s and secret %s are deleted" % (cert_name, secret_name))

    def _remove_subcloud_details(
        self, context, subcloud, ansible_subcloud_inventory_file
    ):
        """Remove subcloud details from database and inform orchestrators"""
        # Inform orchestrators that subcloud has been deleted
        try:
            self.dcorch_rpc_client.del_subcloud(context, subcloud.region_name)
        except RemoteError as e:
            # TODO(kmacleod): this should be caught as explicit remote exception
            # Fix when centos/python2 is no longer supported
            if "SubcloudNotFound" in str(e):
                pass

        # delete the associated alarm entry
        try:
            db_api.subcloud_alarms_delete(context, subcloud.name)
        except RemoteError as e:
            # TODO(kmacleod): fix same with above
            if "SubcloudNotFound" in str(e):
                pass

        # We only delete subcloud endpoints, region and user information
        # in the Central Region. The subcloud is already unmanaged and powered
        # down so is not accessible. Therefore set up a session with the
        # Central Region Keystone ONLY.
        keystone_client = OpenStackDriver(
            region_clients=None,
            fetch_subcloud_ips=utils.fetch_subcloud_mgmt_ips,
        ).keystone_client

        # Delete the routes to this subcloud
        self._delete_subcloud_routes(keystone_client, subcloud)

        # Remove the subcloud from the database
        try:
            db_api.subcloud_destroy(context, subcloud.id)
        except Exception as e:
            LOG.exception(e)
            raise e

        # Delete the ansible inventory for the new subcloud
        utils.delete_subcloud_inventory(ansible_subcloud_inventory_file)

        # Delete the subcloud intermediate certificate
        SubcloudManager._delete_subcloud_cert(subcloud.region_name)

        # Delete the subcloud backup path
        self._delete_subcloud_backup_data(subcloud.name)

        # Regenerate the addn_hosts_dc file
        self._create_addn_hosts_dc(context)

        # Cleanup files inside ANSIBLE_OVERRIDES_PATH
        self._cleanup_ansible_files(subcloud.name)

    def _cleanup_ansible_files(self, subcloud_name):
        LOG.info(
            f"Cleaning up subcloud {subcloud_name} files "
            f"from {dccommon_consts.ANSIBLE_OVERRIDES_PATH}"
        )
        try:
            self._delete_subcloud_overrides_file(subcloud_name)
            self._delete_subcloud_config_files(subcloud_name)
            self._delete_subcloud_install_files(subcloud_name)
            self._delete_subcloud_cloud_init_files(subcloud_name)
        except Exception:
            LOG.exception(
                "Unable to cleanup subcloud ansible files "
                f"for subcloud: {subcloud_name}"
            )

    @staticmethod
    def _delete_subcloud_overrides_file(subcloud_name):
        filepath = utils.get_ansible_filename(subcloud_name)
        if os.path.exists(filepath):
            os.remove(filepath)

    @staticmethod
    def _delete_subcloud_config_files(subcloud_name):
        for postfix in ("_deploy_values.yml", "_deploy_config.yml"):
            filepath = utils.get_ansible_filename(subcloud_name, postfix)
            if os.path.exists(filepath):
                os.remove(filepath)

    @staticmethod
    def _delete_subcloud_install_files(subcloud_name):
        install_path = os.path.join(
            dccommon_consts.ANSIBLE_OVERRIDES_PATH, subcloud_name
        )
        if os.path.exists(install_path):
            shutil.rmtree(install_path)

    @staticmethod
    def _delete_subcloud_cloud_init_files(subcloud_name):
        postfix = "_cloud_init_config.tar"
        filepath = utils.get_ansible_filename(subcloud_name, postfix)
        if os.path.exists(filepath):
            os.remove(filepath)

    def _rename_subcloud_ansible_files(self, cur_sc_name, new_sc_name):
        """Renames the ansible and logs files from the given subcloud"""

        ansible_path = dccommon_consts.ANSIBLE_OVERRIDES_PATH
        log_path = consts.DC_ANSIBLE_LOG_DIR

        ansible_file_list = os.listdir(ansible_path)
        log_file_list = os.listdir(log_path)

        ansible_file_list = [ansible_path + "/" + x for x in ansible_file_list]
        log_file_list = [log_path + "/" + x for x in log_file_list]

        for cur_file in ansible_file_list + log_file_list:
            new_file = cur_file.replace(cur_sc_name, new_sc_name)
            if os.path.exists(cur_file) and new_sc_name in new_file:
                LOG.debug("Renaming file %s to %s" % (cur_file, new_file))
                os.rename(cur_file, new_file)

        # Gets new ansible inventory file
        ansible_inv_file = self._get_ansible_filename(
            new_sc_name, INVENTORY_FILE_POSTFIX
        )

        if os.path.exists(ansible_inv_file):
            # Updates inventory host param with the new subcloud name
            with open(ansible_inv_file, "r") as f:
                data = yaml.safe_load(f)

            mkey = list(data.keys())[0]

            if (
                mkey in data
                and "hosts" in data[mkey]
                and cur_sc_name in data[mkey]["hosts"]
            ):
                data[mkey]["hosts"][new_sc_name] = data[mkey]["hosts"].pop(cur_sc_name)

                with open(ansible_inv_file, "w") as f:
                    yaml.dump(data, f, sort_keys=False)
        else:
            msg = (
                "Could not rename inventory file %s because it does not exist."
                % ansible_inv_file
            )
            LOG.warn(msg)

    @staticmethod
    def _delete_subcloud_backup_data(subcloud_name):
        try:
            backup_path = os.path.join(consts.CENTRAL_BACKUP_DIR, subcloud_name)
            if os.path.exists(backup_path):
                shutil.rmtree(backup_path)
        except Exception as e:
            LOG.exception(e)

    def _clear_subcloud_alarms(self, subcloud: Subcloud):
        # Clear any subcloud alarms.
        # Note that endpoint out-of-sync alarms should have been cleared when
        # the subcloud was unmanaged and the endpoint sync statuses were set to
        # unknown.
        #
        # TODO(kmacleod): Until an API is available to clear all alarms
        # for a subcloud, we manually clear the following:
        # - subcloud offline
        # - subloud resource out of sync
        # - Subcloud Backup Failure
        for alarm_id, entity_instance_id in (
            (fm_const.FM_ALARM_ID_DC_SUBCLOUD_OFFLINE, "subcloud=%s" % subcloud.name),
            (
                fm_const.FM_ALARM_ID_DC_SUBCLOUD_RESOURCE_OUT_OF_SYNC,
                "subcloud=%s.resource=%s"
                % (subcloud.name, dccommon_consts.ENDPOINT_TYPE_DC_CERT),
            ),
            (
                fm_const.FM_ALARM_ID_DC_SUBCLOUD_BACKUP_FAILED,
                "subcloud=%s" % subcloud.name,
            ),
        ):
            try:
                fault = self.fm_api.get_fault(alarm_id, entity_instance_id)
                if fault:
                    self.fm_api.clear_fault(alarm_id, entity_instance_id)
            except Exception as e:
                LOG.info(
                    "Problem clearing fault for subcloud %s, alarm_id=%s"
                    % (subcloud.name, alarm_id)
                )
                LOG.exception(e)

    def delete_subcloud(self, context, subcloud_id):
        """Delete subcloud and notify orchestrators.

        :param context: request context object.
        :param subcloud_id: id of subcloud to delete
        """
        LOG.info("Deleting subcloud %s." % subcloud_id)

        # Retrieve the subcloud details from the database
        subcloud = db_api.subcloud_get(context, subcloud_id)

        # Semantic checking
        if subcloud.management_state != dccommon_consts.MANAGEMENT_UNMANAGED:
            raise exceptions.SubcloudNotUnmanaged()

        if subcloud.availability_status == dccommon_consts.AVAILABILITY_ONLINE:
            raise exceptions.SubcloudNotOffline()

        if utils.is_system_controller_deploying():
            raise exceptions.ValidateFail(
                "Subcloud delete is not allowed while system "
                "controller has a software deployment in progress."
            )

        # Ansible inventory filename for the specified subcloud
        ansible_subcloud_inventory_file = self._get_ansible_filename(
            subcloud.name, INVENTORY_FILE_POSTFIX
        )

        self._remove_subcloud_details(
            context, subcloud, ansible_subcloud_inventory_file
        )

        self._clear_subcloud_alarms(subcloud)

    def rename_subcloud(
        self, context, subcloud_id, curr_subcloud_name, new_subcloud_name=None
    ):
        """Rename subcloud.

        :param context: request context object.
        :param subcloud_id: id of subcloud to rename
        :param curr_subcloud_name: current subcloud name
        :param new_subcloud_name: new subcloud name
        """
        try:
            subcloud = db_api.subcloud_get_by_name_or_region_name(
                context, new_subcloud_name
            )
        except exceptions.SubcloudNameOrRegionNameNotFound:
            pass
        else:
            # If the found subcloud id is not the same as the received
            # subcloud id, it indicates that the name change does not
            # correspond to the current subcloud.
            # Therefore it is not allowed to change the name.
            if subcloud_id != subcloud.id:
                raise exceptions.SubcloudOrRegionNameAlreadyExists(
                    name=new_subcloud_name
                )

        # updates subcloud name
        subcloud = db_api.subcloud_update(context, subcloud_id, name=new_subcloud_name)
        # updates subcloud names on alarms
        db_api.subcloud_rename_alarms(context, curr_subcloud_name, new_subcloud_name)
        # Deletes subcloud alarms
        entity_instance_id = "subcloud=%s" % curr_subcloud_name
        self.fm_api.clear_all(entity_instance_id)

        # Regenerate the dnsmasq host entry
        self._create_addn_hosts_dc(context)

        # Rename related subcloud files
        self._rename_subcloud_ansible_files(curr_subcloud_name, new_subcloud_name)

        # Update the subcloud rehome_data with the new name
        if subcloud.rehome_data:
            rehome_data_dict = json.loads(subcloud.rehome_data)
            if "saved_payload" in rehome_data_dict:
                rehome_data_dict["saved_payload"]["name"] = new_subcloud_name
                rehome_data = json.dumps(rehome_data_dict)
                subcloud = db_api.subcloud_update(
                    context, subcloud_id, rehome_data=rehome_data
                )

        return subcloud

    def get_subcloud_name_by_region_name(self, context, subcloud_region):
        subcloud_name = None
        if subcloud_region is not None:
            sc = db_api.subcloud_get_by_region_name(context, subcloud_region)
            subcloud_name = sc.get("name")

        return subcloud_name

    def _validate_management_state_update(
        self,
        new_management_state: str,
        new_deploy_status: str,
        subcloud: Subcloud,
        force: bool,
    ):
        if new_management_state == dccommon_consts.MANAGEMENT_UNMANAGED:
            if subcloud.management_state == dccommon_consts.MANAGEMENT_UNMANAGED:
                msg = f"Subcloud {subcloud.name} already unmanaged"
                LOG.warning(msg)
                raise exceptions.BadRequest(resource="subcloud", msg=msg)

        elif new_management_state == dccommon_consts.MANAGEMENT_MANAGED:
            if subcloud.management_state == dccommon_consts.MANAGEMENT_MANAGED:
                msg = f"Subcloud {subcloud.name} already managed"
                LOG.warning(msg)
                raise exceptions.BadRequest(resource="subcloud", msg=msg)

            if force:
                # No need for further validation
                return

            allowed_deploy_transition = (
                subcloud.deploy_status == consts.DEPLOY_STATE_REHOME_PENDING
                and new_deploy_status == consts.DEPLOY_STATE_DONE
            )

            if (
                subcloud.deploy_status != consts.DEPLOY_STATE_DONE
                and not allowed_deploy_transition
            ):
                msg = (
                    f"Unable to manage {subcloud.name}: its deploy_status "
                    f"must be either '{consts.DEPLOY_STATE_DONE}' or "
                    f"'{consts.DEPLOY_STATE_REHOME_PENDING}'"
                )
                LOG.warning(msg)
                raise exceptions.BadRequest(resource="subcloud", msg=msg)

            if (
                subcloud.availability_status != dccommon_consts.AVAILABILITY_ONLINE
            ) and (subcloud.deploy_status != consts.DEPLOY_STATE_REHOME_PENDING):
                LOG.warning(f"Subcloud {subcloud.name} is not online")
                raise exceptions.SubcloudNotOnline()

        # The management state can be 'unmanaged', 'managed' or None (which
        # means that it's not being changed), any other value is invalid
        elif new_management_state is not None:
            LOG.error(f"Invalid management_state {new_management_state}")
            raise exceptions.InvalidInputError()

    def _prepare_rehome_data(
        self, subcloud: Subcloud, bootstrap_values, bootstrap_address
    ):
        rehome_data_dict = None
        # load the existing data if it exists
        if subcloud.rehome_data:
            rehome_data_dict = json.loads(subcloud.rehome_data)
        # update saved_payload with the bootstrap values
        if bootstrap_values:
            _bootstrap_address = None
            if not rehome_data_dict:
                rehome_data_dict = utils.create_subcloud_rehome_data_template()
            else:
                # Since bootstrap-address is not original data in bootstrap-values
                # it's necessary to save it first, then put it back after
                # after bootstrap_values is updated.
                if "bootstrap-address" in rehome_data_dict["saved_payload"]:
                    _bootstrap_address = rehome_data_dict["saved_payload"][
                        "bootstrap-address"
                    ]
            bootstrap_values_dict = yaml.load(bootstrap_values, Loader=yaml.SafeLoader)

            # remove sysadmin_password,ansible_ssh_pass,ansible_become_pass
            # encode admin_password
            if "sysadmin_password" in bootstrap_values_dict:
                del bootstrap_values_dict["sysadmin_password"]
            if "ansible_ssh_pass" in bootstrap_values_dict:
                del bootstrap_values_dict["ansible_ssh_pass"]
            if "ansible_become_pass" in bootstrap_values_dict:
                del bootstrap_values_dict["ansible_become_pass"]
            if "admin_password" in bootstrap_values_dict:
                bootstrap_values_dict["admin_password"] = base64.b64encode(
                    bootstrap_values_dict["admin_password"].encode("utf-8")
                ).decode("utf-8")
            rehome_data_dict["saved_payload"] = bootstrap_values_dict
            # put bootstrap_address back into rehome_data_dict
            if _bootstrap_address:
                rehome_data_dict["saved_payload"][
                    "bootstrap-address"
                ] = _bootstrap_address

        # update bootstrap_address
        if bootstrap_address:
            if rehome_data_dict is None:
                raise exceptions.BadRequest(
                    resource="subcloud",
                    msg=(
                        "Cannot update bootstrap_address into rehome data, "
                        "need to import bootstrap_values first"
                    ),
                )
            rehome_data_dict["saved_payload"]["bootstrap-address"] = bootstrap_address

        rehome_data = None
        systemcontroller_gateway_address = None
        if rehome_data_dict:
            rehome_data = json.dumps(rehome_data_dict)
            systemcontroller_gateway_address = rehome_data_dict["saved_payload"].get(
                "systemcontroller_gateway_address"
            )

        return rehome_data, systemcontroller_gateway_address

    def update_subcloud(
        self,
        context,
        subcloud_id,
        management_state=None,
        description=None,
        location=None,
        group_id=None,
        data_install=None,
        force=None,
        deploy_status=None,
        peer_group_id=None,
        bootstrap_values=None,
        bootstrap_address=None,
    ):
        """Update subcloud and notify orchestrators.

        :param context: request context object
        :param subcloud_id: id of subcloud to update
        :param management_state: new management state
        :param description: new description
        :param location: new location
        :param group_id: new subcloud group id
        :param data_install: subcloud install values
        :param force: force flag
        :param deploy_status: update to expected deploy status
        :param peer_group_id: id of peer group
        :param bootstrap_values: bootstrap_values yaml content
        :param bootstrap_address: oam IP for rehome
        """

        LOG.info("Updating subcloud %s." % subcloud_id)

        # Get the subcloud details from the database
        subcloud: Subcloud = db_api.subcloud_get(context, subcloud_id)
        original_management_state = subcloud.management_state
        original_deploy_status = subcloud.deploy_status

        # When trying to manage a 'rehome-pending' subcloud, revert its deploy
        # status back to 'complete' if its not specified
        if (
            management_state == dccommon_consts.MANAGEMENT_MANAGED
            and subcloud.deploy_status == consts.DEPLOY_STATE_REHOME_PENDING
            and not deploy_status
        ):
            deploy_status = consts.DEPLOY_STATE_DONE

        # management_state semantic checking
        self._validate_management_state_update(
            management_state, deploy_status, subcloud, force
        )

        # Update bootstrap values into rehome_data
        rehome_data, systemcontroller_gateway_ip = self._prepare_rehome_data(
            subcloud, bootstrap_values, bootstrap_address
        )

        if deploy_status:
            msg = None
            # Only update deploy_status if subcloud is or will be unmanaged
            if dccommon_consts.MANAGEMENT_UNMANAGED not in (
                management_state,
                subcloud.management_state,
            ):
                msg = (
                    f"Unable to update deploy_status of subcloud {subcloud.name} "
                    f"to {deploy_status}: subcloud must also be unmanaged"
                )
            # Only allow managing if the deploy status is also set to 'complete'
            if (
                management_state == dccommon_consts.MANAGEMENT_MANAGED
                and deploy_status != consts.DEPLOY_STATE_DONE
            ):
                msg = (
                    f"Unable to manage {subcloud.name} while also updating "
                    f"its deploy_status to {deploy_status}: not allowed"
                )
            if msg:
                LOG.warning(msg)
                raise exceptions.BadRequest(resource="subcloud", msg=msg)

        # Update route if the systemcontroller_gateway_ip has been updated
        if (
            systemcontroller_gateway_ip is not None
            and systemcontroller_gateway_ip.split(",")[0]
            != subcloud.systemcontroller_gateway_ip
        ):
            LOG.info(
                f"The systemcontroller_gateway_ip for subcloud {subcloud.name} "
                f"was updated from {subcloud.systemcontroller_gateway_ip} to "
                f"{systemcontroller_gateway_ip.split(',')[0]}. Replacing routes..."
            )
            m_ks_client = OpenStackDriver(
                region_clients=None,
                fetch_subcloud_ips=utils.fetch_subcloud_mgmt_ips,
            ).keystone_client
            self._create_subcloud_route(
                {"management_subnet": subcloud.management_subnet},
                m_ks_client,
                systemcontroller_gateway_ip,
            )
            # Deletes old routes (subcloud obj holds old gateway ip)
            self._delete_subcloud_routes(m_ks_client, subcloud)

        subcloud = db_api.subcloud_update(
            context,
            subcloud_id,
            management_state=management_state,
            description=description,
            location=location,
            group_id=group_id,
            data_install=data_install,
            deploy_status=deploy_status,
            peer_group_id=peer_group_id,
            rehome_data=rehome_data,
            systemcontroller_gateway_ip=(
                systemcontroller_gateway_ip
                if systemcontroller_gateway_ip is None
                else systemcontroller_gateway_ip.split(",")[0]
            ),
        )

        # Inform orchestrators that subcloud has been updated
        if management_state:
            try:
                # Inform orchestrator of state change
                self.dcorch_rpc_client.update_subcloud_states(
                    context,
                    subcloud.region_name,
                    management_state,
                    subcloud.availability_status,
                )

                LOG.info(
                    "Notifying dcorch, subcloud:%s management: %s, availability:%s"
                    % (subcloud.name, management_state, subcloud.availability_status)
                )

            except Exception as e:
                LOG.exception(e)
                LOG.warn(
                    "Problem informing dcorch of subcloud "
                    "state change, resume to original state, subcloud: %s"
                    % subcloud.name
                )
                management_state = original_management_state
                # Also revert the deploy_status otherwise we could have a
                # managed subcloud with the 'secondary' or other invalid deploy
                # status/management state combination.
                deploy_status = original_deploy_status
                subcloud = db_api.subcloud_update(
                    context,
                    subcloud_id,
                    management_state=management_state,
                    description=description,
                    location=location,
                    deploy_status=deploy_status,
                )

            if management_state == dccommon_consts.MANAGEMENT_UNMANAGED:
                # set all endpoint statuses to unknown, except the dc-cert
                # endpoint which continues to be audited for unmanaged
                # subclouds
                ignore_endpoints = [dccommon_consts.ENDPOINT_TYPE_DC_CERT]

                # Do not ignore the dc-cert endpoint for secondary or rehome
                # pending subclouds as cert-mon does not audit them
                if subcloud.deploy_status in (
                    consts.DEPLOY_STATE_SECONDARY,
                    consts.DEPLOY_STATE_REHOME_PENDING,
                ):
                    ignore_endpoints = None

                self.state_rpc_client.update_subcloud_endpoint_status_sync(
                    context,
                    subcloud_name=subcloud.name,
                    subcloud_region=subcloud.region_name,
                    endpoint_type=None,
                    sync_status=dccommon_consts.SYNC_STATUS_UNKNOWN,
                    ignore_endpoints=ignore_endpoints,
                )

                # Clear the subcloud alarm summary
                utils.clear_subcloud_alarm_summary(self.context, subcloud.name)
            elif management_state == dccommon_consts.MANAGEMENT_MANAGED:
                # Subcloud is managed
                # Tell cert-mon to audit endpoint certificate
                LOG.info("Request certmon audit for %s" % subcloud.name)
                dc_notification = dcmanager_rpc_client.DCManagerNotifications()
                dc_notification.subcloud_managed(context, subcloud.region_name)

        # Request the state client to update the subcloud availability
        # status to OFFLINE if subcloud is 'secondary'. The state
        # service will set all endpoint statuses to 'unknown'.
        if deploy_status == consts.DEPLOY_STATE_SECONDARY:
            self.state_rpc_client.update_subcloud_availability(
                context,
                subcloud.name,
                subcloud.region_name,
                dccommon_consts.AVAILABILITY_OFFLINE,
            )

        # Clear existing fault alarm of secondary subcloud
        if subcloud.deploy_status == consts.DEPLOY_STATE_SECONDARY:
            self._clear_subcloud_alarms(subcloud)

        return db_api.subcloud_db_model_to_dict(subcloud)

    def update_subcloud_with_network_reconfig(self, context, subcloud_id, payload):
        subcloud = db_api.subcloud_get(context, subcloud_id)
        subcloud = db_api.subcloud_update(
            context,
            subcloud.id,
            deploy_status=consts.DEPLOY_STATE_RECONFIGURING_NETWORK,
            error_description=consts.ERROR_DESC_EMPTY,
        )
        subcloud_name = payload["name"]
        try:
            self._create_intermediate_ca_cert(payload)
            subcloud_inventory_file = self._get_ansible_filename(
                subcloud_name, INVENTORY_FILE_POSTFIX
            )
            subcloud_params = {
                "name": subcloud_name,
                "bootstrap-address": payload.get("bootstrap_address"),
            }
            utils.create_subcloud_inventory(subcloud_params, subcloud_inventory_file)
            overrides_file = self._create_subcloud_update_overrides_file(
                payload, subcloud_name, "update_values"
            )
            update_command = self.compose_update_command(
                subcloud_name, subcloud_inventory_file, subcloud.software_version
            )
        except Exception:
            LOG.exception("Failed to prepare subcloud %s for update." % subcloud_name)
            return
        try:
            apply_thread = threading.Thread(
                target=self._run_network_reconfiguration,
                args=(
                    subcloud_name,
                    update_command,
                    overrides_file,
                    payload,
                    context,
                    subcloud,
                ),
            )
            apply_thread.start()
        except Exception:
            LOG.exception("Failed to update subcloud %s" % subcloud_name)

    def _run_network_reconfiguration(
        self, subcloud_name, update_command, overrides_file, payload, context, subcloud
    ):
        log_file = (
            os.path.join(consts.DC_ANSIBLE_LOG_DIR, subcloud_name)
            + "_playbook_output.log"
        )
        subcloud_id = subcloud.id
        try:
            ansible = dccommon_utils.AnsiblePlaybook(subcloud_name)
            ansible.run_playbook(log_file, update_command)
            utils.delete_subcloud_inventory(overrides_file)
        except PlaybookExecutionFailed as e:
            msg = utils.find_and_save_ansible_error_msg(
                context,
                subcloud,
                log_file,
                exception=e,
                stage=consts.DEPLOY_STATE_RECONFIGURING_NETWORK,
                deploy_status=consts.DEPLOY_STATE_RECONFIGURING_NETWORK_FAILED,
            )
            LOG.error(msg)
            return

        self._configure_system_controller_network(context, payload, subcloud)

        db_api.subcloud_update(
            context, subcloud_id, deploy_status=consts.DEPLOY_STATE_DONE
        )

        # We are interested only in primary of dual-stack, as system controller
        # and subcloud communication is based upon subcloud's primary.
        subcloud = db_api.subcloud_update(
            context,
            subcloud_id,
            description=payload.get("description", subcloud.description),
            management_subnet=payload.get("management_subnet").split(",")[0],
            management_gateway_ip=payload.get("management_gateway_ip"),
            management_start_ip=payload.get("management_start_ip").split(",")[0],
            management_end_ip=payload.get("management_end_ip").split(",")[0],
            location=payload.get("location", subcloud.location),
            group_id=payload.get("group_id", subcloud.group_id),
            data_install=payload.get("data_install", subcloud.data_install),
        )

        # Regenerate the addn_hosts_dc file
        self._create_addn_hosts_dc(context)

    def _configure_system_controller_network(
        self, context, payload, subcloud, update_db=True
    ):
        """Configure system controller network

        :param context: request context object
        :param payload: subcloud bootstrap configuration
        :param subcloud: subcloud model object
        :param update_db: whether it should update the db on success/failure
        """
        subcloud_name = subcloud.name
        subcloud_region = subcloud.region_name
        subcloud_id = subcloud.id
        sys_controller_gw_ip = payload.get(
            "systemcontroller_gateway_address", subcloud.systemcontroller_gateway_ip
        )

        try:
            m_ks_client = OpenStackDriver(
                region_clients=None,
                fetch_subcloud_ips=utils.fetch_subcloud_mgmt_ips,
            ).keystone_client
            self._create_subcloud_route(payload, m_ks_client, sys_controller_gw_ip)
        except Exception:
            LOG.exception("Failed to create route to subcloud %s." % subcloud_name)
            if update_db:
                db_api.subcloud_update(
                    context,
                    subcloud_id,
                    deploy_status=consts.DEPLOY_STATE_RECONFIGURING_NETWORK_FAILED,
                    error_description=consts.ERROR_DESC_EMPTY,
                )
            return
        try:
            self._update_services_endpoint(
                context, payload, subcloud_region, m_ks_client
            )
        except Exception:
            LOG.exception("Failed to update subcloud %s endpoints" % subcloud_name)
            if update_db:
                db_api.subcloud_update(
                    context,
                    subcloud_id,
                    deploy_status=consts.DEPLOY_STATE_RECONFIGURING_NETWORK_FAILED,
                    error_description=consts.ERROR_DESC_EMPTY,
                )
            return

        # Delete old routes
        if utils.get_primary_management_subnet(payload) != subcloud.management_subnet:
            self._delete_subcloud_routes(m_ks_client, subcloud)

    def _create_subcloud_route(
        self,
        payload: dict,
        keystone_client: KeystoneClient,
        systemcontroller_gateway_ip: str,
    ):
        subcloud_subnet = netaddr.IPNetwork(
            utils.get_primary_management_subnet(payload)
        )
        endpoint = keystone_client.endpoint_cache.get_endpoint("sysinv")
        sysinv_client = SysinvClient(
            keystone_client.region_name,
            keystone_client.session,
            endpoint=endpoint,
        )
        cached_regionone_data = self._get_cached_regionone_data(
            keystone_client, sysinv_client
        )
        for mgmt_if_uuid in cached_regionone_data["mgmt_interface_uuids"]:
            sysinv_client.create_route(
                mgmt_if_uuid,
                str(subcloud_subnet.ip),
                subcloud_subnet.prefixlen,
                systemcontroller_gateway_ip.split(",")[0],
                1,
            )

    def _update_services_endpoint(self, context, payload, subcloud_region, m_ks_client):
        ip = utils.get_primary_management_start_address(payload)
        services_endpoints = dccommon_utils.build_subcloud_endpoint_map(ip)

        LOG.info(
            "Update services endpoint to %s in subcloud region %s"
            % (ip, subcloud_region)
        )
        # Update service URLs in subcloud endpoint cache
        self.audit_rpc_client.trigger_subcloud_endpoints_update(
            context, subcloud_region, services_endpoints
        )
        # Update the management ip inside dcorch database (triggers endpoint update)
        self.dcorch_rpc_client.update_subcloud_management_ip(
            context, subcloud_region, ip
        )
        # Update sysinv URL in cert-mon cache
        dc_notification = dcmanager_rpc_client.DCManagerNotifications()
        dc_notification.subcloud_sysinv_endpoint_update(
            context, subcloud_region, services_endpoints.get("sysinv")
        )

        # Update dcmanager endpoint cache
        endpoint_cache.EndpointCache.update_master_service_endpoint_region(
            subcloud_region, services_endpoints
        )

    def _create_subcloud_update_overrides_file(
        self, payload, subcloud_name, filename_suffix
    ):
        update_overrides_file = os.path.join(
            dccommon_consts.ANSIBLE_OVERRIDES_PATH,
            subcloud_name + "_" + filename_suffix + ".yml",
        )

        self._update_override_values(payload)

        with open(update_overrides_file, "w", encoding="UTF-8") as f_out:
            f_out.write("---\n")
            for key, value in payload["override_values"].items():
                if key in ["ansible_ssh_pass", "ansible_become_pass"]:
                    f_out.write(f"{key}: {value}\n")
                else:
                    f_out.write(f"{key}: {json.dumps(value)}\n")

        return update_overrides_file

    def _update_override_values(self, payload):
        if not payload.get("override_values"):
            payload["override_values"] = {}

        payload["override_values"]["ansible_ssh_pass"] = payload["sysadmin_password"]
        payload["override_values"]["ansible_become_pass"] = payload["sysadmin_password"]

        payload["override_values"]["sc_gateway_address"] = payload[
            "management_gateway_ip"
        ]
        payload["override_values"]["sc_floating_address"] = payload[
            "management_start_ip"
        ]
        payload["override_values"]["system_controller_network"] = payload[
            "system_controller_network"
        ]
        payload["override_values"]["system_controller_network_prefix"] = payload[
            "system_controller_network_prefix"
        ]
        payload["override_values"]["sc_subnet"] = payload["management_subnet"]

        payload["override_values"]["dc_root_ca_cert"] = payload["dc_root_ca_cert"]
        payload["override_values"]["sc_ca_cert"] = payload["sc_ca_cert"]
        payload["override_values"]["sc_ca_key"] = payload["sc_ca_key"]

    def update_subcloud_sync_endpoint_type(
        self, context, subcloud_region, endpoint_type_list, openstack_installed
    ):
        operation = "add" if openstack_installed else "remove"
        func_switcher = {
            "add": (
                self.dcorch_rpc_client.add_subcloud_sync_endpoint_type,
                db_api.subcloud_status_create,
            ),
            "remove": (
                self.dcorch_rpc_client.remove_subcloud_sync_endpoint_type,
                db_api.subcloud_status_delete,
            ),
        }

        try:
            subcloud = db_api.subcloud_get_by_region_name(context, subcloud_region)
        except Exception:
            LOG.exception("Failed to get subcloud by region name: %s" % subcloud_region)
            raise

        try:
            # Notify dcorch to add/remove sync endpoint type list
            func_switcher[operation][0](
                self.context, subcloud_region, endpoint_type_list
            )
            LOG.info(
                "Notifying dcorch, subcloud: %s new sync endpoint: %s"
                % (subcloud.name, endpoint_type_list)
            )

            # Update subcloud status table by adding/removing openstack sync
            # endpoint types
            for endpoint_type in endpoint_type_list:
                func_switcher[operation][1](self.context, subcloud.id, endpoint_type)
            # Update openstack_installed of subcloud table
            db_api.subcloud_update(
                self.context, subcloud.id, openstack_installed=openstack_installed
            )
        except Exception:
            LOG.exception(
                "Problem informing dcorch of subcloud sync endpoint "
                "type change, subcloud region: %s" % subcloud_region
            )

    def handle_subcloud_operations_in_progress(self):
        """Identify subclouds in transitory stages and update subcloud

        state to failure.
        """

        LOG.info("Identifying subclouds in transitory stages.")

        subclouds = db_api.subcloud_get_all(self.context)

        for subcloud in subclouds:
            # Identify subclouds in transitory states
            new_deploy_status = TRANSITORY_STATES.get(subcloud.deploy_status)
            new_backup_status = TRANSITORY_BACKUP_STATES.get(subcloud.backup_status)
            new_prestage_status = TRANSITORY_PRESTAGE_STATES.get(
                subcloud.prestage_status
            )

            # update deploy, backup and prestage states to
            # the corresponding failure states
            if new_deploy_status or new_backup_status or new_prestage_status:
                if new_deploy_status:
                    LOG.info(
                        "Changing subcloud %s deploy status from %s to %s."
                        % (subcloud.name, subcloud.deploy_status, new_deploy_status)
                    )
                if new_backup_status:
                    LOG.info(
                        "Changing subcloud %s backup status from %s to %s."
                        % (subcloud.name, subcloud.backup_status, new_backup_status)
                    )

                if new_prestage_status:
                    LOG.info(
                        "Changing subcloud %s prestage status from %s to %s."
                        % (subcloud.name, subcloud.prestage_status, new_prestage_status)
                    )

                db_api.subcloud_update(
                    self.context,
                    subcloud.id,
                    deploy_status=new_deploy_status or subcloud.deploy_status,
                    backup_status=new_backup_status or subcloud.backup_status,
                    prestage_status=new_prestage_status or subcloud.prestage_status,
                )

    @staticmethod
    def prestage_subcloud(context, payload):
        """Subcloud prestaging"""
        return prestage.prestage_subcloud(context, payload)

    @utils.synchronized("regionone-data-cache", external=False)
    def _get_cached_regionone_data(
        self,
        regionone_keystone_client: KeystoneClient,
        regionone_sysinv_client: SysinvClient = None,
    ):
        if (
            not SubcloudManager.regionone_data
            or SubcloudManager.regionone_data["expiry"] <= timeutils.utcnow()
        ):
            user_list = regionone_keystone_client.get_enabled_users(id_only=False)
            for user in user_list:
                if user.name == dccommon_consts.ADMIN_USER_NAME:
                    SubcloudManager.regionone_data["admin_user_id"] = user.id
                elif user.name == dccommon_consts.SYSINV_USER_NAME:
                    SubcloudManager.regionone_data["sysinv_user_id"] = user.id
                elif user.name == dccommon_consts.DCMANAGER_USER_NAME:
                    SubcloudManager.regionone_data["dcmanager_user_id"] = user.id

            project_list = regionone_keystone_client.get_enabled_projects(id_only=False)
            for project in project_list:
                if project.name == dccommon_consts.ADMIN_PROJECT_NAME:
                    SubcloudManager.regionone_data["admin_project_id"] = project.id
                elif project.name == dccommon_consts.SERVICES_USER_NAME:
                    SubcloudManager.regionone_data["services_project_id"] = project.id

            if regionone_sysinv_client is None:
                endpoint = regionone_keystone_client.endpoint_cache.get_endpoint(
                    "sysinv"
                )
                regionone_sysinv_client = SysinvClient(
                    regionone_keystone_client.region_name,
                    regionone_keystone_client.session,
                    endpoint=endpoint,
                )

            controllers = regionone_sysinv_client.get_controller_hosts()
            mgmt_interface_uuids = []
            for controller in controllers:
                mgmt_interface = regionone_sysinv_client.get_management_interface(
                    controller.hostname
                )
                if mgmt_interface is not None:
                    mgmt_interface_uuids.append(mgmt_interface.uuid)
            SubcloudManager.regionone_data["mgmt_interface_uuids"] = (
                mgmt_interface_uuids
            )
            SubcloudManager.regionone_data["mgmt_pools"] = (
                regionone_sysinv_client.get_management_address_pools()
            )
            SubcloudManager.regionone_data["oam_pools"] = (
                regionone_sysinv_client.get_oam_address_pools()
            )

            SubcloudManager.regionone_data["expiry"] = (
                timeutils.utcnow() + datetime.timedelta(hours=1)
            )
            LOG.info(
                "RegionOne cached data updated %s" % SubcloudManager.regionone_data
            )

        cached_regionone_data = SubcloudManager.regionone_data
        return cached_regionone_data

    def _populate_payload_with_cached_keystone_data(
        self, cached_data, payload, populate_passwords=True
    ):
        payload["system_controller_keystone_admin_user_id"] = cached_data[
            "admin_user_id"
        ]
        payload["system_controller_keystone_admin_project_id"] = cached_data[
            "admin_project_id"
        ]
        payload["system_controller_keystone_services_project_id"] = cached_data[
            "services_project_id"
        ]
        payload["system_controller_keystone_sysinv_user_id"] = cached_data[
            "sysinv_user_id"
        ]
        payload["system_controller_keystone_dcmanager_user_id"] = cached_data[
            "dcmanager_user_id"
        ]

        if populate_passwords:
            # While at it, add the admin and service user passwords to the
            # payload so they get copied to the overrides file
            payload["ansible_become_pass"] = payload["sysadmin_password"]
            payload["ansible_ssh_pass"] = payload["sysadmin_password"]
            payload["admin_password"] = str(keyring.get_password("CGCS", "admin"))

    def _populate_payload_with_dc_intermediate_ca_cert(self, payload):
        subcloud_region = payload["region_name"]
        secret_name = SubcloudManager._get_subcloud_cert_secret_name(subcloud_region)
        kube = kubeoperator.KubeOperator()
        secret = kube.kube_get_secret(secret_name, CERT_NAMESPACE)
        data = secret.data
        payload["dc_root_ca_cert"] = data["ca.crt"]
        payload["sc_ca_cert"] = data["tls.crt"]
        payload["sc_ca_key"] = data["tls.key"]
