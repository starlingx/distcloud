#
# Copyright (c) 2020-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import base64
import uuid

from dcmanager.common import consts
from dcmanager.db import api as db_api

from dcmanager.tests import base
from dcmanager.tests import utils

FAKE_TENANT = utils.UUID1
FAKE_ID = "1"
FAKE_URL = "/v1.0/subclouds"
WRONG_URL = "/v1.0/wrong"

FAKE_SOFTWARE_VERSION = "10.0"

FAKE_HEADERS = {
    "X-Tenant-Id": FAKE_TENANT,
    "X_ROLE": "admin,member,reader",
    "X-Identity-Status": "Confirmed",
    "X-Project-Name": "admin",
}

FAKE_SUBCLOUD_DATA = {
    "id": FAKE_ID,
    "name": "subcloud1",
    "description": "subcloud1 description",
    "location": "subcloud1 location",
    "system_mode": "duplex",
    "management_subnet": "192.168.101.0/24",
    "management_start_address": "192.168.101.2",
    "management_end_address": "192.168.101.50",
    "management_gateway_address": "192.168.101.1",
    "systemcontroller_gateway_address": "192.168.204.101",
    "external_oam_subnet_ip_family": "4",
    "deploy_status": consts.DEPLOY_STATE_DONE,
    "error_description": consts.ERROR_DESC_EMPTY,
    "region_name": base.SUBCLOUD_1["region_name"],
    "external_oam_subnet": "10.10.10.0/24",
    "external_oam_gateway_address": "10.10.10.1",
    "external_oam_floating_address": "10.10.10.12",
    "availability-status": "disabled",
}

FAKE_BOOTSTRAP_VALUE = {
    "bootstrap-address": "10.10.10.12",
    "sysadmin_password": base64.b64encode("testpass".encode("utf-8")),
}

FAKE_SUBCLOUD_BOOTSTRAP_PAYLOAD = {
    "bootstrap-address": "10.10.10.12",
    "system_mode": "simplex",
    "name": "subcloud1",
    "description": "subcloud1 description",
    "location": "subcloud1 location",
    "management_subnet": "192.168.101.0/24",
    "management_gateway_address": "192.168.101.1",
    "management_start_address": "192.168.101.2",
    "management_end_address": "192.168.101.50",
    "systemcontroller_gateway_address": "192.168.204.101",
    "external_oam_subnet": "10.10.10.0/24",
    "external_oam_gateway_address": "10.10.10.1",
    "external_oam_floating_address": "10.10.10.12",
    "sysadmin_password": (base64.b64encode("testpass".encode("utf-8"))).decode("ascii"),
}

FAKE_BOOTSTRAP_FILE_DATA = {
    "system_mode": "simplex",
    "name": "fake_subcloud1",
    "management_subnet": "192.168.101.0/24",
    "management_start_address": "192.168.101.2",
    "management_end_address": "192.168.101.50",
    "management_gateway_address": "192.168.101.1",
    "external_oam_subnet": "10.10.10.0/24",
    "external_oam_gateway_address": "10.10.10.1",
    "external_oam_floating_address": "10.10.10.12",
    "systemcontroller_gateway_address": "192.168.204.101",
}

FAKE_SUBCLOUD_INSTALL_VALUES = {
    "image": "http://192.168.101.2:8080/iso/bootimage.iso",
    "software_version": FAKE_SOFTWARE_VERSION,
    "bootstrap_interface": "eno1",
    "bootstrap_address": "128.224.151.183",
    "bootstrap_address_prefix": 23,
    "bmc_address": "128.224.64.180",
    "bmc_username": "root",
    "nexthop_gateway": "128.224.150.1",
    "network_address": "128.224.144.0",
    "network_mask": "255.255.254.0",
    "install_type": 3,
    "console_type": "tty0",
    "bootstrap_vlan": 128,
    "rootfs_device": "/dev/disk/by-path/pci-0000:5c:00.0-scsi-0:1:0:0",
    "boot_device": "/dev/disk/by-path/pci-0000:5c:00.0-scsi-0:1:0:0",
    "rd.net.timeout.ipv6dad": 300,
}


FAKE_SUBCLOUD_INSTALL_VALUES_WITH_PERSISTENT_SIZE = {
    "image": "http://192.168.101.2:8080/iso/bootimage.iso",
    "software_version": FAKE_SOFTWARE_VERSION,
    "bootstrap_interface": "eno1",
    "bootstrap_address": "128.224.151.183",
    "bootstrap_address_prefix": 23,
    "bmc_address": "128.224.64.180",
    "bmc_username": "root",
    "nexthop_gateway": "128.224.150.1",
    "network_address": "128.224.144.0",
    "network_mask": "255.255.254.0",
    "install_type": 3,
    "console_type": "tty0",
    "bootstrap_vlan": 128,
    "rootfs_device": "/dev/disk/by-path/pci-0000:5c:00.0-scsi-0:1:0:0",
    "boot_device": "/dev/disk/by-path/pci-0000:5c:00.0-scsi-0:1:0:0",
    "rd.net.timeout.ipv6dad": 300,
    "persistent_size": 40000,
}

FAKE_UPGRADES_METADATA = (
    """
    <build>\n<version>0.1</version>\n<supported_upgrades>
    \n<upgrade>\n<version>%s</version>\n</upgrade>
    \n<upgrade>\n<version>21.12</version>\n</upgrade>
    \n<upgrade>\n<version>22.12</version>\n</upgrade>
    \n</supported_upgrades>\n</build>
"""
    % FAKE_SOFTWARE_VERSION
)

# FAKE SYSINV DATA
FAKE_SITE0_SYSTEM_UUID = str(uuid.uuid4())
FAKE_SITE1_SYSTEM_UUID = str(uuid.uuid4())

# SAMPLE SYSTEM PEER DATA
SAMPLE_SYSTEM_PEER_UUID = FAKE_SITE1_SYSTEM_UUID
SAMPLE_SYSTEM_PEER_NAME = "SystemPeer1"
SAMPLE_MANAGER_ENDPOINT = "http://127.0.0.1:5000"
SAMPLE_MANAGER_USERNAME = "admin"
SAMPLE_MANAGER_PASSWORD = (base64.b64encode("password".encode("utf-8"))).decode("ascii")
SAMPLE_PEER_CONTROLLER_GATEWAY_IP = "128.128.128.1"
SAMPLE_ADMINISTRATIVE_STATE = "enabled"
SAMPLE_HEARTBEAT_INTERVAL = 10
SAMPLE_HEARTBEAT_FAILURE_THRESHOLD = 3
SAMPLE_HEARTBEAT_FAILURES_POLICY = "alarm"
SAMPLE_HEARTBEAT_MAINTENANCE_TIMEOUT = 600
SAMPLE_AVAILABILITY_STATE_AVAILABLE = "available"


def create_fake_subcloud(ctxt, **kwargs):
    values = {
        "name": "subcloud1",
        "description": "subcloud1 description",
        "location": "subcloud1 location",
        "software_version": FAKE_SOFTWARE_VERSION,
        "management_subnet": "192.168.101.0/24",
        "management_gateway_ip": "192.168.101.1",
        "management_start_ip": "192.168.101.2",
        "management_end_ip": "192.168.101.50",
        "systemcontroller_gateway_ip": "192.168.204.101",
        "external_oam_subnet_ip_family": "4",
        "deploy_status": consts.DEPLOY_STATE_DONE,
        "error_description": consts.ERROR_DESC_EMPTY,
        "region_name": base.SUBCLOUD_1["region_name"],
        "openstack_installed": False,
        "group_id": 1,
        "data_install": "data from install",
    }
    values.update(kwargs)
    return db_api.subcloud_create(ctxt, **values)


def get_test_system_peer_dict(data_type, **kw):
    # id should not be part of the structure
    system_peer = {
        "peer_uuid": kw.get("peer_uuid", SAMPLE_SYSTEM_PEER_UUID),
        "peer_name": kw.get("peer_name", SAMPLE_SYSTEM_PEER_NAME),
        "administrative_state": kw.get(
            "administrative_state", SAMPLE_ADMINISTRATIVE_STATE
        ),
        "heartbeat_interval": kw.get("heartbeat_interval", SAMPLE_HEARTBEAT_INTERVAL),
        "heartbeat_failure_threshold": kw.get(
            "heartbeat_failure_threshold", SAMPLE_HEARTBEAT_FAILURE_THRESHOLD
        ),
        "heartbeat_failure_policy": kw.get(
            "heartbeat_failure_policy", SAMPLE_HEARTBEAT_FAILURES_POLICY
        ),
        "heartbeat_maintenance_timeout": kw.get(
            "heartbeat_maintenance_timeout", SAMPLE_HEARTBEAT_MAINTENANCE_TIMEOUT
        ),
    }

    if data_type == "db":
        system_peer["endpoint"] = kw.get("manager_endpoint", SAMPLE_MANAGER_ENDPOINT)
        system_peer["username"] = kw.get("manager_username", SAMPLE_MANAGER_USERNAME)
        system_peer["password"] = kw.get("manager_password", SAMPLE_MANAGER_PASSWORD)
        system_peer["gateway_ip"] = kw.get(
            "peer_controller_gateway_ip", SAMPLE_PEER_CONTROLLER_GATEWAY_IP
        )
    else:
        system_peer["manager_endpoint"] = kw.get(
            "manager_endpoint", SAMPLE_MANAGER_ENDPOINT
        )
        system_peer["manager_username"] = kw.get(
            "manager_username", SAMPLE_MANAGER_USERNAME
        )
        system_peer["manager_password"] = kw.get(
            "manager_password", SAMPLE_MANAGER_PASSWORD
        )
        system_peer["peer_controller_gateway_address"] = kw.get(
            "peer_controller_gateway_ip", SAMPLE_PEER_CONTROLLER_GATEWAY_IP
        )

    return system_peer
