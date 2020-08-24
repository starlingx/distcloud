#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

FAKE_SUBCLOUD_INSTALL_VALUES = {
    "image": "http://192.168.101.2:8080/iso/bootimage.iso",
    "software_version": "12.34",
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
