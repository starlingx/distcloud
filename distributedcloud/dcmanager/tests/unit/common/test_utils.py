#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the generic utils.
"""
import unittest

import netaddr

from dcmanager.common import exceptions
from dcmanager.common import utils


class FakeAddressPool(object):
    def __init__(self, floating_address, network, prefix):
        self.floating_address = floating_address
        self.network = network
        self.prefix = prefix
        self.family = netaddr.IPAddress(network).version


class TestCommonUtils(unittest.TestCase):
    def test_fail_validate_network_str(self):
        invalids = [
            {
                "network_str": "192.168.0.0/24,fd00::1/64,192.168.1.0/24",
                "error": "Invalid subnet - more than two IP subnets",
            },
            {
                "network_str": "192.168.0.INV/24",
                "error": "Invalid subnet - not a valid IP subnet",
            },
            {
                "network_str": "fd00:/64",
                "error": "Invalid subnet - not a valid IP subnet",
            },
            {
                "network_str": "192.168.0.0/24,192.167.0.0/24",
                "error": "Invalid subnet - dual-stack of same IP family",
            },
            {
                "network_str": "fd00::0/64,fd01::0/64",
                "error": "Invalid subnet - dual-stack of same IP family",
            },
        ]

        for invalid in invalids:
            with self.assertRaises(exceptions.ValidateFail) as context:
                utils.validate_network_str(invalid["network_str"], 32)
            self.assertEqual(context.exception.msg, invalid["error"])

    def test_pass_validate_network_str(self):
        network_str = "192.168.0.0/24,fd00::/64"
        networks = utils.validate_network_str(network_str, 32)
        self.assertEqual(len(networks), 2)

        network_str = "192.168.0.0/24"
        networks = utils.validate_network_str(network_str, 32)
        self.assertEqual(len(networks), 1)

    def test_fail_validate_address_str(self):
        invalids = [
            {
                "address_str": "192.168.0.1,fd00::1,192.167.0.1",
                "network_str": "192.168.0.0/24",
                "error": "Invalid address - more than two IP addresses",
            },
            {
                "address_str": "192.168.0.INV",
                "network_str": "192.168.0.0/24",
                "error": "Invalid address - not a valid IP address",
            },
            {
                "address_str": "fd00:0",
                "network_str": "fd00::/64",
                "error": "Invalid address - not a valid IP address",
            },
            {
                "address_str": "192.168.0.1,192.167.0.1",
                "network_str": "192.168.0.0/24",
                "error": "Invalid address - dual-stack of same IP family",
            },
            {
                "address_str": "fd00::0,fd01::0",
                "network_str": "192.168.0.0/24",
                "error": "Invalid address - dual-stack of same IP family",
            },
            {
                "address_str": "192.168.0.1",
                "network_str": "192.168.0.0/24,fd00::/64",
                "error": (
                    "Invalid address - Not of same size (single or dual-stack) with "
                    "subnet"
                ),
            },
            {
                "address_str": "192.168.0.1",
                "network_str": "fd00::/64",
                "error": ("Invalid IP version - must match network version IPv6"),
            },
            {
                "address_str": "fd00::1",
                "network_str": "192.168.0.0/24",
                "error": ("Invalid IP version - must match network version IPv4"),
            },
        ]

        for invalid in invalids:
            networks = utils.validate_network_str(invalid["network_str"], 32)
            with self.assertRaises(exceptions.ValidateFail) as context:
                utils.validate_address_str(invalid["address_str"], networks)
            self.assertEqual(context.exception.msg, invalid["error"])

    def test_pass_validate_address_str(self):
        network_str = "192.168.0.0/24,fd00::/64"
        address_str = "192.168.0.1,fd00::1"
        networks = utils.validate_network_str(network_str, 32)
        addresses = utils.validate_address_str(address_str, networks)
        self.assertEqual(len(addresses), 2)

    def test_get_pool_by_ip_family(self):
        POOLS_DUAL_STACK = [
            FakeAddressPool("fdff:719a:bf60:233::2", "fdff:719a:bf60:233::", 64),
            FakeAddressPool("192.168.0.1", "192.168.0.0", 24),
        ]

        ip_family = 6
        pool = utils.get_pool_by_ip_family(POOLS_DUAL_STACK, ip_family)
        self.assertEqual(pool, POOLS_DUAL_STACK[0])

        ip_family = 4
        pool = utils.get_pool_by_ip_family(POOLS_DUAL_STACK, ip_family)
        self.assertEqual(pool, POOLS_DUAL_STACK[1])

        POOLS_IPV4 = [
            FakeAddressPool("192.168.0.1", "192.168.0.0", 24),
        ]
        ip_family = 6
        with self.assertRaises(exceptions.ValidateFail) as context:
            utils.get_pool_by_ip_family(POOLS_IPV4, ip_family)
        self.assertEqual(
            context.exception.msg,
            f"IPv{ip_family} pool not found in pools {POOLS_IPV4}",
        )

    def test_get_management_gateway_address_ip_family(self):
        payload = {
            "admin_gateway_address": "192.168.1.1",
            "management_gateway_address": "fd00::1",
        }
        ip_family = utils.get_management_gateway_address_ip_family(payload)
        self.assertEqual(ip_family, 4)

        payload = {
            "management_gateway_address": "fd00::1",
        }
        ip_family = utils.get_management_gateway_address_ip_family(payload)
        self.assertEqual(ip_family, 6)

        invalid_ip = "fd00::INV"
        payload = {
            "management_gateway_address": invalid_ip,
        }
        with self.assertRaises(exceptions.ValidateFail) as context:
            utils.get_management_gateway_address_ip_family(payload)
        self.assertEqual(
            context.exception.msg,
            f"Invalid address - not a valid IP address: failed to detect a valid IP "
            f"address from '{invalid_ip}'",
        )

    def test_get_primary_oam_address_ip_family(self):
        payload = {
            "external_oam_subnet_ip_family": 4,
        }
        ip_family = utils.get_primary_oam_address_ip_family(payload)
        self.assertEqual(ip_family, 4)

        invalid_family = "inv"
        payload = {
            "external_oam_subnet_ip_family": invalid_family,
        }
        with self.assertRaises(exceptions.ValidateFail) as context:
            utils.get_primary_oam_address_ip_family(payload)
        self.assertEqual(
            context.exception.msg,
            f"Invalid external_oam_subnet_ip_family: "
            f"invalid literal for int() with base 10: '{invalid_family}'",
        )

        payload = {"external_oam_subnet": "192.168.0.1/24,fd00::/64"}
        ip_family = utils.get_primary_oam_address_ip_family(payload)
        self.assertEqual(ip_family, 4)

        payload = {"external_oam_subnet": "fd00::/64,192.168.0.1/24"}
        ip_family = utils.get_primary_oam_address_ip_family(payload)
        self.assertEqual(ip_family, 6)

        payload = {"external_oam_subnet": "fd00::/64"}
        ip_family = utils.get_primary_oam_address_ip_family(payload)
        self.assertEqual(ip_family, 6)

        invalid_subnet = "fd00:/64"
        payload = {"external_oam_subnet": invalid_subnet}
        with self.assertRaises(exceptions.ValidateFail) as context:
            utils.get_primary_oam_address_ip_family(payload)
        self.assertEqual(
            context.exception.msg,
            f"Invalid OAM network - not a valid IP Network: "
            f"invalid IPNetwork {invalid_subnet}",
        )
