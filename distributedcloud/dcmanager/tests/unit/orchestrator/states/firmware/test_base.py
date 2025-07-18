#
# Copyright (c) 2020, 2024-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import uuid

from dcmanager.common import consts
from dcmanager.tests.unit.fakes import FakeVimStrategy
from dcmanager.tests.unit.orchestrator.states.fakes import FakeDevice
from dcmanager.tests.unit.orchestrator.states.fakes import FakeDeviceImage
from dcmanager.tests.unit.orchestrator.states.fakes import FakeDeviceLabel
from dcmanager.tests.unit.orchestrator.test_base import TestSwUpdate


class DeviceImageState(object):
    def __init__(self, pcidevice_uuid, image_uuid, status):
        self.pcidevice_uuid = pcidevice_uuid
        self.image_uuid = image_uuid
        self.status = status


class TestFwUpdateState(TestSwUpdate):
    def setUp(self):
        super().setUp()

        # Setting strategy_type to firmware will setup the firmware
        # orchestration worker, and will mock away the other orch threads
        self.strategy_type = consts.SW_UPDATE_TYPE_FIRMWARE

    def _create_fake_strategy(self, state, apply_phase=None, build_phase=None):
        return FakeVimStrategy(
            state=state, apply_phase=apply_phase, build_phase=build_phase
        )

    def _create_fake_device(self, pvendor_id, pdevice_id, enabled=True):
        return FakeDevice(
            str(uuid.uuid4()),
            pvendor_id=pvendor_id,
            pdevice_id=pdevice_id,
            enabled=enabled,
        )

    def _create_fake_device_label(self, label_key, label_value, pcidevice_uuid):
        return FakeDeviceLabel(
            label_key=label_key, label_value=label_value, pcidevice_uuid=pcidevice_uuid
        )

    def _create_fake_device_image(
        self, pci_vendor, pci_device, applied, applied_labels
    ):
        return FakeDeviceImage(
            str(uuid.uuid4()),
            pci_vendor=pci_vendor,
            pci_device=pci_device,
            applied=applied,
            applied_labels=applied_labels,
        )

    def _create_fake_device_image_state(self, pcidevice_uuid, image_uuid, status):
        return DeviceImageState(pcidevice_uuid, image_uuid, status)
