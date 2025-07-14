#
# Copyright (c) 2020-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import uuid

from dccommon import consts as dccommon_consts
from dcmanager.common import consts

PREVIOUS_PREVIOUS_VERSION = "01.23"
PREVIOUS_VERSION = "12.34"
UPGRADED_VERSION = "56.78"

PREVIOUS_KUBE_VERSION = "v1.2.3"
UPGRADED_KUBE_VERSION = "v1.2.4"

FAKE_VENDOR = "8086"
FAKE_DEVICE = "0b30"


class FakeController(object):
    def __init__(
        self,
        host_id=1,
        hostname="controller-0",
        administrative=consts.ADMIN_UNLOCKED,
        operational=consts.OPERATIONAL_ENABLED,
        availability=dccommon_consts.AVAILABILITY_ONLINE,
        ihost_action=None,
        target_load=UPGRADED_VERSION,
        software_load=PREVIOUS_VERSION,
        task=None,
        capabilities={"Personality": "Controller-Active"},
    ):
        self.uuid = str(uuid.uuid4())
        self.id = host_id
        self.hostname = hostname
        self.administrative = administrative
        self.operational = operational
        self.availability = availability
        self.ihost_action = ihost_action
        self.target_load = target_load
        self.software_load = software_load
        self.task = task
        self.capabilities = capabilities


class FakeDevice(object):
    def __init__(
        self, obj_id, pvendor_id=FAKE_VENDOR, pdevice_id=FAKE_DEVICE, enabled=True
    ):
        self.uuid = obj_id
        self.pvendor_id = pvendor_id
        self.pdevice_id = pdevice_id
        self.enabled = enabled


class FakeDeviceImage(object):
    def __init__(
        self,
        obj_id,
        pci_vendor=FAKE_VENDOR,
        pci_device=FAKE_DEVICE,
        bitstream_type="functional",
        applied=False,
        applied_labels=None,
    ):
        self.uuid = obj_id
        self.pci_vendor = pci_vendor
        self.pci_device = pci_device
        self.bitstream_type = bitstream_type
        self.applied = applied
        self.applied_labels = applied_labels


class FakeDeviceLabel(object):
    def __init__(self, label_key=None, label_value=None, pcidevice_uuid=None):
        self.uuid = str(uuid.uuid4())
        self.label_key = label_key
        self.label_value = label_value
        self.pcidevice_uuid = pcidevice_uuid


class FakeHostFilesystem(object):
    def __init__(self, name="scratch", logical_volume="scratch-lv", size=16):
        self.name = name
        self.logical_volume = logical_volume
        self.size = size
        self.uuid = str(uuid.uuid4())


class FakeKubeRootCaUpdate(object):
    def __init__(self, obj_id=1, state="update-started"):
        self.id = obj_id
        self.uuid = str(uuid.uuid4())
        self.state = state


class FakeKubeUpgrade(object):
    def __init__(
        self,
        obj_id=1,
        from_version=PREVIOUS_KUBE_VERSION,
        to_version=UPGRADED_KUBE_VERSION,
        state="upgrade-complete",
    ):
        self.id = obj_id
        self.uuid = str(uuid.uuid4())
        self.from_version = state
        self.to_version = to_version
        self.state = state


class FakeKubeVersion(object):
    def __init__(
        self, obj_id=1, version=UPGRADED_KUBE_VERSION, target=True, state="active"
    ):
        self.id = obj_id
        self.uuid = str(uuid.uuid4())
        self.version = version
        self.target = target
        self.state = state
        self.upgrade_from = []
        self.applied_patches = []
        self.available_patches = []

    def to_dict(self):
        return dict(self.__dict__)


class FakeLoad(object):
    def __init__(
        self,
        obj_id,
        compatible_version="N/A",
        required_patches="N/A",
        software_version=PREVIOUS_VERSION,
        state="active",
        created_at=None,
        updated_at=None,
    ):
        self.id = obj_id
        self.uuid = str(uuid.uuid4())
        self.compatible_version = compatible_version
        self.required_patches = required_patches
        self.software_version = software_version
        self.state = state
        self.created_at = created_at
        self.updated_at = updated_at

    @staticmethod
    def from_dict(load_data):
        return FakeLoad(**load_data)

    def to_dict(self):
        return dict(self.__dict__)


class FakeSystem(object):
    def __init__(self, obj_id=1, software_version=UPGRADED_VERSION):
        self.id = obj_id
        self.uuid = str(uuid.uuid4())
        self.software_version = software_version


class FakeUpgrade(object):
    def __init__(
        self,
        obj_id=1,
        state="completed",
        from_release=PREVIOUS_VERSION,
        to_release=UPGRADED_VERSION,
    ):
        self.id = obj_id
        self.uuid = str(uuid.uuid4())
        self.state = state
        self.from_release = from_release
        self.to_release = to_release
        self.links = []


class FakeAlarm(object):
    def __init__(self, alarm_id="12.34", mgmt_affecting="False"):
        self.alarm_id = alarm_id
        self.mgmt_affecting = mgmt_affecting
