#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock
import uuid

from dcmanager.common import consts
from oslo_utils import timeutils

from dcmanager.tests.unit.common.fake_subcloud import FAKE_SUBCLOUD_INSTALL_VALUES


PREVIOUS_PREVIOUS_VERSION = '01.23'
PREVIOUS_VERSION = '12.34'
UPGRADED_VERSION = '56.78'

FAKE_VENDOR = '8086'
FAKE_DEVICE = '0b30'

# VIM constants for Strategy
APPLY_TYPE_SERIAL = 'serial'
INSTANCE_ACTION_STOP_START = 'stop-start'
ALARM_RESTRICTIONS_STRICT = 'strict'


class FakeController(object):
    def __init__(self,
                 host_id=1,
                 hostname='controller-0',
                 administrative=consts.ADMIN_UNLOCKED,
                 operational=consts.OPERATIONAL_ENABLED,
                 availability=consts.AVAILABILITY_ONLINE,
                 ihost_action=None,
                 target_load=UPGRADED_VERSION,
                 task=None):
        self.uuid = str(uuid.uuid4())
        self.id = host_id
        self.hostname = hostname
        self.administrative = administrative
        self.operational = operational
        self.availability = availability
        self.ihost_action = ihost_action
        self.target_load = target_load
        self.task = task


class FakeDevice(object):
    def __init__(self,
                 obj_id,
                 pvendor_id=FAKE_VENDOR,
                 pdevice_id=FAKE_DEVICE,
                 enabled=True):
        self.uuid = obj_id
        self.pvendor_id = pvendor_id
        self.pdevice_id = pdevice_id
        self.enabled = enabled


class FakeDeviceImage(object):
    def __init__(self,
                 obj_id,
                 pci_vendor=FAKE_VENDOR,
                 pci_device=FAKE_DEVICE,
                 bitstream_type='functional',
                 applied=False,
                 applied_labels=None):
        self.uuid = obj_id
        self.pci_vendor = pci_vendor
        self.pci_device = pci_device
        self.bitstream_type = bitstream_type
        self.applied = applied
        self.applied_labels = applied_labels


class FakeDeviceLabel(object):
    def __init__(self,
                 label_key=None,
                 label_value=None,
                 pcidevice_uuid=None):
        self.uuid = str(uuid.uuid4())
        self.label_key = label_key
        self.label_value = label_value
        self.pcidevice_uuid = pcidevice_uuid


class FakeHostFilesystem(object):
    def __init__(self,
                 name='scratch',
                 logical_volume='scratch-lv',
                 size=16):
        self.name = name
        self.logical_volume = logical_volume
        self.size = size
        self.uuid = str(uuid.uuid4())


class FakeKeystoneClient(object):
    def __init__(self):
        self.session = mock.MagicMock()


class FakeLoad(object):
    def __init__(self,
                 obj_id,
                 compatible_version='N/A',
                 required_patches='N/A',
                 software_version=PREVIOUS_VERSION,
                 state='active',
                 created_at=None,
                 updated_at=None):
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


class FakeSubcloud(object):
    def __init__(self,
                 subcloud_id=1,
                 name='subcloud1',
                 description='subcloud',
                 location='A location',
                 software_version=PREVIOUS_VERSION,
                 management_state=consts.MANAGEMENT_MANAGED,
                 availability_status=consts.AVAILABILITY_ONLINE,
                 deploy_status=consts.DEPLOY_STATE_DONE,
                 data_install=FAKE_SUBCLOUD_INSTALL_VALUES):
        self.id = subcloud_id
        self.name = name
        self.description = description
        self.location = location
        self.software_version = software_version
        self.management_state = management_state
        self.availability_status = availability_status
        self.deploy_status = deploy_status
        # todo(abailey): add these and re-factor other unit tests to use
        # self.management_subnet = management_subnet
        # self.management_gateway_ip = management_gateway_ip
        # self.management_start_ip = management_start_ip
        # self.management_end_ip = management_end_ip
        # self.external_oam_subnet = external_oam_subnet
        # self.external_oam_gateway_address = external_oam_gateway_address
        # self.external_oam_floating_address = external_oam_floating_address
        # self.systemcontroller_gateway_ip = systemcontroller_gateway_ip
        self.data_install = data_install
        self.created_at = timeutils.utcnow()
        self.updated_at = timeutils.utcnow()


class FakeSysinvClient(object):
    def __init__(self):
        pass


class FakeSystem(object):
    def __init__(self,
                 obj_id=1,
                 software_version=UPGRADED_VERSION):
        self.id = obj_id
        self.uuid = str(uuid.uuid4())
        self.software_version = software_version


class FakeUpgrade(object):
    def __init__(self,
                 obj_id=1,
                 state='completed',
                 from_release=PREVIOUS_VERSION,
                 to_release=UPGRADED_VERSION):
        self.id = obj_id
        self.uuid = str(uuid.uuid4())
        self.state = state
        self.from_release = from_release
        self.to_release = to_release
        self.links = []


class FakeVimClient(object):
    def __init__(self):
        pass


class FakeVimStrategy(object):
    """Represents a VIM Strategy object defined in:

       starlingx/nfv/nfv-client/nfv_client/openstack/sw_update.py
    """

    def __init__(self,
                 name="VIM Strategy",
                 controller_apply_type=APPLY_TYPE_SERIAL,
                 storage_apply_type=APPLY_TYPE_SERIAL,
                 swift_apply_type=APPLY_TYPE_SERIAL,
                 worker_apply_type=APPLY_TYPE_SERIAL,
                 max_parallel_worker_hosts=2,
                 default_instance_action=INSTANCE_ACTION_STOP_START,
                 alarm_restrictions=ALARM_RESTRICTIONS_STRICT,
                 current_phase=None,
                 current_phase_completion_percentage=0,
                 state=None,
                 build_phase=None,
                 apply_phase=None,
                 abort_phase=None):
        self.uuid = str(uuid.uuid4())
        self.name = name
        self.controller_apply_type = controller_apply_type
        self.storage_apply_type = storage_apply_type
        self.swift_apply_type = swift_apply_type
        self.worker_apply_type = worker_apply_type
        self.max_parallel_worker_hosts = max_parallel_worker_hosts
        self.default_instance_action = default_instance_action
        self.alarm_restrictions = alarm_restrictions
        self.current_phase = current_phase
        self.current_phase_completion_percentage =\
            current_phase_completion_percentage
        self.state = state
        self.build_phase = build_phase
        self.apply_phase = apply_phase
        self.abort_phase = abort_phase
