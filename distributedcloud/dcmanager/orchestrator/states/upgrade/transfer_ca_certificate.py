#
# Copyright (c) 2022-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import time

from dcmanager.common import consts
from dcmanager.common import utils
from dcmanager.orchestrator.states.base import BaseState


# Max time: 1.5 minutes = 3 retries x 30 seconds between each
DEFAULT_MAX_RETRIES = 3
DEFAULT_SLEEP_DURATION = 30


class TransferCACertificateState(BaseState):
    """Upgrade step for transfering CA certificate"""

    def __init__(self, region_name):
        self.subcloud_type = self.get_sysinv_client(
            region_name).get_system().system_mode
        if self.subcloud_type == consts.SYSTEM_MODE_SIMPLEX:
            super(TransferCACertificateState, self).__init__(
                next_state=consts.STRATEGY_STATE_LOCKING_CONTROLLER_0,
                region_name=region_name)
        else:
            super(TransferCACertificateState, self).__init__(
                next_state=consts.STRATEGY_STATE_LOCKING_CONTROLLER_1,
                region_name=region_name)

        self.max_retries = DEFAULT_MAX_RETRIES
        self.sleep_duration = DEFAULT_SLEEP_DURATION

    def perform_state_action(self, strategy_step):
        """Transfer CA certificate for an upgrade to a subcloud

        Returns the next state in the state machine on success.
        Any exceptions raised by this method set the strategy to FAILED.
        """

        if self.subcloud_type == consts.SYSTEM_MODE_SIMPLEX:
            return self.next_state

        self.info_log(strategy_step, "Start transferring CA certificate...")

        retry_counter = 0
        while True:
            try:
                sysinv_client = \
                    self.get_sysinv_client(strategy_step.subcloud.region_name)

                data = {'mode': 'openldap_ca'}
                ldap_ca_cert, ldap_ca_key = utils.get_certificate_from_secret(
                    consts.OPENLDAP_CA_CERT_SECRET_NAME,
                    consts.CERT_NAMESPACE_PLATFORM_CA_CERTS)

                sysinv_client.update_certificate(
                    '', ldap_ca_cert + ldap_ca_key, data)
                break
            except Exception as e:
                self.warn_log(strategy_step,
                              "Encountered exception: %s" % str(e))
                retry_counter += 1
                if retry_counter > self.max_retries:
                    raise Exception(
                        "Failed to transfer CA certificate for subcloud %s."
                        % strategy_step.subcloud.name)
                self.warn_log(strategy_step,
                              "Retry (%i/%i) in %i secs."
                              % (retry_counter,
                                 self.max_retries,
                                 self.sleep_duration))
                time.sleep(self.sleep_duration)

        self.info_log(strategy_step, "CA certificate transfer completed.")
        return self.next_state
