#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import os

# TODO(srana): Refactor DC role usage due to deprecation.
DC_ROLE_UNDETECTED = "unknown"
DC_ROLE_SUBCLOUD = "subcloud"
DC_ROLE_SYSTEMCONTROLLER = "systemcontroller"

# Unique name of certificate
CERTIFICATE_TYPE_ADMIN_ENDPOINT = "admin-endpoint-cert"
CERTIFICATE_TYPE_ADMIN_ENDPOINT_INTERMEDIATE_CA = "intermediate-ca-cert"
CERT_MODE_SSL_CA = "ssl_ca"

DC_ADMIN_ENDPOINT_SECRET_NAME = "dc-adminep-certificate"
DC_ADMIN_ROOT_CA_SECRET_NAME = "dc-adminep-root-ca-certificate"

SC_INTERMEDIATE_CA_SECRET_NAME = "sc-adminep-ca-certificate"
SC_ADMIN_ENDPOINT_SECRET_NAME = "sc-adminep-certificate"

DC_ROOT_CA_CERT_FILE = "dc-adminep-root-ca.crt"
SSL_CERT_CA_DIR = "/etc/pki/ca-trust/source/anchors/"
DC_ROOT_CA_CERT_PATH = os.path.join(SSL_CERT_CA_DIR, DC_ROOT_CA_CERT_FILE)

SYSTEM_CONTROLLER_REGION = "SystemController"

SERVICE_TYPE_PLATFORM = "platform"
SYSINV_USERNAME = "sysinv"

# The periodic audit runs every 5 seconds to process background audits across
# all subclouds. Notification-triggered audits run more frequently (every 2
# seconds) to ensure prompt handling when a subcloud comes online.
# This separation allows faster responsiveness to events without interfering
# with the regular audit cadence.
PERIODIC_AUDIT_INTERVAL_SECS = 5
NOTIFICATION_QUEUE_AUDIT_INTERVAL_SECS = 2
