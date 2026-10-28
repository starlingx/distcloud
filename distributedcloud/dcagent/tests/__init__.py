# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_service.backend import BackendType
from oslo_service.backend import init_backend

# oslo.service defaults to the eventlet backend. Select the threading backend
# used by dccommon.scheduler before any test imports oslo_service.threadgroup.
init_backend(BackendType.THREADING)
