#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""Policy engine For DC."""

from oslo_config import cfg
from oslo_policy import policy
from webob import exc

from dcmanager.api import policies as controller_policies

CONF = cfg.CONF
_ENFORCER = None


def reset():
    """Discard current Enforcer object."""
    global _ENFORCER
    _ENFORCER = None


def init(policy_file="policy.yaml"):
    """Init an Enforcer class.

    :param policy_file: Custom policy file to be used.

    :return: Returns a Enforcer instance.
    """
    global _ENFORCER
    if not _ENFORCER:

        # https://docs.openstack.org/oslo.policy/latest/user/usage.html
        _ENFORCER = policy.Enforcer(
            CONF,
            policy_file=policy_file,
            default_rule="default",
            use_conf=True,
            overwrite=True,
        )
        _ENFORCER.register_defaults(controller_policies.list_rules())
    return _ENFORCER


def authorize(rule, target, creds, do_raise=True):
    """A wrapper around 'authorize' from 'oslo_policy.policy'."""
    init()
    return _ENFORCER.authorize(
        rule, target, creds, do_raise=do_raise, exc=exc.HTTPForbidden
    )
