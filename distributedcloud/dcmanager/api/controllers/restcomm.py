# Copyright (c) 2015 Huawei Tech. Co., Ltd.
# Copyright (c) 2017-2022 Wind River Systems, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

import abc

from pecan import expose
from pecan import request
import six

import dcmanager.common.context as k_context


def extract_context_from_environ():
    context_paras = {'auth_token': 'HTTP_X_AUTH_TOKEN',
                     'user': 'HTTP_X_USER_ID',
                     'project': 'HTTP_X_TENANT_ID',
                     'user_name': 'HTTP_X_USER_NAME',
                     'tenant_name': 'HTTP_X_PROJECT_NAME',
                     'domain': 'HTTP_X_DOMAIN_ID',
                     'roles': 'HTTP_X_ROLE',
                     'user_domain': 'HTTP_X_USER_DOMAIN_ID',
                     'project_domain': 'HTTP_X_PROJECT_DOMAIN_ID',
                     'request_id': 'openstack.request_id'}

    environ = request.environ

    for key, val in context_paras.items():
        context_paras[key] = environ.get(val)
    role = environ.get('HTTP_X_ROLE')

    context_paras['is_admin'] = 'admin' in role.split(',')
    return k_context.RequestContext(**context_paras)


def extract_credentials_for_policy():
    context_paras = {'project_name': 'HTTP_X_PROJECT_NAME',
                     'roles': 'HTTP_X_ROLE'}
    environ = request.environ
    for key, val in context_paras.items():
        context_paras[key] = environ.get(val)
    context_paras['roles'] = context_paras['roles'].split(',')
    return context_paras


def _get_pecan_data(obj):
    return getattr(obj, "_pecan", {})


def _is_exposed(obj):
    return getattr(obj, "exposed", False)


def _is_generic(obj):
    data = _get_pecan_data(obj)
    return "generic" in data.keys()


def _is_generic_handler(obj):
    data = _get_pecan_data(obj)
    return "generic_handler" in data.keys()


@six.add_metaclass(abc.ABCMeta)
class GenericPathController(object):
    """A controller that allows path parameters to be equal to handler names.

    The _route method provides a custom route resolution that checks if the
    next object is marked as generic or a generic handler, pointing to the
    generic index method in case it is. Pecan will properly handle the rest
    of the routing process by redirecting it to the proper method function
    handler (GET, POST, PATCH, DELETE, etc.).

    Useful when part of the URL contains path parameters that might have
    the same name as an already defined exposed controller method.

    Requires the definition of an index method with the generator:
    @expose(generic=True, ...)

    Does not support nested subcontrollers.
    """

    RESERVED_NAMES = ("_route", "_default", "_lookup")

    @abc.abstractmethod
    def index(self):
        pass

    @expose()
    def _route(self, remainder, request):
        next_url_part, rest = remainder[0], remainder[1:]
        next_obj = getattr(self, next_url_part, None)

        is_generic = _is_generic(next_obj) or _is_generic_handler(next_obj)
        is_reserved_name = next_url_part in self.__class__.RESERVED_NAMES

        if _is_exposed(next_obj) and not is_generic and not is_reserved_name:
            # A non-generic exposed method with a non-reserved name
            return next_obj, rest
        else:
            return self.index, remainder
