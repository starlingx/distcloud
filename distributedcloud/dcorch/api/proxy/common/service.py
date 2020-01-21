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
# Copyright (c) 2017 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

from oslo_log import log as logging
from oslo_service.wsgi import Request
import webob.dec
import webob.exc

LOG = logging.getLogger(__name__)


class Application(object):

    @classmethod
    def factory(cls, global_config, **local_config):
        """Used for paste app factories in paste.deploy config files.

        """
        return cls(**local_config)

    def __call__(self, environ, start_response):
        raise NotImplementedError('You must implement __call__')


class Middleware(Application):

    """Base WSGI middleware wrapper.

    These classes require an application to be
    initialized that will be called next.  By default the middleware will
    simply call its wrapped app, or you can override __call__ to customize its
    behavior.
    """

    @classmethod
    def factory(cls, global_config, **local_config):

        """Used for paste app factories in paste.deploy config files.

        Any local configuration (that is, values under the [filter:APPNAME]
        section of the paste config) will be passed into the `__init__` method
        as kwargs.
        """

        def _factory(app):
            # https://bugs.launchpad.net/starlingx/+bug/1865085
            return cls(app, global_config, **local_config)  # pylint: disable=too-many-function-args
        return _factory

    def __init__(self, application):
        self.application = application

    def process_request(self, req):

        """Called on each request.

        If this returns None, the next application down the stack will be
        executed. If it returns a response then that response will be returned
        and execution will stop here.
        """

        return None

    def process_response(self, response):
        """Do whatever you'd like to the response."""
        return response

    @webob.dec.wsgify(RequestClass=Request)
    def __call__(self, req):
        response = self.process_request(req)
        if response:
            return response
        # call the next app on the stack to process the request
        response = req.get_response(self.application)
        return self.process_response(response)
