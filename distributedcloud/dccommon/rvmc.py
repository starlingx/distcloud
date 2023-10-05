# Copyright (c) 2019-2023 Wind River Systems, Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
# Redfish Virtual Media Controller
#
# Note that any changes in error messages need to be reflected in
# the installation Ansible playbook.

import base64
import datetime
import json
import os
import socket
import sys
import time
import yaml

# Import Redfish Python Library
# Module: https://pypi.org/project/redfish/
import redfish
from redfish.rest.v1 import InvalidCredentialsError

from dccommon import exceptions


# Constants
# ---------
POWER_ON = 'On'
POWER_OFF = "Off"

REDFISH_ROOT_PATH = '/redfish/v1'
SUPPORTED_VIRTUAL_MEDIA_DEVICES = ['CD', 'DVD']  # Maybe add USB to list

# headers for each request type
HDR_CONTENT_TYPE = "'Content-Type': 'application/json'"
HDR_ACCEPT = "'Accept': 'application/json'"

# they all happen to be the same right now
GET_HEADERS = {HDR_CONTENT_TYPE, HDR_ACCEPT}
POST_HEADERS = {HDR_CONTENT_TYPE, HDR_ACCEPT}
PATCH_HEADERS = {HDR_CONTENT_TYPE, HDR_ACCEPT}

# HTTP request types ; only 3 are required by this tool
POST = 'POST'
GET = 'GET'
PATCH = 'PATCH'

# max number of polling retries while waiting for some long task to complete
MAX_POLL_COUNT = 200
# some servers timeout on inter comm gaps longer than 10 secs
RETRY_DELAY_SECS = 10
# 2 second delay constant
DELAY_2_SECS = 2

# max number of establishing BMC connection attempts
MAX_CONNECTION_ATTEMPTS = 3
# interval in seconds between BMC connection attempts
CONNECTION_RETRY_INTERVAL = 15

# max number of session creation attempts
MAX_SESSION_CREATION_ATTEMPTS = 3
# interval in seconds between session creation attempts
SESSION_CREATION_RETRY_INTERVAL = 15

# max number of retries for http transient error (e.g. response status: 500)
MAX_HTTP_TRANSIENT_ERROR_RETRIES = 5
# interval in seconds between http request retries
HTTP_REQUEST_RETRY_INTERVAL = 10


class LoggingUtil(object):
    """The logging utility class.

    If no logger is given, the messages will be written to the standard
    output stream.
    """

    def __init__(self, logger=None, subcloud_name='', debug_level=0):
        """Logger object constructor.

        :param logger: the logger of the class which is calling rvmc module
        :type logger: logging.Logger.
        :param subcloud_name: the subcloud name to be appended to the logging
                              messages
        :type subcloud_name: str.
        :param debug_level: the debug level
        :type debug_level: int.
        """

        self.logger = logger
        self.subcloud_name = subcloud_name
        self.debug_level = debug_level

    def t(self):
        """Return current time for log functions."""

        return datetime.datetime.now().replace(microsecond=0)

    def ilog(self, string):
        """Info Log Utility"""

        if self.logger:
            self.logger.info(
                self.subcloud_name + ': ' + string if self.subcloud_name
                else string)
        else:
            sys.stdout.write("\n%s Info  : %s" % (self.t(), string))

    def wlog(self, string):
        """Warning Log Utility"""

        if self.logger:
            self.logger.warn(
                self.subcloud_name + ': ' + string if self.subcloud_name
                else string)
        else:
            sys.stdout.write("\n%s Warn  : %s" % (self.t(), string))

    def elog(self, string):
        """Error Log Utility"""

        if self.logger:
            self.logger.error(
                self.subcloud_name + ': ' + string if self.subcloud_name
                else string)
        else:
            sys.stdout.write("\n%s Error : %s" % (self.t(), string))

    def alog(self, string):
        """Action Log Utility"""

        if self.logger:
            self.logger.info(
                self.subcloud_name + ': ' + string if self.subcloud_name
                else string)
        else:
            sys.stdout.write("\n%s Action: %s" % (self.t(), string))

    def dlog1(self, string, level=1):
        """Debug Log - Level"""

        if self.debug_level and level <= self.debug_level:
            if self.logger:
                self.logger.debug(
                    self.subcloud_name + ': ' + string if self.subcloud_name
                    else string)
            else:
                sys.stdout.write("\n%s Debug%d: %s" %
                                 (self.t(), level, string))

    def dlog2(self, string):
        """Debug Log - Level 2"""

        self.dlog1(string, 2)

    def dlog3(self, string):
        """Debug Log - Level 3"""

        self.dlog1(string, 3)

    def dlog4(self, string):
        """Debug Log - Level 4"""

        self.dlog1(string, 4)

    def slog(self, stage):
        """Execution Stage Log"""

        if self.logger:
            self.logger.info(
                self.subcloud_name + ': ' + stage if self.subcloud_name
                else stage)
        else:
            sys.stdout.write("\n%s Stage : %s" % (self.t(), stage))


class ExitHandler(object):
    """A utility class for handling different exit scenarios in a process.

    Provides methods to manage the process exit in various situations.
    """

    def exit(self, code):
        """Early fault handling

        :param code: the exit status code
        :type code: int.
        """
        if code != 0:
            raise exceptions.RvmcExit(rc=code)


def is_ipv6_address(address, logging_util):
    """Check IPv6 Address.

    :param address: the ip address to compare user name.
    :type address: str.
    :param logging_util: the logging utility.
    :type logging_util: LoggingUtil
    :returns bool: True if address is an IPv6 address else False
    """
    try:
        socket.inet_pton(socket.AF_INET6, address)
        logging_util.dlog3("Address     : %s is IPv6" % address)
    except socket.error:
        logging_util.dlog3("Address     : %s is IPv4" % address)
        return False
    return True


def supported_device(devices):
    """Supported Device

    :param devices: list of devices
    :type : list
    :returns True if a device in devices list is in the
             SUPPORTED_VIRTUAL_MEDIA_DEVICES list.
             Otherwise, False is returned.
    """
    for device in devices:
        if device in SUPPORTED_VIRTUAL_MEDIA_DEVICES:
            return True
    return False


def parse_target(target_name, target_dict, config_file, logging_util,
                 exit_handler):
    """Parse key value pairs in the target config file.

    :param target_name: the subcloud name
    :type target_name: str.
    :param target_dict: dictionary of key value config file pairs
    :type target_dict: dictionary
    :param logging_util: the RVMC config file.
    :type logging_util: str
    :param logging_util: the logging utility.
    :type logging_util: LoggingUtil
    :param exit_handler: the exit handler.
    :type exit_handler: ExitHandler
    :returns the control object; None if any error
    """
    logging_util.dlog3("Parse Target: %s:%s" % (target_name, target_dict))

    pw = target_dict.get('bmc_password')
    if pw is None:
        logging_util.elog("Failed get bmc password from config file")
        return None

    try:
        pw_dec = base64.b64decode(pw).decode('utf-8')
    except Exception as ex:
        logging_util.elog(
            "Failed to decode bmc password found in config file (%s)" % ex)
        logging_util.alog(
            "Verify config file's bmc password is base64 encoded")
        return None

    address = target_dict.get('bmc_address')
    if address is None:
        logging_util.elog("Failed to decode bmc password found in %s" %
                          config_file)
        logging_util.alog(
            "Verify config file's bmc password is base64 encoded")
        return None

    ####################################################################
    #
    # Add url encoding [] for ipv6 addresses only.
    #
    # Note: The imported redfish library produces a python exception
    #       on the session close if the ipv4 address has [] around it.
    #
    #       I debugged the issue and know what it is and how to fix it
    #       but requires an upstream change that is not worth doing.
    #
    # URL Encoding for IPv6 only is an easy solution.
    #
    ######################################################################
    if is_ipv6_address(address, logging_util) is True:
        bmc_ipv6 = True
        address = '[' + address + ']'
    else:
        bmc_ipv6 = False

    # Create control object
    try:
        vmc_obj = VmcObject(target_name,
                            address,
                            target_dict.get('bmc_username'),
                            pw,
                            str(pw_dec),
                            target_dict.get('image'),
                            logging_util,
                            exit_handler)
        if vmc_obj:
            vmc_obj.ipv6 = bmc_ipv6
            return vmc_obj
        else:
            logging_util.elog(
                "Unable to create control object for target:%s ; "
                "skipping ..." % target_dict)

    except Exception as ex:
        logging_util.elog(
            "Unable to parse configuration '%s' (%s) in %s config file." %
            (target_dict, ex, target_name))
        logging_util.alog(
            "Check presence and spelling of configuration members in "
            "%s config file." % target_name)
    return None


def parse_config_file(target_name, config_file, logging_util, exit_handler):
    """Parse BMC target info from config file.

    Create target object through parse_target.

    :param target_name: the subcloud_name
    :type target_name: str
    :param config_file: the RVMC config file
    :type config_file: str
    :param logging_util: the logging utility.
    :type logging_util: LoggingUtil
    :param exit_handler: the exit handler.
    :type exit_handler: ExitHandler
    :returns binary data with configuration loaded from the config file
             and the target object
    """
    # Find, Open and Read callers config file
    cfg = None
    if not os.path.exists(config_file):
        logging_util.elog("Unable to find specified config file: %s" %
                          config_file)
        logging_util.alog("Check config file spelling and presence\n\n")
        exit_handler.exit(1)
    try:
        with open(config_file, 'r') as yaml_config:
            logging_util.dlog1("Config File : %s" % config_file)
            cfg = yaml.safe_load(yaml_config)
            logging_util.dlog3("Config Data : %s" % cfg)
    except Exception as ex:
        logging_util.elog("Unable to open specified config file: %s (%s)" %
                          (config_file, ex))
        logging_util.alog("Check config file access and permissions.\n\n")
        exit_handler.exit(1)

    # Parse the config file
    target_object = parse_target(
        target_name, cfg, config_file, logging_util, exit_handler)

    return cfg, target_object


class VmcObject(object):
    """Virtual Media Controller Class Object. One for each BMC."""

    def __init__(self,
                 hostname,
                 address,
                 username,
                 password,
                 password_decoded,
                 image,
                 logging_util,
                 exit_handler):

        self.target = hostname
        self.uri = "https://" + address
        self.url = REDFISH_ROOT_PATH
        self.un = username.rstrip()
        self.ip = address.rstrip()
        self.pw_encoded = password.rstrip()
        self.pw = password_decoded
        self.img = image.rstrip()
        self.logging_util = logging_util
        self.exit_handler = exit_handler
        self.ipv6 = False
        self.redfish_obj = None     # redfish client connection object
        self.session = False        # True when session for this BMC is created

        self.response = None        # holds response from last http request
        self.response_json = None   # json formatted version of above response
        self.response_dict = None   # dictionary version of aboe response

        # redfish root query response
        self.root_query_info = None  # json version of the full root query

        # Managers Info
        self.managers_group_url = None
        self.manager_members_list = []

        # Virtual Media Info
        self.vm_url = None
        self.vm_eject_url = None
        self.vm_group_url = None
        self.vm_group = None
        self.vm_label = None
        self.vm_version = None
        self.vm_actions = {}
        self.vm_members_array = []
        self.vm_media_types = []

        # systems info
        self.systems_group_url = None
        self.systems_member_url = None
        self.systems_members_list = []
        self.systems_members = 0
        self.power_state = None

        # boot control info
        self.boot_control_dict = {}

        # systems reset info
        self.reset_command_url = None
        self.reset_action_dict = {}

        # parsed target object info
        if self.target is not None:
            self.logging_util.dlog1("Target      : %s" % self.target)
        self.logging_util.dlog1("BMC IP      : %s" % self.ip)
        self.logging_util.dlog1("Username    : %s" % self.un)
        self.logging_util.dlog1("Password    : %s" % self.pw_encoded)
        self.logging_util.dlog1("Image       : %s" % self.img)

    def make_request(self, operation=None, path=None, payload=None, retry=-1):
        """Issue a Redfish http request

        Check response,
        Convert response to dictionary format
        Convert response to json format

        :param operation: HTTP GET, POST or PATCH operation
        :type operation: str.
        :param path: url to perform request to
        :type path: str
        :param payload: POST or PATCH payload data
        :type payload: dictionary
        :param retry: The number of retries. The default value -1 means
         disabling retry. If the number is in
         [0 .. MAX_HTTP_TRANSIENT_ERROR_RETRIES), the retry will be executed
         at most (MAX_HTTP_TRANSIENT_ERROR_RETRIES - retry) time(s).
        :type retry: int
        :returns True if request succeeded (200,202(accepted),204(no content)
        """
        self.response = None
        if path is not None:
            url = path
        else:
            url = self.url

        before_request_time = datetime.datetime.now().replace(microsecond=0)
        request_log = "Request     : %s %s" % (operation, url)
        try:
            if operation == GET:
                request_log += "\nHeaders     : %s : %s" % \
                               (operation, GET_HEADERS)
                self.response = self.redfish_obj.get(url, headers=GET_HEADERS)

            elif operation == POST:
                request_log += "\nHeaders     : %s : %s" % \
                               (operation, POST_HEADERS)
                request_log += "\nPayload     : %s" % payload
                self.response = self.redfish_obj.post(url,
                                                      body=payload,
                                                      headers=POST_HEADERS)
            elif operation == PATCH:
                request_log += "\nHeaders     : %s : %s" % \
                               (operation, PATCH_HEADERS)
                request_log += "\nPayload     : %s" % payload
                self.response = self.redfish_obj.patch(url,
                                                       body=payload,
                                                       headers=PATCH_HEADERS)
            else:
                self.logging_util.dlog3(request_log)
                self.logging_util.elog("Unsupported operation: %s" % operation)
                return False

            self.logging_util.dlog3(request_log)

        except Exception as ex:
            self.logging_util.elog("Failed operation on '%s' (%s)" % (url, ex))

        if self.response is not None:
            after_request_time = datetime.datetime.now().replace(microsecond=0)
            delta = after_request_time - before_request_time
            # if we got a response, check its status
            if self.check_ok_status(url, operation, delta.seconds) is False:
                self.logging_util.elog("Got an error response for: \n%s" %
                                       request_log)
                if retry < 0 or retry >= MAX_HTTP_TRANSIENT_ERROR_RETRIES:
                    self._exit(1)
                elif self.response.status < 500:
                    self.logging_util.ilog(
                        "Stop retrying for the non-transient error (%s)." %
                        self.response.status)
                    self._exit(1)
                else:
                    retry += 1
                    self.logging_util.ilog(
                        "Make request: retry (%i of %i) in %i secs." %
                        (retry, MAX_HTTP_TRANSIENT_ERROR_RETRIES,
                         HTTP_REQUEST_RETRY_INTERVAL))
                    time.sleep(HTTP_REQUEST_RETRY_INTERVAL)
                    return self.make_request(operation=operation,
                                             path=path,
                                             payload=payload,
                                             retry=retry)

            # handle 204 success with no content ; clear last response
            if self.response.status == 204:
                self.response = ""
                return True
            try:
                if self.resp_dict() is True:
                    if self.format() is True:
                        self.logging_util.dlog4(
                            "Response:\n%s\n" % self.response_json)
                        return True
                    else:
                        self.logging_util.elog(
                            "Failed to parse BMC %s response '%s'" %
                            (operation, url))

            except Exception as ex:
                self.logging_util.elog(
                    "Failed to parse BMC %s response '%s' (%s)" %
                    (operation, url, ex))
        else:
            self.logging_util.elog("No response from %s:%s" % (operation, url))
        return False

    def resp_dict(self):
        """Create Response Dictionary"""

        if self.response.read:
            self.response_dict = None
            try:
                self.response_dict = json.loads(self.response.read)
                return True
            except Exception as ex:
                self.logging_util.elog(
                    "Got exception key valuing response ; (%s)" % ex)
                self.logging_util.elog("Response: %s" % self.response.read)
        else:
            self.logging_util.elog("No response from last command")
        return False

    def format(self):
        """Format Response as Json"""

        self.response_json = None
        try:
            if self.resp_dict() is True:
                self.response_json = json.dumps(self.response_dict,
                                                indent=4,
                                                sort_keys=True)
                return True
            else:
                return False

        except Exception as ex:
            self.logging_util.elog(
                "Got exception formatting response ; (%s)\n" % ex)
            return False

    def get_key_value(self, key1, key2=None):
        """Retrieve a value by providing key(s)

        Get key1 value if no key2 is specified.
        Get key2 value from key1 value if key2 is specified.

        :param : key1 value is returned if no key2 is provided.
        :type : str.
        :param : key2 value is optional but if provided its value is returned
        :type : str
        :returns key1 value or key2 value if key2 is specified
        """
        value1 = self.response_dict.get(key1)
        if key2 is None:
            return value1
        return value1.get(key2)

    def check_ok_status(self, function, operation, seconds):
        """Status

        :param function: description of operation
        :type : str
        :param operation: http GET, POST or PATCH
        :type : str
        :returns True if response status is OK. Otherwise False.
        """
        # Accept applicable 400 series error from an Eject Request POST.
        # This error is dealt with by the eject handler.
        if self.response.status in [400, 403, 404] and \
                function == self.vm_eject_url and \
                operation == POST:
            return True

        if self.response.status not in [200, 202, 204]:
            try:
                self.logging_util.elog(
                    "HTTP Status : %d ; %s %s failed after %i seconds\n%s\n" %
                    (self.response.status,
                     operation, function, seconds,
                     json.dumps(self.response.dict,
                                indent=4, sort_keys=True)))
                return False
            except Exception as ex:
                self.logging_util.elog("check status exception ; %s" % ex)

        self.logging_util.dlog2(
            "HTTP Status : %s %s Ok (%d) (took %i seconds)" %
            (operation, function, self.response.status, seconds))
        return True

    def _exit(self, code):
        """Exit the tool but not before closing an open Redfish

        client connection.

        :param code: the exit code
        :type code: int
        """
        if self.redfish_obj is not None and self.session is True:
            try:
                self.redfish_obj.logout()
                self.redfish_obj = None
                self.session = False
                self.logging_util.dlog1("Session     : Closed")

            except Exception as ex:
                self.logging_util.elog("Session close failed ; %s" % ex)
                self.logging_util.alog(
                    "Check BMC username and password in config file")

        if code:
            sys.stdout.write("\n-------------------------------------------\n")

            # If exit with reason code then print that reason code and dump
            # the redfish query data that was learned up to that point
            self.logging_util.elog("Code : %s" % code)

            # Other info
            self.logging_util.ilog("IPv6      : %s" % self.ipv6)

            # Root Query Info
            self.logging_util.ilog("Root Query: %s" % self.root_query_info)

            # Managers Info
            self.logging_util.ilog("Manager URL: %s" % self.managers_group_url)
            self.logging_util.ilog("Manager Members List: %s" %
                                   self.manager_members_list)

            # Systems Info
            self.logging_util.ilog("Systems Group URL: %s" %
                                   self.systems_group_url)
            self.logging_util.ilog("Systems Member URL: %s" %
                                   self.systems_member_url)
            self.logging_util.ilog("Systems Members: %d" %
                                   self.systems_members)
            self.logging_util.ilog("Systems Members List: %s" %
                                   self.systems_members_list)

            self.logging_util.ilog("Power State: %s" % self.power_state)
            self.logging_util.ilog("Reset Actions: %s" %
                                   self.reset_action_dict)
            self.logging_util.ilog("Reset Command URL: %s" %
                                   self.reset_command_url)
            self.logging_util.ilog("Boot Control Dict: %s" %
                                   self.boot_control_dict)

            self.logging_util.ilog("VM Members Array: %s" %
                                   self.vm_members_array)
            self.logging_util.ilog("VM Group URL: %s" % self.vm_group_url)
            self.logging_util.ilog("VM Group: %s" % self.vm_group)
            self.logging_util.ilog("VM URL: %s" % self.vm_url)
            self.logging_util.ilog("VM Label: %s" % self.vm_label)
            self.logging_util.ilog("VM Version: %s" % self.vm_version)
            self.logging_util.ilog("VM Actions: %s" % self.vm_actions)
            self.logging_util.ilog("VM Media Types: %s" % self.vm_media_types)

            self.logging_util.ilog("Last Response raw: %s" % self.response)
            self.logging_util.ilog("Last Response json: %s" %
                                   self.response_json)

        self.exit_handler.exit(code)

    ###########################################################################
    #
    #     P R I V A T E    S T A G E    M E M B E R    F U N C T I O N S
    #
    ###########################################################################

    ###########################################################################
    # Redfish Client Connect
    ###########################################################################
    def _redfish_client_connect(self):
        """Connect to target Redfish service."""

        stage = 'Redfish Client Connection'
        self.logging_util.slog(stage)

        # Verify ping response
        ping_ok = False
        ping_count = 0
        MAX_PING_COUNT = 10
        while ping_count < MAX_PING_COUNT and ping_ok is False:
            if self.ipv6 is True:
                response = os.system("ping -6 -c 1 " +
                                     self.ip[1:-1] + " > /dev/null 2>&1")
            else:
                response = os.system("ping -c 1 " +
                                     self.ip + " > /dev/null 2>&1")

            if response == 0:
                ping_ok = True
            else:
                ping_count = ping_count + 1
                self.logging_util.ilog("BMC Ping     : retry (%i of %i)" %
                                       (ping_count, MAX_PING_COUNT))
                time.sleep(2)

        if ping_ok is False:
            self.logging_util.elog("Unable to ping '%s' (%i)" %
                                   (self.ip, ping_count))
            self.logging_util.alog("Check BMC ip address is pingable")
            self._exit(1)
        else:
            self.logging_util.ilog("BMC Ping Ok : %s (%i)" %
                                   (self.ip, ping_count))

        # try to connect
        fail_counter = 0
        err_msg = "Unable to establish %s to BMC at %s." % (stage, self.uri)
        while fail_counter < MAX_CONNECTION_ATTEMPTS:
            ex_log = ""
            try:
                # One time Redfish Client Object Create
                self.redfish_obj = \
                    redfish.redfish_client(base_url=self.uri,
                                           username=self.un,
                                           password=self.pw,
                                           default_prefix=REDFISH_ROOT_PATH)
                if self.redfish_obj is None:
                    fail_counter += 1
                else:
                    return
            except Exception as ex:
                fail_counter += 1
                ex_log = " (%s)" % str(ex)

            if fail_counter < MAX_CONNECTION_ATTEMPTS:
                self.logging_util.wlog(err_msg + " Retry (%i/%i) in %i secs." %
                                       (fail_counter,
                                        MAX_CONNECTION_ATTEMPTS - 1,
                                        CONNECTION_RETRY_INTERVAL) + ex_log)
                time.sleep(CONNECTION_RETRY_INTERVAL)

        self.logging_util.elog(err_msg)
        self.logging_util.alog(
            "Check BMC ip address is pingable and supports Redfish")
        self._exit(1)

    ###########################################################################
    # Redfish Root Query
    ###########################################################################
    def _redfish_root_query(self):
        """Redfish Root Query"""

        stage = 'Root Query'
        self.logging_util.slog(stage)

        if self.make_request(operation=GET, path=None) is False:
            self.logging_util.elog("Failed %s GET request")
            self._exit(1)

        if self.response_json:
            self.root_query_info = self.response_json

        # extract the systems get url needed to learn reset
        # actions for the eventual reset.
        #
        # "Systems": { "@odata.id": "/redfish/v1/Systems/" },
        #
        # See Reset section below ; following iso insertion where
        # systems_group_url is used.
        self.systems_group_url = self.get_key_value('Systems', '@odata.id')

    ###########################################################################
    # Create Redfish Communication Session
    ###########################################################################
    def _redfish_create_session(self):
        """Create Redfish Communication Session"""

        stage = 'Create Communication Session'
        self.logging_util.slog(stage)

        fail_counter = 0
        while fail_counter < MAX_SESSION_CREATION_ATTEMPTS:
            try:
                self.redfish_obj.login(auth="session")
                self.logging_util.dlog1("Session     : Open")
                self.session = True
                return
            except InvalidCredentialsError:
                self.logging_util.elog(
                    "Failed to Create session due to invalid credentials.")
                self.logging_util.alog(
                    "Check BMC username and password in config file")
                self._exit(2)
            except Exception as ex:
                err_msg = "Failed to Create session ; %s." % str(ex)
                fail_counter += 1
                if fail_counter >= MAX_SESSION_CREATION_ATTEMPTS:
                    self.logging_util.elog(err_msg)
                    self._exit(1)
                self.logging_util.wlog(err_msg + " Retry (%i/%i) in %i secs." %
                                       (fail_counter,
                                        MAX_SESSION_CREATION_ATTEMPTS - 1,
                                        CONNECTION_RETRY_INTERVAL))
                time.sleep(SESSION_CREATION_RETRY_INTERVAL)

    ###########################################################################
    # Query Redfish Managers
    ###########################################################################
    def _redfish_get_managers(self):
        """Query Redfish Managers"""

        stage = 'Get Managers'
        self.logging_util.slog(stage)

        # Virtual Media support is located through the
        # Managers link of the root query response.
        #
        # This section learns that Managers URL Link from the
        # Root Query Result:
        #
        # Expecting something like this ...
        #
        # {
        #    ...
        #    "Managers":
        #    {
        #        "@odata.id": "/redfish/v1/Managers/"
        #    },
        #    ...
        # }

        # Get Managers Link from the last Get response currently
        # in self.response_json
        self.managers_group_url = self.get_key_value('Managers', '@odata.id')
        if self.managers_group_url is None:
            self.logging_util.elog("Failed to learn BMC RedFish Managers link")
            self._exit(1)

        # Managers Query (/redfish/v1/Managers/)
        if self.make_request(operation=GET,
                             path=self.managers_group_url) is False:
            self.logging_util.elog("Failed GET Managers from %s" %
                                   self.managers_group_url)
            self._exit(1)

        # Look for the Managers 'Members' URL Link list from the Managers Query
        #
        # Expect something like this ...
        #
        # {
        #    ...
        #    "Members":
        #    [
        #         { "@odata.id": "/redfish/v1/Managers/1/" }
        #    ],
        #   ...
        # }
        # Support multiple Managers in the list

        self.manager_members_list = self.get_key_value('Members')

    ######################################################################
    # Get Systems Members
    ######################################################################
    def _redfish_get_systems_members(self):
        """Get Systems Members"""

        stage = 'Get Systems'
        self.logging_util.slog(stage)

        # Query Systems Group URL for list of Systems Members
        if self.make_request(operation=GET,
                             path=self.systems_group_url) is False:
            self.logging_util.elog("Unable to %s Members from %s" %
                                   (stage, self.systems_group_url))
            self._exit(1)

        self.systems_members_list = self.get_key_value('Members')
        self.logging_util.dlog3("Systems Members List: %s" %
                                self.systems_members_list)
        if self.systems_members_list is None:
            self.logging_util.elog("Systems Members URL GET Response\n%s" %
                                   self.response_json)
            self._exit(1)

        self.systems_members = len(self.systems_members_list)
        if self.systems_members == 0:
            self.logging_util.elog(
                "BMC not publishing any System Members:\n%s" %
                self.response_json)
            self._exit(1)

    ######################################################################
    # Power On or Off Host
    ######################################################################
    def _redfish_powerctl_host(self, state, verify=True, request_command=None):
        """Power On or Off the Host

        :param state: The power state (On/Off).
        :type state: str.
        :param verify: True if verification of power state is required.
        :type verify: bool.
        :param request_command: Specify a dedicated type of power-off.
        :type request_command: str.
        """
        stage = 'Power ' + state + ' Host'
        self.logging_util.slog(stage)

        if self.power_state == state:
            # already in required state
            return

        # Walk the Systems Members list looking for Action support.
        #
        #  "Members": [ { "@odata.id": "/redfish/v1/Systems/1/" } ],
        #
        # Loop over Systems Members List looking for Reset Actions Dictionary
        info = 'Redfish Systems Actions Member'
        self.systems_member_url = None
        for member in range(self.systems_members):
            systems_member = self.systems_members_list[member]
            if systems_member:
                self.systems_member_url = systems_member.get('@odata.id')
            if self.systems_member_url is None:
                self.logging_util.elog("Unable to get %s URL:\n%s\n" %
                                       (info, self.response_json))
                self._exit(1)

            if self.make_request(operation=GET,
                                 path=self.systems_member_url,
                                 retry=0) is False:
                self.logging_util.elog("Unable to get %s from %s" %
                                       (info, self.systems_member_url))
                self._exit(1)

            # Look for Reset Actions Dictionary
            self.reset_action_dict = \
                self.get_key_value('Actions', '#ComputerSystem.Reset')
            if self.reset_action_dict is None:
                # try other URL
                self.logging_util.dlog2(
                    "No #ComputerSystem.Reset actions from %s. Try other URL."
                    % self.systems_member_url)
                self.systems_member_url = None
                continue
            else:
                # Got the Reset Actions Dictionary

                # get powerState
                self.power_state = self.get_key_value('PowerState')

                # Ensure we don't issue current state command
                if state in [POWER_OFF, POWER_ON]:
                    # This is a Power ON or Off command
                    if self.power_state == state:
                        self.logging_util.dlog2("Power already %s" % state)
                        # ... AND we are already in that state then
                        # we are done. Issuing a power command while
                        # in the same state will error out.
                        # So don't do it.
                        return
                break

        info = 'Systems Reset Action Dictionary'
        if self.reset_action_dict is None:
            self.logging_util.elog("BMC not publishing %s:\n%s\n" %
                                   (info, self.response_json))
            self._exit(1)

        ##############################################################
        # Reset Actions Dictionary. This is what we are looking for  #
        ##############################################################
        #
        # Look for Reset Actions label
        #
        # "Actions":
        # {
        #   "#ComputerSystem.Reset":
        #   {
        #     "ResetType@Redfish.AllowableValues": [
        #       "On",
        #       "ForceOff",
        #       "ForceRestart",
        #       "Nmi",
        #       "PushPowerButton"
        #     ],
        #     "target":"/redfish/v1/Systems/1/Actions/ComputerSystem.Reset/"
        #   }
        # }
        #
        # Need to get 2 pieces of information out of the Actions output
        #
        #  1. the Redfish Systems Reset Action Target
        #  2. the Redfish Systems Reset Action List
        #
        ###############################################################

        info = 'Systems Reset Action Target'
        self.reset_command_url = self.reset_action_dict.get('target')
        if self.reset_command_url is None:
            self.logging_util.elog(
                "Unable to get Reset Command URL (members:%d)\n%s" %
                (self.systems_members, self.reset_action_dict))
            self._exit(1)

        # With the reset target url in hand, all that is needed now
        # is the reset command this target supports
        #
        # The reset command list looks like this.
        #
        #        "ResetType@Redfish.AllowableValues": [
        #            "On",
        #            "ForceOff",
        #            "ForceRestart",
        #            "Nmi",
        #            "PushPowerButton"
        #        ],
        #
        # Some targets support GracefulRestart and/or ForceRestart

        info = 'Allowable Reset Actions'
        reset_command_list = \
            self.reset_action_dict.get('ResetType@Redfish.AllowableValues')
        if reset_command_list is None:
            self.logging_util.elog("BMC is not publishing any %s" % info)
            self._exit(1)

        self.logging_util.ilog("ResetActions: %s" % reset_command_list)

        if request_command:
            acceptable_commands = [request_command]
        else:
            # load the appropriate acceptable command list
            if state == POWER_OFF:
                acceptable_commands = ['ForceOff', 'GracefulShutdown']
            elif state == POWER_ON:
                acceptable_commands = ['ForceOn', 'On']
            else:
                acceptable_commands = ['ForceRestart', 'GracefulRestart']

        # Look for the best command for the power state requested.
        command = None
        for acceptable_command in acceptable_commands:
            for reset_command in reset_command_list:
                if reset_command == acceptable_command:
                    self.logging_util.ilog(
                        "Selected Command: %s" % reset_command)
                    command = reset_command
                    break
            else:
                continue
            break

        if command is None:
            self.logging_util.elog(
                "Failed to find acceptable Power %s command in:\n%s" %
                (state, reset_command_list))
            self._exit(1)

        # All that is left to do is POST the reset command
        # to the reset_command_url.
        payload = {'ResetType': command}
        if self.make_request(operation=POST,
                             payload=payload,
                             path=self.reset_command_url) is False:
            self.logging_util.elog("Failed to Power %s Host" % state)
            self._exit(1)

        if (state not in [POWER_OFF, POWER_ON]) or (not verify):
            # no need to refresh power state if
            # this was not a power command;
            # no need to verify the power state
            return

        # Set the timeout in seconds (14 minutes = 840 seconds)
        timeout = int(os.environ.get('RVMC_POWER_ACTION_TIMEOUT', 840))
        self.logging_util.ilog("%s timeout is %d seconds" % (stage, timeout))

        # Get the start time
        start_time = time.time()

        # init wait duration
        duration = 0

        # poll for requested power state.
        while time.time() - start_time < timeout and self.power_state != state:
            time.sleep(10)

            # update wait duration
            duration = int(time.time() - start_time)

            # get systems info
            if self.make_request(operation=GET,
                                 path=self.systems_member_url) is False:
                self.logging_util.elog(
                    "Failed to Get System State (after %d secs)" % duration)
            else:
                # get powerState
                self.power_state = self.get_key_value('PowerState')
                if self.power_state != state:
                    self.logging_util.dlog1(
                        "Waiting for Power %s (currently %s) (%d secs)" %
                        (state, self.power_state, duration))

        if self.power_state != state:
            self.logging_util.elog(
                "Failed to Set System Power State to %s after %d secs (%s)" %
                (state, duration, self.systems_member_url))
            self._exit(1)
        else:
            self.logging_util.ilog("%s verified (after %d seconds)" %
                                   (stage, duration))

    ######################################################################
    # Get CD/DVD Virtual Media URL
    ######################################################################
    def _redfish_get_vm_url(self):
        """Get CD/DVD Virtual Media URL from one of the Manager Members list"""

        stage = 'Get CD/DVD Virtual Media'
        self.logging_util.slog(stage)

        if self.manager_members_list is None:
            self.logging_util.elog("Unable to index Managers Members from %s" %
                                   self.managers_group_url)
            self._exit(1)

        members = len(self.manager_members_list)
        if members == 0:
            self.logging_util.elog(
                "BMC is not publishing any redfish Manager Members")
            self._exit(1)

        # Issue a Get from each 'Manager Member URL Link looking
        # for supported virtual devices.
        for member in range(members):
            member_url = None
            this_member = self.manager_members_list[member]
            if this_member:
                member_url = this_member.get('@odata.id')
            if member_url is None:
                continue
            if self.make_request(operation=GET, path=member_url) is False:
                self.logging_util.elog(
                    "Unable to get Manager Member from %s" % member_url)
                self._exit(1)

            ########################################################
            #                Query Virtual Media                   #
            ########################################################
            # Look for Virtual Media Support by this Manager Member
            #
            # Expect something like this ...
            #
            # {
            #    ...
            #    "VirtualMedia":
            #    {
            #        "@odata.id": "/redfish/v1/Managers/1/VirtualMedia/"
            #    }
            #    ...
            # }
            self.vm_group_url = None
            self.vm_group = self.get_key_value('VirtualMedia')
            if self.vm_group is None:
                if (member + 1) == members:
                    self.logging_util.elog(
                        "Virtual Media not supported by target BMC")
                    self._exit(1)
                else:
                    self.logging_util.dlog3(
                        "Virtual Media not supported by member %d" % member)
                    continue
            else:
                try:
                    self.vm_group_url = self.vm_group.get('@odata.id')
                except Exception:
                    self.logging_util.elog(
                        "Unable to get Virtual Media Group from %s" %
                        self.vm_group_url)
                    self._exit(1)

            # Query this member's Virtual Media Service Group
            if self.make_request(
                    operation=GET, path=self.vm_group_url) is False:
                self.logging_util.elog(
                    "Failed to GET Virtual Media Service group from %s" %
                    self.vm_group_url)
                continue

            # Look for Virtual Media Device URL Links
            #
            # Expect something like this ...
            #
            # {
            #   ...
            #   "Members":
            #   [
            #       { "@odata.id": "/redfish/v1/Managers/1/VirtualMedia/1/" },
            #       { "@odata.id": "/redfish/v1/Managers/1/VirtualMedia/2/" }
            #   ],
            #    ...
            # }
            self.vm_members_array = []
            try:
                self.vm_members_array = self.get_key_value('Members')
                vm_members = len(self.vm_members_array)
            except Exception:
                vm_members = 0

            if vm_members == 0:
                self.logging_util.elog("No Virtual Media members found at %s" %
                                       self.vm_group_url)
                self._exit(1)

            # Loop over each member's URL looking for the CD or DVD device
            # Consider trying the USB device as well if BMC supports that.
            for vm_member in range(vm_members):

                # Look for Virtual Media Device URL
                this_member = self.vm_members_array[vm_member]
                if this_member:
                    self.vm_url = this_member.get('@odata.id')

                if self.make_request(operation=GET, path=self.vm_url) is False:
                    self.logging_util.elog(
                        "Failed to GET Virtual Media Service group from %s" %
                        self.vm_group_url)
                    continue

                # Query Virtual Media Device Type looking for supported device
                self.vm_media_types = self.get_key_value('MediaTypes')
                if self.vm_media_types is None:
                    self.logging_util.dlog3(
                        "No Virtual MediaTypes found at %s ; "
                        "trying other members" % self.vm_url)
                    break

                self.logging_util.dlog4("Virtual Media Service:\n%s" %
                                        self.response_json)

                if supported_device(self.vm_media_types) is True:
                    self.logging_util.dlog3(
                        "Supported Virtual Media found at %s ; %s" %
                        (self.vm_url, self.vm_media_types))
                    break
                else:
                    self.logging_util.dlog3(
                        "Virtual Media %s does not support CD/DVD ; "
                        "trying other members" % self.vm_url)
                    self.vm_url = None

            if self.vm_url is None:
                self.logging_util.elog(
                    "Failed to find CD or DVD Virtual media type")
                self._exit(1)

    ######################################################################
    # Load Selected Virtual Media Version and Actions
    ######################################################################
    def _redfish_load_vm_actions(self):
        """Load Selected Virtual Media Version and Actions"""

        stage = 'Load Selected Virtual Media Version and Actions'
        self.logging_util.slog(stage)

        if self.vm_url is None:
            self.logging_util.elog(
                "Failed to find CD or DVD Virtual media type")
            self._exit(1)

        # Extract Virtual Media Version and Insert/Eject Actions
        #
        # Looks something like this. First half of odata.type is the VM label
        #
        # {
        #   ...
        #   "@odata.type": "#VirtualMedia.v1_2_0.VirtualMedia",
        #   "Actions": {
        #   "#VirtualMedia.EjectMedia":
        #   {
        #     "target" :
        #     ".../Managers/1/VirtualMedia/2/Actions/VirtualMedia.EjectMedia/"
        #   },
        #   "#VirtualMedia.InsertMedia":
        #   {
        #     "target":
        #     ".../Managers/1/VirtualMedia/2/Actions/VirtualMedia.InsertMedia/"
        #   }
        #   ...
        # },
        vm_data_type = self.get_key_value('@odata.type')
        if vm_data_type:
            self.vm_label = vm_data_type.split('.')[0]
            self.vm_version = vm_data_type.split('.')[1]
            self.vm_actions = self.get_key_value('Actions')
        self.logging_util.dlog1("VM Version  : %s" % self.vm_version)
        self.logging_util.dlog1("VM Label    : %s" % self.vm_label)
        self.logging_util.dlog3("VM Actions  :\n%s\n" % self.vm_actions)

    ######################################################################
    # Power Off Host
    ######################################################################
    def _redfish_poweroff_host(self, verify=True, request_command=None):
        """Power Off the Host

        :param verify: True if verification of power state is required.
        :type verify: bool.
        :param request_command: Specify a dedicated type of power-off.
        :type request_command: str.
        """
        self._redfish_powerctl_host(POWER_OFF, verify, request_command)

    ######################################################################
    # Eject Current Image
    ######################################################################
    def _redfish_eject_image(self):
        """Eject Current Image"""

        stage = 'Eject Current Image'
        self.logging_util.slog(stage)

        if self.make_request(operation=GET, path=self.vm_url) is False:
            self.logging_util.elog(
                "Virtual media status query failed (%s)" % self.vm_url)
            self._exit(1)

        if self.get_key_value('Inserted') is False:
            self.logging_util.ilog(
                "Skip ejection of the image because no image is inserted.")
            return

        # Ensure there is no image inserted and handle the case where
        # one might be in the process of loading.
        MAX_EJECT_RETRY_COUNT = 10
        eject_retry_count = 0
        ejecting = True
        eject_media_label = '#VirtualMedia.EjectMedia'
        while eject_retry_count < MAX_EJECT_RETRY_COUNT and ejecting:
            eject_retry_count = eject_retry_count + 1
            vm_eject = self.vm_actions.get(eject_media_label)
            if not vm_eject:
                self.logging_util.elog(
                    "Failed to get eject target (%s)" % eject_media_label)
                self._exit(1)

            self.vm_eject_url = vm_eject.get('target')
            if self.vm_eject_url:
                if self.get_key_value('Image'):
                    self.logging_util.ilog("Eject Request Image %s" %
                                           (self.get_key_value('Image')))
                else:
                    self.logging_util.dlog1("Eject Request")

                if self.make_request(operation=POST,
                                     payload={},
                                     path=self.vm_eject_url) is False:
                    self.logging_util.elog(
                        "Eject request failed (%s)" % self.vm_eject_url)
                    # accept this and continue to poll

                time.sleep(DELAY_2_SECS)
                poll_count = 0
                while poll_count < MAX_POLL_COUNT and ejecting:
                    # verify the image is not in inserted
                    poll_count = poll_count + 1
                    if self.make_request(operation=GET,
                                         path=self.vm_url) is True:
                        if self.get_key_value('Inserted') is False:
                            self.logging_util.ilog("Ejected")
                            ejecting = False
                        elif self.get_key_value('Image'):
                            # if image is present then its ready to
                            # retry the eject, break out of poll loop
                            self.logging_util.dlog1(
                                "Image Present  ; %s" %
                                self.get_key_value('Image'))
                            break
                        else:
                            self.logging_util.dlog1(
                                "Eject Wait     ; Image: %s" %
                                self.get_key_value('Image'))
                            time.sleep(RETRY_DELAY_SECS)
                    else:
                        self.logging_util.elog(
                            "Failed to query vm state (%s)" % self.vm_url)
                        self._exit(1)

        if ejecting is True:
            self.logging_util.elog("%s wait timeout" % stage)
            self._exit(1)

    ######################################################################
    # Insert Image into Virtual Media CD/DVD
    ######################################################################
    def _redfish_insert_image(self):
        """Insert Image into Virtual Media CD/DVD"""

        stage = 'Insert Image into Virtual Media CD/DVD'
        self.logging_util.slog(stage)

        vm_insert_url = None
        vm_insert_act = self.vm_actions.get('#VirtualMedia.InsertMedia')
        if vm_insert_act:
            vm_insert_url = vm_insert_act.get('target')

        if vm_insert_url is None:
            self.logging_util.elog(
                "Unable to get Virtual Media Insertion URL\n%s\n" %
                self.response_json)
            self._exit(1)

        payload = {'Image': self.img,
                   'Inserted': True,
                   'WriteProtected': True}
        if self.make_request(operation=POST,
                             payload=payload,
                             path=vm_insert_url) is False:
            self.logging_util.elog("Failed to Insert Media")
            self._exit(1)

        # Handle case where the BMC loads the iso image during the insertion.
        # In that case the 'Inserted' is True but the Image is not immediately
        # mounted.
        poll_count = 0
        ImageInserting = True
        while poll_count < MAX_POLL_COUNT and ImageInserting:
            if self.make_request(operation=GET, path=self.vm_url) is False:
                self.logging_util.elog(
                    "Unable to verify Image insertion (%s)" % self.vm_url)
                self._exit(1)

            if self.get_key_value('Image') == self.img:
                self.logging_util.ilog("Image Insertion (took %i seconds)" %
                                       (poll_count * RETRY_DELAY_SECS))
                ImageInserting = False
            else:
                time.sleep(RETRY_DELAY_SECS)
                poll_count = poll_count + 1
                self.logging_util.dlog1(
                    "Image Insertion Wait ; %3d secs (%3d of %3d)" %
                    (poll_count * RETRY_DELAY_SECS,
                     poll_count,
                     MAX_POLL_COUNT))

        if ImageInserting is True:
            self.logging_util.elog("Image insertion timeout")
            self._exit(1)
        else:
            self.logging_util.ilog("%s verified (took %i seconds)" %
                                   (stage, poll_count * RETRY_DELAY_SECS))

        if self.get_key_value('Image') != self.img:
            self.logging_util.elog("Insertion verification failed.")
            self.logging_util.ilog("Expected Image: %s" % self.img)
            self.logging_util.ilog(
                "Detected Image: %s" % self.get_key_value('Image'))
            self._exit(1)

        # Verify Insertion
        #
        # Looking for the following values
        #
        self.logging_util.dlog3(
            "Image URI   : %s" % self.get_key_value('Image'))
        self.logging_util.dlog3(
            "ImageName   : %s" % self.get_key_value('ImageName'))
        self.logging_util.dlog3(
            "Inserted    : %s" % self.get_key_value('Inserted'))
        self.logging_util.dlog3(
            "Protected   : %s" % self.get_key_value('WriteProtected'))

    ######################################################################
    # Set Next Boot Override to CD/DVD
    ######################################################################
    def _redfish_set_boot_override(self):
        """Set Next Boot Override to CD/DVD"""

        stage = 'Set Next Boot Override to CD/DVD'
        self.logging_util.slog(stage)

        # Walk the Systems Members list looking for Boot support.
        #
        #  "Members": [ { "@odata.id": "/redfish/v1/Systems/1/" } ],
        #
        # Loop over Systems Members List looking for Boot Dictionary
        info = 'Systems Boot Member'
        for member in range(self.systems_members):

            self.systems_member_url = None
            systems_member = self.systems_members_list[member]
            if systems_member:
                self.systems_member_url = systems_member.get('@odata.id')
            if self.systems_member_url is None:
                self.logging_util.elog("Unable to get %s from %s" %
                                       (info, self.systems_members_list))
                self._exit(1)

            if self.make_request(operation=GET,
                                 path=self.systems_member_url) is False:
                self.logging_util.elog("Unable to get %s from %s" %
                                       (info, self.systems_member_url))
                self._exit(1)

            # Look for Reset Actions Dictionary
            self.boot_control_dict = self.get_key_value('Boot')
            if self.boot_control_dict is None:
                continue

        if self.boot_control_dict is None:
            self.logging_util.elog(
                "Unable to get %s from %s" % (info, self.systems_member_url))
            self._exit(1)
        else:
            allowable_label = 'BootSourceOverrideMode@Redfish.AllowableValues'
            mode_list = self.get_key_value('Boot', allowable_label)
            if mode_list is None:
                payload = {"Boot": {"BootSourceOverrideEnabled": "Once",
                                    "BootSourceOverrideTarget": "Cd"}}
            else:
                self.logging_util.dlog1("Boot Override Modes: %s" % mode_list)

                # Prioritize UEFI over Legacy
                if "UEFI" in mode_list:
                    payload = {"Boot": {"BootSourceOverrideEnabled": "Once",
                                        "BootSourceOverrideMode": "UEFI",
                                        "BootSourceOverrideTarget": "Cd"}}
                elif "Legacy" in mode_list:
                    payload = {"Boot": {"BootSourceOverrideEnabled": "Once",
                                        "BootSourceOverrideMode": "Legacy",
                                        "BootSourceOverrideTarget": "Cd"}}
                else:
                    self.logging_util.elog(
                        "BootSourceOverrideModes %s not supported" % mode_list)
                    self._exit(0)

                self.logging_util.dlog2("Boot Override Payload: %s" % payload)

        if self.make_request(operation=PATCH,
                             path=self.systems_member_url,
                             payload=payload) is False:
            self.logging_util.elog(
                "Unable to Set Boot Override (%s)" % self.vm_url)
            self._exit(1)

        if self.make_request(operation=GET,
                             path=self.systems_member_url) is False:
            self.logging_util.elog(
                "Unable to verify Set Boot Override (%s)" % self.vm_url)
            self._exit(1)
        else:
            enabled = self.get_key_value('Boot', 'BootSourceOverrideEnabled')
            device = self.get_key_value('Boot', 'BootSourceOverrideTarget')
            mode = self.get_key_value('Boot', 'BootSourceOverrideMode')
            if enabled == "Once" and \
                    supported_device(self.vm_media_types) is True:
                self.logging_util.ilog("%s verified [%s:%s:%s]" %
                                       (stage, enabled, device, mode))
            else:
                self.logging_util.elog(
                    "Unable to verify Set Boot Override [%s:%s:%s]" %
                    (enabled, device, mode))
                self._exit(1)

    ######################################################################
    # Power On Host
    ######################################################################
    def _redfish_poweron_host(self):
        """Power On or Off the Host"""

        self._redfish_powerctl_host(POWER_ON)

    def execute(self):
        """The main controller function that executes the iso insertion

        algorithm for the specified target object (self)
        """
        self._redfish_client_connect()
        self._redfish_root_query()
        self._redfish_create_session()
        self._redfish_get_managers()
        self._redfish_get_systems_members()
        self._redfish_get_vm_url()
        self._redfish_load_vm_actions()
        self._redfish_eject_image()
        self._redfish_poweroff_host()
        self._redfish_insert_image()
        self._redfish_set_boot_override()
        self._redfish_poweron_host()

        self.logging_util.ilog("Done")

        if self.redfish_obj is not None and self.session is True:
            self.redfish_obj.logout()
            self.logging_util.dlog1("Session     : Closed")

    def poweroff_only(self, verify=False, request_command='ForceOff'):
        """Power-off only without any iso related operations.

        :param verify: True if verification of power state is required.
        :type verify: bool.
        :param request_command: Specify a dedicated type of power-off.
        :type request_command: str.
        """
        self._redfish_client_connect()
        self._redfish_root_query()
        self._redfish_create_session()
        self._redfish_get_managers()
        self._redfish_get_systems_members()
        self._redfish_poweroff_host(verify, request_command)

        vstr = 'with' if verify else 'without'
        self.logging_util.ilog("%s request was sent out %s verification." %
                               (request_command, vstr))

        if self.redfish_obj is not None and self.session is True:
            self.redfish_obj.logout()
            self.logging_util.dlog1("Session     : Closed")


##############################################################################
# Methods to be called from rvmc module
##############################################################################
def power_off(subcloud_name, config_file, logger):
    """Power Off the Host.

    :param subcloud_name: Subcloud name.
    :type subcloud_name: str.
    :param config_file: RVMC config file containing BMC info.
    :type config_file: str.
    :param logger: The logger
    :type logger: logging.Logger
    """
    if not subcloud_name or subcloud_name == '':
        raise exceptions.RvmcException("Subcloud name is missing.")

    logging_util = LoggingUtil(logger, subcloud_name)
    exit_handler = ExitHandler()

    if not (config_file and os.path.exists(config_file)):
        raise exceptions.RvmcException("RVMC config file is missing.")
    else:
        logging_util.dlog1("Config file  : %s" % config_file)

    logging_util.ilog("Starting power-off.")

    config, target_object = parse_config_file(
        subcloud_name, config_file, logging_util, exit_handler)

    if target_object:
        try:
            if target_object.target is not None:
                logging_util.ilog("BMC Target  : %s" % target_object.target)
                logging_util.ilog("BMC IP Addr : %s" % target_object.ip)
                logging_util.ilog("Host Image  : %s" % target_object.img)
            target_object.poweroff_only(False, 'ForceOff')
        except Exception as e:
            raise e
    else:
        if config_file and config:
            logging_util.ilog("Config File :\n%s" % config)
        raise exceptions.RvmcException(
            "Operation aborted ; no valid bmc information found")
