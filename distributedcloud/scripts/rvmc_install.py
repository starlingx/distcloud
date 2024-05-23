#!/usr/bin/python3
###############################################################################
#
# Copyright (c) 2019-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Redfish Virtual Media Controller Installer Script"""
#
###############################################################################
#
# This Redfish Virtual Media Controller forces an install of a specified BMC's
# host using the Redfish Platform management protocol.
#
# To do so the following Redfish operations are performed
#
#     Step 1: Client Connect ... Establish a client connection to the BMC
#     Step 2: Root Query     ... Learn Redfish Services offered by the BMC
#     Step 3: Find CD/DVD    ... Locate the virtual media CD/DVD device
#     Step 4: Power Off Host ... Host power needs to be off
#     Step 5: Eject Iso      ... Eject iso if needed
#     Step 6: Inject Iso     ... Inject the URL based ISO image into CD/DVD
#     Step 7: Force DVD Boot ... Set Net boot device to be CD/DVD
#     Step 8: Power On Host  ... Host will boot and install from DVD
#
# Note: All server starting state conditions such as the server running or
#       being stuck in POST, say at the grub prompt due to previous host boot
#       failure, the host needs to be in the powered off state for the ISO
#       Insertion and Set DVD for Next Boot steps.
#
# Mandatory Arguments:
#
#    --config_file <A yaml file with BMC information>
#
#    Config file is assumed to be a yaml file with the following format.
#
#    bmc_address: <bmc ip address>
#    bmc_username: <the bmc username>
#    bmc_password: <base64 encoded password>
#    image: http://<ip>:<port>/<path>/bootimage.iso
#
#    Real Example:
#
#    bmc_address: 123.45.67.89
#    bmc_username: root
#    bmc_password: TGk2OW51eCo=
#    image: http://[2620:10a:a001:a103::81]:8080/iso/sub_cloud_bootimage.iso
#
#    > rvmc_install.py --config_file
#                      "/opt/dc-vault/ansible/subcloud1/rvmc-config.yaml"
#
#    --subcloud_name <subcloud name>
#
#    The subcloud name is used as the bmc target name, and used for tracking
#    the RVMC installation process ID. The process ID file is generated under
#    '/var/run/rvmc', eg. '/var/run/rvmc/subcloud1_rvmc.pid'.
#
#    > rvmc_install.py --subcloud_name subcloud1 --config_file <config_file>
#
# Optional Argument:
#
#    --debug <0 .. 4>
#
#             Note: 0   no debug info (default value)
#                   1 = execution stage
#                   2 + http request logs
#                   3 + headers and payloads and misc other
#                   4 + json output of all command responses
#
#    > rvmc_install.py --debug 4 --subcloud_name <subcloud name>
#                      --config_file <config_file>
###############################################################################
#
# Code structure: Note: any error causes error log, session close and exit.
#
#   parse command line arguments
#
#   create target control object
#
#   execute:
#       _redfish_client_connect     ... connect to bmc
#       _redfish_root_query         ... get base url tree
#       _redfish_create_session     ... authenticated session
#       _redfish_get_managers       ... get managers urls
#       _redfish_get_systems_members .. get systems members info
#       _redfish_get_vm_url         ... get cd/dvd vm url
#       _redfish_load_vm_actions    ... get eject/insert action urls/info
#       _redfish_poweroff_host      ... tell bmc to power-off the host
#       _redfish_eject_image        ... eject current media if present
#       _redfish_insert_image       ... insert and verify insertion of iso
#       _redfish_set_boot_override  ... set boot from cd/dvd on next reset
#       _redfish_poweron_host       ... tell bmc to power-on the host
#
#   exit code:
#       0 - Success
#       1 - Retryable failures:
#         - Config file not found/opened
#         - BNC IP address ping failure
#         - Redfish GET query failures (managers, system members, URLs, status,
#                                       virtual media group, etc.)
#         - Power command not found
#         - Host power on/off failure
#         - Virtual media not supported by BMC
#         - CD/DVD virtual media type not found
#         - Eject target not found
#         - VM state query failure
#         - Image insertion/ejection timeout
#         - Media insertion failure
#         - Image verification failure
#         - Boot override set/verification failure
#         - ...
#       2 - Non-retryable failures:
#         - Invalid credentials
#         - Script execution time out
#         - Failed to terminate the previous process
###############################################################################

import argparse
import eventlet
import os
import signal
import sys
import time

from dccommon import consts
from dccommon import rvmc


# Constants
# ---------
FEATURE_NAME = 'Redfish Virtual Media Controller'
VERSION_MAJOR = 3
VERSION_MINOR = 1

# The path for RVMC PID file
RVMC_PID_FILE_PATH = '/var/run/rvmc/'
RVMC_PID_FILENAME_POSTFIX = '_rvmc.pid'

# The signals to be caught for abnormal termination
EXIT_SIGNALS = [signal.SIGTERM, signal.SIGABRT, signal.SIGINT]

# Global variables
# ------------------
# The logging utility
logging_util = None
# The exit handler
exit_handler = None


def parse_arguments():
    """Parse command line arguments.

    :returns argparse.Namespace: the arguments with name and value
    """
    parser = argparse.ArgumentParser(description=FEATURE_NAME)

    parser.add_argument("--debug", type=int, required=False, default=0,
                        help="Optional debug level ; 0..4")

    parser.add_argument("--subcloud_name", type=str, required=False,
                        help="Subcloud name")

    parser.add_argument("--config_file", type=str, required=True,
                        help="RVMC config file")

    return parser.parse_args()


def prepare_execution(rvmc_pid_file):
    """Terminate the previous RMVC process if it's still running.

    :param rvmc_pid_file: The RVMC PID file
    :param type: str
    """
    if not rvmc_pid_file:
        return

    if not os.path.exists(RVMC_PID_FILE_PATH):
        os.makedirs(RVMC_PID_FILE_PATH)

    # Check if the PID file exists.
    # Usually, it exists only when the parent process was manually killed.
    if os.path.exists(rvmc_pid_file):
        with open(rvmc_pid_file, 'r') as pid_file:
            pid = pid_file.read()
        # Attempt to kill the previous RVMC process using SIGTERM (15)
        if pid:
            try:
                os.kill(int(pid), 15)
            except ProcessLookupError:
                # Ignore the error if the process with this PID doesn't exit
                logging_util.ilog(
                    "Process %s not found or already terminated." % pid)
            except Exception:
                logging_util.elog(
                    "Failed to terminate the previous process %s," % pid)
                logging_util.alog(
                    "Please terminate the previous process %s "
                    "before running the RVMC script again." % pid)
                exit_handler.exit(2)
        # Give some time between reading and writing to the same PID file
        time.sleep(3)

    # Get the current process ID
    current_pid = os.getpid()

    # Write the PID to the file
    logging_util.dlog1("Save process ID %d to the file %s." %
                       (current_pid, rvmc_pid_file))
    with open(rvmc_pid_file, 'w') as pid_file:
        pid_file.write(str(current_pid))


def signal_handler():
    """This function handles signals received by the script"""
    logging_util.elog("Received exit signal.")
    exit_handler.exit(1)


class ExitHandler(rvmc.ExitHandler):
    """A utility class for handling different exit scenarios in a process.

    Provides methods to manage the process exit in various situations.
    """
    def __init__(self, rvmc_pid_file):
        """Handler object constructor.

        :param rvmc_pid_file: the RVMC PID file.
        :type rvmc_pid_file: str.
        """
        self.rvmc_pid_file = rvmc_pid_file

    def exit(self, code):
        """Early fault handling.

        :param code: the exit status code
        :type code: int.
        """

        if self.rvmc_pid_file and os.path.exists(self.rvmc_pid_file):
            os.remove(self.rvmc_pid_file)
        sys.stdout.write("\n\n")
        sys.exit(code)


##############################################################################
#
# Main steps:
# 1. Parse script arguments.
# 2. Register the signal handler.
# 3. Load BMC target info from config file.
# 4. Insert BMC iso for the target through self.execute
#
##############################################################################
if __name__ == "__main__":
    args = parse_arguments()

    # get debug level
    debug = args.debug

    # get subcloud name
    subcloud_name = args.subcloud_name

    # get config file
    config_file = args.config_file

    # RVMC PID file
    rvmc_pid_file = os.path.join(
        RVMC_PID_FILE_PATH, subcloud_name + RVMC_PID_FILENAME_POSTFIX)

    # Set logging utility and exit handler
    logging_util = rvmc.LoggingUtil(debug_level=debug)
    exit_handler = ExitHandler(rvmc_pid_file)

    logging_util.ilog("%s version %d.%d\n" %
                      (FEATURE_NAME, VERSION_MAJOR, VERSION_MINOR))

    # Register the signal handler
    for sig in EXIT_SIGNALS:
        signal.signal(sig, signal_handler)

    config, target_object = rvmc.parse_config_file(
        subcloud_name, config_file, logging_util, exit_handler)

    if target_object:
        prepare_execution(rvmc_pid_file)
        # TODO(lzhu1): support --timeout <value> option
        script_timeout = eventlet.timeout.Timeout(
            int(os.environ.get('RVMC_SCRIPT_TIMEOUT', 1800)))
        try:
            # Load the Iso for the target
            logging_util.ilog("BMC Target  : %s" % target_object.target)
            logging_util.ilog("BMC IP Addr : %s" % target_object.ip)
            logging_util.ilog("Host Image  : %s" % target_object.img)

            excluded_operations = []
            if (os.path.basename(target_object.img) ==
                    consts.ENROLL_INIT_SEED_ISO_NAME):
                # If the host image is a seed ISO,
                # the boot order should not be changed.
                excluded_operations = ["set_boot_override"]

            target_object.execute(excluded_operations)
        except eventlet.timeout.Timeout as e:
            if e is not script_timeout:
                raise
            logging_util.elog("RVMC script execution timed out.")
            exit_handler.exit(2)
        except Exception as e:
            logging_util.elog("Got exception: %s" % e)
            exit_handler.exit(1)
        finally:
            script_timeout.cancel()
    else:
        logging_util.elog("Operation aborted ; no valid bmc information found")
        if config_file and config:
            logging_util.ilog("Config File :\n%s" % config)
        exit_handler.exit(1)

    exit_handler.exit(0)
