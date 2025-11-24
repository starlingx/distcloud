#!/usr/bin/env python3
#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Monitors the IPMI System Event Log (SEL) for a specific target event and
associated event data, or retrieves the last event ID.

The script operates in three modes:
- In monitoring mode, it periodically checks the SEL for the desired events.
  If any of the events are found, the script returns a return code of 0 and the
  matched event in json format. If an event is not found after the maximum
  number of checks, a non-zero return code is returned.
- In success/failure monitoring mode, it'll return immediately on any success
  event (returning the latest/most recent one found) or failure event. This
  allows the playbook to call the script multiple times and get feedback about
  which stage completed.
- Alternatively, using --get-last-event makes the script simply return the ID of
  the most recent event in the SEL and exit. If the SEL is empty, it returns -1.

For the monitoring modes, it only monitors new events, existing events are
ignored unless --initial-event-id is specified to start monitoring from a
specific point.
"""

import argparse
import base64
import json
import logging
import os
import subprocess
import sys
import time
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import Union

import netaddr
import yaml

# Configure logging to stderr so stdout stays clean for Ansible JSON output
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
)


def hex_to_int(hex_str: str) -> int:
    return int(hex_str, 16)


def run_command(cmd: list[str]) -> str:
    """Run a shell command and return its output"""
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
        return result.stdout

    except subprocess.CalledProcessError as e:
        exit_script(False, f"Command failed: {e.stderr.strip()}")


def exit_script(
    success: bool,
    message: str,
    matched_data: Optional[str] = None,
    result_data: Optional[Dict] = None,
) -> None:
    if not success:
        logging.error(message)

    # Output as JSON to stdout for Ansible to parse
    result = {"success": success, "message": message}

    # Add additional info if an event was matched
    if matched_data:
        result["matched_data"] = matched_data

    # Add extra result data for the success/failure mode
    if result_data:
        result.update(result_data)

    print(json.dumps(result))
    sys.exit(0 if success else 1)


class IpmiTool:
    def __init__(self, host, user, password, ciphersuite=None):
        self.base_cmd = [
            "ipmitool",
            "-I",
            "lanplus",
            "-H",
            host,
            "-U",
            user,
            "-P",
            password,
        ]

        if ciphersuite:
            self.base_cmd.extend(
                [
                    "-C",
                    str(ciphersuite),
                ]
            )

    @classmethod
    def from_config(cls, path: str) -> "IpmiTool":
        """Instantiates IpmiTool using a BMC config file"""

        logging.info(f"Parsing BMC config from {path}")

        if not os.path.isfile(path):
            exit_script(False, f"BMC config file not found: {path}")

        try:
            with open(path, "r", encoding="utf-8") as yaml_config:
                cfg = yaml.safe_load(yaml_config)

        except Exception as ex:
            exit_script(
                False,
                f"Unable to open or parse the BMC configuration file: {path} ({ex})",
            )

        for key in ("bmc_password", "bmc_address", "bmc_username"):
            if key not in cfg:
                exit_script(False, f"{key} is missing from the BMC configuration file")
        try:
            cfg["bmc_password"] = base64.b64decode(cfg["bmc_password"]).decode("utf-8")
        except Exception as ex:
            exit_script(
                False, f"Failed to decode BMC password found in config file ({ex})"
            )

        # Validate IP address
        try:
            netaddr.IPAddress(cfg["bmc_address"])
        except Exception as ex:
            exit_script(
                False,
                "Invalid bmc_address found in the BMC configuration "
                f"file: {cfg['bmc_address']} ({ex})",
            )

        return cls(
            cfg["bmc_address"],
            cfg["bmc_username"],
            cfg["bmc_password"],
            cfg.get("bmc_ciphersuite"),
        )

    @staticmethod
    def get_id_from_line(event_line: str) -> int:
        return hex_to_int(event_line.split("|")[0].strip())

    @staticmethod
    def parse_verbose_sel_output(output: str) -> Dict[int, Dict[str, str]]:
        """Parse the verbose SEL list output and return a dictionary of events

        ipmitools sel list -v sample output:

        SEL Record ID          : 01ae
         Record Type           : 02
         Timestamp             : 09/26/2025 21:10:19
         Generator ID          : 0041
         EvM Revision          : 04
         Sensor Type           : System Event
         Sensor Number         : cc
         Event Type            : Reserved
         Event Direction       : Assertion Event
         Event Data            : cc10ef
         Description           :

        SEL Record ID          : 01af
         Record Type           : 02
         Timestamp             : 09/26/2025 21:20:51
         Generator ID          : 0020
         EvM Revision          : 04
         Sensor Type           : System ACPI Power State
         Sensor Number         : aa
         Event Type            : Sensor-specific Discrete
         Event Direction       : Assertion Event
         Event Data            : 00ffff
         Description           : S0/G0: working
        """
        events = {}
        current_event = {}
        current_event_id = None

        for line in output.splitlines():
            line = line.strip()

            # Skip empty lines and known error messages
            if (
                not line
                or line.startswith("Running")
                or line.startswith("Error")
                or line.startswith("Invalid")
                or line.startswith("Discovered")
            ):
                continue

            # If it's a new event line, store the old one and create a new one
            if line.startswith("SEL Record ID"):
                if current_event_id is not None and current_event:
                    events[current_event_id] = current_event

                current_event_id = hex_to_int(line.split(":")[1].strip())
                current_event = {}
                continue

            if ":" in line:
                key, value = line.split(":", 1)
                current_event[key.strip()] = value.strip()

        # Handle the last event
        if current_event_id is not None and current_event:
            events[current_event_id] = current_event

        return events

    def get_all_events_detailed(self) -> Dict[int, Dict[str, str]]:
        """Get all events with detailed information using sel list -v"""
        cmd = self.base_cmd + ["sel", "list", "-v"]

        output = run_command(cmd)
        if not output:
            return {}

        return self.parse_verbose_sel_output(output)

    def get_all_events(self) -> list[str]:
        """Get all events in the SEL"""
        cmd = self.base_cmd + ["sel", "list"]

        output = run_command(cmd)
        if not output:
            return []
        return output.strip().splitlines()

    def get_last_event_id(self) -> Optional[int]:
        """Get the ID of the most recent event in the SEL"""
        lines = self.get_all_events()

        if not lines:
            return None

        return self.get_id_from_line(lines[-1])


def get_last_event_only(ipmi_tool: IpmiTool) -> None:
    """Get the last event ID and exit"""
    last_event_id = ipmi_tool.get_last_event_id()
    if last_event_id is not None:
        message = f"Last event ID: {last_event_id}"
        result = {"success": True, "message": message, "last_event_id": last_event_id}
    else:
        # SEL is empty, return -1 as the last event ID
        message = "SEL is empty, returning -1 as last event ID"
        result = {"success": True, "message": message, "last_event_id": -1}

    print(json.dumps(result))
    sys.exit(0)


def get_success_failure_events(
    matching_events: Dict[int, Dict[str, str]],
    failure_codes_lower: List[str],
    success_codes_lower: List[str],
    elapsed_time: float,
) -> Optional[Tuple[bool, str, Dict]]:
    """Process events in success/failure monitoring mode.

    Returns immediately on first failure event, or returns the latest success event
    after processing all events. Returns None if no success or failure events found.
    """
    success_events = []

    # Process events in ascending order by event ID
    for event_id in sorted(matching_events.keys()):
        event_details = matching_events[event_id]
        event_data = event_details.get("Event Data", "")
        if not event_data:
            logging.warning(f"Event {event_id} has no Event Data field")
            continue

        event_data_lower = event_data.lower()
        logging.info(f"Processing event ID {event_id}, data: {event_data}")

        if event_data_lower in failure_codes_lower:
            failure_event = {
                "event_id": event_id,
                "data": event_data,
                "timestamp": event_details.get("Timestamp", ""),
                "sensor_type": event_details.get("Sensor Type", ""),
                "sensor_number": event_details.get("Sensor Number", ""),
            }

            message = (
                f"FAILURE event detected! Event ID: {event_id}, "
                f"Event Data: {event_data}"
            )

            failure_result = {
                "failure_detected": True,
                "failure_event": failure_event,
                "elapsed_time": elapsed_time,
            }

            logging.error(message)

            # Return immediately if we found any failure event
            return False, message, failure_result

        elif event_data_lower in success_codes_lower:
            success_events.append(
                {
                    "event_id": event_id,
                    "data": event_data,
                    "timestamp": event_details.get("Timestamp", ""),
                    "sensor_type": event_details.get("Sensor Type", ""),
                    "sensor_number": event_details.get("Sensor Number", ""),
                }
            )
            logging.info(
                f"SUCCESS event found! Event ID: {event_id}, "
                f"Event Data: {event_data}"
            )

    # Return the latest detected success event
    if success_events:
        latest_success_event = success_events[-1]
        message = (
            "SUCCESS event detected! "
            f"Event ID: {latest_success_event['event_id']}, "
            f"Event Data: {latest_success_event['data']}"
        )

        success_result = {
            "success_event_detected": True,
            "success_event": latest_success_event,
            "elapsed_time": elapsed_time,
        }

        return True, message, success_result

    return None


def get_first_matching_event(
    matching_events: Dict[int, Dict[str, str]],
    target_codes_lower: List[str],
) -> Optional[Tuple[bool, str, str]]:
    """Process events in standard monitoring mode.

    Returns the first matching event if found, returns None otherwise.
    """
    for event_id, event_details in matching_events.items():
        event_data = event_details.get("Event Data", "")
        if not event_data:
            logging.warning(f"Event {event_id} has no Event Data field")
            continue

        event_data_lower = event_data.lower()
        logging.info(f"Processing event ID {event_id}, data: {event_data}")

        if event_data_lower in target_codes_lower:
            message = (
                f"Target event found! Event ID: {event_id}, "
                f"Event Data: {event_data}"
            )
            logging.info(message)
            return True, message, event_data

        logging.debug(
            f"Event {event_id} data '{event_data}' doesn't match target codes"
        )

    return None


def monitor_events(
    ipmi_tool: IpmiTool,
    sensor_type_filter: Optional[str],
    sensor_number_filter: Optional[str],
    target_codes: List[str],
    interval: float,
    timeout: int,
    initial_event_id: Optional[int] = None,
    success_codes: Optional[List[str]] = None,
    failure_codes: Optional[List[str]] = None,
) -> Union[Tuple[bool, str, Optional[str]], Tuple[bool, str, Dict]]:
    """Monitor IPMI SEL for target events

    Monitoring mode (success_codes=None, failure_codes=None):
        - Returns first matching event from target_codes
        - Returns: (success, message, matched_data)

    Success/failure monitoring mode (success_codes and failure_codes provided):
        - Exits immediately on any failure_codes
        - Exits immediately on any success_codes (returns latest one found)
        - Returns: (success, message, result_dict)
    """

    success_failure_mode = success_codes is not None and failure_codes is not None

    if initial_event_id is not None:
        last_event_id = initial_event_id
        logging.info(f"Using provided initial event ID: {last_event_id}")
    else:
        last_event_id = ipmi_tool.get_last_event_id()
        if last_event_id is None:
            message = "Failed to get initial event ID, SEL might be empty"
            logging.warning(message)
            last_event_id = -1

    logging.info(f"Starting monitoring from event ID: {last_event_id}")

    target_codes_lower = [code.lower() for code in target_codes]

    if success_failure_mode:
        success_codes_lower = [code.lower() for code in success_codes]
        failure_codes_lower = [code.lower() for code in failure_codes]

        logging.info(
            f"Success/failure mode: Success codes (return on any): {success_codes}"
        )
        logging.info(
            f"Success/failure mode: Failure codes (exit on any): {failure_codes}"
        )
    else:
        logging.info(f"Monitoring mode: Target codes: {target_codes}")

    filter_info = []
    if sensor_type_filter:
        filter_info.append(f"sensor type: '{sensor_type_filter}'")
    if sensor_number_filter:
        filter_info.append(f"sensor number: '{sensor_number_filter}'")
    if filter_info:
        logging.info(f"Applying sensor filters: {', '.join(filter_info)}")

    last_event_id_int = last_event_id

    start_time = time.monotonic()
    next_check_time = start_time
    check_num = 0

    while time.monotonic() - start_time < timeout:
        check_num += 1
        current_time = time.monotonic()

        if current_time < next_check_time:
            sleep_time = next_check_time - current_time
            logging.debug(f"Waiting {sleep_time:.2f}s until next check")
            time.sleep(sleep_time)

        next_check_time += interval

        elapsed_time = time.monotonic() - start_time
        remaining_time = timeout - elapsed_time

        logging.info(
            f"Check {check_num}: Checking for new events... "
            f"(elapsed: {elapsed_time:.1f}s, remaining: {remaining_time:.1f}s)"
        )

        check_start_time = time.monotonic()

        all_events_detailed = ipmi_tool.get_all_events_detailed()

        if not all_events_detailed:
            logging.warning("Failed to get events or SEL is empty")
            continue

        current_event_id_int = max(all_events_detailed.keys())
        logging.debug(
            f"Current last event ID: {current_event_id_int}, "
            f"previous: {last_event_id_int}"
        )

        if current_event_id_int == last_event_id_int:
            check_duration = time.monotonic() - check_start_time
            logging.debug(f"No new events found (check took {check_duration:.2f}s)")
            continue

        if current_event_id_int < last_event_id_int:
            logging.info(
                "Current last event ID is smaller than the previous ID, "
                "assuming SEL was cleared..."
            )
            last_event_id_int = 0

        new_events = {
            event_id: details
            for event_id, details in all_events_detailed.items()
            if event_id > last_event_id_int
        }

        logging.info(f"Found {len(new_events)} new events")

        # Filter events based on sensor type and number
        matching_events = {}
        for event_id, event_details in new_events.items():
            sensor_type = event_details.get("Sensor Type", "")
            sensor_number = event_details.get("Sensor Number", "")

            if sensor_type_filter and sensor_type_filter.lower() != sensor_type.lower():
                continue

            if (
                sensor_number_filter
                and sensor_number_filter.lower() != sensor_number.lower()
            ):
                continue

            matching_events[event_id] = event_details

        logging.info(f"Found {len(matching_events)} events matching sensor filters")

        result = None
        if success_failure_mode:
            result = get_success_failure_events(
                matching_events, failure_codes_lower, success_codes_lower, elapsed_time
            )
        else:
            result = get_first_matching_event(matching_events, target_codes_lower)

        # If we found a matching event during this poll interval, return immediately
        if result is not None:
            return result

        last_event_id_int = current_event_id_int

        check_duration = time.monotonic() - check_start_time
        logging.debug(f"Check completed in {check_duration:.2f}s")

    # Timeout reached
    elapsed_time = time.monotonic() - start_time

    if success_failure_mode:
        message = (
            f"Monitoring timed out after {elapsed_time:.1f}s without "
            "detecting any success or failure events"
        )
        logging.warning(message)

        timeout_result = {
            "timeout_reached": True,
            "elapsed_time": elapsed_time,
        }

        return False, message, timeout_result

    message = f"Monitoring timed out after {elapsed_time:.1f} seconds"
    logging.warning(message)
    return False, message, None


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Monitor new IPMI SEL entries for success/failure events or get "
            "last event ID."
        ),
        epilog="""\
Examples:

  1) Query mode: get the last SEL event id (or -1 if empty) and exit.
     ipmi_sel_event_monitor.py \\
       --config-file rvmc-config.yaml \\
       --get-last-event

  2) Monitoring mode: wait for first matching event and return immediately
     ipmi_sel_event_monitor.py \\
       --config-file rvmc-config.yaml \\
       --sensor-type "System Event" \\
       --sensor-number "cc" \\
       --data-values "ffffe6,ffffe7" \\
       --interval 15 \\
       --timeout 300

  3) Success/failure monitoring mode: return immediately on ANY success event
     (latest one) or failure event.
     ipmi_sel_event_monitor.py \\
       --config-file rvmc-config.yaml \\
       --sensor-type "System Event" \\
       --sensor-number "cc" \\
       --success-codes "ffffe0,ffffe9,ffffe2,ffffea,ffffe4,ffffe6" \\
       --failure-codes "ffffe1,ffffec,ffffed,ffffee,ffffe3,fffff0" \\
       --interval 15 \\
       --timeout 300
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Common args
    parser.add_argument(
        "--config-file",
        required=True,
        help="Path to BMC configuration file containing host, username, and password",
    )
    parser.add_argument(
        "--sensor-type",
        help="Filter by sensor type (e.g., 'Unknown', 'System Event')",
    )
    parser.add_argument(
        "--sensor-number",
        help="Filter by sensor number (e.g., '01', 'ff')",
    )
    parser.add_argument(
        "--initial-event-id",
        type=int,
        help=(
            "Initial event ID to start monitoring from "
            "(only monitor events after this ID)"
        ),
    )
    parser.add_argument(
        "--interval", type=int, default=30, help="Check interval in seconds"
    )
    parser.add_argument("--timeout", type=int, default=3600, help="Timeout in seconds")

    # Monitoring mode
    parser.add_argument(
        "--data-values",
        help="Comma-separated list of event data values to match",
    )

    # Failure/success mode
    parser.add_argument(
        "--success-codes",
        help=(
            "Comma-separated list of success event codes "
            "(return immediately on ANY of these)"
        ),
    )
    parser.add_argument(
        "--failure-codes",
        help=(
            "Comma-separated list of failure event codes "
            "(exit immediately on ANY of these)"
        ),
    )

    # Query mode
    parser.add_argument(
        "--get-last-event",
        action="store_true",
        help="Get the last event ID and exit (ignores other monitoring parameters)",
    )

    args = parser.parse_args()

    if args.get_last_event or args.data_values:
        # For query or monitoring mode, no extra validation is necessary
        pass
    elif args.success_codes or args.failure_codes:
        if not args.success_codes:
            parser.error("--success-codes is required when using success/failure mode")
        if not args.failure_codes:
            parser.error("--failure-codes is required when using success/failure mode")
    else:
        parser.error(
            "Must specify either --get-last-event, --data-values, or both "
            "--success-codes and --failure-codes"
        )

    try:
        ipmi_tool = IpmiTool.from_config(args.config_file)

        if args.get_last_event:
            get_last_event_only(ipmi_tool)

        elif args.success_codes and args.failure_codes:
            success_codes = [code.strip() for code in args.success_codes.split(",")]
            failure_codes = [code.strip() for code in args.failure_codes.split(",")]
            all_target_codes = success_codes + failure_codes

            success, message, result_data = monitor_events(
                ipmi_tool,
                args.sensor_type,
                args.sensor_number,
                all_target_codes,
                args.interval,
                args.timeout,
                args.initial_event_id,
                success_codes,
                failure_codes,
            )

            exit_script(success, message, None, result_data)

        else:
            event_data_values = [d.strip() for d in args.data_values.split(",")]

            success, message, matched_data = monitor_events(
                ipmi_tool,
                args.sensor_type,
                args.sensor_number,
                event_data_values,
                args.interval,
                args.timeout,
                args.initial_event_id,
            )

            exit_script(success, message, matched_data)

    except Exception as e:
        exit_script(
            False,
            f"Unexpected exception while monitoring IPMI SEL for target events: {e}",
        )


if __name__ == "__main__":
    main()
