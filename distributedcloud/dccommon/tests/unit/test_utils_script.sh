#!/bin/bash
#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

handle_signal_ignore() {
  local signal=$?
  echo "Caught signal: $signal (ignoring)"
}

echo "Process id: $BASHPID"
sleep_arg=${1:-30}
do_trap_arg=
if [ -n "$do_trap_arg" ]; then
  # trap handle_signal_ignore INT QUIT TERM
  trap handle_signal_ignore $do_trap_arg
fi

sleep "$sleep_arg"
