#!/usr/bin/env sh
set -eu

export SKILLINQUISITOR_CONFIG="${SKILLINQUISITOR_CONFIG:-/opt/skillinquisitor/config.yaml}"

exec skillinquisitor "$@"
