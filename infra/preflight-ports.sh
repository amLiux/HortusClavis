#!/bin/sh
# Fail fast when a host port this stack needs is already taken.
#
# Usage: RUNTIME=podman sh infra/preflight-ports.sh 5433 6380 [8001]
#
# Prints the container that owns the port and the exact command to stop it.
set -eu

RUNTIME="${RUNTIME:-podman}"
status=0

for port in "$@"; do
  owner=$(
    "$RUNTIME" ps --format '{{.Names}} {{.Ports}}' 2>/dev/null \
      | awk -v p=":${port}->" 'index($0, p) { print $1; exit }'
  )

  if [ -n "${owner}" ]; then
    echo "error: host port ${port} is already taken by container '${owner}'"
    echo "       stop it first:  ${RUNTIME} stop ${owner}"
    case "${owner}" in
      *_iam_*) echo "       (that is the iam container from 'make deps-up-all'; use 'make deps-down-all')" ;;
    esac
    status=1
    continue
  fi

  if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | grep -qE ":${port}[[:space:]]"; then
    echo "error: host port ${port} is in use by a process outside the container runtime"
    echo "       find it with:  ss -ltnp | grep :${port}"
    status=1
  fi
done

if [ "${status}" -ne 0 ]; then
  case " $* " in
    *" 5433 "*|*" 6380 "*)
      echo "       ports 5433 (postgres) and 6380 (redis) belong to this compose stack" ;;
  esac
  exit 1
fi

exit 0
