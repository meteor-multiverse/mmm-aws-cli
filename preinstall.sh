#!/usr/bin/env bash


SCRIPT_PATH="${BASH_SOURCE[0]}"
SCRIPT_DIR=$( cd "$( dirname "${SCRIPT_PATH}" )" && pwd )

if [[ $(uname -s) == 'Darwin' ]]; then
  mkdir -p "${HOME}/.aws"
  cp -n "${SCRIPT_DIR}/aws_config_tmpl.ini" "${HOME}/.aws/credentials"

  sudo -H bash "${SCRIPT_DIR}/preinstall_mac.sh"
  exit $?
else
  echo 'The preinstall script will not be executed because you are not running on MacOSX.'
fi

exit 0
