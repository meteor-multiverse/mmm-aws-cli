#!/usr/bin/env bash


SCRIPT_PATH="${BASH_SOURCE[0]}"
SCRIPT_DIR=$( cd "$( dirname "${SCRIPT_PATH}" )" && pwd )

if [[ $(uname -s) == 'Darwin' ]]; then
  mkdir -p "${HOME}/.aws"
  cp -n "${SCRIPT_DIR}/aws_config_tmpl.ini" "${HOME}/.aws/credentials"

  sudo -H bash "${SCRIPT_DIR}/preinstall_mac.sh"
  exit $?
elif [[ $(uname -s) == 'Linux' ]]; then
  mkdir -p "${HOME}/.aws"
  cp -n "${SCRIPT_DIR}/aws_config_tmpl.ini" "${HOME}/.aws/credentials"

  sudo -H bash "${SCRIPT_DIR}/preinstall_linux.sh"
  exit $?
else
  echo 'WARNING: The preinstall script will not be executed because the running Operating System is neither MacOSX nor Linux.'
fi

exit 0
