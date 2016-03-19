#!/usr/bin/env bash


# Only execute this on Mac
if [[ $(uname -s) != 'Darwin' ]]; then
  echo 'This script can ONLY be run on MacOSX!'
  exit 1
fi


function install_homebrew()
{
  if [ "x`which brew`" == "x" ]; then
    if [ "x`which ruby`" != "x" ] && [ "x`which curl`" != "x" ]; then
      ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
      if [ $? -eq 0 ] && [ "x`which brew`" != "x" ]; then
        # Ensure that the Homebrew installations will be preferred before
        # other installations (e.g. Apple stock installations) in other dirs
        echo "export PATH=/usr/local/bin:$PATH" >> ~/.bash_profile
        export PATH="/usr/local/bin:$PATH"
        echo "Successfully installed Homebrew via Ruby"
      else
        echo "Failed to install Homebrew via Ruby"
        exit 1
      fi
    else
      echo "Failed to install Homebrew because either Ruby or cURL (or both) were missing"
      exit 1
    fi
  else
    echo "Homebrew was already installed"
  fi
}

function install_python()
{
  # Ensure Homebrew is installed
  install_homebrew

  if [ "x`which python`" == "x" ]; then
    brew install python
    if [ $? -eq 0 ] && [ "x`which python`" != "x" ]; then
      echo "Successfully installed Python via Homebrew"
    else
      echo "Failed to install Python via Homebrew"
      exit 1
    fi
  else
    echo "Python was already installed"
  fi
}

function install_pip()
{
  # Ensure Python is installed
  install_python

  local PASSED=false

  if [ "x`which pip`" != "x" ]; then
    echo "PIP was already installed"
    PASSED=true

    echo "Check for PIP upgrades..."
    pip install pip --upgrade
    if [ $? -eq 0 ] && [ "x`which pip`" != "x" ]; then
      echo "Successfully upgraded PIP via PIP"
    elif [ "x`which pip`" != "x" ]; then
      echo "Failed to upgrade PIP via PIP"
    else
      echo "Failed to upgrade PIP via PIP... and possibly deleted it!?"
      PASSED=false
    fi
  else
    if [ "x`which easy_install`" != "x" ]; then
      easy_install pip
      if [ $? -eq 0 ] && [ "x`which pip`" != "x" ]; then
        echo "Successfully installed PIP via EasyInstall"
        PASSED=true
      else
        echo "Failed to install PIP via EasyInstall"
      fi
    else
      echo "Failed to install PIP because EasyInstall was missing"
    fi

    if [ "x`which pip`" == "x" ] && [ "x`which curl`" != "x" ] && [ "x`which python`" != "x" ]; then
      curl -O http://python-distribute.org/distribute_setup.py
      python distribute_setup.py
      curl -O https://raw.github.com/pypa/pip/master/contrib/get-pip.py
      python get-pip.py
      rm -f distribute_setup.py get-pip.py

      if [ $? -eq 0 ] && [ "x`which pip`" != "x" ]; then
        echo "Successfully installed PIP via Python"
        PASSED=true
      else
        echo "Failed to install PIP via Python"
      fi
    else
      echo "Failed to install PIP because Python or cURL (or both) were missing"
    fi

    if [[ "$PASSED" == false ]] || [ "x`which pip`" == "x" ]; then
      exit 1
    fi
  fi
}

function install_awscli()
{
  # Ensure PIP is installed
  install_pip

  local PASSED=false

  if [ "x`which aws`" == "x" ]; then
    pip install awscli
    if [ $? -eq 0 ] && [ "x`which aws`" != "x" ]; then
      echo "Successfully installed AWS CLI via PIP"
      PASSED=true
    else
      echo "Failed to install AWS CLI via PIP"
    fi
  else
    pip install awscli --upgrade --ignore-installed six
    if [ $? -eq 0 ] && [ "x`which aws`" != "x" ]; then
      echo "Successfully upgraded AWS CLI via PIP"
      PASSED=true
    elif [ "x`which aws`" != "x" ]; then
      echo "WARNING: Failed to upgrade AWS CLI via PIP"
      PASSED=true
    else
      echo "ERROR: Failed to upgrade AWS CLI via PIP... and possibly deleted it!?"
    fi
  fi

  if [[ "$PASSED" == false ]] || [ "x`which pip`" == "x" ]; then
    exit 1
  fi
}


install_awscli

exit 0
