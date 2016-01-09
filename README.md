# mmm-aws-cli
[![GitHub Latest Release](https://badge.fury.io/gh/edSpring%2Fmmm-aws-cli.svg)](https://github.com/edSpring/mmm-aws-cli) [![Build Status](https://secure.travis-ci.org/edSpring/mmm-aws-cli.svg?branch=master)](https://travis-ci.org/edSpring/mmm-aws-cli)

Meteor Multiverse Manager wrapper for the Amazon AWS CLI


## Install

Install via NPM:

```shell
npm install mmm-aws-cli
```

**IMPORTANT:** _This module will only work on MacOSX and/or Linux!_


## Configure

### Get Your Amazon IAM User Access Keys

If you have not previously downloaded your IAM User Access Keys from Amazon, you will need to [create (and download) a new set of User Access Keys](http://docs.aws.amazon.com/IAM/latest/UserGuide/ManagingCredentials.html#Using_CreateAccessKey).


### Configure Your Local AWS Credentials

#### Update Your AWS Config File

Open the file `~/.aws/credentials` for editing, e.g. with TextEdit on MacOSX:

```shell
open -a TextEdit ~/.aws/credentials
```

Here's what that file will look like initially:

```ini
[default]
aws_access_key_id=ACCESS_KEY
aws_secret_access_key=SECRET_KEY
aws_session_token=OPTIONAL_TOKEN
region=us-east-1

[{{LOCAL_PROFILE_NAME_OR_USERNAME_GOES_HERE}}]
aws_access_key_id={{YOUR_ACCESS_KEY_ID_GOES_HERE}}
aws_secret_access_key={{YOUR_SECRET_KEY_GOES_HERE}}
region=us-east-1
```

Whereever you see a `{{SOME_FIELD_NAME}}` annotation above, substitute in the corresponding value from your downloaded AWS Access Keys CSV file.

So, for example, my [fake] credentials file might look like this:

```ini
[default]
aws_access_key_id=ACCESS_KEY
aws_secret_access_key=SECRET_KEY
aws_session_token=OPTIONAL_TOKEN
region=us-east-1

[jgreene]
aws_access_key_id=BKICIINQZH2LTSDKLJVE
aws_secret_access_key=3dKaqob+KAjTXN6ugw9a2buYHguzsxgtptuS3fH2
region=us-east-1
```


#### Export New Environment Variables

Add the following new environment variables to your `~/.bash_profile` file (or similar):

```shell
# AWS Access Credentials (combined with "~/.aws/credentials" file)
export AWS_PROFILE="{{LOCAL_PROFILE_NAME_OR_USERNAME}}"  # For AWS SDK
export AWS_DEFAULT_PROFILE="${AWS_PROFILE}"              # For AWS CLI

# AWS SDK looks for a "~/.aws/credentials" file and is not configurable.
# AWS CLI looks for a "~/.aws/config" file but IS configurable:
export AWS_CONFIG_FILE="${HOME}/.aws/credentials"
```

For example, mine looks like:

```shell
# AWS Access Credentials (combined with "~/.aws/credentials" file)
export AWS_PROFILE="jgreene"                 # For AWS SDK
export AWS_DEFAULT_PROFILE="${AWS_PROFILE}"  # For AWS CLI

# AWS SDK looks for a "~/.aws/credentials" file and is not configurable.
# AWS CLI looks for a "~/.aws/config" file but IS configurable:
export AWS_CONFIG_FILE="${HOME}/.aws/credentials"
```

**NOTE:** As always, you will need to open a new terminal session or else run `source ~/.bash_profile` in order for these environment variables to take effect.
