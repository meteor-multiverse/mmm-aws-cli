var path = require('path');
var _ = require('lodash');
var execSync = require('sync-exec');
var customCommands = require('./customCommands');

var _inited = false;



/**
 * Install the AWS CLI and its many dependencies
 * @private
 */
function _init() {
  if (!_inited) {
    console.warn('About to install/upgrade your AWS CLI utility... (may require `sudo` password!)');
    var result = execSync('sudo -H bash ' + path.join(__dirname, 'installAwsCli.sh'));
    if (result.status === 0) {
      _inited = true;
      console.warn('Successfully installed/upgraded AWS CLI utility!');
    }
    else {
      throw new Error('Failed to install AWS CLI utility!\n\n' + (result.stderr || result.stdout));
    }
  }
}

function mergeOptions(opts) {
  if (this && this._options && opts) {
    _.merge(this._options, opts);
  }
}

function makeJsonSafeForCommandLine(json) {
  return (
    '\'' +
    json
      .replace(/'/g, '\'"\'"\'')
      .replace(/(\$OBSCURED_KEY_[\d]+)/g, '\'"$1"\'') +
    '\''
  );
}



// For more info, see: http://docs.aws.amazon.com/cli/latest/userguide/shorthand-syntax.html
function _optsToFlags(opts) {
  return !_.isPlainObject(opts) ? (opts || []) :
    _.reduce(
      opts,
      function(result, val, key) {
        if (val != null) {
          result.push(key + (val ? ' ' + val : ''));
        }
        return result;
      },
      []
    );
}

var keysForPasswordPrivateExporting = ['HaproxyStatsPassword', 'MysqlRootPassword', 'GangliaPassword'];

var keysToConsiderForCertPrivateExporting = ['SshKey', 'SshPrivateKey', 'Certificate', 'PrivateKey', 'Chain'];
var valPrefixRequiredForCertPrivateExporting = /^[\r\n]*-----BEGIN (RSA PRIVATE KEY|CERTIFICATE)-----[\r\n]/;
var valSuffixRequiredForCertPrivateExporting = /[\r\n]-----END (RSA PRIVATE KEY|CERTIFICATE)-----[\r\n]*$/;

var keysForDoubleEncodingAndDecoding = ['CustomJson', 'AssumeRolePolicyDocument', 'PolicyDocument'];

function _prepareInput(input) {
  var preppedInput = {
    json: '',
    exports: ''
  };

  var rawFlagsStr = '';
  var json = '';
  var exports = [];

  if (typeof input === 'string' && input) {
    rawFlagsStr = input;
  }
  else if (input) {
    json =
      JSON.stringify(
        input,
        function(key, val) {
          var exportIndex = exports.length + 1;

          // Handle passwords and certificates slightly differently by
          // exporting their values to a temporary environment variable and then
          // referencing that variable within the JSON string during the
          // command's execution. This helps provide a better attempt at
          // security/privacy for consumers by not visibly displaying their
          // passwords/certificates on the terminal screen!
          if (
            typeof val === 'string' && val &&
            (
              _.contains(keysForPasswordPrivateExporting, key) ||
              (
                _.contains(keysToConsiderForCertPrivateExporting, key) &&
                valPrefixRequiredForCertPrivateExporting.test(val) &&
                valSuffixRequiredForCertPrivateExporting.test(val)
              )
            )
          ) {
            exports.push([
              'OBSCURED_KEY_' + exportIndex,
              val
            ]);
            return '$OBSCURED_KEY_' + exportIndex;
          }

          // Double-encode some objects into a JSON stringified-string (as the API demands)
          if (_.contains(keysForDoubleEncodingAndDecoding, key) && _.isPlainObject(val)) {
            return JSON.stringify(val);
          }

          // Convert Filters to final format:
          //   [{ Name: 'Name1', Values: ['Val1', ...] }, ...]
          if (key === 'Filters' && _.isPlainObject(val)) {

            var isFilterHash = _.every(val, function(v, k) { return typeof k === 'string' && !!k && v != null && (_.isArray(v) || !_.isObject(v)); });
            if (isFilterHash) {
              return _.reduce(
                val,
                function(result, v, k) {
                  result.push({
                    Name:   k,
                    Values: _.map((_.isArray(v) ? v : [v]), String)  // Force to an Array of Strings
                  });
                  return result;
                },
                []
              );
            }

          }

          // Convert PolicyAttributes to final format:
          //   [{ AttributeName: 'Name1', AttributeValue: 'Val1' }, ...]
          if (key === 'PolicyAttributes' && _.isPlainObject(val)) {

            var isAttrHash = _.every(val, function(v, k) { return typeof k === 'string' && typeof v !== 'undefined' && !!k && v != null; });
            if (isAttrHash) {
              return _.reduce(
                val,
                function(result, v, k) {
                  result.push({
                    AttributeName: k,
                    AttributeValue: '' + v   // AttributeValue must be a String
                  });
                  return result;
                },
                []
              );
            }

          }

          // Convert Tags to final format:
          //   [{ Key: 'Tag1', Value: 'TagVal1'}, ...]
          if (key === 'Tags' || key === 'AdditionalAttributes') {

            if (_.isArray(val)) {
              // From:
              //   [['Tag1', 'TagVal1'], ['Tag2', 'TagVal2']]
              var isArrArr = _.every(val, function(arr) { return _.isArray(arr) && arr.length === 2 && _.every(arr, function(s) { return typeof s === 'string' && !!s; }); });
              if (isArrArr) {
                return _.map(val, function(arr) {
                  return {
                    Key: arr[0],
                    Value: arr[1]
                  };
                });
              }

              // Or from:
              //   [{ Tag1: 'TagVal1' }, { Tag2: 'TagVal2' }]
              // But NOT from:
              //   << the correct final format, mentioned above >>
              var isArrHash = _.every(val, function(h) { return _.isPlainObject(h) && _.keys(h).length === 1 && _.every(h, function(v, k) { return typeof k === 'string' && !!k && typeof v === 'string' && !!v; }); });
              if (isArrHash) {
                return _.flatten(
                  _.map(
                    val,
                    function(h) {
                      return _.map(
                        h,
                        function(v, k) {
                          return {
                            Key: k,
                            Value: v
                          };
                        }
                      );
                    }
                  )
                );
              }
            }

            else if (_.isPlainObject(val)) {

              // Or from:
              //   { Tag1: 'TagVal1', Tag2: 'TagVal2' }
              var isHash = _.every(val, function(v, k) { return typeof k === 'string' && typeof v === 'string' && !!k && !!v; });
              if (isHash) {
                return _.reduce(
                  val,
                  function(result, v, k) {
                    result.push({
                      Key: k,
                      Value: v
                    });
                    return result;
                  },
                  []
                );
              }

            }
          }

          // Other just return the original
          return val;
        }
      );
  }

  if (exports.length > 0) {
    preppedInput.exports =
      _.map(exports, function(pair) {
        return 'export ' + pair[0] + '=\'' + JSON.stringify(pair[1]).slice(1, -1) + '\'';
      })
      .join('; ');
  }

  preppedInput.json = json ? '--cli-input-json ' + makeJsonSafeForCommandLine(json) : rawFlagsStr;

  return preppedInput;
}

function _parseOutput(json) {
  return (
    !json ?
      null :
      JSON.parse(
        json || 'null',
        function(key, val) {
          // Double-decode some objects from a JSON stringified-string (as the API provides)
          if (_.contains(keysForDoubleEncodingAndDecoding, key) && _.isString(val)) {
            return JSON.parse(val);
          }
          return val;
        }
      )
  );
}

function _awsExec(rawCmd, customOptions, exports) {
  customOptions = customOptions || {};

  var cmd = 'aws ' + rawCmd;
  if (customOptions.cmdTrace === true) {
    // IMPORTANT: For security/privacy reasons, we do NOT normally show the custom shell exports
    //console.warn('[TRACE] Exports preamble:\n  ' + exports + '\n[/TRACE]\n');

    console.warn('[TRACE] Raw AWS command:\n  ' + cmd + '\n[/TRACE]\n');
  }

  // If we have any `exports`, we must add surrounding parentheses to create a sub-shell or else the
  // variable references don't seem to resolve correctly
  var result = execSync((exports ? '(' + exports + '; ' : '') + cmd + (exports ? ')' : ''));
  if (result.status !== 0) {
    throw new Error('Failed to execute AWS command:\n   ' + cmd + '\n\n' + (result.stderr || result.stdout));
  }

  if (customOptions.cmdTrace === true) {
    console.warn('[TRACE] Raw AWS response:\n' + result.stdout + '\n[/TRACE]\n');
  }
  return _parseOutput(result.stdout);
}

var AwsCli =
module.exports =
function AwsCli(opts) {
  if (!(this instanceof AwsCli)) {
    return new AwsCli(opts);
  }

  // Install the AWS CLI and its many dependencies... but only a max of once!
  if (AwsCli.autoInstall === true) {
    _init();
  }

  this._options = opts || {};
};

// Control whether or not using this module auto-installs the underlying AWS CLI
AwsCli.autoInstall = false;


AwsCli.prototype.o = AwsCli.prototype.options = mergeOptions;

var AwsService =
AwsCli.prototype.s =
AwsCli.prototype.serv =
AwsCli.prototype.service =
function AwsService(name, opts, cli) {
  if (!(this instanceof AwsService)) {
    if (this instanceof AwsCli) {
      return new AwsService(name, opts, this);
    }
    return new AwsService(name, opts);
  }

  this._cli = cli || new AwsCli();
  this._name = name;
  this._options = opts || {};

  // OpsWorks currently only has a service endpoint in region "us-east-1", so force that
  if (this._name === 'opsworks') {
    if (!this._options.flags) {
      this._options.flags = {};
    }
    this._options.flags['--region'] = 'us-east-1';
  }
};

AwsService.prototype.o = AwsService.prototype.options = mergeOptions;

var AwsCommand =
AwsService.prototype.c =
AwsService.prototype.cmd =
AwsService.prototype.command =
function AwsCommand(cmd, input, overrideOpts) {
  var service = this;
  if (!(service instanceof AwsService)) {
    throw new Error('Trying to execute AwsCommand without a parent AwsService');
  }

  input = input || {};
  overrideOpts = overrideOpts || {};

  // Internal-only hack
  var printOnly = arguments[2] === true;
  var _exec = !printOnly ? _awsExec : function(rawCmd, options /* , exports */) {
    console.warn('[NOT EXECUTING]\n  Command: ' + rawCmd + '\n  Options: ' + JSON.stringify(options) + '\n');
  };

  var serviceName = service._name;

  var mergedFlags = _.merge(
    {},
    service._cli._options.flags,
    service._options.flags,
    overrideOpts.flags
  );

  var mergedOptions = _.merge(
    _.omit(service._cli._options, 'flags'),
    _.omit(service._options, 'flags'),
    _.omit(overrideOpts, 'flags')
  );

  var _execWrapper = function(realCmd, realInput, realOverrideOpts) {
    var finalFlags = _.merge({}, mergedFlags, (realOverrideOpts || {}).flags);
    var finalOptions = _.merge({}, mergedOptions, _.omit(realOverrideOpts || {}, 'flags'));
    var preppedRealInput = _prepareInput(realInput || {});

    var cliFlagKeys = _.keys(service._cli._options.flags);
    var serviceFlagKeys = _.difference(_.keys(service._options.flags), cliFlagKeys);
    var otherFlagKeys = _.difference(_.keys(finalFlags), cliFlagKeys, serviceFlagKeys);

    var cliFlagsStr = _optsToFlags(_.pick(finalFlags, cliFlagKeys)).join(' ');
    var serviceFlagsStr = _optsToFlags(_.pick(finalFlags, serviceFlagKeys)).join(' ');
    var otherFlagsStr = _optsToFlags(_.pick(finalFlags, otherFlagKeys)).join(' ');

    var globalAndServiceBaseCommandStr =
      (cliFlagsStr ? cliFlagsStr + ' ' : '') +
      serviceName + ' ' +
      (serviceFlagsStr ? serviceFlagsStr + ' ' : '') +
      (otherFlagsStr ? otherFlagsStr + ' ' : '');

    return _exec(
      globalAndServiceBaseCommandStr + realCmd + ' ' + preppedRealInput.json,
      finalOptions,
      preppedRealInput.exports
    );
  };

  // If there is a custom command mapping, delegate to that function instead, e.g. "associate-network-acl"
  if (
    customCommands.hasOwnProperty(serviceName) &&
    customCommands[serviceName] != null &&
    customCommands[serviceName].hasOwnProperty(cmd) &&
    typeof customCommands[serviceName][cmd] === 'function'
  ) {
    return customCommands[serviceName][cmd](input, _execWrapper);
  }

  return _execWrapper(cmd, input);
};

AwsCommand.printOnly = function(cmd, input) {
  if (!(this instanceof AwsService)) {
    throw new Error('Trying to execute AwsCommand without a parent AwsService');
  }

  var _printOnly = true;
  return this.command(cmd, input, _printOnly);
};


AwsCli.prototype.run =
function AwsCliRun(service, cmd, input) {
  if (!(this instanceof AwsCli)) {
    throw new Error('Trying to execute AwsCommand without an ancestor AwsCli');
  }

  return this.service(service).command(cmd, input);
};
