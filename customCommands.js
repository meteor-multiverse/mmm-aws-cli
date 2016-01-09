// customCommands.js

var IAM_POLICY_SCHEMA_VERSION = '2012-10-17';

var _ = require('lodash');

function toInt(n) {
  return parseInt(n, 10);
}

function toIntOrRange(n) {
  var nRange = !_.isString(n) ? n : n.replace(/^([\d]+)\s*-\s*([\d]+)$/, '$1-$2');
  if (!/^([\d]+)-([\d]+)$/.test(nRange)) {
    nRange = '' + toInt(n);
  }
  return nRange;
}

function isFiniteOrRange(n) {
  return _.isString(n) && (_.isFinite(Number(n)) || /^([\d]+)\s*-\s*([\d]+)$/.test(n));
}

function parsePorts(ports) {
  var newPorts;

  if (_.isArray(ports)) {
    newPorts = ports;
  }
  else if (_.isNumber(ports)) {
    newPorts = ['' + ports];
  }
  else if (_.isString(ports)) {
    newPorts = ports.split(/\s*,\s*/);
  }
  else {
    newPorts = [];
  }

  return _.uniq(_.filter(_.map(newPorts, toIntOrRange), isFiniteOrRange));
}

var customCommands = module.exports = {

  iam: {

    /**
     * Required `input`: N/A
     *
     * Output structure:
        {
          'AccountId': '065248308209'
        }
     */
    'get-account-id': function(input, commandFn) {
      if (typeof commandFn !== 'function') {
        throw new Error('Did not receive the implicit `commandFn` final argument');
      }
      var roles = commandFn(
        'list-roles',
        // For some reason, the JSON version of this limiter param does NOT work with the AWS CLI as of 2015-03-30
        // { MaxItems: 1 }
        '--max-items 1'
      );
      var accountId = roles.Roles[0].Arn.replace(/^arn:aws:iam::(\d+):role\/.+$/, '$1');
      return { AccountId: accountId };
    },


    /**
     * Required `input`:
        {
          'RoleName': 'opsworks-service-role-only-better',
          'Path': '/',
          'Services': ['opsworks', 'ec2'],
          'Allowances': [
            {
              'Action': ['ec2:*', 'iam:PassRole', 'cloudwatch:GetMetricStatistics', 'elasticloadingbalancing:*', 'rds:*'],
              'Resource': ['*']
            }
          ]
        }
     *
     * Output structure:
        {
          "RoleId": "AROAI3WSVV55JCZZMKOWZ",
          "CreateDate": "2014-10-14T19:25:04Z",
          "RoleName": "opsworks-service-role-only-better",
          "Path": "/",
          "Arn": "arn:aws:iam::065248308209:role/opsworks-service-role-only-better",
          "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
              {
                "Sid": "1",
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Principal": {
                  "Service": "ec2.amazonaws.com"
                }
              }
            ]
          },
          InlinePolicies: [
            ...
          ],
          AttachedPolicies: [
            ...
          ],
          ...
        }
     */
    'create-role-with-policies': function(input, commandFn) {
      if (typeof commandFn !== 'function') {
        throw new Error('Did not receive the implicit `commandFn` final argument');
      }
      if (!input) {
        throw new Error('Missing required input');
      }

      var roleName = input.RoleName;
      var servicePrincipals = input.Services;
      var allowances = input.Allowances;
      if (!roleName) {
        throw new Error('Missing required input arg: RoleName`');
      }
      if (!servicePrincipals || servicePrincipals.length === 0) {
        throw new Error('Missing required input arg: Services');
      }
      if (!allowances || allowances.length === 0) {
        throw new Error('Missing required input arg: Allowances');
      }
      if (!_.every(allowances, 'PolicyName')) {
        throw new Error('Missing required input arg: Allowances.PolicyName');
      }
      if (!_.every(allowances, 'Action')) {
        throw new Error('Missing required input arg: Allowances.Action');
      }
      if (!_.every(allowances, 'Resource')) {
        throw new Error('Missing required input arg: Allowances.Resource');
      }

      /**
       * Docs: http://docs.aws.amazon.com/cli/latest/reference/iam/create-role.html
       * Docs: http://docs.aws.amazon.com/IAM/latest/UserGuide/AccessPolicyLanguage_ElementDescriptions.html
       */
      // Create the role and attach the trust policy that enables an Amazon
      // service (e.g. OpsWorks, EC2, etc.) to assume this role.
      var role = commandFn(
        'create-role',
        {
          RoleName: roleName,
          Path: input.Path || undefined,
          AssumeRolePolicyDocument: {
            Version: IAM_POLICY_SCHEMA_VERSION,
            Statement:
              _.map(
                servicePrincipals,
                function(service, i /*, c */) {
                  return {
                    Effect: 'Allow',
                    Action: 'sts:AssumeRole',
                    Principal: {
                      Service: service.toLowerCase() + '.amazonaws.com'
                    },
                    Sid: '' + (i + 1)
                  };
                }
              )
            }
          }
        ).Role;

      // Attach a handful of "inline policies" (rather than external "managed policies") to the role.
      _.forEach(
        allowances,
        function(allowance, i /*, c */) {

          /**
           * Docs: http://docs.aws.amazon.com/cli/latest/reference/iam/put-role-policy.html
           * Docs: http://docs.aws.amazon.com/IAM/latest/UserGuide/policies-managed-vs-inline.html
           * Docs: http://docs.aws.amazon.com/IAM/latest/UserGuide/AccessPolicyLanguage_ElementDescriptions.html
           */
          commandFn(
            'put-role-policy',
            {
              RoleName: role.RoleName,
              PolicyName: allowance.PolicyName,
              PolicyDocument: {
                Version: IAM_POLICY_SCHEMA_VERSION,
                Statement: {
                  Effect: 'Allow',
                  Action: allowance.Action,
                  Resource: allowance.Resource,
                  Condition: allowance.Condition || undefined,
                  Sid: '' + (i + 1)
                }
              }
            }
          );

        }
      );


      // Finally, get the updated role object with inline and attached policies
      return customCommands.iam['get-role-with-policies']({ RoleName: role.RoleName }, commandFn);
    },


    /**
     * Required `input`:
        {
          'RoleName': 'opsworks-service-role-only-better'
        }
     *
     * Output structure:
        {
          "RoleId": "AROAI3WSVV55JCZZMKOWZ",
          "CreateDate": "2014-10-14T19:25:04Z",
          "RoleName": "opsworks-service-role-only-better",
          "Path": "/",
          "Arn": "arn:aws:iam::065248308209:role/opsworks-service-role-only-better",
          "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
              {
                "Sid": "1",
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Principal": {
                  "Service": "ec2.amazonaws.com"
                }
              }
            ]
          },
          InlinePolicies: [
            ...
          ],
          AttachedPolicies: [
            ...
          ],
          ...
        }
     */
    'get-role-with-policies': function(input, commandFn) {
      if (typeof commandFn !== 'function') {
        throw new Error('Did not receive the implicit `commandFn` final argument');
      }
      if (!input) {
        throw new Error('Missing required input');
      }

      var roleName = input.RoleName;
      if (!roleName) {
        throw new Error('Missing required input arg: RoleName`');
      }

      /**
       * Docs: http://docs.aws.amazon.com/cli/latest/reference/iam/get-role.html
       */
      var role = commandFn(
        'get-role',
        {
          RoleName: roleName
        }
      ).Role;

      // If no such role exists, throw
      if (!role) {
        throw new Error('No IAM Role exists with RoleName ' + JSON.stringify(roleName));
      }

      /**
       * Docs: http://docs.aws.amazon.com/cli/latest/reference/iam/list-role-policies.html
       * Docs: http://docs.aws.amazon.com/cli/latest/reference/iam/get-role-policy.html
       */
      role.InlinePolicies =
        _.map(
          commandFn('list-role-policies', { RoleName: roleName }).PolicyNames,
          function(policyName) {
            return commandFn(
              'get-role-policy',
              {
                RoleName: roleName,
                PolicyName: policyName
              }
            );
          }
        );

      /**
       * Docs: http://docs.aws.amazon.com/cli/latest/reference/iam/list-attached-role-policies.html
       * Docs: http://docs.aws.amazon.com/cli/latest/reference/iam/get-policy.html
       */
      role.AttachedPolicies =
        _.map(
          commandFn('list-attached-role-policies', { RoleName: roleName }).AttachedPolicies,
          function(policyAttachment) {
            return commandFn('get-policy', { PolicyArn: policyAttachment.PolicyArn }).Policy;
          }
        );

      return role;
    },


    /**
     * Required `input`:
        {
          'RoleName': 'opsworks-service-role-only-better'
        }
     *
     * Output structure: `null`
     */
    'delete-role-with-policies': function(input, commandFn) {
      if (typeof commandFn !== 'function') {
        throw new Error('Did not receive the implicit `commandFn` final argument');
      }
      if (!input) {
        throw new Error('Missing required input');
      }

      var roleName = input.RoleName;
      if (!roleName) {
        throw new Error('Missing required input arg: RoleName`');
      }

      // Get the role object with inline and attached policies
      var role;
      try {
        role = customCommands.iam['get-role-with-policies']({ RoleName: roleName }, commandFn);
      }
      catch (err) {
        // Ignore that... we're trying to delete the entity anyway
        role = null;
      }

      // If no such role exists, bail out
      if (!role) {
        return;
      }

      _.forEach(
        role.AttachedPolicies,
        function(managedPolicy) {
          /**
           * Docs: http://docs.aws.amazon.com/cli/latest/reference/iam/detach-role-policy.html
           */
          commandFn(
            'detach-role-policy',
            {
              RoleName: roleName,
              PolicyArn: managedPolicy.Arn
            }
          );
        }
      );

      _.forEach(
        role.InlinePolicies,
        function(policy) {
          /**
           * Docs: http://docs.aws.amazon.com/cli/latest/reference/iam/delete-role-policy.html
           */
          commandFn(
            'delete-role-policy',
            {
              RoleName: roleName,
              PolicyName: policy.PolicyName
            }
          );
        }
      );

      /**
       * Docs: http://docs.aws.amazon.com/cli/latest/reference/iam/delete-role.html
       */
      // Delete the role
      commandFn(
        'delete-role',
        {
          RoleName: roleName
        }
      );
    },


    /**
     * Required `input`:
        {
          'InstanceProfileName': 'my-profile',
          'Path': '/',
          'RoleNames': ['my-role']
        }
     *
     * Output structure:
        {
          "InstanceProfileId": "AROAI3WSVV55JCEXAMPLE",
          "InstanceProfileName": "my-profile",
          "CreateDate": "2014-10-14T19:25:04Z",
          "Path": "/",
          "Arn": "arn:aws:iam::065248308209:instance-profile/my-profile",
          "Roles": [
            {
              "RoleId": "AROAI3WSVV55JCZZMKOYZ",
              "CreateDate": "2014-10-14T19:25:04Z",
              "RoleName": "my-role",
              "Path": "/",
              "Arn": "arn:aws:iam::065248308209:role/my-role",
              "AssumeRolePolicyDocument": "<URL-encoded-JSON>"
            }
          ]
        }
     */
    'create-instance-profile-with-roles': function(input, commandFn) {
      if (typeof commandFn !== 'function') {
        throw new Error('Did not receive the implicit `commandFn` final argument');
      }
      if (!input) {
        throw new Error('Missing required input');
      }

      var instanceProfileName = input.InstanceProfileName;
      var roleNames = input.RoleNames;
      if (!instanceProfileName) {
        throw new Error('Missing required input arg: InstanceProfileName`');
      }
      if (!roleNames || roleNames.length === 0) {
        throw new Error('Missing required input arg: RoleNames');
      }

      /**
       * Docs: http://docs.aws.amazon.com/cli/latest/reference/iam/create-instance-profile.html
       */
      // Create the instance profile required by EC2 to contain the role
      var instanceProfile = commandFn(
        'create-instance-profile',
        {
          InstanceProfileName: instanceProfileName,
          Path: input.Path || undefined
        }
      ).InstanceProfile;

      /**
       * Docs: http://docs.aws.amazon.com/cli/latest/reference/iam/add-role-to-instance-profile.html
       */
      // Add the role(s) to the instance profile
      _.forEach(
        roleNames,
        function(roleName) {
          commandFn(
            'add-role-to-instance-profile',
            {
              RoleName: roleName,
              InstanceProfileName: instanceProfile.InstanceProfileName
            }
          );
        }
      );

      /**
       * Docs: http://docs.aws.amazon.com/cli/latest/reference/iam/get-instance-profile.html
       */
      // Finally, get the updated instance profile object (with roles attached)
      instanceProfile = commandFn(
        'get-instance-profile',
        {
          InstanceProfileName: instanceProfile.InstanceProfileName
        }
      ).InstanceProfile;

      return instanceProfile;
    },


    /**
     * Required `input`:
        {
          'InstanceProfileName': 'my-profile'
        }
     *
     * Output structure: `null`
     */
    'delete-instance-profile-with-roles': function(input, commandFn) {
      if (typeof commandFn !== 'function') {
        throw new Error('Did not receive the implicit `commandFn` final argument');
      }
      if (!input) {
        throw new Error('Missing required input');
      }

      var instanceProfileName = input.InstanceProfileName;
      if (!instanceProfileName) {
        throw new Error('Missing required input arg: InstanceProfileName`');
      }

      /**
       * Docs:
       */
      // Get all of the roles on this instance profile
      var instanceProfile = commandFn(
        'get-instance-profile',
        {
          InstanceProfileName: instanceProfileName
        }
      ).InstanceProfile;


      // If no InstanceProfile exists, bail out
      if (!instanceProfile) {
        return;
      }


      /**
       * Docs: http://docs.aws.amazon.com/cli/latest/reference/iam/remove-role-from-instance-profile.html
       */
      // Remove all roles from the instance profile
      _.forEach(
        _.pluck(instanceProfile.Roles, 'RoleName'),
        function(roleName) {
          commandFn(
            'remove-role-from-instance-profile',
            {
              RoleName: roleName,
              InstanceProfileName: instanceProfileName
            }
          );
        }
      );


      /**
       * Docs: http://docs.aws.amazon.com/cli/latest/reference/iam/delete-instance-profile.html
       */
      // Delete the instance profile
      commandFn(
        'delete-instance-profile',
        {
          InstanceProfileName: instanceProfileName
        }
      );
    }

  },


  ec2: {

    /**
     * Required `input`:
        {
          'SubnetId': 'subnet-MySubnetId',
          'NetworkAclId': 'acl-MyNetworkAclId'
        }
     *
     * Output structure:
        {
          'AssociationId': 'aclassoc-MyNewNetworkAclSubnetAssocId'
        }
     */
    'associate-network-acl': function(input, commandFn) {
      if (typeof commandFn !== 'function') {
        throw new Error('Did not receive the implicit `commandFn` final argument');
      }
      if (!input) {
        throw new Error('Missing required input');
      }

      var subnetId = input.SubnetId;
      var networkAclId = input.NetworkAclId;
      if (!subnetId) {
        throw new Error('Missing required input arg: SubnetId`');
      }
      if (!networkAclId) {
        throw new Error('Missing required input arg: NetworkAclId');
      }

      /**
       * Docs: http://docs.aws.amazon.com/cli/latest/reference/ec2/describe-network-acls.html
       *
       * Output structure:
          {
            'NetworkAcls': [
              {
                'Associations': [
                  {
                    'SubnetId': 'subnet-MySubnetId',
                    'NetworkAclId': 'acl-9aeb5ef7',
                    'NetworkAclAssociationId': 'aclassoc-67ea5f0a'
                  }
                ],
                'NetworkAclId': 'acl-9aeb5ef7',
                'VpcId': 'MyVpcId'
              }
            ]
          }
       */
      var networkAclAssociationsForSubnet = commandFn(
        'describe-network-acls',
        {
          Filters: {
            'association.subnet-id': subnetId
          }
        }
      ).NetworkAcls;

      // If we couldn't find any Subnet-NetworkAcl association (the Subnet probably doesn't exist), bail out
      if (!networkAclAssociationsForSubnet || networkAclAssociationsForSubnet.length === 0) {
        return { AssociationId: null };
      }

      var networkAclAssociatedWithSubnet =
        _.find(
          networkAclAssociationsForSubnet,
          function(acl) {
            return !!acl &&
              _.findWhere(acl.Associations, { SubnetId: subnetId }) != null;
          }
        );

      var associationIdForSubnet =
        _.findWhere(
          networkAclAssociatedWithSubnet.Associations,
          { SubnetId: subnetId }
        ).NetworkAclAssociationId;

      // If the Subnet is already associated with this NetworkAclId, bail out
      if (networkAclAssociatedWithSubnet.NetworkAclId === networkAclId) {
        return { AssociationId: associationIdForSubnet };
      }

      /**
       * Docs: http://docs.aws.amazon.com/cli/latest/reference/ec2/replace-network-acl-association.html
       *
       * Output structure:
          {
            'NewAssociationId': 'aclassoc-3999875b'
          }
       */
      var newNetworkAclSubnetAssoc = commandFn(
        'replace-network-acl-association',
        {
          AssociationId: associationIdForSubnet,
          NetworkAclId: networkAclId
        }
      );

      // Final output
      return { AssociationId: newNetworkAclSubnetAssoc.NewAssociationId };
    },


    /**
     * Required `input`:
        {
          'SubnetId': 'subnet-MySubnetId',
          'NetworkAclId': 'acl-MyNetworkAclId'
        }
     *
     * Output structure: `null`
     */
    'disassociate-network-acl': function(input, commandFn) {
      if (typeof commandFn !== 'function') {
        throw new Error('Did not receive the implicit `commandFn` final argument');
      }
      if (!input) {
        throw new Error('Missing required input');
      }

      var subnetId = input.SubnetId;
      var networkAclId = input.NetworkAclId;
      if (!subnetId) {
        throw new Error('Missing required input arg: SubnetId`');
      }
      if (!networkAclId) {
        throw new Error('Missing required input arg: NetworkAclId');
      }

      // Verify that the Subnet and NetworkAcl belong to the same VPC
      var subnet = commandFn('describe-subnets', { SubnetIds: [subnetId] }).Subnets[0];
      var networkAcl = commandFn('describe-network-acls', { NetworkAclIds: [networkAclId] }).NetworkAcls[0];

      if (!subnet) {
        throw new Error('SubnetId ' + JSON.stringify(subnetId) + ' does not exist');
      }
      if (!networkAcl) {
        throw new Error('NetworkAclId ' + JSON.stringify(networkAclId) + ' does not exist');
      }
      if (!(subnet.VpcId && subnet.VpcId === networkAcl.VpcId)) {
        throw new Error(
          'SubnetId ' + JSON.stringify(subnetId) + ' and NetworkAclId ' + JSON.stringify(networkAclId) +
          ' belong to different VPCs; respectively, VpcIds ' +
          JSON.stringify(subnet.VpcId) + ' and ' + JSON.stringify(networkAcl.VpcId)
        );
      }

      // Get the default NetworkAcl for the VPC
      var vpcId = subnet.VpcId;
      var defaultNetworkAcl = commandFn(
        'describe-network-acls',
        {
          Filters: {
            'vpc-id': vpcId,
            'default': true
          }
        }
      ).NetworkAcls[0];

      var defaultNetworkAclId = defaultNetworkAcl && defaultNetworkAcl.NetworkAclId;

      if (!defaultNetworkAcl || !defaultNetworkAclId) {
        throw new Error('Could not find a default NetworkAcl for VpcId ' + JSON.stringify(vpcId));
      }

      if (defaultNetworkAclId === networkAclId) {
        throw new Error(
          'NetworkAclId ' + JSON.stringify(networkAclId) + ' is the default NetworkAcl for its VPC. ' +
          'It cannot be disassociated from a Subnet, so you must instead override it by associating a ' +
          'different non-default NetworkAcl with the Subnet.'
        );
      }


      /**
       * Docs: http://docs.aws.amazon.com/cli/latest/reference/ec2/describe-network-acls.html
       *
       * Output structure:
          {
            'NetworkAcls': [
              {
                'Associations': [
                  {
                    'SubnetId': 'subnet-MySubnetId',
                    'NetworkAclId': 'acl-9aeb5ef7',
                    'NetworkAclAssociationId': 'aclassoc-67ea5f0a'
                  }
                ],
                'NetworkAclId': 'acl-9aeb5ef7',
                'VpcId': 'MyVpcId'
              }
            ]
          }
       */
      var networkAclsAssociatedWithSubnet = commandFn(
        'describe-network-acls',
        {
          Filters: {
            'association.subnet-id': subnetId,
            'association.network-acl-id': networkAclId,
            'default': false
          }
        }
      ).NetworkAcls;

      // If we couldn't find any Subnet-NetworkAcl associations, bail out
      if (!networkAclsAssociatedWithSubnet || networkAclsAssociatedWithSubnet.length === 0) {
        return;
      }

      _.forEach(
        _.flatten(_.pluck(networkAclsAssociatedWithSubnet, 'Associations')),
        function(assoc) {
          if (
            assoc.SubnetId === subnetId &&
            assoc.NetworkAclId === networkAclId &&
            assoc.NetworkAclAssociationId
          ) {

            /**
             * Docs: http://docs.aws.amazon.com/cli/latest/reference/ec2/replace-network-acl-association.html
             *
             * Output structure:
                {
                  'NewAssociationId': 'aclassoc-3999875b'
                }
             */
            //var newNetworkAclSubnetAssoc =
            commandFn(
              'replace-network-acl-association',
              {
                AssociationId: assoc.NetworkAclAssociationId,
                NetworkAclId: defaultNetworkAclId
              }
            );

          }
        }
      );
    },


    /**
     * Required `input`:
        {
          'GroupId': 'sg-MySecurityGroupId',
          'IpProtocol': 'tcp',
          'Ports': [80, 443, '1024-65535'],
          // Must have either CidrIp or SourceSecurityGroupId but NOT both
          'CidrIp': ['0.0.0.0/0'],
          'SourceSecurityGroupId': ['sg-MyOtherSecurityGroupId']
        }
     *
     * Output structure: `null`
     */
    'authorize-security-group-inbound-traffic': function(input, commandFn) {
      if (typeof commandFn !== 'function') {
        throw new Error('Did not receive the implicit `commandFn` final argument');
      }
      if (!input) {
        throw new Error('Missing required input');
      }

      var groupId = input.GroupId;
      var ipProtocol = input.IpProtocol;
      var ports = parsePorts(input.Ports);
      var cidrBlocks = _.isArray(input.CidrIp) ? input.CidrIp : _.isString(input.CidrIp) && input.CidrIp ? [input.CidrIp] : [];
      var sourceGroupIds = _.isArray(input.SourceSecurityGroupId) ? input.SourceSecurityGroupId : _.isString(input.SourceSecurityGroupId) && input.SourceSecurityGroupId ? [input.SourceSecurityGroupId] : [];

      if (!groupId) {
        throw new Error('Missing required input arg: GroupId`');
      }
      if (!ipProtocol) {
        throw new Error('Missing required input arg: IpProtocol');
      }
      if (!ports || !_.isArray(ports) || ports.length === 0) {
        throw new Error('Missing required input arg: Ports`');
      }
      if ((!cidrBlocks || cidrBlocks.length === 0) && (!sourceGroupIds || sourceGroupIds.length === 0)) {
        throw new Error('Missing required input args: must provide either CidrIp or SourceSecurityGroupId');
      }
      if ((cidrBlocks && cidrBlocks.length > 0) && (sourceGroupIds && sourceGroupIds.length > 0)) {
        throw new Error('Conflicting required input args: must provide either CidrIp or SourceSecurityGroupId (but not both!)');
      }

      var cidrBlocksExpanded = _.map(cidrBlocks, function(cidr) { return { CidrIp: cidr }; });
      var sourceGroupIdsExpanded = _.map(sourceGroupIds, function(groupId) { return { GroupId: groupId }; });

      /**
       * Docs: http://docs.aws.amazon.com/cli/latest/reference/ec2/authorize-security-group-ingress.html
       */
      commandFn(
        'authorize-security-group-ingress',
        {
          GroupId: groupId,
          IpPermissions:
            _.map(
              ports,
              function(p) {
                var portBits = p === '-1' ? [p] : p.split('-');
                if (portBits.length !== 1 && portBits.length !== 2) {
                  throw new Error('Provided Port value is invalid: ' + p);
                }
                return {
                  IpProtocol: /^(all|-1)$/i.test(ipProtocol) ? '-1' : ipProtocol,
                  FromPort: toInt(portBits[0]),
                  ToPort: toInt(portBits[1] != null ? portBits[1] : portBits[0]),
                  IpRanges: cidrBlocksExpanded,
                  UserIdGroupPairs: sourceGroupIdsExpanded
                };
              }
            )
        }
      );
    },


    /**
     * Required `input`:
        {
          'GroupId': 'sg-MySecurityGroupId',
          'IpProtocol': 'tcp',
          'Ports': [80, 443, '1024-65535'],
          // Must have either CidrIp or SourceSecurityGroupId but NOT both
          'CidrIp': ['0.0.0.0/0'],
          'SourceSecurityGroupId': 'sg-MyOtherSecurityGroupId'
        }
     *
     * Output structure: `null`
     */
    'authorize-security-group-outbound-traffic': function(input, commandFn) {
      if (typeof commandFn !== 'function') {
        throw new Error('Did not receive the implicit `commandFn` final argument');
      }
      if (!input) {
        throw new Error('Missing required input');
      }

      var groupId = input.GroupId;
      var ipProtocol = input.IpProtocol;
      var ports = parsePorts(input.Ports);
      var cidrBlocks = _.isArray(input.CidrIp) ? input.CidrIp : _.isString(input.CidrIp) && input.CidrIp ? [input.CidrIp] : [];
      var sourceGroupIds = _.isArray(input.SourceSecurityGroupId) ? input.SourceSecurityGroupId : _.isString(input.SourceSecurityGroupId) && input.SourceSecurityGroupId ? [input.SourceSecurityGroupId] : [];

      if (!groupId) {
        throw new Error('Missing required input arg: GroupId`');
      }
      if (!ipProtocol) {
        throw new Error('Missing required input arg: IpProtocol');
      }
      if (!ports || !_.isArray(ports) || ports.length === 0) {
        throw new Error('Missing required input arg: Ports`');
      }
      if ((!cidrBlocks || cidrBlocks.length === 0) && (!sourceGroupIds || sourceGroupIds.length === 0)) {
        throw new Error('Missing required input args: must provide either CidrIp or SourceSecurityGroupId');
      }
      if ((cidrBlocks && cidrBlocks.length > 0) && (sourceGroupIds && sourceGroupIds.length > 0)) {
        throw new Error('Conflicting required input args: must provide either CidrIp or SourceSecurityGroupId (but not both!)');
      }

      var cidrBlocksExpanded = _.map(cidrBlocks, function(cidr) { return { CidrIp: cidr }; });
      var sourceGroupIdsExpanded = _.map(sourceGroupIds, function(groupId) { return { GroupId: groupId }; });

      /**
       * Docs: http://docs.aws.amazon.com/cli/latest/reference/ec2/authorize-security-group-egress.html
       */
      commandFn(
        'authorize-security-group-egress',
        {
          GroupId: groupId,
          IpPermissions:
            _.map(
              ports,
              function(p) {
                var portBits = p === '-1' ? [p] : p.split('-');
                if (portBits.length !== 1 && portBits.length !== 2) {
                  throw new Error('Provided Port value is invalid: ' + p);
                }
                return {
                  IpProtocol: /^(all|-1)$/i.test(ipProtocol) ? '-1' : ipProtocol,
                  FromPort: toInt(portBits[0]),
                  ToPort: toInt(portBits[1] != null ? portBits[1] : portBits[0]),
                  IpRanges: cidrBlocksExpanded,
                  UserIdGroupPairs: sourceGroupIdsExpanded
                };
              }
            )
        }
      );
    },


    /**
     * This is a method signature override to the input that I prefer.  However,
     * if the `input` matches the real underlying method signature, it will just
     * defer back to the raw AWS command.
     *
     * This method signature makes it symmetrical with the method signature for
     * its antithetic 'associate-route-table' command.
     *
     * Required `input`:
        {
          'SubnetId': 'subnet-MySubnetId',
          'RouteTableId': 'rtb-MyRouteTableId'
        }
     *
     * Output structure: `null`
     */
    'disassociate-route-table': function(input, commandFn) {
      if (typeof commandFn !== 'function') {
        throw new Error('Did not receive the implicit `commandFn` final argument');
      }
      if (!input) {
        throw new Error('Missing required input');
      }

      // Immediately defer to the raw AWS command if this particular input parameter is provided
      if (input.AssociationId) {

        /**
         * Docs: http://docs.aws.amazon.com/cli/latest/reference/ec2/disassociate-route-table.html
         */
        commandFn(
          'disassociate-route-table',
          {
            AssociationId: input.AssociationId
          }
        );
        return;

      }

      var subnetId = input.SubnetId;
      var routeTableId = input.RouteTableId;

      if (!subnetId) {
        throw new Error('Missing required input arg: SubnetId`');
      }
      if (!routeTableId) {
        throw new Error('Missing required input arg: RouteTableId');
      }

      /**
       * Docs: http://docs.aws.amazon.com/cli/latest/reference/ec2/describe-route-tables.html
       */
      var routeTable =
        commandFn(
          'describe-route-tables',
          {
            RouteTableIds: [routeTableId]
          }
        ).RouteTables[0];


      var rtbAssocIds =
        _.pluck(
          _.filter(
            routeTable.Associations,
            function(assoc) {
              return assoc && !assoc.Main && assoc.RouteTableAssociationId && assoc.SubnetId === subnetId;
            }
          ),
          'RouteTableAssociationId'
        );

      if (rtbAssocIds.length === 0) {
        throw new Error('SubnetId ' + JSON.stringify(subnetId) + ' is not associated with RouteTableId ' + JSON.stringify(routeTableId));
      }

      _.forEach(
        rtbAssocIds,
        function(assocId) {
          /**
           * Docs: http://docs.aws.amazon.com/cli/latest/reference/ec2/disassociate-route-table.html
           */
          commandFn(
            'disassociate-route-table',
            {
              AssociationId: assocId
            }
          );
        }
      );
    },


    /**
     * Required `input`: `null`
     *
     * Output structure:
        {
          'RegionName': 'us-east-1',
          'Endpoint': 'ec2.us-east-1.amazonaws.com'
        }
     */
    'get-current-region': function(input, commandFn) {
      if (typeof commandFn !== 'function') {
        throw new Error('Did not receive the implicit `commandFn` final argument');
      }

      /**
       * Docs: http://docs.aws.amazon.com/cli/latest/reference/ec2/describe-availability-zones.html
       */
      var availZones;
      try {
        availZones = commandFn('describe-availability-zones', {}).AvailabilityZones;
      }
      catch(err) {
        // Ignore that, it actually proves a point: no region was specified
      }
      if (!availZones || availZones.length === 0) {
        return null;
      }

      var regionNames =
        _.pluck(
          availZones,
          'RegionName'
        );

      var regionName =
        _.uniq(regionNames).length === 1 ?
          regionNames[0] :
          // I don't THINK that the following scenario is even possible, at least currently, but... just in case!
          (function() {
            var regionCounts = _.countBy(regionNames);
            var maxCount = _.max(_.values(regionCounts));
            return _.findKey(regionCounts, function(val) { return val === maxCount; });
          })();

      return commandFn(
        'describe-regions',
        {
          RegionNames: [regionName]
        }
      ).Regions[0];
    },


    /**
     * Required `input`: `null`
     * Optional `input`:
        {
          'RegionName': 'us-east-1',
          'State': ['available']
        }
     *
     * Output structure:
        {
          'AvailabilityZones': [
            {
              'RegionName': 'us-east-1',
              'ZoneName': 'us-east-1b',
              'State': 'available',
              'Messages': []
            },
            ...
          ]
        }
     */
    'describe-vpc-capable-availability-zones': function(input, commandFn) {
      if (typeof commandFn !== 'function') {
        throw new Error('Did not receive the implicit `commandFn` final argument');
      }
      if (input != null && !input) {
        throw new Error('Invalid optional input');
      }

      var regionName = input ? input.RegionName : null;
      var states =
        input && input.State && input.State.length > 0 ?
          (
            _.isArray(input.State) ?
              input.State :
              (
                _.isString(input.State) ?
                  [input.State] :
                  null
              )
          ) :
          null;

      if (input && _.has(input, 'RegionName') && !(typeof regionName === 'string' && regionName)) {
        throw new Error('Invalid value provided for optional input arg: RegionName`');
      }

      var cmdOptionPrefix = regionName ? '--region ' + regionName.toLowerCase().replace(/[^a-z0-9-]/g, '') + ' ' : '';

      /**
       * Docs: http://docs.aws.amazon.com/cli/latest/reference/ec2/describe-availability-zones.html
       */
      var availZones =
        commandFn(
          'describe-availability-zones',
          // Must use the string (non-JSON) version of this command's flags/options in order to override any configured current/default region
          cmdOptionPrefix + (states && states.length > 0 ? ' --filters Name=state,Values=' + states.join(',').toLowerCase().replace(/[^a-z0-9-,]/g, '') : '')
        ).AvailabilityZones;

      /**
       * Docs: http://docs.aws.amazon.com/cli/latest/reference/ec2/create-subnet.html
       */
      var subnetErrorMsg;
      try {
        commandFn(
          'create-subnet',
          // Must use the string (non-JSON) version of this command's flags/options in order to override any configured current/default region
          cmdOptionPrefix + '--vpc-id GARBAGE --cidr-block 123.45.67.89/28 --availability-zone GARBAGE'
        );
      }
      catch(err) {
        subnetErrorMsg = err.toString();
      }

      // If the previous command failed with an error message citing the invalid VpcId instead of the
      // invalid AvailabilityZone, create a temporary VPC and reissue the command
      if (
        subnetErrorMsg &&
        subnetErrorMsg.toLowerCase().indexOf(' availability zones: ') === -1 &&
        subnetErrorMsg.indexOf('InvalidVpcID.NotFound') >= 0
      ) {

        /**
         * Docs: http://docs.aws.amazon.com/cli/latest/reference/ec2/create-vpc.html
         */
        var vpc = commandFn(
          'create-vpc',
          // Must use the string (non-JSON) version of this command's flags/options in order to override any configured current/default region
          cmdOptionPrefix + '--cidr-block 123.45.67.89/28'
        ).Vpc;

        /**
         * Docs: http://docs.aws.amazon.com/cli/latest/reference/ec2/create-subnet.html
         */
        try {
          commandFn(
            'create-subnet',
            // Must use the string (non-JSON) version of this command's flags/options in order to override any configured current/default region
            cmdOptionPrefix + '--vpc-id ' + vpc.VpcId + ' --cidr-block 123.45.67.89/28 --availability-zone GARBAGE'
          );
        }
        catch(err) {
          subnetErrorMsg = err.toString();
        }

        /**
         * Docs: http://docs.aws.amazon.com/cli/latest/reference/ec2/delete-vpc.html
         */
        commandFn(
          'delete-vpc',
          // Must use the string (non-JSON) version of this command's flags/options in order to override any configured current/default region
          cmdOptionPrefix + '--vpc-id ' + vpc.VpcId
        );
      }

      if (subnetErrorMsg && subnetErrorMsg.toLowerCase().indexOf(' availability zones: ') >= 0) {
        var vpcCapableAzNames = _.compact(subnetErrorMsg.slice(subnetErrorMsg.lastIndexOf(':') + 1).split(/[\s,.'"]/));

        if (vpcCapableAzNames.length > 0) {
          availZones =
            _.filter(
              availZones,
              function(az) {
                return _.contains(vpcCapableAzNames, az.ZoneName);
              }
            );
        }
      }

      return {
        AvailabilityZones: availZones
      };
    }

  },


  opsworks: {

    /**
     * This is a method signature override to the input that I often prefer.
     * However, if the `input` does not include the custom arguments, it will
     * just defer back to the raw AWS command.
     *
     * Note that 'AppId'/'AppName'/'AppShortname' is also a required `input` field when
     * executing any App-specific commands/deployments (e.g. `Command: { Name: 'deploy' }`.
     *
     * Required `input`:
        {
          'StackId':  'stack-MyOpsWorksStackGuid123',
          'Command':  { Name: 'setup', Args: {} },
          'LayerIds': ['layer-MyOpsWorksStaticContentLayerGuid456']
        }
     * OR:
        {
          'StackId':         'stack-MyOpsWorksStackGuid123',
          'Command':         { Name: 'configure', Args: {} },
          'LayerShortnames': ['lb']
        }
     * OR:
        {
          'StackId':    'stack-MyOpsWorksStackGuid123',
          'AppId':      'app-MyOpsWorksAppGuid789',
          'Command':    {
                          Name: 'execute_recipes',
                          Args: {
                            recipes: [
                              'static_layer::app_restart',
                              'meteor_layer::app_restart'
                            ]
                          }
                        },
          'LayerNames': ['Static Content Servers', 'Meteor App Servers']
        }
     *
     * Output structure: `null`
     */
    'create-deployment': function(input, commandFn) {
      if (typeof commandFn !== 'function') {
        throw new Error('Did not receive the implicit `commandFn` final argument');
      }
      if (!input) {
        throw new Error('Missing required input');
      }

      // Immediately defer to the raw AWS command if none of the custom input parameters are present
      if (
        !(
          (input.LayerIds && input.LayerIds.length > 0 && _.trim(input.LayerIds[0])) ||
          (input.LayerShortnames && input.LayerShortnames.length > 0 && _.trim(input.LayerShortnames[0])) ||
          (input.LayerNames && input.LayerNames.length > 0 && _.trim(input.LayerNames[0])) ||
          (input.AppId && _.trim(input.AppId)) ||
          (input.AppShortname && _.trim(input.AppShortname)) ||
          (input.AppName && _.trim(input.AppName))
        )
      ) {

        /**
         * Docs: http://docs.aws.amazon.com/cli/latest/reference/opsworks/create-deployment.html
         */
        return commandFn('create-deployment', input);

      }
      else if (
        (
          (input.LayerIds && input.LayerIds.length > 0 && _.trim(input.LayerIds[0])) ||
          (input.LayerShortnames && input.LayerShortnames.length > 0 && _.trim(input.LayerShortnames[0])) ||
          (input.LayerNames && input.LayerNames.length > 0 && _.trim(input.LayerNames[0]))
        ) &&
        (input.InstanceIds && input.InstanceIds.length > 0 && _.trim(input.InstanceIds[0]))
      ) {
        throw new Error('Cannot combine input arg "InstanceIds" with input args "LayerIds"/"LayerNames"/"LayerShortnames"');
      }

      var stackId = input.StackId;
      var appId = input.AppId;
      var instanceIds = input.InstanceIds;

      if (!stackId) {
        throw new Error('Missing required input arg: StackId`');
      }

      if (!appId) {
        if (_.trim(input.AppShortname || '')) {
          var expectedAppShortname = _.trim(input.AppShortname);

          /**
           * Docs: http://docs.aws.amazon.com/cli/latest/reference/opsworks/describe-apps.html
           */
          var appByShortname =
            _.findWhere(
              commandFn('describe-apps', { StackId: stackId }).Apps,
              { Shortname: expectedAppShortname }
            );

          if (!appByShortname) {
            throw new Error('Could not find any OpsWorks App in Stack ' + JSON.stringify(stackId) + ' with AppShortname: ' + JSON.stringify(expectedAppShortname));
          }

          appId = appByShortname.AppId;
        }
        else if (_.trim(input.AppName || '')) {
          var expectedAppName = _.trim(input.AppName);

          /**
           * Docs: http://docs.aws.amazon.com/cli/latest/reference/opsworks/describe-apps.html
           */
          var appByName =
            _.findWhere(
              commandFn('describe-apps', { StackId: stackId }).Apps,
              { Name: expectedAppName }
            );

          if (!appByName) {
            throw new Error('Could not find any OpsWorks App in Stack ' + JSON.stringify(stackId) + ' with AppName: ' + JSON.stringify(expectedAppName));
          }

          appId = appByName.AppId;
        }
      }


      var layerIds = (input.LayerIds && input.LayerIds.length > 0 && _.trim(input.LayerIds[0])) ? input.LayerIds : null;
      if (layerIds) {
        var expectedLayerIds = _.uniq(_.compact(_.map(layerIds, function(layerId) { return _.trim(layerId); })));

        /**
         * Docs: http://docs.aws.amazon.com/cli/latest/reference/opsworks/describe-layers.html
         */
        var layersById = _.filter(
          commandFn('describe-layers', { StackId: stackId }).Layers,
          function(layer) {
            return _.contains(expectedLayerIds, layer.LayerId);
          }
        );

        var missingLayerIds = _.difference(expectedLayerIds, layersById);
        var extraLayerIds = _.difference(layersById, expectedLayerIds);
        if (missingLayerIds.length > 0) {
          throw new Error('Some of the provided LayerIds were not found in the OpsWorks Stack ' + JSON.stringify(stackId) + ': ' + JSON.stringify(missingLayerIds));
        }
        if (extraLayerIds.length > 0) {
          throw new Error('Some unexpected LayerIds were matched in the OpsWorks Stack ' + JSON.stringify(stackId) + ': ' + JSON.stringify(extraLayerIds));
        }
        if (layersById.length !== expectedLayerIds.length) {
          throw new Error('Unexpected/mismatched number of LayerIds');
        }

        layerIds = _.pluck(layersById, 'LayerId');
      }
      else {
        var layerShortnames = (input.LayerShortnames && input.LayerShortnames.length > 0 && _.trim(input.LayerShortnames[0])) ? input.LayerShortnames : null;
        if (layerShortnames) {
          var expectedLayerShortnames = _.uniq(_.compact(_.map(layerShortnames, function(layerShortname) { return _.trim(layerShortname); })));

          /**
           * Docs: http://docs.aws.amazon.com/cli/latest/reference/opsworks/describe-layers.html
           */
          var layersByShortname = _.filter(
            commandFn('describe-layers', { StackId: stackId }).Layers,
            function(layer) {
              return _.contains(expectedLayerShortnames, layer.Shortname);
            }
          );

          var missingLayerShortnames = _.difference(expectedLayerShortnames, layersByShortname);
          var extraLayerShortnames = _.difference(layersByShortname, expectedLayerShortnames);
          if (missingLayerShortnames.length > 0) {
            throw new Error('Some of the provided LayerShortnames were not found in the OpsWorks Stack ' + JSON.stringify(stackId) + ': ' + JSON.stringify(missingLayerShortnames));
          }
          if (extraLayerShortnames.length > 0) {
            throw new Error('Some unexpected LayerShortnames were matched in the OpsWorks Stack ' + JSON.stringify(stackId) + ': ' + JSON.stringify(extraLayerShortnames));
          }
          if (layersByShortname.length !== expectedLayerShortnames.length) {
            throw new Error('Unexpected/mismatched number of LayerShortnames');
          }

          layerIds = _.pluck(layersByShortname, 'LayerId');
        }
        else {
          var layerNames = (input.LayerNames && input.LayerNames.length > 0 && _.trim(input.LayerNames[0])) ? input.LayerNames : null;
          if (layerNames) {
            var expectedLayerNames = _.uniq(_.compact(_.map(layerNames, function(layerName) { return _.trim(layerName); })));

            /**
             * Docs: http://docs.aws.amazon.com/cli/latest/reference/opsworks/describe-layers.html
             */
            var layersByName = _.filter(
              commandFn('describe-layers', { StackId: stackId }).Layers,
              function(layer) {
                return _.contains(expectedLayerNames, layer.Name);
              }
            );

            var missingLayerNames = _.difference(expectedLayerNames, layersByName);
            var extraLayerNames = _.difference(layersByName, expectedLayerNames);
            if (missingLayerNames.length > 0) {
              throw new Error('Some of the provided LayerNames were not found in the OpsWorks Stack ' + JSON.stringify(stackId) + ': ' + JSON.stringify(missingLayerNames));
            }
            if (extraLayerNames.length > 0) {
              throw new Error('Some unexpected LayerNames were matched in the OpsWorks Stack ' + JSON.stringify(stackId) + ': ' + JSON.stringify(extraLayerNames));
            }
            if (layersByName.length !== expectedLayerNames.length) {
              throw new Error('Unexpected/mismatched number of LayerNames');
            }

            layerIds = _.pluck(layersByName, 'LayerId');
          }
        }
      }

      if (!(layerIds && layerIds.length > 0) && !(instanceIds && instanceIds.length > 0 && _.trim(instanceIds[0]))) {
        throw new Error('Could not find any associated LayerIds and did not provide any InstanceIds');
      }


      if (!(instanceIds && instanceIds.length > 0 && _.trim(instanceIds[0]))) {
        /**
         * Docs: http://docs.aws.amazon.com/cli/latest/reference/opsworks/describe-instances.html
         */
        instanceIds =
          _.uniq(
            _.flatten(
              _.map(
                layerIds,
                function(layerId) {
                  var instances = commandFn(
                    'describe-instances',
                    {
                      LayerId: layerId
                    }
                  ).Instances;

                  var availableInstances = _.filter(
                    instances,
                    function(inst) {
                      return (
                        inst && (
                          inst.Status === 'online' ||
                          (
                            inst.Status === 'setup_failed' &&
                            (
                              input.Command && input.Command.Name &&
                              _.trim(input.Command.Name.toLowerCase()) === 'setup'
                            )
                          )
                        )
                      );
                    }
                  );

                  return _.pluck(availableInstances, 'InstanceId');
                }
              )
            )
          );
      }

      if (!(instanceIds && instanceIds.length > 0 && _.trim(instanceIds[0]))) {
        throw new Error('There are no available Instances to execute command/deployment against within those OpsWorks Layers');
      }

      // Make a clone of the original `input` parameters, removing all Layer* and App* arguments,
      // then adding the newly established AppId and/or list of InstanceIds
      var revisedInput = _.cloneDeep(input);
      delete revisedInput.LayerIds;
      delete revisedInput.LayerShortnames;
      delete revisedInput.LayerNames;
      delete revisedInput.AppShortname;
      delete revisedInput.AppName;
      revisedInput.AppId = appId;              // May be `undefined`
      revisedInput.InstanceIds = instanceIds;  // May be `undefined`

      /**
       * Docs: http://docs.aws.amazon.com/cli/latest/reference/opsworks/create-deployment.html
       */
      return commandFn('create-deployment', revisedInput);
    }

  }

};
