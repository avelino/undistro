/*
Copyright 2020 The UnDistro authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cloudformation

const Template = `AWSTemplateFormatVersion: 2010-09-09
Resources:
  AWSIAMInstanceProfileControlPlane:
    Properties:
      InstanceProfileName: control-plane.cluster-api-provider-aws.sigs.k8s.io
      Roles:
      - Ref: AWSIAMRoleControlPlane
    Type: AWS::IAM::InstanceProfile
  AWSIAMInstanceProfileControllers:
    Properties:
      InstanceProfileName: controllers.cluster-api-provider-aws.sigs.k8s.io
      Roles:
      - Ref: AWSIAMRoleControllers
    Type: AWS::IAM::InstanceProfile
  AWSIAMInstanceProfileNodes:
    Properties:
      InstanceProfileName: nodes.cluster-api-provider-aws.sigs.k8s.io
      Roles:
      - Ref: AWSIAMRoleNodes
    Type: AWS::IAM::InstanceProfile
  AWSIAMManagedPolicyCloudProviderControlPlane:
    Properties:
      Description: For the Kubernetes Cloud Provider AWS Control Plane
      ManagedPolicyName: control-plane.cluster-api-provider-aws.sigs.k8s.io
      PolicyDocument:
        Statement:
        - Action:
          - autoscaling:DescribeAutoScalingGroups
          - autoscaling:DescribeLaunchConfigurations
          - autoscaling:DescribeTags
          - ec2:DescribeInstances
          - ec2:DescribeImages
          - ec2:DescribeRegions
          - ec2:DescribeRouteTables
          - ec2:DescribeSecurityGroups
          - ec2:DescribeSubnets
          - ec2:DescribeVolumes
          - ec2:CreateSecurityGroup
          - ec2:CreateTags
          - ec2:CreateVolume
          - ec2:ModifyInstanceAttribute
          - ec2:ModifyVolume
          - ec2:AttachVolume
          - ec2:AuthorizeSecurityGroupIngress
          - ec2:CreateRoute
          - ec2:DeleteRoute
          - ec2:DeleteSecurityGroup
          - ec2:DeleteVolume
          - ec2:DetachVolume
          - ec2:RevokeSecurityGroupIngress
          - ec2:DescribeVpcs
          - elasticloadbalancing:AddTags
          - elasticloadbalancing:AttachLoadBalancerToSubnets
          - elasticloadbalancing:ApplySecurityGroupsToLoadBalancer
          - elasticloadbalancing:CreateLoadBalancer
          - elasticloadbalancing:CreateLoadBalancerPolicy
          - elasticloadbalancing:CreateLoadBalancerListeners
          - elasticloadbalancing:ConfigureHealthCheck
          - elasticloadbalancing:DeleteLoadBalancer
          - elasticloadbalancing:DeleteLoadBalancerListeners
          - elasticloadbalancing:DescribeLoadBalancers
          - elasticloadbalancing:DescribeLoadBalancerAttributes
          - elasticloadbalancing:DetachLoadBalancerFromSubnets
          - elasticloadbalancing:DeregisterInstancesFromLoadBalancer
          - elasticloadbalancing:ModifyLoadBalancerAttributes
          - elasticloadbalancing:RegisterInstancesWithLoadBalancer
          - elasticloadbalancing:SetLoadBalancerPoliciesForBackendServer
          - elasticloadbalancing:AddTags
          - elasticloadbalancing:CreateListener
          - elasticloadbalancing:CreateTargetGroup
          - elasticloadbalancing:DeleteListener
          - elasticloadbalancing:DeleteTargetGroup
          - elasticloadbalancing:DescribeListeners
          - elasticloadbalancing:DescribeLoadBalancerPolicies
          - elasticloadbalancing:DescribeTargetGroups
          - elasticloadbalancing:DescribeTargetHealth
          - elasticloadbalancing:ModifyListener
          - elasticloadbalancing:ModifyTargetGroup
          - elasticloadbalancing:RegisterTargets
          - elasticloadbalancing:SetLoadBalancerPoliciesOfListener
          - iam:CreateServiceLinkedRole
          - kms:DescribeKey
          Effect: Allow
          Resource:
          - '*'
        Version: 2012-10-17
      Roles:
      - Ref: AWSIAMRoleControlPlane
    Type: AWS::IAM::ManagedPolicy
  AWSIAMManagedPolicyCloudProviderNodes:
    Properties:
      Description: For the Kubernetes Cloud Provider AWS nodes
      ManagedPolicyName: nodes.cluster-api-provider-aws.sigs.k8s.io
      PolicyDocument:
        Statement:
        - Action:
          - ec2:DescribeInstances
          - ec2:DescribeRegions
          - ecr:GetAuthorizationToken
          - ecr:BatchCheckLayerAvailability
          - ecr:GetDownloadUrlForLayer
          - ecr:GetRepositoryPolicy
          - ecr:DescribeRepositories
          - ecr:ListImages
          - ecr:BatchGetImage
          Effect: Allow
          Resource:
          - '*'
        - Action:
          - secretsmanager:DeleteSecret
          - secretsmanager:GetSecretValue
          Effect: Allow
          Resource:
          - arn:*:secretsmanager:*:*:secret:aws.cluster.x-k8s.io/*
        - Action:
          - ssm:UpdateInstanceInformation
          - ssmmessages:CreateControlChannel
          - ssmmessages:CreateDataChannel
          - ssmmessages:OpenControlChannel
          - ssmmessages:OpenDataChannel
          - s3:GetEncryptionConfiguration
          Effect: Allow
          Resource:
          - '*'
        Version: 2012-10-17
      Roles:
      - Ref: AWSIAMRoleControlPlane
      - Ref: AWSIAMRoleNodes
    Type: AWS::IAM::ManagedPolicy
  AWSIAMManagedPolicyControllers:
    Properties:
      Description: For the Kubernetes Cluster API Provider AWS Controllers
      ManagedPolicyName: controllers.cluster-api-provider-aws.sigs.k8s.io
      PolicyDocument:
        Statement:
        - Action:
          - ec2:AllocateAddress
          - ec2:AssociateRouteTable
          - ec2:AttachInternetGateway
          - ec2:AuthorizeSecurityGroupIngress
          - ec2:CreateInternetGateway
          - ec2:CreateNatGateway
          - ec2:CreateRoute
          - ec2:CreateRouteTable
          - ec2:CreateSecurityGroup
          - ec2:CreateSubnet
          - ec2:CreateTags
          - ec2:CreateVpc
          - ec2:ModifyVpcAttribute
          - ec2:DeleteInternetGateway
          - ec2:DeleteNatGateway
          - ec2:DeleteRouteTable
          - ec2:DeleteSecurityGroup
          - ec2:DeleteSubnet
          - ec2:DeleteTags
          - ec2:DeleteVpc
          - ec2:DescribeAccountAttributes
          - ec2:DescribeAddresses
          - ec2:DescribeAvailabilityZones
          - ec2:DescribeInstances
          - ec2:DescribeInternetGateways
          - ec2:DescribeImages
          - ec2:DescribeNatGateways
          - ec2:DescribeNetworkInterfaces
          - ec2:DescribeNetworkInterfaceAttribute
          - ec2:DescribeRouteTables
          - ec2:DescribeSecurityGroups
          - ec2:DescribeSubnets
          - ec2:DescribeVpcs
          - ec2:DescribeVpcAttribute
          - ec2:DescribeVolumes
          - ec2:DetachInternetGateway
          - ec2:DisassociateRouteTable
          - ec2:DisassociateAddress
          - ec2:ModifyInstanceAttribute
          - ec2:ModifyNetworkInterfaceAttribute
          - ec2:ModifySubnetAttribute
          - ec2:ReleaseAddress
          - ec2:RevokeSecurityGroupIngress
          - ec2:RunInstances
          - ec2:TerminateInstances
          - tag:GetResources
          - elasticloadbalancing:AddTags
          - elasticloadbalancing:CreateLoadBalancer
          - elasticloadbalancing:ConfigureHealthCheck
          - elasticloadbalancing:DeleteLoadBalancer
          - elasticloadbalancing:DescribeLoadBalancers
          - elasticloadbalancing:DescribeLoadBalancerAttributes
          - elasticloadbalancing:DescribeTags
          - elasticloadbalancing:ModifyLoadBalancerAttributes
          - elasticloadbalancing:RegisterInstancesWithLoadBalancer
          - elasticloadbalancing:DeregisterInstancesFromLoadBalancer
          - elasticloadbalancing:RemoveTags
          Effect: Allow
          Resource:
          - '*'
        - Action:
          - iam:CreateServiceLinkedRole
          Condition:
            StringLike:
              iam:AWSServiceName: elasticloadbalancing.amazonaws.com
          Effect: Allow
          Resource:
          - arn:*:iam::*:role/aws-service-role/elasticloadbalancing.amazonaws.com/AWSServiceRoleForElasticLoadBalancing
        - Action:
          - iam:CreateServiceLinkedRole
          Condition:
            StringLike:
              iam:AWSServiceName: spot.amazonaws.com
          Effect: Allow
          Resource:
          - arn:*:iam::*:role/aws-service-role/spot.amazonaws.com/AWSServiceRoleForEC2Spot
        - Action:
          - iam:PassRole
          Effect: Allow
          Resource:
          - arn:*:iam::*:role/*.cluster-api-provider-aws.sigs.k8s.io
        - Action:
          - secretsmanager:CreateSecret
          - secretsmanager:DeleteSecret
          - secretsmanager:TagResource
          Effect: Allow
          Resource:
          - arn:*:secretsmanager:*:*:secret:aws.cluster.x-k8s.io/*
        - Action:
          - ssm:GetParameter
          Effect: Allow
          Resource:
          - arn:aws:ssm:*:*:parameter/aws/service/eks/optimized-ami/*
        - Action:
          - iam:GetRole
          - iam:ListAttachedRolePolicies
          - iam:DetachRolePolicy
          - iam:DeleteRole
          - iam:CreateRole
          - iam:TagRole
          - iam:AttachRolePolicy
          Effect: Allow
          Resource:
          - arn:aws:iam::*:role/*
        - Action:
          - iam:GetPolicy
          Effect: Allow
          Resource:
          - arn:aws:iam::aws:policy/AmazonEKSClusterPolicy
        - Action:
          - eks:DescribeCluster
          - eks:ListClusters
          - eks:CreateCluster
          - eks:TagResource
          - eks:UpdateClusterVersion
          - eks:DeleteCluster
          - eks:UpdateClusterConfig
          - eks:UntagResource
          - eks:UpdateNodegroupVersion
          - eks:DescribeNodegroup
          - eks:DeleteNodegroup
          - eks:UpdateNodegroupConfig
          - eks:CreateNodegroup
          Effect: Allow
          Resource:
          - arn:aws:eks:*:*:cluster/*
          - arn:aws:eks:*:*:nodegroup/*/*/*
        - Action:
          - iam:PassRole
          Condition:
            StringEquals:
              iam:PassedToService: eks.amazonaws.com
          Effect: Allow
          Resource:
          - '*'
        Version: 2012-10-17
      Roles:
      - Ref: AWSIAMRoleControllers
      - Ref: AWSIAMRoleControlPlane
    Type: AWS::IAM::ManagedPolicy
  AWSIAMRoleControlPlane:
    Properties:
      AssumeRolePolicyDocument:
        Statement:
        - Action:
          - sts:AssumeRole
          Effect: Allow
          Principal:
            Service:
            - ec2.amazonaws.com
        Version: 2012-10-17
      RoleName: control-plane.cluster-api-provider-aws.sigs.k8s.io
    Type: AWS::IAM::Role
  AWSIAMRoleControllers:
    Properties:
      AssumeRolePolicyDocument:
        Statement:
        - Action:
          - sts:AssumeRole
          Effect: Allow
          Principal:
            Service:
            - ec2.amazonaws.com
        Version: 2012-10-17
      RoleName: controllers.cluster-api-provider-aws.sigs.k8s.io
    Type: AWS::IAM::Role
  AWSIAMRoleEKSControlPlane:
    Properties:
      AssumeRolePolicyDocument:
        Statement:
        - Action:
          - sts:AssumeRole
          Effect: Allow
          Principal:
            Service:
            - eks.amazonaws.com
        Version: 2012-10-17
      ManagedPolicyArns:
      - arn:aws:iam::aws:policy/AmazonEKSClusterPolicy
      RoleName: eks-controlplane.cluster-api-provider-aws.sigs.k8s.io
    Type: AWS::IAM::Role
  AWSIAMRoleEKSNodegroup:
    Properties:
      AssumeRolePolicyDocument:
        Statement:
        - Action:
          - sts:AssumeRole
          Effect: Allow
          Principal:
            Service:
            - ec2.amazonaws.com
            - eks.amazonaws.com
        Version: 2012-10-17
      ManagedPolicyArns:
      - arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy
      - arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy
      - arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly
      RoleName: eks-nodegroup.cluster-api-provider-aws.sigs.k8s.io
    Type: AWS::IAM::Role
  AWSIAMRoleNodes:
    Properties:
      AssumeRolePolicyDocument:
        Statement:
        - Action:
          - sts:AssumeRole
          Effect: Allow
          Principal:
            Service:
            - ec2.amazonaws.com
        Version: 2012-10-17
      ManagedPolicyArns:
      - arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy
      - arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy
      - arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly
      RoleName: nodes.cluster-api-provider-aws.sigs.k8s.io
    Type: AWS::IAM::Role

`