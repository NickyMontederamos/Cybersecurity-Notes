☁️ Cloud Security Comprehensive Guide
Last Updated: December 2024 | Version: 3.0 | Author: Nicole Dominique Montederamos

📚 Table of Contents
Cloud Security Fundamentals

AWS Security Implementation

Azure Security Configuration

GCP Security Architecture

Cloud Identity & Access Management

Network Security in Cloud

Data Protection & Encryption

Container & Serverless Security

Cloud Monitoring & Logging

Cloud Compliance & Governance

Multi-Cloud Security Strategy

Incident Response in Cloud

Quick Reference & Cheatsheets

Cloud Security Fundamentals
🏗️ Cloud Security Architecture
Shared Responsibility Model:

graph TB
    A[Cloud Security Responsibility] --> B[Customer Responsibility]
    A --> C[Cloud Provider Responsibility]
    
    B --> B1[Customer Data]
    B --> B2[Platform & Application Management]
    B --> B3[Identity & Access Management]
    B --> B4[Operating System & Network Configuration]
    B --> B5[Client-Side Data Encryption]
    
    C --> C1[Physical Infrastructure]
    C --> C2[Network Infrastructure]
    C --> C3[Virtualization Layer]
    C --> C4[Regions & Availability Zones]
    C --> C5[Compute, Storage, Database Services]
Cloud Security Pillars:

yaml
# AWS Well-Architected Framework Security Pillar
Security_Pillars:
  Identity_and_Access_Management:
    - Principle of least privilege
    - Separation of duties
    - Centralized identity management
    
  Detective_Controls:
    - Logging and monitoring
    - Security information and event management
    - Audit and compliance
    
  Infrastructure_Protection:
    - Network security
    - Compute security
    - Edge protection
    
  Data_Protection:
    - Encryption at rest
    - Encryption in transit
    - Backup and recovery
    
  Incident_Response:
    - Response planning
    - Investigation and analysis
    - Recovery procedures
🔐 Cloud Security Principles
Zero Trust Architecture for Cloud:

python
# Zero Trust principles implementation
class ZeroTrustCloud:
    principles = [
        "Never trust, always verify",
        "Assume breach mentality",
        "Verify explicitly",
        "Use least privilege access",
        "Monitor and log everything"
    ]
    
    def implement(self):
        steps = [
            "1. Identity verification for every access request",
            "2. Micro-segmentation of networks",
            "3. Continuous authentication and authorization",
            "4. Encryption everywhere",
            "5. Real-time monitoring and analytics"
        ]
        return steps
Cloud Security Assessment Framework:

bash
#!/bin/bash
# cloud_security_assessment.sh

# Check for common cloud security misconfigurations
echo "=== Cloud Security Assessment ==="
echo "Date: $(date)"
echo

# 1. Check for public S3 buckets/Blob storage
echo "1. Checking for publicly accessible storage..."
# AWS S3
aws s3api list-buckets --query "Buckets[].Name" | while read bucket; do
    aws s3api get-bucket-acl --bucket "$bucket" | grep -q "AllUsers" && echo "  ⚠️ Public bucket found: $bucket"
done

# 2. Check IAM policies
echo "2. Reviewing IAM policies..."
aws iam get-account-authorization-details --query "Policies[?PolicyDocument.Statement[?Effect=='Allow' && Action=='*' && Resource=='*']].Arn"

# 3. Check security groups
echo "3. Checking security groups..."
aws ec2 describe-security-groups --query "SecurityGroups[?IpPermissions[?IpRanges[?CidrIp=='0.0.0.0/0']]].GroupId"
AWS Security Implementation
🔐 AWS Identity & Access Management
IAM Best Practices Configuration:

yaml
# AWS CloudFormation template for secure IAM setup
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  # IAM Group with permissions boundary
  SecurityAdminsGroup:
    Type: AWS::IAM::Group
    Properties:
      GroupName: Security-Admins
      Policies:
        - PolicyName: Security-Admin-Policy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - "iam:List*"
                  - "iam:Get*"
                  - "cloudtrail:*"
                  - "cloudwatch:*"
                  - "guardduty:*"
                Resource: "*"
  
  # IAM Role with MFA requirement
  EC2InstanceRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: EC2-Instance-Role
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: ec2.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: EC2-Permissions
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - "s3:Get*"
                  - "s3:List*"
                Resource: "arn:aws:s3:::my-secure-bucket/*"
AWS Organizations & SCP Implementation:

json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyLeavingOrganization",
      "Effect": "Deny",
      "Action": [
        "organizations:LeaveOrganization"
      ],
      "Resource": "*"
    },
    {
      "Sid": "RequireMFA",
      "Effect": "Deny",
      "NotAction": [
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:GetUser",
        "iam:ListMFADevices",
        "iam:ListVirtualMFADevices",
        "iam:ResyncMFADevice",
        "sts:GetSessionToken"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    },
    {
      "Sid": "BlockHighRiskRegions",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": [
            "us-east-1",
            "us-west-2",
            "eu-west-1"
          ]
        }
      }
    }
  ]
}
🛡️ AWS Network Security
VPC Security Configuration:

bash
#!/bin/bash
# secure_vpc_setup.sh

# Create VPC with security best practices
VPC_ID=$(aws ec2 create-vpc --cidr-block 10.0.0.0/16 --query 'Vpc.VpcId' --output text)

# Enable DNS hostnames and DNS support
aws ec2 modify-vpc-attribute --vpc-id $VPC_ID --enable-dns-hostnames
aws ec2 modify-vpc-attribute --vpc-id $VPC_ID --enable-dns-support

# Create Internet Gateway
IGW_ID=$(aws ec2 create-internet-gateway --query 'InternetGateway.InternetGatewayId' --output text)
aws ec2 attach-internet-gateway --vpc-id $VPC_ID --internet-gateway-id $IGW_ID

# Create subnets with proper NACLs
aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block 10.0.1.0/24 --availability-zone us-east-1a
aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block 10.0.2.0/24 --availability-zone us-east-1b

# Create security groups
SG_ID=$(aws ec2 create-security-group \
  --group-name Web-SG \
  --description "Security group for web servers" \
  --vpc-id $VPC_ID \
  --query 'GroupId' \
  --output text)

# Configure security group rules
aws ec2 authorize-security-group-ingress \
  --group-id $SG_ID \
  --protocol tcp \
  --port 80 \
  --cidr 0.0.0.0/0

aws ec2 authorize-security-group-ingress \
  --group-id $SG_ID \
  --protocol tcp \
  --port 443 \
  --cidr 0.0.0.0/0

# Deny all other inbound traffic by default (AWS default)
echo "Secure VPC setup completed: $VPC_ID"
AWS WAF Configuration:

yaml
# CloudFormation for AWS WAF Web ACL
WebACL:
  Type: AWS::WAFv2::WebACL
  Properties:
    Name: Production-WebACL
    DefaultAction:
      Allow: {}
    Scope: REGIONAL
    VisibilityConfig:
      SampledRequestsEnabled: true
      CloudWatchMetricsEnabled: true
      MetricName: ProductionWebACL
    Rules:
      # Rate-based rule
      - Name: RateLimitRule
        Priority: 1
        Statement:
          RateBasedStatement:
            Limit: 2000
            AggregateKeyType: IP
        Action:
          Block: {}
        VisibilityConfig:
          SampledRequestsEnabled: true
          CloudWatchMetricsEnabled: true
          MetricName: RateLimitRule
      
      # SQL Injection protection
      - Name: SQLInjectionRule
        Priority: 2
        Statement:
          ManagedRuleGroupStatement:
            VendorName: AWS
            Name: AWSManagedRulesSQLiRuleSet
        OverrideAction:
          None: {}
        VisibilityConfig:
          SampledRequestsEnabled: true
          CloudWatchMetricsEnabled: true
          MetricName: SQLInjectionRule
      
      # XSS protection
      - Name: XSSRule
        Priority: 3
        Statement:
          ManagedRuleGroupStatement:
            VendorName: AWS
            Name: AWSManagedRulesCommonRuleSet
        OverrideAction:
          None: {}
        VisibilityConfig:
          SampledRequestsEnabled: true
          CloudWatchMetricsEnabled: true
          MetricName: XSSRule
📊 AWS Monitoring & Logging
CloudTrail & CloudWatch Configuration:

bash
#!/bin/bash
# aws_monitoring_setup.sh

# Enable CloudTrail in all regions
aws cloudtrail create-trail \
  --name Security-Trail \
  --s3-bucket-name my-security-logs \
  --is-multi-region-trail \
  --enable-log-file-validation

# Configure CloudWatch Logs for VPC Flow Logs
aws logs create-log-group --log-group-name VPC-Flow-Logs
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids $VPC_ID \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name VPC-Flow-Logs \
  --deliver-logs-permission-arn arn:aws:iam::123456789012:role/FlowLogsRole

# Create CloudWatch Alarms for security events
aws cloudwatch put-metric-alarm \
  --alarm-name "UnauthorizedAPICalls" \
  --metric-name "UnauthorizedAttemptCount" \
  --namespace "AWS/CloudTrail" \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions arn:aws:sns:us-east-1:123456789012:Security-Alerts

# Enable GuardDuty
aws guardduty create-detector --enable
AWS Security Hub Configuration:

bash
# Enable Security Hub with all standards
aws securityhub enable-security-hub \
  --enable-default-standards

# Subscribe to security standards
aws securityhub batch-enable-standards \
  --standards-subscription-requests '[
    {
      "StandardsArn": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
    },
    {
      "StandardsArn": "arn:aws:securityhub:::ruleset/pci-dss/v/3.2.1"
    },
    {
      "StandardsArn": "arn:aws:securityhub:::ruleset/nist-800-53/v/5.0.0"
    }
  ]'

# Configure automated response
aws securityhub update-action-target \
  --action-target-arn arn:aws:securityhub:us-east-1:123456789012:action/custom/Response \
  --name "Security Response" \
  --description "Automated response to security findings"
Azure Security Configuration
🔐 Azure Identity & Access Management
Azure AD Security Configuration:

powershell
# Configure Azure AD security defaults
Connect-AzureAD

# Enable security defaults
Set-AzureADTenantDetail -SecurityDefaultsEnabled $true

# Configure Conditional Access Policies
$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "All"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "All"

$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = @("mfa")

New-AzureADMSConditionalAccessPolicy `
    -DisplayName "Require MFA for all users" `
    -State "enabled" `
    -Conditions $conditions `
    -GrantControls $controls
Azure RBAC and PIM Configuration:

json
{
  "properties": {
    "roleDefinitionId": "/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c",
    "principalId": "{principalId}",
    "scope": "/subscriptions/{subscriptionId}",
    "principalType": "User",
    "description": "Just-in-time access for admin tasks",
    "type": "BuiltInRole",
    "condition": "@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:Name] StringEqualsIgnoreCase 'excluded-container'",
    "conditionVersion": "1.0"
  }
}
🛡️ Azure Network Security
Azure NSG and Firewall Configuration:

powershell
# Create Network Security Group with secure rules
$rule1 = New-AzNetworkSecurityRuleConfig `
    -Name "Allow-HTTPS" `
    -Description "Allow HTTPS inbound" `
    -Access Allow `
    -Protocol Tcp `
    -Direction Inbound `
    -Priority 100 `
    -SourceAddressPrefix Internet `
    -SourcePortRange * `
    -DestinationAddressPrefix * `
    -DestinationPortRange 443

$rule2 = New-AzNetworkSecurityRuleConfig `
    -Name "Deny-All-Inbound" `
    -Description "Deny all other inbound" `
    -Access Deny `
    -Protocol * `
    -Direction Inbound `
    -Priority 4096 `
    -SourceAddressPrefix * `
    -SourcePortRange * `
    -DestinationAddressPrefix * `
    -DestinationPortRange *

$nsg = New-AzNetworkSecurityGroup `
    -ResourceGroupName "Security-RG" `
    -Location "EastUS" `
    -Name "Web-NSG" `
    -SecurityRules $rule1, $rule2

# Configure Azure Firewall
$azfw = New-AzFirewall `
    -Name "Prod-Firewall" `
    -ResourceGroupName "Security-RG" `
    -Location "EastUS" `
    -VirtualNetworkName "VNet" `
    -PublicIpName "Firewall-PIP"

# Add application rule
$appRule = New-AzFirewallApplicationRule `
    -Name "Allow-Web" `
    -SourceAddress "10.0.0.0/16" `
    -Protocol "http:80", "https:443" `
    -TargetFqdn "*.microsoft.com"

$appRuleCollection = New-AzFirewallApplicationRuleCollection `
    -Name "App-Rule-Collection" `
    -Priority 100 `
    -Rule $appRule `
    -ActionType "Allow"

$azfw.ApplicationRuleCollections = $appRuleCollection
Set-AzFirewall -AzureFirewall $azfw
Azure DDoS Protection:

powershell
# Enable DDoS Protection Standard
$ddosProtectionPlan = New-AzDdosProtectionPlan `
    -ResourceGroupName "Security-RG" `
    -Name "DDoS-Protection-Plan" `
    -Location "EastUS"

# Associate with virtual network
$vnet = Get-AzVirtualNetwork -Name "Prod-VNet" -ResourceGroupName "Network-RG"
$vnet.DdosProtectionPlan = New-Object Microsoft.Azure.Commands.Network.Models.PSDdosProtectionPlan
$vnet.DdosProtectionPlan.Id = $ddosProtectionPlan.Id
$vnet.EnableDdosProtection = $true

Set-AzVirtualNetwork -VirtualNetwork $vnet
📊 Azure Security Monitoring
Azure Sentinel Configuration:

powershell
# Deploy Azure Sentinel
New-AzResourceGroupDeployment `
    -ResourceGroupName "Security-RG" `
    -TemplateUri "https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Tools/ARM-Templates/Workspace/azuredeploy.json" `
    -workspaceName "Security-Workspace" `
    -location "EastUS"

# Connect data sources
# Connect Azure Activity
New-AzSentinelDataConnector -ResourceGroupName "Security-RG" `
    -WorkspaceName "Security-Workspace" `
    -AzureActivity -SubscriptionId (Get-AzContext).Subscription.Id

# Connect Security Center
New-AzSentinelDataConnector -ResourceGroupName "Security-RG" `
    -WorkspaceName "Security-Workspace" `
    -ASC -SubscriptionId (Get-AzContext).Subscription.Id

# Deploy security playbooks
New-AzResourceGroupDeployment `
    -ResourceGroupName "Security-RG" `
    -TemplateUri "https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Playbooks/Block-AADUser/azuredeploy.json" `
    -PlaybookName "BlockCompromisedUser"
Azure Monitor Security Configuration:

json
{
  "type": "Microsoft.Insights/activityLogAlerts",
  "apiVersion": "2020-10-01",
  "name": "SecurityEventAlert",
  "location": "global",
  "properties": {
    "scopes": ["/subscriptions/{subscription-id}"],
    "condition": {
      "allOf": [
        {
          "field": "category",
          "equals": "Security"
        },
        {
          "field": "operationName",
          "equals": "Microsoft.Security/detections"
        }
      ]
    },
    "actions": {
      "actionGroups": [
        {
          "actionGroupId": "/subscriptions/{subscription-id}/resourceGroups/{resource-group}/providers/microsoft.insights/actionGroups/{action-group}"
        }
      ]
    },
    "enabled": true,
    "description": "Alert for security events"
  }
}
GCP Security Architecture
🔐 Google Cloud IAM & Identity
GCP IAM Best Practices:

bash
#!/bin/bash
# gcp_iam_setup.sh

# Enable Cloud Identity
gcloud alpha identity groups create --organization=example.com \
  --labels=cloudidentity.googleapis.com/groups.discussion_forum

# Create custom IAM role
gcloud iam roles create SecurityAuditor \
  --project=my-project \
  --title="Security Auditor" \
  --description="Role for security auditing" \
  --permissions="compute.instances.list,storage.buckets.get,logging.logEntries.list"

# Assign IAM roles with conditions
gcloud projects add-iam-policy-binding my-project \
  --member="user:security@example.com" \
  --role="roles/viewer" \
  --condition='expression=request.time < timestamp("2024-12-31T23:59:59Z"),title=expires_end_of_2024'

# Configure Organization Policies
gcloud resource-manager org-policies enable-enforce compute.requireOsLogin \
  --organization=123456789012

# Set up Service Account with least privilege
gcloud iam service-accounts create app-service-account \
  --display-name="Application Service Account"

gcloud projects add-iam-policy-binding my-project \
  --member="serviceAccount:app-service-account@my-project.iam.gserviceaccount.com" \
  --role="roles/storage.objectViewer"
GCP Identity-Aware Proxy (IAP):

bash
# Enable IAP on App Engine
gcloud iap web enable --resource-type=app-engine

# Create IAP access policy
gcloud iap web set-iam-policy my-project \
  --policy=iap_policy.yaml

# Configure IAP TCP forwarding
gcloud compute firewall-rules create allow-iap-tcp \
  --direction=INGRESS \
  --action=allow \
  --rules=tcp:22,tcp:3389 \
  --source-ranges=35.235.240.0/20
🛡️ GCP Network Security
VPC Service Controls & Firewall Rules:

bash
#!/bin/bash
# gcp_network_security.sh

# Create VPC with subnet
gcloud compute networks create secure-vpc \
  --subnet-mode=custom

gcloud compute networks subnets create secure-subnet \
  --network=secure-vpc \
  --range=10.0.0.0/24 \
  --region=us-central1 \
  --enable-private-ip-google-access

# Configure firewall rules
gcloud compute firewall-rules create allow-iap-ingress \
  --network=secure-vpc \
  --allow=tcp:22,tcp:3389 \
  --source-ranges=35.235.240.0/20 \
  --direction=INGRESS

gcloud compute firewall-rules create deny-all-ingress \
  --network=secure-vpc \
  --deny=all \
  --direction=INGRESS \
  --priority=65534

# Enable VPC Flow Logs
gcloud compute networks subnets update secure-subnet \
  --region=us-central1 \
  --enable-flow-logs

# Configure Cloud Armor
gcloud compute security-policies create waf-policy \
  --description="WAF policy for web applications"

gcloud compute security-policies rules create 1000 \
  --security-policy=waf-policy \
  --expression="eval(request.path) = '/admin'" \
  --action=deny-403

gcloud compute security-policies rules create 2000 \
  --security-policy=waf-policy \
  --expression="src.ip.geoip.country in ('CN', 'RU')" \
  --action=deny-403
Google Cloud Armor WAF Rules:

yaml
# security-policy.yaml
name: waf-policy
rules:
  - action: deny
    priority: 1000
    match:
      expr:
        expression: "request.path.matches('/admin.*')"
    description: "Block admin access"
  
  - action: rate_based_ban
    priority: 2000
    match:
      expr:
        expression: "true"
    rateLimitOptions:
      rateLimitThreshold:
        count: 100
        intervalSec: 60
      conformAction: allow
      exceedAction: deny
    description: "Rate limiting"
  
  - action: allow
    priority: 2147483647
    match:
      expr:
        expression: "true"
    description: "Default allow rule"
📊 GCP Security Monitoring
Cloud Security Command Center:

bash
#!/bin/bash
# gcp_security_monitoring.sh

# Enable Security Command Center
gcloud services enable securitycenter.googleapis.com

# Configure SCC organization settings
gcloud scc settings update \
  --organization=123456789012 \
  --enable-asset-discovery

# Create notification configs
gcloud scc notifications create scc-notifications \
  --organization=123456789012 \
  --description="Security findings notifications" \
  --pubsub-topic=projects/my-project/topics/security-alerts

# Enable Security Health Analytics
gcloud scc settings sh enable \
  --organization=123456789012

# Export findings to BigQuery
gcloud scc findings list \
  --organization=123456789012 \
  --filter="state=\"ACTIVE\"" \
  --format=json | bq load --autodetect security.findings
Cloud Audit Logging Configuration:

bash
# Configure log sinks
gcloud logging sinks create security-logs \
  bigquery.googleapis.com/projects/my-project/datasets/audit_logs \
  --log-filter='logName:"cloudaudit.googleapis.com"'

# Set up log-based metrics
gcloud logging metrics create failed-auth-attempts \
  --description="Count of failed authentication attempts" \
  --log-filter='resource.type="gce_instance" AND jsonPayload.message:"Authentication failed"'

# Configure alerting policies
gcloud alpha monitoring policies create \
  --policy-from-file=alert_policy.json
Cloud Identity & Access Management
🔑 Multi-Cloud IAM Strategy
Identity Federation Configuration:

yaml
# AWS SSO with Azure AD
AWSSSO:
  IdentityStore: AWS SSO
  IdentitySource: Azure AD
  PermissionSets:
    - Name: ReadOnly
      Policy: arn:aws:iam::aws:policy/ReadOnlyAccess
    - Name: PowerUser
      Policy: arn:aws:iam::aws:policy/PowerUserAccess
  
AzureAD:
  EnterpriseApps:
    - Name: AWS
      SSOConfiguration:
        SAML: Enabled
        Claims:
          - Name: https://aws.amazon.com/SAML/Attributes/Role
            Value: "arn:aws:iam::123456789012:saml-provider/AzureAD,arn:aws:iam::123456789012:role/AWS-ReadOnly"
Just-In-Time Access Implementation:

python
# JIT Access Manager
import boto3
import datetime
from typing import Dict, List

class JITAccessManager:
    def __init__(self):
        self.iam = boto3.client('iam')
        self.sns = boto3.client('sns')
        
    def request_access(self, user: str, role: str, duration: int, reason: str):
        """Request temporary elevated access"""
        # Create temporary role assumption
        response = self.iam.assume_role(
            RoleArn=f"arn:aws:iam::123456789012:role/{role}",
            RoleSessionName=user,
            DurationSeconds=duration * 3600
        )
        
        # Log the access request
        self.log_access_request(user, role, duration, reason)
        
        # Notify security team
        self.sns.publish(
            TopicArn='arn:aws:sns:us-east-1:123456789012:Security-Alerts',
            Message=f"JIT Access granted: {user} to {role} for {duration}h"
        )
        
        return response['Credentials']
    
    def log_access_request(self, user: str, role: str, duration: int, reason: str):
        """Log all access requests for audit"""
        with open('/var/log/jit_access.log', 'a') as f:
            timestamp = datetime.datetime.now().isoformat()
            f.write(f"{timestamp},{user},{role},{duration},{reason}\n")
🔐 Secrets Management
AWS Secrets Manager Configuration:

python
import boto3
import json
from cryptography.fernet import Fernet

class SecretsManager:
    def __init__(self):
        self.client = boto3.client('secretsmanager')
        self.kms = boto3.client('kms')
        
    def create_secret(self, name: str, secret_value: Dict):
        """Create a new secret with rotation"""
        response = self.client.create_secret(
            Name=name,
            SecretString=json.dumps(secret_value),
            Description=f"Application secret for {name}",
            KmsKeyId='alias/aws/secretsmanager',
            RotationRules={
                'AutomaticallyAfterDays': 30
            },
            RotationLambdaARN='arn:aws:lambda:us-east-1:123456789012:function:rotateSecret'
        )
        return response
    
    def get_secret(self, name: str):
        """Retrieve and decrypt secret"""
        response = self.client.get_secret_value(SecretId=name)
        return json.loads(response['SecretString'])
    
    def rotate_secret(self, name: str):
        """Manual secret rotation"""
        response = self.client.rotate_secret(SecretId=name)
        return response
Azure Key Vault Implementation:

powershell
# Create Key Vault with access policies
$keyVault = New-AzKeyVault `
    -Name "prod-keyvault" `
    -ResourceGroupName "Security-RG" `
    -Location "EastUS" `
    -EnabledForDiskEncryption `
    -EnabledForTemplateDeployment `
    -EnabledForDeployment `
    -SoftDeleteRetentionInDays 90 `
    -EnablePurgeProtection

# Set access policies
Set-AzKeyVaultAccessPolicy `
    -VaultName "prod-keyvault" `
    -UserPrincipalName "admin@example.com" `
    -PermissionsToSecrets get,list,set,delete

# Create secrets
$secretValue = ConvertTo-SecureString "MySecretPassword" -AsPlainText -Force
Set-AzKeyVaultSecret `
    -VaultName "prod-keyvault" `
    -Name "DatabasePassword" `
    -SecretValue $secretValue `
    -ContentType "text/plain" `
    -Expires (Get-Date).AddDays(90) `
    -NotBefore (Get-Date)

# Configure automatic rotation
$rotationPolicy = @{
    lifetimeActions = @(
        @{
            action = @{ type = "Rotate" }
            trigger = @{ timeAfterCreate = "P90D" }
        }
    )
    attributes = @{ enabled = $true }
}

Set-AzKeyVaultSecretRotationPolicy `
    -VaultName "prod-keyvault" `
    -Name "DatabasePassword" `
    -Policy $rotationPolicy
Network Security in Cloud
🌐 Cloud Network Architecture
Hub-and-Spoke Model Implementation:

terraform
# Terraform for hub-and-spoke architecture
resource "azurerm_virtual_network" "hub" {
  name                = "hub-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.security.location
  resource_group_name = azurerm_resource_group.security.name
}

resource "azurerm_virtual_network" "spoke1" {
  name                = "spoke1-vnet"
  address_space       = ["10.1.0.0/16"]
  location            = azurerm_resource_group.security.location
  resource_group_name = azurerm_resource_group.security.name
}

resource "azurerm_virtual_network_peering" "hub_to_spoke1" {
  name                      = "hub-to-spoke1"
  resource_group_name       = azurerm_resource_group.security.name
  virtual_network_name      = azurerm_virtual_network.hub.name
  remote_virtual_network_id = azurerm_virtual_network.spoke1.id
  
  allow_virtual_network_access = true
  allow_forwarded_traffic      = true
  allow_gateway_transit        = true
  use_remote_gateways          = false
}

resource "azurerm_firewall" "hub_firewall" {
  name                = "hub-firewall"
  location            = azurerm_resource_group.security.location
  resource_group_name = azurerm_resource_group.security.name
  sku_name            = "AZFW_VNet"
  sku_tier            = "Standard"
  
  ip_configuration {
    name                 = "configuration"
    subnet_id            = azurerm_subnet.firewall.id
    public_ip_address_id = azurerm_public_ip.firewall.id
  }
}
Transit Gateway Architecture:

yaml
# AWS Transit Gateway configuration
TransitGateway:
  Description: "Central network transit"
  AmazonSideAsn: 64512
  AutoAcceptSharedAttachments: disable
  DefaultRouteTableAssociation: disable
  DefaultRouteTablePropagation: disable
  VpnEcmpSupport: enable
  DnsSupport: enable
  
Attachments:
  - VpcId: vpc-12345678
    SubnetIds: [subnet-123, subnet-456]
    
RouteTables:
  - Name: "Security-VPC-Routes"
    Routes:
      - DestinationCidrBlock: "0.0.0.0/0"
        TransitGatewayAttachmentId: "tgw-attach-123"
🛡️ Cloud Web Application Firewall
Multi-Cloud WAF Configuration:

python
class CloudWAFManager:
    def __init__(self):
        self.waf_clients = {
            'aws': boto3.client('wafv2'),
            'azure': self._get_azure_waf_client(),
            'gcp': self._get_gcp_waf_client()
        }
    
    def deploy_waf_rules(self, rules: List[Dict]):
        """Deploy consistent WAF rules across clouds"""
        for cloud, client in self.waf_clients.items():
            for rule in rules:
                if cloud == 'aws':
                    self._deploy_aws_waf_rule(client, rule)
                elif cloud == 'azure':
                    self._deploy_azure_waf_rule(client, rule)
                elif cloud == 'gcp':
                    self._deploy_gcp_waf_rule(client, rule)
    
    def _deploy_aws_waf_rule(self, client, rule):
        """Deploy rule to AWS WAF"""
        response = client.create_rule_group(
            Name=rule['name'],
            Scope='REGIONAL',
            Capacity=100,
            Rules=[
                {
                    'Name': rule['name'],
                    'Priority': rule['priority'],
                    'Statement': {
                        'ManagedRuleGroupStatement': {
                            'VendorName': 'AWS',
                            'Name': rule['rule_set']
                        }
                    },
                    'Action': {'Block': {}},
                    'VisibilityConfig': {
                        'SampledRequestsEnabled': True,
                        'CloudWatchMetricsEnabled': True,
                        'MetricName': rule['name']
                    }
                }
            ],
            VisibilityConfig={
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': rule['name']
            }
        )
        return response
Data Protection & Encryption
🔐 Encryption Implementation
AWS KMS Configuration:

python
import boto3
from cryptography.fernet import Fernet
import base64

class KMSEncryptionManager:
    def __init__(self):
        self.kms = boto3.client('kms')
        self.key_id = 'alias/prod-encryption-key'
    
    def generate_data_key(self, key_spec='AES_256'):
        """Generate data encryption key"""
        response = self.kms.generate_data_key(
            KeyId=self.key_id,
            KeySpec=key_spec
        )
        return {
            'plaintext': response['Plaintext'],
            'ciphertext': response['CiphertextBlob']
        }
    
    def encrypt_data(self, data: bytes):
        """Encrypt data using KMS"""
        data_key = self.generate_data_key()
        
        # Use Fernet symmetric encryption
        f = Fernet(base64.urlsafe_b64encode(data_key['plaintext']))
        encrypted_data = f.encrypt(data)
        
        return {
            'encrypted_data': encrypted_data,
            'encrypted_key': data_key['ciphertext']
        }
    
    def decrypt_data(self, encrypted_data: bytes, encrypted_key: bytes):
        """Decrypt data using KMS"""
        # Decrypt the data key
        response = self.kms.decrypt(CiphertextBlob=encrypted_key)
        plaintext_key = response['Plaintext']
        
        # Use Fernet to decrypt data
        f = Fernet(base64.urlsafe_b64encode(plaintext_key))
        decrypted_data = f.decrypt(encrypted_data)
        
        return decrypted_data
Azure Encryption Configuration:

powershell
# Enable encryption for Storage Account
$storageAccount = New-AzStorageAccount `
    -ResourceGroupName "Security-RG" `
    -Name "securestorage" `
    -Location "EastUS" `
    -SkuName Standard_LRS `
    -Kind StorageV2 `
    -EnableHttpsTrafficOnly $true `
    -AllowBlobPublicAccess $false `
    -MinimumTlsVersion TLS1_2

# Enable encryption at rest
Set-AzStorageAccount `
    -ResourceGroupName "Security-RG" `
    -AccountName "securestorage" `
    -EncryptionKeyType "Microsoft.Storage" `
    -EncryptionKeySource "Microsoft.Storage" `
    -RequireInfrastructureEncryption

# Enable encryption for Managed Disks
$diskConfig = New-AzDiskConfig `
    -Location "EastUS" `
    -CreateOption Empty `
    -DiskSizeGB 128 `
    -EncryptionType EncryptionAtRestWithPlatformKey `
    -HyperVGeneration V2

New-AzDisk `
    -ResourceGroupName "Security-RG" `
    -DiskName "encrypted-disk" `
    -Disk $diskConfig
💾 Data Loss Prevention
AWS Macie Configuration:

bash
#!/bin/bash
# aws_macie_setup.sh

# Enable Macie
aws macie2 enable-macie --status ENABLED

# Create classification job
aws macie2 create-classification-job \
  --job-type ONE_TIME \
  --name "S3-PII-Scan" \
  --s3-job-definition '{
    "bucketDefinitions": [
      {
        "accountId": "123456789012",
        "buckets": ["customer-data", "user-uploads"]
      }
    ],
    "scoping": {
      "excludes": {
        "and": [
          {
            "simpleScopeTerm": {
              "comparator": "EQ",
              "key": "OBJECT_EXTENSION",
              "values": ["jpg", "png", "gif"]
            }
          }
        ]
      }
    }
  }' \
  --sampling-percentage 100

# Configure findings
aws macie2 update-findings-filter \
  --id "pii-findings" \
  --action ARCHIVE \
  --finding-criteria '{
    "criterion": {
      "category": {
        "eq": ["PII"]
      },
      "severity": {
        "gte": "HIGH"
      }
    }
  }'
Google Cloud DLP:

python
from google.cloud import dlp_v2

class DLPManager:
    def __init__(self):
        self.client = dlp_v2.DlpServiceClient()
    
    def inspect_content(self, content: str, info_types: List[str]):
        """Inspect content for sensitive data"""
        parent = f"projects/my-project"
        
        # Construct inspection config
        inspect_config = {
            "info_types": [{"name": info_type} for info_type in info_types],
            "min_likelihood": dlp_v2.Likelihood.POSSIBLE,
            "limits": {"max_findings_per_request": 100}
        }
        
        # Construct item
        item = {"value": content}
        
        # Call the API
        response = self.client.inspect_content(
            request={"parent": parent, "inspect_config": inspect_config, "item": item}
        )
        
        return response.result.findings
    
    def deidentify_content(self, content: str, info_types: List[str]):
        """De-identify sensitive data"""
        parent = f"projects/my-project"
        
        # Construct de-identification config
        deidentify_config = {
            "info_type_transformations": {
                "transformations": [
                    {
                        "primitive_transformation": {
                            "replace_config": {
                                "new_value": {"string_value": "[REDACTED]"}
                            }
                        }
                    }
                ]
            }
        }
        
        # Construct inspection config
        inspect_config = {
            "info_types": [{"name": info_type} for info_type in info_types]
        }
        
        # Call the API
        response = self.client.deidentify_content(
            request={
                "parent": parent,
                "deidentify_config": deidentify_config,
                "inspect_config": inspect_config,
                "item": {"value": content}
            }
        )
        
        return response.result.item.value
Container & Serverless Security
🐳 Container Security
Docker Security Scanning:

bash
#!/bin/bash
# container_security_scan.sh

# Scan Docker images for vulnerabilities
docker scan nginx:latest

# Build secure Docker images
docker build \
  --tag secure-app:latest \
  --file Dockerfile.secure \
  --build-arg BUILDKIT_PROGRESS=plain \
  --security-opt seccomp=/path/to/seccomp.json \
  .

# Run container with security constraints
docker run -d \
  --name secure-container \
  --read-only \
  --security-opt=no-new-privileges \
  --cap-drop=ALL \
  --cap-add=NET_BIND_SERVICE \
  --memory=512m \
  --pids-limit=100 \
  --user=1000:1000 \
  secure-app:latest

# Check running container security
docker inspect secure-container --format='{{.HostConfig.SecurityOpt}}'
docker exec secure-container cat /proc/self/status | grep -E "NoNewPriv|Seccomp"
Kubernetes Security Context:

yaml
# pod-security.yaml
apiVersion: v1
kind: Pod
metadata:
  name: security-context-demo
spec:
  securityContext:
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: sec-ctx-demo
    image: nginx
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
        - ALL
      readOnlyRootFilesystem: true
      privileged: false
⚡ Serverless Security
AWS Lambda Security Configuration:

python
import json
import boto3
from botocore.exceptions import ClientError

class LambdaSecurity:
    def __init__(self):
        self.lambda_client = boto3.client('lambda')
        self.iam_client = boto3.client('iam')
    
    def create_secure_function(self, function_name: str, role_arn: str):
        """Create Lambda function with security best practices"""
        response = self.lambda_client.create_function(
            FunctionName=function_name,
            Runtime='python3.9',
            Role=role_arn,
            Handler='lambda_function.lambda_handler',
            Code={'ZipFile': open('function.zip', 'rb').read()},
            Description='Secure Lambda function',
            Timeout=30,
            MemorySize=256,
            Publish=True,
            VpcConfig={
                'SubnetIds': ['subnet-123', 'subnet-456'],
                'SecurityGroupIds': ['sg-789']
            },
            Environment={
                'Variables': {
                    'ENVIRONMENT': 'production'
                }
            },
            TracingConfig={'Mode': 'Active'},
            Layers=[
                'arn:aws:lambda:us-east-1:123456789012:layer:security-layer:1'
            ],
            FileSystemConfigs=[
                {
                    'Arn': 'arn:aws:elasticfilesystem:us-east-1:123456789012:access-point/fsap-12345678',
                    'LocalMountPath': '/mnt/efs'
                }
            ],
            ImageConfig={
                'EntryPoint': ['/lambda-entrypoint.sh'],
                'Command': ['app.handler'],
                'WorkingDirectory': '/var/task'
            },
            PackageType='Image'
        )
        return response
    
    def enable_runtime_management(self, function_name: str):
        """Enable runtime management controls"""
        response = self.lambda_client.put_function_event_invoke_config(
            FunctionName=function_name,
            MaximumRetryAttempts=2,
            MaximumEventAgeInSeconds=3600,
            DestinationConfig={
                'OnSuccess': {
                    'Destination': 'arn:aws:sqs:us-east-1:123456789012:success-queue'
                },
                'OnFailure': {
                    'Destination': 'arn:aws:sqs:us-east-1:123456789012:error-queue'
                }
            }
        )
        return response
Azure Functions Security:

json
{
  "bindings": [
    {
      "authLevel": "function",
      "type": "httpTrigger",
      "direction": "in",
      "name": "req",
      "methods": ["get", "post"]
    }
  ],
  "scriptFile": "../dist/FunctionApp/index.js",
  "disabled": false
}
powershell
# Configure Azure Functions security
$functionApp = Get-AzFunctionApp -Name "secure-function-app"

# Enable Managed Identity
Update-AzFunctionApp -Name $functionApp.Name `
  -ResourceGroupName $functionApp.ResourceGroupName `
  -IdentityType SystemAssigned

# Configure authentication
$authSettings = @{
  enabled = $true
  runtimeVersion = "~1"
  unauthenticatedClientAction = "RedirectToLoginPage"
  tokenStoreEnabled = $true
  allowedExternalRedirectUrls = @("https://myapp.com")
  defaultProvider = "AzureActiveDirectory"
  clientId = $clientId
  clientSecret = $clientSecret
  issuer = "https://sts.windows.net/{tenant-id}/"
}

Update-AzFunctionApp -Name $functionApp.Name `
  -ResourceGroupName $functionApp.ResourceGroupName `
  -AuthenticationSettings $authSettings
Cloud Monitoring & Logging
📊 Centralized Logging Architecture
Multi-Cloud Log Aggregation:

python
import boto3
from google.cloud import logging
from azure.monitor import LogAnalyticsDataClient
from datetime import datetime, timedelta

class CloudLogAggregator:
    def __init__(self):
        self.cloudwatch = boto3.client('logs')
        self.stackdriver = logging.Client()
        self.log_analytics = LogAnalyticsDataClient()
    
    def aggregate_logs(self, time_range: timedelta):
        """Aggregate logs from all cloud providers"""
        logs = {
            'aws': self._get_cloudwatch_logs(time_range),
            'gcp': self._get_stackdriver_logs(time_range),
            'azure': self._get_log_analytics_logs(time_range)
        }
        
        # Process and analyze logs
        security_events = self._analyze_security_events(logs)
        
        return {
            'total_logs': sum(len(l) for l in logs.values()),
            'security_events': security_events,
            'raw_logs': logs
        }
    
    def _get_cloudwatch_logs(self, time_range):
        """Retrieve CloudWatch logs"""
        end_time = datetime.now()
        start_time = end_time - time_range
        
        response = self.cloudwatch.filter_log_events(
            logGroupName='/aws/security/events',
            startTime=int(start_time.timestamp() * 1000),
            endTime=int(end_time.timestamp() * 1000),
            filterPattern='{ $.eventType = "AWSConsoleSignIn" }'
        )
        
        return response['events']
    
    def _analyze_security_events(self, logs):
        """Analyze logs for security events"""
        security_events = []
        
        for cloud_provider, log_entries in logs.items():
            for entry in log_entries:
                if self._is_security_event(entry):
                    security_events.append({
                        'provider': cloud_provider,
                        'timestamp': entry.get('timestamp'),
                        'event': entry.get('message'),
                        'severity': self._determine_severity(entry)
                    })
        
        return security_events
🚨 Cloud Security Alerts
Automated Alert Configuration:

yaml
# alert-configuration.yaml
alerts:
  - name: "UnauthorizedAccessAttempt"
    description: "Multiple failed login attempts"
    providers:
      aws:
        source: "CloudTrail"
        filter: "eventName = ConsoleLogin AND errorMessage = 'Failed authentication'"
        threshold: 5
        period: "5 minutes"
        
      azure:
        source: "AzureAD"
        filter: "Category eq 'SignInLogs' and ResultType eq '50057'"
        threshold: 3
        period: "10 minutes"
        
      gcp:
        source: "CloudAudit"
        filter: "protoPayload.methodName='google.login.LoginService.loginFailed'"
        threshold: 5
        period: "5 minutes"
    
    actions:
      - type: "email"
        recipients: ["security-team@example.com"]
      
      - type: "slack"
        webhook: "https://hooks.slack.com/services/..."
        channel: "#security-alerts"
      
      - type: "ticket"
        system: "Jira"
        project: "SEC"
        issue_type: "Incident"
    
    escalation:
      after: "30 minutes"
      recipients: ["security-manager@example.com"]
Cloud Compliance & Governance
📋 Compliance Automation
Automated Compliance Scanning:

python
import boto3
import pandas as pd
from typing import Dict, List

class ComplianceScanner:
    def __init__(self):
        self.config_client = boto3.client('config')
        self.securityhub = boto3.client('securityhub')
    
    def run_compliance_scan(self, standards: List[str]) -> Dict:
        """Run compliance scan against specified standards"""
        results = {}
        
        for standard in standards:
            if standard == 'CIS':
                results['CIS'] = self._scan_cis_compliance()
            elif standard == 'PCI':
                results['PCI'] = self._scan_pci_compliance()
            elif standard == 'HIPAA':
                results['HIPAA'] = self._scan_hipaa_compliance()
            elif standard == 'GDPR':
                results['GDPR'] = self._scan_gdpr_compliance()
        
        # Generate compliance report
        report = self._generate_compliance_report(results)
        
        return report
    
    def _scan_cis_compliance(self) -> Dict:
        """Scan for CIS AWS Foundations Benchmark compliance"""
        rules = [
            'cloudtrail-enabled',
            'cloudtrail-encryption-enabled',
            'cloudtrail-log-file-validation-enabled',
            'cloudtrail-multi-region-enabled'
        ]
        
        compliance_results = {}
        
        for rule in rules:
            response = self.config_client.describe_config_rules(
                ConfigRuleNames=[rule]
            )
            
            evaluation_results = self.config_client.get_compliance_details_by_config_rule(
                ConfigRuleName=rule,
                ComplianceTypes=['NON_COMPLIANT']
            )
            
            compliance_results[rule] = {
                'status': 'COMPLIANT' if not evaluation_results['EvaluationResults'] else 'NON_COMPLIANT',
                'violations': len(evaluation_results['EvaluationResults'])
            }
        
        return compliance_results
    
    def _generate_compliance_report(self, results: Dict) -> pd.DataFrame:
        """Generate comprehensive compliance report"""
        report_data = []
        
        for standard, standard_results in results.items():
            for rule, rule_results in standard_results.items():
                report_data.append({
                    'Standard': standard,
                    'Rule': rule,
                    'Status': rule_results['status'],
                    'Violations': rule_results['violations'],
                    'Timestamp': pd.Timestamp.now()
                })
        
        df = pd.DataFrame(report_data)
        
        # Calculate compliance scores
        compliance_score = (df['Status'] == 'COMPLIANT').mean() * 100
        
        return {
            'report': df,
            'summary': {
                'total_rules': len(df),
                'compliant_rules': (df['Status'] == 'COMPLIANT').sum(),
                'non_compliant_rules': (df['Status'] == 'NON_COMPLIANT').sum(),
                'compliance_score': f"{compliance_score:.2f}%"
            }
        }
🏛️ Cloud Governance Framework
Policy as Code Implementation:

python
import yaml
import json
from typing import Dict, Any

class CloudGovernance:
    def __init__(self, policy_file: str):
        with open(policy_file, 'r') as f:
            self.policies = yaml.safe_load(f)
    
    def validate_resource(self, resource_type: str, resource_config: Dict) -> Dict:
        """Validate resource against governance policies"""
        violations = []
        
        if resource_type in self.policies['resource_policies']:
            policy = self.policies['resource_policies'][resource_type]
            
            # Check required tags
            if 'required_tags' in policy:
                for tag in policy['required_tags']:
                    if tag not in resource_config.get('tags', {}):
                        violations.append(f"Missing required tag: {tag}")
            
            # Check configuration rules
            if 'configuration_rules' in policy:
                for rule_name, rule in policy['configuration_rules'].items():
                    if not self._evaluate_rule(rule, resource_config):
                        violations.append(f"Violates configuration rule: {rule_name}")
        
        return {
            'resource_type': resource_type,
            'resource_name': resource_config.get('name'),
            'compliant': len(violations) == 0,
            'violations': violations,
            'timestamp': json.dumps(pd.Timestamp.now(), default=str)
        }
    
    def _evaluate_rule(self, rule: Dict, resource_config: Dict) -> bool:
        """Evaluate a single governance rule"""
        rule_type = rule.get('type')
        
        if rule_type == 'property_equals':
            path = rule['property_path']
            expected_value = rule['expected_value']
            actual_value = self._get_nested_value(resource_config, path)
            return actual_value == expected_value
        
        elif rule_type == 'property_in_list':
            path = rule['property_path']
            allowed_values = rule['allowed_values']
            actual_value = self._get_nested_value(resource_config, path)
            return actual_value in allowed_values
        
        elif rule_type == 'regex_match':
            path = rule['property_path']
            pattern = rule['pattern']
            actual_value = self._get_nested_value(resource_config, path)
            import re
            return bool(re.match(pattern, str(actual_value)))
        
        return True
    
    def _get_nested_value(self, obj: Dict, path: str) -> Any:
        """Get nested value from dictionary using dot notation"""
        keys = path.split('.')
        current = obj
        
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        
        return current
Multi-Cloud Security Strategy
🌍 Multi-Cloud Security Architecture
Unified Security Dashboard:

python
import dash
from dash import dcc, html
import plotly.graph_objects as go
from datetime import datetime, timedelta

class UnifiedSecurityDashboard:
    def __init__(self):
        self.app = dash.Dash(__name__)
        self.security_data = self._collect_security_data()
        
    def create_dashboard(self):
        """Create unified security dashboard"""
        self.app.layout = html.Div([
            html.H1('Multi-Cloud Security Dashboard'),
            
            # Security Score Cards
            html.Div([
                html.Div([
                    html.H3('Overall Security Score'),
                    html.H2(f"{self._calculate_security_score()}%", 
                           style={'color': 'green' if self._calculate_security_score() > 90 else 'orange'})
                ], className='score-card'),
                
                html.Div([
                    html.H3('Open Vulnerabilities'),
                    html.H2(f"{self._count_vulnerabilities()}", 
                           style={'color': 'red' if self._count_vulnerabilities() > 10 else 'green'})
                ], className='score-card'),
                
                html.Div([
                    html.H3('Compliance Status'),
                    html.H2(f"{self._calculate_compliance_score()}%", 
                           style={'color': 'green' if self._calculate_compliance_score() > 95 else 'orange'})
                ], className='score-card')
            ], className='score-row'),
            
            # Security Events Timeline
            dcc.Graph(
                id='security-events-timeline',
                figure=self._create_timeline_chart()
            ),
            
            # Cloud Provider Comparison
            dcc.Graph(
                id='cloud-provider-comparison',
                figure=self._create_provider_comparison_chart()
            ),
            
            # Real-time Alerts
            html.Div([
                html.H3('Recent Security Alerts'),
                html.Ul([
                    html.Li(alert) for alert in self._get_recent_alerts()
                ])
            ])
        ])
        
        return self.app
    
    def _collect_security_data(self):
        """Collect security data from all cloud providers"""
        data = {
            'aws': self._get_aws_security_data(),
            'azure': self._get_azure_security_data(),
            'gcp': self._get_gcp_security_data()
        }
        return data
    
    def _calculate_security_score(self):
        """Calculate overall security score"""
        scores = []
        for provider, data in self.security_data.items():
            if 'security_score' in data:
                scores.append(data['security_score'])
        
        return sum(scores) / len(scores) if scores else 0
    
    def _create_timeline_chart(self):
        """Create timeline chart of security events"""
        fig = go.Figure()
        
        for provider, data in self.security_data.items():
            if 'security_events' in data:
                events = data['security_events']
                timestamps = [e['timestamp'] for e in events]
                counts = [e['count'] for e in events]
                
                fig.add_trace(go.Scatter(
                    x=timestamps,
                    y=counts,
                    mode='lines+markers',
                    name=provider.upper()
                ))
        
        fig.update_layout(
            title='Security Events Timeline',
            xaxis_title='Time',
            yaxis_title='Number of Events'
        )
        
        return fig
🔄 Cloud Security Automation
Infrastructure as Code Security:

python
import terraform
import pulumi
import boto3
from typing import Dict, List

class IaCSecurityScanner:
    def __init__(self):
        self.terraform = terraform.Terraform()
        self.pulumi = pulumi.automation.LocalWorkspace()
        
    def scan_terraform_files(self, directory: str) -> Dict:
        """Scan Terraform files for security issues"""
        issues = []
        
        # Parse Terraform files
        tf_files = self._find_terraform_files(directory)
        
        for tf_file in tf_files:
            with open(tf_file, 'r') as f:
                content = f.read()
                
                # Check for hardcoded secrets
                if self._contains_hardcoded_secrets(content):
                    issues.append({
                        'file': tf_file,
                        'issue': 'Hardcoded secrets found',
                        'severity': 'HIGH'
                    })
                
                # Check for insecure configurations
                if self._has_insecure_configurations(content):
                    issues.append({
                        'file': tf_file,
                        'issue': 'Insecure configuration detected',
                        'severity': 'MEDIUM'
                    })
        
        return {
            'total_files': len(tf_files),
            'issues_found': len(issues),
            'issues': issues
        }
    
    def _contains_hardcoded_secrets(self, content: str) -> bool:
        """Check for hardcoded secrets in content"""
        secret_patterns = [
            r'password\s*=\s*["\'].*["\']',
            r'secret\s*=\s*["\'].*["\']',
            r'token\s*=\s*["\'].*["\']',
            r'aws_access_key\s*=\s*["\'].*["\']',
            r'aws_secret_key\s*=\s*["\'].*["\']'
        ]
        
        import re
        for pattern in secret_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False
    
    def _has_insecure_configurations(self, content: str) -> bool:
        """Check for insecure configurations"""
        insecure_patterns = [
            r'publicly_accessible\s*=\s*true',
            r'encrypted\s*=\s*false',
            r'allow_major_version_upgrade\s*=\s*true'
        ]
        
        import re
        for pattern in insecure_patterns:
            if re.search(pattern, content):
                return True
        
        return False
Incident Response in Cloud
🚨 Cloud Incident Response Plan
Automated Incident Response Framework:

python
import boto3
from azure.mgmt.security import SecurityCenter
from google.cloud import securitycenter
from datetime import datetime
from typing import Dict, List

class CloudIncidentResponse:
    def __init__(self):
        self.aws_client = boto3.client('securityhub')
        self.azure_client = SecurityCenter()
        self.gcp_client = securitycenter.SecurityCenterClient()
        
    def handle_security_incident(self, incident: Dict):
        """Handle security incident across cloud providers"""
        # Step 1: Triage incident
        severity = incident.get('severity', 'MEDIUM')
        affected_resources = incident.get('affected_resources', [])
        
        # Step 2: Execute containment actions
        containment_actions = self._execute_containment(affected_resources)
        
        # Step 3: Collect forensic data
        forensic_data = self._collect_forensic_data(affected_resources)
        
        # Step 4: Notify stakeholders
        self._notify_stakeholders(incident, severity)
        
        # Step 5: Begin remediation
        remediation_actions = self._execute_remediation(affected_resources)
        
        # Step 6: Document incident
        incident_report = self._create_incident_report(
            incident, 
            containment_actions, 
            forensic_data, 
            remediation_actions
        )
        
        return incident_report
    
    def _execute_containment(self, resources: List[Dict]) -> List[Dict]:
        """Execute containment actions"""
        actions = []
        
        for resource in resources:
            provider = resource.get('provider')
            resource_id = resource.get('id')
            resource_type = resource.get('type')
            
            if provider == 'aws':
                if resource_type == 'ec2-instance':
                    # Stop the instance
                    ec2 = boto3.client('ec2')
                    ec2.stop_instances(InstanceIds=[resource_id])
                    actions.append({
                        'action': 'stopped_instance',
                        'resource': resource_id,
                        'timestamp': datetime.now().isoformat()
                    })
                
                elif resource_type == 's3-bucket':
                    # Make bucket private
                    s3 = boto3.client('s3')
                    s3.put_public_access_block(
                        Bucket=resource_id,
                        PublicAccessBlockConfiguration={
                            'BlockPublicAcls': True,
                            'IgnorePublicAcls': True,
                            'BlockPublicPolicy': True,
                            'RestrictPublicBuckets': True
                        }
                    )
                    actions.append({
                        'action': 'blocked_public_access',
                        'resource': resource_id,
                        'timestamp': datetime.now().isoformat()
                    })
            
            # Similar actions for Azure and GCP...
        
        return actions
    
    def _create_incident_report(self, incident: Dict, containment: List, 
                               forensic: Dict, remediation: List) -> Dict:
        """Create comprehensive incident report"""
        return {
            'incident_id': incident.get('id'),
            'title': incident.get('title'),
            'description': incident.get('description'),
            'severity': incident.get('severity'),
            'status': 'RESOLVED',
            'timeline': {
                'detected_at': incident.get('detected_at'),
                'containment_started': containment[0]['timestamp'] if containment else None,
                'remediation_completed': remediation[-1]['timestamp'] if remediation else None,
                'resolved_at': datetime.now().isoformat()
            },
            'affected_resources': incident.get('affected_resources'),
            'containment_actions': containment,
            'forensic_findings': forensic,
            'remediation_actions': remediation,
            'root_cause_analysis': self._analyze_root_cause(incident, forensic),
            'lessons_learned': self._document_lessons_learned(incident),
            'preventive_measures': self._suggest_preventive_measures(incident)
        }
📋 Incident Response Playbooks
Ransomware Response Playbook:

yaml
# ransomware-response-playbook.yaml
playbook:
  name: "Cloud Ransomware Response"
  version: "1.0"
  triggers:
    - "Detection of unusual file encryption patterns"
    - "Ransom note detection"
    - "Abnormal network traffic to known ransomware C2 servers"
  
  phases:
    phase1_identification:
      name: "Identification & Alerting"
      steps:
        - step: "Confirm ransomware activity"
          actions:
            - "Check for ransom notes in file systems"
            - "Analyze file extension changes"
            - "Review security alerts for encryption events"
        
        - step: "Activate incident response team"
          actions:
            - "Page on-call security engineer"
            - "Notify legal and PR teams"
            - "Establish war room"
    
    phase2_containment:
      name: "Containment"
      steps:
        - step: "Isolate affected systems"
          actions:
            aws:
              - "Update security groups to block all inbound/outbound"
              - "Detach IAM roles from affected instances"
              - "Disable API keys for affected services"
            
            azure:
              - "Update NSG rules"
              - "Revoke access tokens"
              - "Suspend affected service principals"
        
        - step: "Preserve evidence"
          actions:
            - "Take memory snapshots of affected instances"
            - "Capture network traffic logs"
            - "Document all actions taken"
    
    phase3_eradication:
      name: "Eradication"
      steps:
        - step: "Remove malicious artifacts"
          actions:
            - "Terminate compromised instances"
            - "Rotate all credentials and keys"
            - "Remove malicious IAM policies"
        
        - step: "Restore from backup"
          actions:
            - "Verify backup integrity"
            - "Restore data to clean environment"
            - "Test restored systems"
    
    phase4_recovery:
      name: "Recovery"
      steps:
        - step: "Restore services"
          actions:
            - "Deploy clean infrastructure"
            - "Restore validated data"
            - "Gradually bring services online"
        
        - step: "Post-incident activities"
          actions:
            - "Conduct lessons learned session"
            - "Update security controls"
            - "Enhance monitoring rules"
  
  communication_plan:
    internal:
      - "Security team: Immediate"
      - "Executive leadership: Within 30 minutes"
      - "Legal department: Within 1 hour"
      - "All employees: Within 4 hours"
    
    external:
      - "Customers: Based on impact assessment"
      - "Law enforcement: If data breach confirmed"
      - "Regulators: As required by compliance"
Quick Reference & Cheatsheets
⚡ Cloud Security Commands
AWS Security Commands:

bash
# IAM Security
aws iam get-account-summary
aws iam list-users --query "Users[?CreateDate>='2024-01-01'].UserName"
aws iam list-roles --query "Roles[?RoleName=='Admin']"

# Security Assessment
aws securityhub get-findings --filters '{"SeverityLabel": [{"Value": "HIGH", "Comparison": "EQUALS"}]}'
aws configservice describe-config-rules --query "ConfigRules[?ConfigRuleState=='ACTIVE'].ConfigRuleName"

# Encryption Status
aws kms list-keys --query "Keys[].KeyId"
aws s3api get-bucket-encryption --bucket my-bucket

# Network Security
aws ec2 describe-security-groups --query "SecurityGroups[?IpPermissions[?IpRanges[?CidrIp=='0.0.0.0/0']]].GroupId"
aws wafv2 list-web-acls --scope REGIONAL
Azure Security Commands:

powershell
# Security Center
Get-AzSecurityAlert
Get-AzSecurityTask

# Identity Security
Get-AzureADUser -All $true | Where-Object {$_.AccountEnabled -eq $true}
Get-AzureADConditionalAccessPolicy

# Network Security
Get-AzNetworkSecurityGroup
Get-AzFirewall

# Compliance
Get-AzPolicyState -ResourceGroupName "Security-RG"
GCP Security Commands:

bash
# Security Command Center
gcloud scc findings list --organization=123456789012
gcloud scc assets list --organization=123456789012

# IAM Security
gcloud iam service-accounts list
gcloud iam roles list --organization=123456789012

# Network Security
gcloud compute firewall-rules list
gcloud compute ssl-policies list

# Compliance
gcloud services list --enabled
📋 Security Configuration Templates
Cloud Security Baseline Template:

yaml
# cloud-security-baseline.yaml
version: "1.0"
framework: "CIS Cloud Foundations"

aws:
  identity_and_access_management:
    - control: "1.1 - Maintain current contact details"
      status: "implemented"
      implementation: "AWS Account Alternate Contacts"
    
    - control: "1.2 - Ensure security contact information is registered"
      status: "implemented"
      implementation: "AWS Security Hub"
  
  logging:
    - control: "2.1 - Ensure CloudTrail is enabled in all regions"
      status: "implemented"
      implementation: "AWS Organizations CloudTrail"
    
    - control: "2.2 - Ensure CloudTrail log file validation is enabled"
      status: "implemented"
      implementation: "CloudTrail configuration"

azure:
  security_center:
    - control: "2.1 - Ensure that Azure Defender is set to On for Servers"
      status: "implemented"
      implementation: "Azure Security Center policies"
  
  storage:
    - control: "3.1 - Ensure that 'Secure transfer required' is set to 'Enabled'"
      status: "implemented"
      implementation: "Storage account configuration"

gcp:
  iam:
    - control: "1.1 - Ensure that corporate login credentials are used"
      status: "implemented"
      implementation: "Cloud Identity"
  
  networking:
    - control: "3.1 - Ensure that the default network does not exist in a project"
      status: "implemented"
      implementation: "VPC network management"
🚨 Emergency Response Checklist
markdown
# Cloud Security Incident Response Checklist

## Phase 1: Preparation (Always)
- [ ] Maintain updated contact lists
- [ ] Test backup restoration procedures quarterly
- [ ] Conduct tabletop exercises bi-annually
- [ ] Document escalation procedures
- [ ] Establish communication channels

## Phase 2: Identification
- [ ] Confirm incident scope and impact
- [ ] Document initial findings
- [ ] Activate incident response team
- [ ] Establish timeline of events
- [ ] Categorize incident severity

## Phase 3: Containment
- [ ] Isolate affected systems
- [ ] Preserve evidence
- [ ] Block malicious IPs/domains
- [ ] Revoke compromised credentials
- [ ] Implement temporary security controls

## Phase 4: Eradication
- [ ] Remove malicious artifacts
- [ ] Patch vulnerabilities
- [ ] Rotate all credentials
- [ ] Update security configurations
- [ ] Validate cleanup

## Phase 5: Recovery
- [ ] Restore from clean backups
- [ ] Monitor for re-infection
- [ ] Gradually restore services
- [ ] Validate business functionality
- [ ] Update monitoring rules

## Phase 6: Lessons Learned
- [ ] Conduct post-mortem analysis
- [ ] Update incident response plan
- [ ] Implement preventive measures
- [ ] Share findings with stakeholders
- [ ] Update training materials
📚 Additional Resources
Recommended Tools & Services
AWS: Security Hub, GuardDuty, Macie, Inspector

Azure: Security Center, Sentinel, Key Vault, Defender

GCP: Security Command Center, Cloud Armor, DLP, VPC SC

Multi-Cloud: Prisma Cloud, Qualys, Tenable.io, Splunk

Certifications
AWS: Security Specialty, Advanced Networking Specialty

Azure: Security Engineer Associate, Security Operations Analyst

GCP: Professional Cloud Security Engineer

Vendor Neutral: CCSP (Certified Cloud Security Professional), CCSK

Learning Resources
Books:

"Cloud Security and Privacy" by Tim Mather

"AWS Security" by Dylan Shields

"Azure Security Handbook" by Ashish Raj and Rama Ramani

Courses:

Cloud Security Specialization (Coursera)

SANS SEC488: Cloud Security Essentials

Pluralsight Cloud Security Learning Paths

Blogs & Newsletters:

AWS Security Blog

Azure Security Blog

Google Cloud Security Blog

Cloud Security Alliance

Communities
Forums: Cloud Security Alliance, Reddit r/cloudsecurity

Conferences: AWS re:Inforce, Microsoft Ignite Security, Google Cloud Next

Meetups: Local cloud security meetups, OWASP Cloud Security

This guide is continuously updated with the latest cloud security practices and configurations.

Remember: Cloud security is a shared responsibility. While cloud providers secure the infrastructure, you must secure your data, applications, and configurations.

<div align="center">
☁️ Stay Secure in the Cloud! Your vigilance is the best defense. ☁️

https://img.shields.io/badge/License-MIT-yellow.svg
https://img.shields.io/badge/Cloud-Security-blue.svg
https://img.shields.io/badge/Multi--Cloud-Supported-green.svg

</div>