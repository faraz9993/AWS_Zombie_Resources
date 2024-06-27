import boto3
from datetime import datetime
import pandas as pd
import xlsxwriter

# Initialize boto3 client for EC2 to get regions
ec2_client = boto3.client('ec2')
regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

# Initialize boto3 clients for each service
clients = {
    'ec2': boto3.client('ec2'),
    'iam': boto3.client('iam'),
    'efs': boto3.client('efs'),
    's3': boto3.client('s3'),
    'route53': boto3.client('route53'),
    'sns': boto3.client('sns'),
    'ecs': boto3.client('ecs'),
    'ecr': boto3.client('ecr'),
    'eks': boto3.client('eks'),
    'iot': boto3.client('iot'),
    'secretsmanager': boto3.client('secretsmanager'),
    'rds': boto3.client('rds'),
    'kms': boto3.client('kms'),
    'lambda': boto3.client('lambda'),
    'cloudformation': boto3.client('cloudformation')
}

# Initialize a dictionary to hold our data
data = {
    'Resource': [],
    'Details': []
}

# Function to add data to our dictionary with formatting
def add_data(resource, details):
    data['Resource'].append(resource)
    data['Details'].append(details)

# Function to add a blank row to the dictionary
def add_blank_row(region=None):
    if region:
        data['Resource'].append(f"Region: {region}")
        data['Details'].append('')
    else:
        data['Resource'].append('')
        data['Details'].append('')

# Function to check if IAM user has been active in the last 30 days
def is_user_active(user_name):
    response = clients['iam'].get_user(UserName=user_name)
    
    # Check for password last used
    password_last_used = response['User'].get('PasswordLastUsed')
    if password_last_used:
        delta = datetime.now(password_last_used.tzinfo) - password_last_used
        if delta.days <= 30:
            last_login_date = password_last_used.strftime('%Y-%m-%d %H:%M:%S %Z')
        else:
            last_login_date = 'N/A'
    else:
        last_login_date = 'N/A'
    
    # Check for access key usage
    access_keys = clients['iam'].list_access_keys(UserName=user_name)['AccessKeyMetadata']
    active_access_keys = [key for key in access_keys if key['Status'] == 'Active']
    access_key_count = len(active_access_keys)
    last_access_key_usage = 'N/A'
    
    if access_key_count > 0:
        last_access_key_usage = max([key['LastUsedDate'] for key in active_access_keys])
        delta = datetime.now() - last_access_key_usage.replace(tzinfo=None)
        if delta.days > 30:
            last_access_key_usage = 'N/A'
        else:
            last_access_key_usage = last_access_key_usage.strftime('%Y-%m-%d %H:%M:%S %Z')
    
    # Check if MFA is enabled
    mfa_devices = clients['iam'].list_mfa_devices(UserName=user_name)['MFADevices']
    mfa_enabled = len(mfa_devices) > 0
    
    return {
        'Active': password_last_used is not None or access_key_count > 0,
        'Last Login Date': last_login_date,
        'Last Access Key Usage': last_access_key_usage,
        'Access Key Count': access_key_count,
        'MFA Enabled': mfa_enabled
    }

# Function to check if IAM role is actively used by services
def is_role_used(role_name):
    role_arn = f'arn:aws:iam::123456789012:role/{role_name}'
    
    # Check EC2 instances
    ec2_instances = clients['ec2'].describe_instances(Filters=[{'Name': 'iam-instance-profile.arn', 'Values': [role_arn]}])
    if ec2_instances['Reservations']:
        return True
    
    # Check Lambda functions
    lambda_functions = clients['lambda'].list_functions()['Functions']
    for func in lambda_functions:
        if 'Role' in func and func['Role'] == role_arn:
            return True
    
    # Check ECS clusters and tasks
    ecs_clusters = clients['ecs'].list_clusters()['clusterArns']
    for cluster_arn in ecs_clusters:
        tasks = clients['ecs'].list_tasks(cluster=cluster_arn)['taskArns']
        for task_arn in tasks:
            task = clients['ecs'].describe_tasks(cluster=cluster_arn, tasks=[task_arn])['tasks'][0]
            if task['taskRoleArn'] == role_arn or task['executionRoleArn'] == role_arn:
                return True
    
    # Check EKS nodegroups
    eks_clusters = clients['eks'].list_clusters()['clusters']
    for cluster_name in eks_clusters:
        nodegroups = clients['eks'].list_nodegroups(clusterName=cluster_name)['nodegroups']
        for nodegroup in nodegroups:
            nodegroup_details = clients['eks'].describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup)['nodegroup']
            if nodegroup_details['nodeRole'] == role_arn:
                return True
    
    # Check CloudFormation stack resources
    stacks = clients['cloudformation'].list_stacks(StackStatusFilter=['CREATE_COMPLETE', 'UPDATE_COMPLETE', 'ROLLBACK_COMPLETE'])['StackSummaries']
    for stack in stacks:
        stack_resources = clients['cloudformation'].describe_stack_resources(StackName=stack['StackName'])['StackResources']
        for resource in stack_resources:
            if resource['ResourceType'] == 'AWS::IAM::Role' and resource['PhysicalResourceId'] == role_name:
                return True
    
    # Add more service checks as needed
    
    return False

# Start of the script execution
print("Starting to check AWS resources across all regions...")

# Loop through each region
for region in regions:
    print(f"Checking resources in region: {region}")
    add_blank_row(region=region)
    
    # Update clients to use the current region
    for service, client in clients.items():
        clients[service] = boto3.client(service, region_name=region)
    
    # EC2: Unattached Elastic IP Addresses
    addresses = clients['ec2'].describe_addresses()
    for address in addresses['Addresses']:
        if 'InstanceId' not in address:
            add_data('Unattached Elastic IP Address', address['PublicIp'])
    add_blank_row()
    print(f"Checked Unattached Elastic IP Addresses in region: {region}")

    # EC2: Unattached EBS Volumes
    volumes = clients['ec2'].describe_volumes(Filters=[{'Name': 'status', 'Values': ['available']}])
    for volume in volumes['Volumes']:
        details = {
            'EBS Name:': volume['VolumeId'],
            'EBS Total Size:': f"{volume['Size']} GiB",
            'Creation Date:': str(volume['CreateTime']),
            'Availability Zone:': volume['AvailabilityZone'],
            'Encrypted:': str(volume['Encrypted']),
            'KMS Key Alias:': '',
            'KMS Key ID:': ''
        }
        if volume['Encrypted']:
            kms_key_id = volume['KmsKeyId']
            kms_key_aliases = clients['kms'].list_aliases(KeyId=kms_key_id)
            alias = next((alias['AliasName'] for alias in kms_key_aliases['Aliases'] if alias['TargetKeyId'] == kms_key_id), 'N/A')
            details['KMS Key Alias:'] = alias
            details['KMS Key ID:'] = kms_key_id
    
        add_data('Unattached EBS Volume', details)
    add_blank_row()
    print(f"Checked Unattached EBS Volumes in region: {region}")

    # IAM: Users
    print(f"Checking IAM Users in region: {region}...")
    users_response = clients['iam'].list_users()
    users = users_response['Users']
    for user in users:
        user_name = user['UserName']
        user_activity = is_user_active(user_name)
        if not user_activity['Active']:
            add_data('IAM User', {
                'User Name': user_name,
                'Last Login Date': user_activity['Last Login Date'],
                'Last Access Key Usage': user_activity['Last Access Key Usage'],
                'Access Key Count': user_activity['Access Key Count'],
                'MFA Enabled': user_activity['MFA Enabled']
            })
    add_blank_row()
    print(f"Checked IAM Users in region: {region}")

    # IAM: Roles
    print(f"Checking IAM Roles in region: {region}...")
    roles = clients['iam'].list_roles()['Roles']
    for role in roles:
        role_name = role['RoleName']
        if not is_role_used(role_name):
            add_data('IAM Role', role_name)
    add_blank_row()
    print(f"Checked IAM Roles in region: {region}")

    # IAM: Policies
    attached_policies = {}
    # List all policies attached to users
    for user in users:
        user_name = user['UserName']
        attached_policies[user_name] = []
        attached_user_policies = clients['iam'].list_attached_user_policies(UserName=user_name)['AttachedPolicies']
        for policy in attached_user_policies:
            attached_policies[user_name].append(policy['PolicyName'])

    # List all policies attached to groups
    groups = clients['iam'].list_groups()['Groups']
    for group in groups:
        group_name = group['GroupName']
        attached_policies[group_name] = []
        attached_group_policies = clients['iam'].list_attached_group_policies(GroupName=group_name)['AttachedPolicies']
        for policy in attached_group_policies:
            attached_policies[group_name].append(policy['PolicyName'])

    # List all policies attached to roles
    for role in roles:
        role_name = role['RoleName']
        attached_policies[role_name] = []
        attached_role_policies = clients['iam'].list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
        for policy in attached_role_policies:
            attached_policies[role_name].append(policy['PolicyName'])

    # Now, check if any policy is not attached to any user, group, or role
    all_policies = clients['iam'].list_policies(Scope='Local')['Policies']
    for policy in all_policies:
        policy_name = policy['PolicyName']
        if not any(policy_name in policies for policies in attached_policies.values()):
            add_data('IAM Policy', policy_name)

    # EFS: File systems with no files
    print(f"Checking EFS File Systems in region: {region}...")
    efs_file_systems = clients['efs'].describe_file_systems()['FileSystems']
    for fs in efs_file_systems:
        if fs['SizeInBytes']['Value'] < 10240:
            add_data('EFS File System with size less than 10 KB', fs['FileSystemId'])
    add_blank_row()
    print(f"Checked EFS File Systems in region: {region}")

    # S3: Buckets with no objects
    print(f"Checking S3 Buckets in region: {region}...")
    s3_buckets = clients['s3'].list_buckets()['Buckets']
    for bucket in s3_buckets:
        bucket_name = bucket['Name']
        try:
            s3_objects = clients['s3'].list_objects_v2(Bucket=bucket_name).get('Contents', [])
            if not s3_objects:
                add_data('S3 Bucket with no objects', bucket_name)
        except Exception as e:
            add_data('S3 Bucket with no objects (Access Denied)', bucket_name)
        add_blank_row()

    print(f"Checked S3 Buckets in region: {region}")

    # Route 53: Hosted zones with no DNS queries
    print(f"Checking Route 53 Hosted Zones in region: {region}...")
    hosted_zones = clients['route53'].list_hosted_zones()['HostedZones']
    for zone in hosted_zones:
        zone_id = zone['Id'].split('/')[-1]
        traffic_policy_instances = clients['route53'].list_traffic_policy_instances(HostedZoneId=zone_id)['TrafficPolicyInstances']
        if not traffic_policy_instances:
            add_data('Route 53 Hosted Zone with no DNS queries', zone['Name'])
    add_blank_row()
    print(f"Checked Route 53 Hosted Zones in region: {region}")

    # SNS: Topics with no subscriptions
    print(f"Checking SNS Topics in region: {region}...")
    sns_topics = clients['sns'].list_topics()['Topics']
    for topic in sns_topics:
        subscriptions = clients['sns'].list_subscriptions_by_topic(TopicArn=topic['TopicArn'])['Subscriptions']
        if not subscriptions:
            add_data('SNS Topic with no subscriptions', topic['TopicArn'])
    add_blank_row()
    print(f"Checked SNS Topics in region: {region}")

    # ECS: Inactive Task Definitions
    print(f"Checking ECS Task Definitions in region: {region}...")
    ecs_task_definitions = clients['ecs'].list_task_definitions(status='INACTIVE')['taskDefinitionArns']
    for task_definition in ecs_task_definitions:
        add_data('ECS Inactive Task Definition', task_definition)
    add_blank_row()
    print(f"Checked ECS Task Definitions in region: {region}")

    # ECS: Clusters with no running services
    print(f"Checking ECS Clusters in region: {region}...")
    ecs_clusters = clients['ecs'].list_clusters()['clusterArns']
    for cluster_arn in ecs_clusters:
        services = clients['ecs'].list_services(cluster=cluster_arn)['serviceArns']
        if not services:
            cluster_name = cluster_arn.split('/')[-1]
            add_data('ECS Cluster with no running services', cluster_name)

    # ECR: Repositories with no images
    print(f"Checking ECR Repositories in region: {region}...")
    ecr_repositories = clients['ecr'].describe_repositories()['repositories']
    for repo in ecr_repositories:
        repository_name = repo['repositoryName']
        
        # Check if the repository has any images
        images = clients['ecr'].describe_images(repositoryName=repository_name)['imageDetails']
        if not images:
            add_data('ECR Repository with no images', repository_name)

    # EKS: Clusters with no active nodes
    print(f"Checking EKS Clusters in region: {region}...")
    eks_clusters = clients['eks'].list_clusters()['clusters']
    for cluster_name in eks_clusters:
        nodegroups = clients['eks'].list_nodegroups(clusterName=cluster_name)['nodegroups']
        has_active_nodes = False
        if not nodegroups:  # Check if there are no node groups at all
            add_data('EKS Cluster with no active nodes', cluster_name)
            continue
        for nodegroup in nodegroups:
            nodegroup_details = clients['eks'].describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup)['nodegroup']
            if nodegroup_details['status'] == 'ACTIVE':
                has_active_nodes = True
                break
        if not has_active_nodes:
            add_data('EKS Cluster with no active nodes', cluster_name)

    # # IoT: Things
    # print(f"Checking IoT Things in region: {region}...")
    # iot_things = clients['iot'].list_things()['things']
    # for thing in iot_things:
    #     add_data('IoT Thing', thing['thingName'])

    # RDS: Unused RDS instances
    print(f"Checking RDS Instances in region: {region}...")
    rds_instances = clients['rds'].describe_db_instances()['DBInstances']
    for instance in rds_instances:
        if instance['DBInstanceStatus'] == 'available' and instance['DBInstanceArn'] not in clients['iam'].list_roles():
            add_data('Unused RDS Instance', instance['DBInstanceIdentifier'])

    add_blank_row()
    print(f"Checked RDS Instances in region: {region}")

# Convert to DataFrame
df = pd.DataFrame(data)

# Save to Excel file with formatting
excel_file = 'unused_aws_resources.xlsx'
writer = pd.ExcelWriter(excel_file, engine='xlsxwriter')
df.to_excel(writer, index=False, sheet_name='Unused AWS Resources')

# Access the XlsxWriter workbook and worksheet objects.
workbook = writer.book
worksheet = writer.sheets['Unused AWS Resources']

# Define formats
red_format = workbook.add_format({'bold': True, 'font_color': '#FF0000'})
green_format = workbook.add_format({'bold': True, 'font_color': '#008000'})

# Apply formats to the columns
worksheet.set_column('A:A', None, green_format)  # Entire first column in green

# Iterate through rows to find and format region names in red
for row_num in range(len(data['Resource'])):
    if data['Resource'][row_num].startswith('Region:'):
        worksheet.write(row_num + 1, 0, data['Resource'][row_num], red_format)  # Adjust row_num + 1 to account for header

# Close the Pandas Excel writer and save the Excel file
writer._save()

print(f"Data saved to {excel_file}")