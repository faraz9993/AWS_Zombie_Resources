# AWS_Zombie_Resources

## To Run This Code You Need Below Dpendencies:
### pip install boto3 pandas openpyxl xlsxwriter

## Logic behind every resource:
1. EBS Volume (If not attched to any instance)
2. IAM User (If inactive for continous 30 days)
3. IAM policies (If not attached to any user)
4. IAM Roles (If not attached to these services :  EC2 Instance, Lambda Function, ECS Cluster, TD, EKS Nodes, Node Groups, Cloud Formation Stack Resource)
5. S3 Bucket (If it doesn't have any object in it)
6. EFS File System (If Total size of the EFS Is less than 10 KB then will be counted as Zombie. When EFS created defauly size with 10KB is already there.)
7. SNS Topic (If topic is not subscribed.)
8. ECS - Task Definition (Inactive)
9. ECS - Cluster (If no service is running in it.)
10. ECR (Repository that has no image in it.)
11. EKS - Cluster (If no active node in it.)
12. Secret Manager (Thinking the logic)
13. RDS (If RDS status is stopped. Stopped RDS charges include manual snapshots and automated backups within your specified retention window)