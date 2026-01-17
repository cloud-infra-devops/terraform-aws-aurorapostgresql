# Security and Compliance Guide

## Overview

This Aurora PostgreSQL Terraform module implements comprehensive security controls following AWS Well-Architected Framework security pillar and industry best practices.

## Security Controls Implemented

### 1. Network Security

#### VPC Isolation
- **Private Subnets Only**: Aurora instances deployed exclusively in private subnets
- **No Internet Gateway Access**: Database instances have no direct internet connectivity
- **VPC Endpoints**: All AWS service communication routed through VPC interface endpoints

#### Security Groups (Principle of Least Privilege)
- **Database Security Group**:
  - Ingress: PostgreSQL port (5432) from specified CIDR blocks or security groups only
  - Egress: HTTPS (443) to VPC endpoints, DNS (53) for resolution
- **Lambda Security Group**:
  - Ingress: None (Lambda doesn't accept inbound connections)
  - Egress: HTTPS (443) to VPC endpoints, PostgreSQL (5432) to database, DNS (53)
- **VPC Endpoint Security Group**:
  - Ingress: HTTPS (443) from Lambda and database security groups
  - Egress: All traffic (required for VPC endpoint functionality)

#### VPC Endpoints Implemented
- **Secrets Manager**: For secret retrieval and rotation
- **Lambda**: For rotation function execution
- **CloudWatch Logs**: For log streaming
- **KMS**: For encryption/decryption operations
- **RDS**: For database management operations

### 2. Encryption

#### Encryption at Rest
- **Database Storage**: AES-256 encryption using customer-managed KMS keys
- **Automated Backups**: Encrypted using the same KMS key as the database
- **Performance Insights**: Encrypted using customer-managed KMS keys
- **Secrets Manager**: Secrets encrypted using customer-managed KMS keys

#### Encryption in Transit
- **Database Connections**: SSL/TLS enforced for all client connections
- **AWS Service Communication**: HTTPS/TLS for all AWS API calls
- **VPC Endpoint Traffic**: Encrypted using AWS PrivateLink

#### KMS Key Management
- **Customer-Managed Keys**: Full control over key lifecycle and permissions
- **Key Rotation**: Automatic annual key rotation enabled
- **Cross-Service Permissions**: Granular permissions for RDS, Secrets Manager, Lambda, and CloudWatch Logs
- **Least Privilege Access**: Service-specific conditions in key policies

### 3. Identity and Access Management

#### IAM Roles and Policies
- **Lambda Execution Role**:
  - Basic execution permissions for CloudWatch Logs
  - VPC networking permissions for ENI management
  - Specific secret access for rotation operations
  - KMS permissions for encryption/decryption
  - RDS permissions for password updates

- **Secrets Manager Service Role**:
  - Lambda invocation permissions for rotation
  - Secret access permissions for version management

#### Resource-Based Policies
- **Secret Resource Policy**:
  - Rotation role access for secret operations
  - Account root access for administrative operations
  - Deny all other access

### 4. Secret Management

#### AWS Secrets Manager Integration
- **Secure Storage**: Database credentials stored in Secrets Manager
- **Automatic Rotation**: AWS managed Lambda function for single-user rotation
- **Version Management**: Automatic secret version staging (AWSCURRENT, AWSPENDING, AWSPREVIOUS)
- **Encryption**: All secrets encrypted with customer-managed KMS keys

#### Rotation Process
1. **Create Secret**: Generate new password with complexity requirements
2. **Set Secret**: Update database with new password
3. **Test Secret**: Validate new credentials work
4. **Finish Secret**: Promote new secret to current version

#### Password Policy
- **Length**: 32 characters (configurable)
- **Complexity**: Includes uppercase, lowercase, numbers, and special characters
- **Excluded Characters**: Excludes problematic characters (/, @, ", ', \, space)
- **Randomization**: Cryptographically secure random generation

### 5. Monitoring and Logging

#### CloudWatch Logs
- **PostgreSQL Logs**: Error logs and slow query logs exported to CloudWatch
- **Lambda Logs**: Rotation function execution logs
- **VPC Flow Logs**: Network traffic monitoring (recommended to enable separately)

#### CloudWatch Alarms
- **Performance Metrics**: CPU, memory, connections, latency
- **Availability Metrics**: Replica lag, deadlocks
- **Security Metrics**: Failed connection attempts (via log analysis)
- **Custom Metrics**: Slow query count, error count

#### Audit Trail
- **CloudTrail**: All API calls logged (enable separately)
- **Database Audit Logs**: Connection and query logging
- **Secret Access Logs**: Secrets Manager access logging

### 6. Backup and Recovery

#### Automated Backups
- **Point-in-Time Recovery**: Up to 35 days retention
- **Encrypted Backups**: Same encryption as source database
- **Cross-Region Backup**: Optional for disaster recovery
- **Final Snapshot**: Configurable final snapshot on deletion

#### High Availability
- **Multi-AZ Deployment**: Automatic failover across availability zones
- **Read Replicas**: Up to 15 read replicas for read scaling
- **Aurora Global Database**: Optional for cross-region disaster recovery

## Compliance Frameworks

### SOC 2 Type II
- **Security**: Encryption, access controls, monitoring
- **Availability**: Multi-AZ deployment, automated backups
- **Processing Integrity**: Data validation, error handling
- **Confidentiality**: Encryption, access controls
- **Privacy**: Data minimization, access logging

### PCI DSS
- **Requirement 3**: Protect stored cardholder data (encryption at rest)
- **Requirement 4**: Encrypt transmission of cardholder data (TLS)
- **Requirement 7**: Restrict access by business need (IAM, security groups)
- **Requirement 8**: Identify and authenticate access (IAM, database authentication)
- **Requirement 10**: Track and monitor access (CloudWatch, CloudTrail)

### HIPAA
- **Administrative Safeguards**: Access controls, audit logs
- **Physical Safeguards**: AWS data center security
- **Technical Safeguards**: Encryption, access controls, audit logs

### GDPR
- **Data Protection by Design**: Encryption, access controls
- **Data Minimization**: Least privilege access
- **Accountability**: Audit logs, monitoring
- **Data Subject Rights**: Backup and recovery capabilities

## Security Best Practices

### 1. Network Security
- Deploy in private subnets only
- Use VPC endpoints for all AWS service communication
- Implement security group rules with specific ports and protocols
- Enable VPC Flow Logs for network monitoring

### 2. Access Control
- Use IAM roles instead of IAM users where possible
- Implement least privilege access principles
- Enable MFA for administrative access
- Regularly review and rotate access keys

### 3. Encryption
- Use customer-managed KMS keys for full control
- Enable encryption for all data at rest and in transit
- Regularly rotate encryption keys
- Monitor key usage through CloudTrail

### 4. Monitoring
- Enable comprehensive CloudWatch alarms
- Set up SNS notifications for critical alerts
- Implement log aggregation and analysis
- Regular security assessments and penetration testing

### 5. Backup and Recovery
- Test backup and recovery procedures regularly
- Implement cross-region backup for disaster recovery
- Document recovery time objectives (RTO) and recovery point objectives (RPO)
- Maintain offline backup copies for critical data

### 6. Incident Response
- Develop incident response procedures
- Implement automated response for common scenarios
- Regular incident response training and tabletop exercises
- Maintain contact information for security team

## Security Checklist

### Pre-Deployment
- [ ] Review and approve security group rules
- [ ] Validate KMS key policies
- [ ] Confirm VPC endpoint configuration
- [ ] Review IAM roles and policies
- [ ] Validate backup and retention settings

### Post-Deployment
- [ ] Verify encryption is enabled for all components
- [ ] Test secret rotation functionality
- [ ] Validate CloudWatch alarms are triggering
- [ ] Confirm VPC endpoints are being used
- [ ] Test backup and recovery procedures

### Ongoing Maintenance
- [ ] Regular security assessments
- [ ] Monitor CloudWatch alarms and logs
- [ ] Review and update access permissions
- [ ] Test disaster recovery procedures
- [ ] Keep Aurora engine version updated
- [ ] Review and update security group rules

## Threat Model

### Threats Mitigated
1. **Data Breach**: Encryption at rest and in transit
2. **Unauthorized Access**: IAM, security groups, VPC isolation
3. **Credential Compromise**: Automatic secret rotation, secure storage
4. **Network Attacks**: VPC endpoints, private subnets, security groups
5. **Insider Threats**: Least privilege access, audit logging
6. **Data Loss**: Automated backups, point-in-time recovery

### Residual Risks
1. **Application-Level Vulnerabilities**: Requires secure application development
2. **Social Engineering**: Requires user training and awareness
3. **Supply Chain Attacks**: Requires vendor security assessments
4. **Zero-Day Exploits**: Requires regular patching and monitoring

## Contact Information

For security questions or concerns:
- Security Team: security@company.com
- Platform Team: platform@company.com
- Emergency: security-emergency@company.com