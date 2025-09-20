#!/usr/bin/env python3
"""
ISO 27001 Compliance Checker
Automated assessment of AWS infrastructure against ISO 27001 controls
"""

import boto3
import json
import argparse
from datetime import datetime
from typing import Dict, List, Any

class ISO27001Checker:
    def __init__(self, region='us-east-1'):
        self.region = region
        self.ec2 = boto3.client('ec2', region_name=region)
        self.iam = boto3.client('iam')
        self.s3 = boto3.client('s3')
        self.cloudtrail = boto3.client('cloudtrail', region_name=region)
        self.config = boto3.client('config', region_name=region)

        self.results = {
            'timestamp': datetime.utcnow().isoformat(),
            'region': region,
            'controls': {},
            'summary': {
                'total_checks': 0,
                'passed': 0,
                'failed': 0,
                'not_applicable': 0
            }
        }

    def check_control_a9_1_2_access_management(self):
        """A.9.1.2 - Access to networks and network services"""
        control_id = "A.9.1.2"
        checks = []

        try:
            # Check security groups for overly permissive rules
            sg_response = self.ec2.describe_security_groups()

            for sg in sg_response['SecurityGroups']:
                for rule in sg.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            if rule.get('FromPort') == 22 or rule.get('FromPort') == 3389:
                                checks.append({
                                    'check': f"Security Group {sg['GroupId']} allows unrestricted admin access",
                                    'status': 'FAIL',
                                    'details': f"Port {rule.get('FromPort')} open to 0.0.0.0/0"
                                })
                            else:
                                checks.append({
                                    'check': f"Security Group {sg['GroupId']} network access review",
                                    'status': 'WARN',
                                    'details': f"Port {rule.get('FromPort')} open to 0.0.0.0/0"
                                })

            if not any(check['status'] == 'FAIL' for check in checks):
                checks.append({
                    'check': 'Security groups access control',
                    'status': 'PASS',
                    'details': 'No unrestricted admin access found'
                })

        except Exception as e:
            checks.append({
                'check': 'Security groups assessment',
                'status': 'ERROR',
                'details': str(e)
            })

        self.results['controls'][control_id] = {
            'title': 'Access to networks and network services',
            'checks': checks
        }

    def check_control_a12_4_1_logging(self):
        """A.12.4.1 - Event logging"""
        control_id = "A.12.4.1"
        checks = []

        try:
            # Check CloudTrail configuration
            trails = self.cloudtrail.describe_trails()

            active_trails = []
            for trail in trails['trailList']:
                trail_status = self.cloudtrail.get_trail_status(Name=trail['TrailARN'])
                if trail_status['IsLogging']:
                    active_trails.append(trail)

            if active_trails:
                checks.append({
                    'check': 'CloudTrail logging enabled',
                    'status': 'PASS',
                    'details': f"{len(active_trails)} active trail(s) found"
                })

                # Check for multi-region trails
                multi_region_trails = [t for t in active_trails if t.get('IsMultiRegionTrail', False)]
                if multi_region_trails:
                    checks.append({
                        'check': 'Multi-region logging',
                        'status': 'PASS',
                        'details': f"{len(multi_region_trails)} multi-region trail(s)"
                    })
                else:
                    checks.append({
                        'check': 'Multi-region logging',
                        'status': 'FAIL',
                        'details': 'No multi-region trails configured'
                    })
            else:
                checks.append({
                    'check': 'CloudTrail logging enabled',
                    'status': 'FAIL',
                    'details': 'No active CloudTrail found'
                })

        except Exception as e:
            checks.append({
                'check': 'CloudTrail assessment',
                'status': 'ERROR',
                'details': str(e)
            })

        self.results['controls'][control_id] = {
            'title': 'Event logging',
            'checks': checks
        }

    def check_control_a10_1_1_encryption(self):
        """A.10.1.1 - Use of cryptographic controls"""
        control_id = "A.10.1.1"
        checks = []

        try:
            # Check S3 bucket encryption
            buckets = self.s3.list_buckets()

            encrypted_buckets = 0
            total_buckets = len(buckets['Buckets'])

            for bucket in buckets['Buckets']:
                try:
                    encryption = self.s3.get_bucket_encryption(Bucket=bucket['Name'])
                    encrypted_buckets += 1
                except self.s3.exceptions.ClientError as e:
                    if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                        checks.append({
                            'check': f"S3 bucket {bucket['Name']} encryption",
                            'status': 'FAIL',
                            'details': 'No encryption configuration found'
                        })

            if encrypted_buckets > 0:
                checks.append({
                    'check': 'S3 bucket encryption',
                    'status': 'PASS' if encrypted_buckets == total_buckets else 'WARN',
                    'details': f"{encrypted_buckets}/{total_buckets} buckets encrypted"
                })

            # Check EBS volume encryption
            volumes = self.ec2.describe_volumes()
            encrypted_volumes = sum(1 for vol in volumes['Volumes'] if vol.get('Encrypted', False))
            total_volumes = len(volumes['Volumes'])

            checks.append({
                'check': 'EBS volume encryption',
                'status': 'PASS' if encrypted_volumes == total_volumes else 'WARN',
                'details': f"{encrypted_volumes}/{total_volumes} volumes encrypted"
            })

        except Exception as e:
            checks.append({
                'check': 'Encryption assessment',
                'status': 'ERROR',
                'details': str(e)
            })

        self.results['controls'][control_id] = {
            'title': 'Use of cryptographic controls',
            'checks': checks
        }

    def check_control_a9_2_1_user_registration(self):
        """A.9.2.1 - User registration and de-registration"""
        control_id = "A.9.2.1"
        checks = []

        try:
            # Check IAM user configuration
            users = self.iam.list_users()

            # Check for users without MFA
            users_without_mfa = []
            inactive_users = []

            for user in users['Users']:
                # Check MFA devices
                mfa_devices = self.iam.list_mfa_devices(UserName=user['UserName'])
                if not mfa_devices['MFADevices']:
                    users_without_mfa.append(user['UserName'])

                # Check for inactive users (no recent activity)
                # This would require more detailed analysis with CloudTrail data

            if users_without_mfa:
                checks.append({
                    'check': 'IAM users MFA enforcement',
                    'status': 'FAIL',
                    'details': f"{len(users_without_mfa)} users without MFA: {', '.join(users_without_mfa[:5])}"
                })
            else:
                checks.append({
                    'check': 'IAM users MFA enforcement',
                    'status': 'PASS',
                    'details': 'All users have MFA enabled'
                })

            # Check root account MFA
            account_summary = self.iam.get_account_summary()
            if account_summary['SummaryMap'].get('AccountMFAEnabled', 0) == 1:
                checks.append({
                    'check': 'Root account MFA',
                    'status': 'PASS',
                    'details': 'Root account MFA is enabled'
                })
            else:
                checks.append({
                    'check': 'Root account MFA',
                    'status': 'FAIL',
                    'details': 'Root account MFA not enabled'
                })

        except Exception as e:
            checks.append({
                'check': 'IAM user assessment',
                'status': 'ERROR',
                'details': str(e)
            })

        self.results['controls'][control_id] = {
            'title': 'User registration and de-registration',
            'checks': checks
        }

    def run_all_checks(self):
        """Run all ISO 27001 compliance checks"""
        print("Running ISO 27001 compliance checks...")

        self.check_control_a9_1_2_access_management()
        self.check_control_a12_4_1_logging()
        self.check_control_a10_1_1_encryption()
        self.check_control_a9_2_1_user_registration()

        # Calculate summary
        for control_id, control in self.results['controls'].items():
            for check in control['checks']:
                self.results['summary']['total_checks'] += 1
                if check['status'] == 'PASS':
                    self.results['summary']['passed'] += 1
                elif check['status'] in ['FAIL', 'ERROR']:
                    self.results['summary']['failed'] += 1
                else:  # WARN, N/A, etc.
                    self.results['summary']['not_applicable'] += 1

    def generate_report(self) -> str:
        """Generate a formatted compliance report"""
        report = f"""
=== ISO 27001 Compliance Assessment Report ===
Generated: {self.results['timestamp']}
Region: {self.results['region']}

SUMMARY:
Total Checks: {self.results['summary']['total_checks']}
Passed: {self.results['summary']['passed']}
Failed: {self.results['summary']['failed']}
Warnings/N/A: {self.results['summary']['not_applicable']}

CONTROL DETAILS:
"""

        for control_id, control in self.results['controls'].items():
            report += f"\n{control_id} - {control['title']}\n"
            report += "-" * (len(control_id) + len(control['title']) + 3) + "\n"

            for check in control['checks']:
                status_symbol = {
                    'PASS': '✅',
                    'FAIL': '❌',
                    'WARN': '⚠️',
                    'ERROR': '🔥',
                    'N/A': 'ℹ️'
                }.get(check['status'], '❓')

                report += f"{status_symbol} {check['check']}: {check['details']}\n"

        return report

def main():
    parser = argparse.ArgumentParser(description='ISO 27001 compliance checker for AWS')
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    parser.add_argument('--output', choices=['text', 'json'], default='text', help='Output format')
    parser.add_argument('--controls', nargs='+', help='Specific controls to check')

    args = parser.parse_args()

    try:
        checker = ISO27001Checker(region=args.region)
        checker.run_all_checks()

        if args.output == 'json':
            print(json.dumps(checker.results, indent=2))
        else:
            print(checker.generate_report())

    except Exception as e:
        print(f"Error running compliance checks: {str(e)}")
        return 1

    return 0

if __name__ == '__main__':
    exit(main())