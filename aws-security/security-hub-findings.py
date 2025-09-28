#!/usr/bin/env python3
"""
AWS Security Hub Findings Analyzer
Comprehensive security findings analysis with automated remediation recommendations
Advanced threat detection and compliance validation for enterprise environments
"""

import boto3
import json
import argparse
import csv
import logging
import os
import yaml
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SecurityHubAnalyzer:
    def __init__(self, region='eu-west-2', config_file: Optional[str] = None):
        self.securityhub = boto3.client('securityhub', region_name=region)
        self.config = boto3.client('config', region_name=region)
        self.guardduty = boto3.client('guardduty', region_name=region)
        self.iam = boto3.client('iam')
        self.region = region
        self.config_data = self._load_config(config_file)

    def get_findings(self, severity=['HIGH', 'CRITICAL'], days_back=7):
        """Retrieve Security Hub findings by severity and time range."""
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days_back)

        filters = {
            'SeverityLabel': [{'Value': sev, 'Comparison': 'EQUALS'} for sev in severity],
            'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}],
            'UpdatedAt': [
                {
                    'Start': start_date.isoformat() + 'Z',
                    'End': end_date.isoformat() + 'Z'
                }
            ]
        }

        findings = []
        paginator = self.securityhub.get_paginator('get_findings')

        for page in paginator.paginate(Filters=filters):
            findings.extend(page['Findings'])

        return findings

    def analyze_findings(self, findings):
        """Analyze findings and generate statistics."""
        stats = {
            'total_findings': len(findings),
            'by_severity': defaultdict(int),
            'by_type': defaultdict(int),
            'by_resource': defaultdict(int),
            'by_compliance': defaultdict(int)
        }

        for finding in findings:
            # Count by severity
            severity = finding.get('Severity', {}).get('Label', 'UNKNOWN')
            stats['by_severity'][severity] += 1

            # Count by finding type
            finding_type = finding.get('Types', ['Unknown'])[0]
            stats['by_type'][finding_type] += 1

            # Count by resource type
            for resource in finding.get('Resources', []):
                resource_type = resource.get('Type', 'Unknown')
                stats['by_resource'][resource_type] += 1

            # Count by compliance standard
            for compliance in finding.get('Compliance', {}).get('AssociatedStandards', []):
                standard_id = compliance.get('StandardsId', 'Unknown')
                stats['by_compliance'][standard_id] += 1

        # Add timing and performance metrics
        stats['analysis_metadata'] = {
            'analysis_timestamp': datetime.utcnow().isoformat(),
            'findings_processed': len(findings),
            'unique_resource_types': len(stats['by_resource']),
            'compliance_frameworks_found': len(stats['by_compliance'])
        }

        return stats

    def _load_config(self, config_file: Optional[str]) -> Dict:
        """Load configuration from file or use defaults"""
        default_config = {
            'severity_thresholds': {
                'critical_max': 0,
                'high_max': 5,
                'medium_max': 20
            },
            'auto_remediation': {
                'enabled': False,
                'dry_run': True,
                'allowed_actions': ['tag_resource', 'update_security_group']
            },
            'notifications': {
                'email_enabled': False,
                'slack_webhook': None,
                'sns_topic_arn': None
            },
            'compliance_frameworks': ['aws-foundational-security-standard', 'cis-aws-foundations-benchmark'],
            'excluded_finding_types': [],
            'custom_rules': []
        }

        if config_file and os.path.exists(config_file):
            with open(config_file, 'r') as f:
                user_config = yaml.safe_load(f)
                default_config.update(user_config)

        return default_config

    def get_advanced_findings(self, include_suppressed=False, compliance_standards=None):
        """Advanced findings retrieval with compliance filtering"""
        logger.info("Retrieving advanced Security Hub findings...")

        filters = {
            'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}]
        }

        if not include_suppressed:
            filters['WorkflowState'] = [{'Value': 'SUPPRESSED', 'Comparison': 'NOT_EQUALS'}]

        if compliance_standards:
            filters['ComplianceAssociatedStandardsId'] = [
                {'Value': std, 'Comparison': 'EQUALS'} for std in compliance_standards
            ]

        findings = []
        paginator = self.securityhub.get_paginator('get_findings')

        try:
            for page in paginator.paginate(Filters=filters):
                findings.extend(page['Findings'])
        except Exception as e:
            logger.error(f"Error retrieving findings: {str(e)}")
            return []

        logger.info(f"Retrieved {len(findings)} findings")
        return findings

    def enrich_findings_with_context(self, findings):
        """Enrich findings with additional AWS context"""
        logger.info("Enriching findings with additional context...")

        enriched_findings = []

        for finding in findings:
            enriched_finding = finding.copy()

            # Add resource details
            for resource in finding.get('Resources', []):
                resource_id = resource.get('Id', '')
                resource_type = resource.get('Type', '')

                # Enrich EC2 instances
                if 'EC2 Instance' in resource_type and 'i-' in resource_id:
                    try:
                        ec2 = boto3.client('ec2', region_name=self.region)
                        instance_id = resource_id.split('/')[-1]
                        response = ec2.describe_instances(InstanceIds=[instance_id])

                        if response['Reservations']:
                            instance = response['Reservations'][0]['Instances'][0]
                            resource['InstanceDetails'] = {
                                'State': instance.get('State', {}).get('Name'),
                                'InstanceType': instance.get('InstanceType'),
                                'VpcId': instance.get('VpcId'),
                                'SubnetId': instance.get('SubnetId'),
                                'PublicIp': instance.get('PublicIpAddress'),
                                'Tags': instance.get('Tags', [])
                            }
                    except Exception as e:
                        logger.debug(f"Could not enrich EC2 instance {resource_id}: {e}")

                # Enrich S3 buckets
                elif 'S3 Bucket' in resource_type:
                    try:
                        s3 = boto3.client('s3')
                        bucket_name = resource_id.split(':')[-1]

                        # Get bucket location
                        location = s3.get_bucket_location(Bucket=bucket_name)
                        resource['BucketDetails'] = {
                            'Region': location.get('LocationConstraint', 'us-east-1'),
                            'PublicAccess': 'Unknown'  # Would need additional calls
                        }
                    except Exception as e:
                        logger.debug(f"Could not enrich S3 bucket {resource_id}: {e}")

            enriched_findings.append(enriched_finding)

        return enriched_findings

    def generate_remediation_recommendations(self, findings):
        """Generate automated remediation recommendations"""
        logger.info("Generating remediation recommendations...")

        recommendations = []

        for finding in findings:
            finding_type = finding.get('Types', ['Unknown'])[0]
            severity = finding.get('Severity', {}).get('Label', 'UNKNOWN')
            title = finding.get('Title', '')

            remediation = {
                'finding_id': finding.get('Id'),
                'title': title,
                'severity': severity,
                'remediation_steps': [],
                'automation_possible': False,
                'estimated_effort': 'Medium',
                'risk_level': severity
            }

            # Security Group recommendations
            if 'Security Group' in title or 'security-groups' in finding_type.lower():
                remediation['remediation_steps'] = [
                    "Review security group rules and remove unnecessary open ports",
                    "Implement principle of least privilege",
                    "Use specific IP ranges instead of 0.0.0.0/0 where possible",
                    "Consider using AWS Systems Manager Session Manager for instance access"
                ]
                remediation['automation_possible'] = True
                remediation['aws_cli_commands'] = [
                    "aws ec2 describe-security-groups --group-ids <sg-id>",
                    "aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol <protocol> --port <port> --cidr <cidr>"
                ]

            # IAM recommendations
            elif 'IAM' in title or 'iam' in finding_type.lower():
                remediation['remediation_steps'] = [
                    "Review IAM policies and remove excessive permissions",
                    "Implement IAM roles instead of long-term access keys",
                    "Enable MFA for all users",
                    "Regularly rotate access keys and passwords"
                ]
                remediation['automation_possible'] = True
                remediation['aws_cli_commands'] = [
                    "aws iam list-attached-user-policies --user-name <username>",
                    "aws iam detach-user-policy --user-name <username> --policy-arn <policy-arn>"
                ]

            # S3 recommendations
            elif 'S3' in title or 's3' in finding_type.lower():
                remediation['remediation_steps'] = [
                    "Enable S3 bucket encryption",
                    "Configure S3 bucket public access block",
                    "Enable S3 bucket logging",
                    "Review bucket policies and ACLs"
                ]
                remediation['automation_possible'] = True
                remediation['aws_cli_commands'] = [
                    "aws s3api put-bucket-encryption --bucket <bucket-name> --server-side-encryption-configuration",
                    "aws s3api put-public-access-block --bucket <bucket-name> --public-access-block-configuration"
                ]

            # RDS recommendations
            elif 'RDS' in title or 'rds' in finding_type.lower():
                remediation['remediation_steps'] = [
                    "Enable RDS encryption at rest",
                    "Enable RDS backup retention",
                    "Configure RDS security groups properly",
                    "Enable RDS enhanced monitoring"
                ]
                remediation['automation_possible'] = False
                remediation['estimated_effort'] = 'High'

            recommendations.append(remediation)

        return recommendations

    def check_compliance_status(self, findings):
        """Check compliance status against major frameworks"""
        logger.info("Analyzing compliance status...")

        compliance_status = {
            'aws_foundational': {'passed': 0, 'failed': 0, 'score': 0},
            'cis_benchmark': {'passed': 0, 'failed': 0, 'score': 0},
            'pci_dss': {'passed': 0, 'failed': 0, 'score': 0},
            'iso_27001': {'passed': 0, 'failed': 0, 'score': 0}
        }

        for finding in findings:
            compliance_data = finding.get('Compliance', {})
            status = compliance_data.get('Status', 'FAILED')

            for standard in compliance_data.get('AssociatedStandards', []):
                standard_id = standard.get('StandardsId', '').lower()

                if 'aws-foundational' in standard_id:
                    if status == 'PASSED':
                        compliance_status['aws_foundational']['passed'] += 1
                    else:
                        compliance_status['aws_foundational']['failed'] += 1

                elif 'cis' in standard_id:
                    if status == 'PASSED':
                        compliance_status['cis_benchmark']['passed'] += 1
                    else:
                        compliance_status['cis_benchmark']['failed'] += 1

        # Calculate compliance scores
        for framework, data in compliance_status.items():
            total = data['passed'] + data['failed']
            if total > 0:
                data['score'] = (data['passed'] / total) * 100

        return compliance_status

    def generate_executive_dashboard(self, findings, stats, compliance_status):
        """Generate executive-level dashboard data"""

        critical_findings = [f for f in findings if f.get('Severity', {}).get('Label') == 'CRITICAL']
        high_findings = [f for f in findings if f.get('Severity', {}).get('Label') == 'HIGH']

        # Risk assessment
        risk_score = min(100, len(critical_findings) * 10 + len(high_findings) * 5)

        if risk_score >= 80:
            risk_level = "CRITICAL"
        elif risk_score >= 60:
            risk_level = "HIGH"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        dashboard = {
            'timestamp': datetime.utcnow().isoformat(),
            'region': self.region,
            'summary': {
                'total_findings': stats['total_findings'],
                'critical_findings': len(critical_findings),
                'high_findings': len(high_findings),
                'risk_score': risk_score,
                'risk_level': risk_level
            },
            'compliance': compliance_status,
            'trends': {
                'last_7_days': stats['total_findings'],  # Would need historical data
                'improvement_areas': []
            },
            'top_risks': []
        }

        # Identify top risks
        resource_risk = sorted(stats['by_resource'].items(), key=lambda x: x[1], reverse=True)[:5]
        for resource_type, count in resource_risk:
            dashboard['top_risks'].append({
                'type': 'Resource',
                'description': f"{resource_type} has {count} findings",
                'priority': 'HIGH' if count > 10 else 'MEDIUM'
            })

        return dashboard

    def export_findings(self, findings, format='json', output_file=None):
        """Export findings in various formats"""
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')

        if not output_file:
            output_file = f"security_findings_{timestamp}.{format}"

        if format == 'json':
            with open(output_file, 'w') as f:
                json.dump(findings, f, indent=2, default=str)

        elif format == 'csv':
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)

                # Headers
                writer.writerow([
                    'ID', 'Title', 'Severity', 'Type', 'Resource', 'Description', 'CreatedAt', 'UpdatedAt'
                ])

                # Data
                for finding in findings:
                    resources = ', '.join([r.get('Id', '') for r in finding.get('Resources', [])])
                    writer.writerow([
                        finding.get('Id', ''),
                        finding.get('Title', ''),
                        finding.get('Severity', {}).get('Label', ''),
                        ', '.join(finding.get('Types', [])),
                        resources,
                        finding.get('Description', ''),
                        finding.get('CreatedAt', ''),
                        finding.get('UpdatedAt', '')
                    ])

        elif format == 'yaml':
            with open(output_file, 'w') as f:
                yaml.dump(findings, f, default_flow_style=False)

        logger.info(f"Findings exported to {output_file}")
        return output_file

    def run_comprehensive_analysis(self):
        """Run comprehensive security analysis with all enterprise features"""
        print("AWS Security Hub Enterprise Analyzer")
        print("=====================================")

        try:
            # Get comprehensive findings with compliance filtering
            findings = self.get_advanced_findings(
                include_suppressed=False,
                compliance_standards=self.config_data['compliance_frameworks']
            )

            if not findings:
                print("No Security Hub findings found in this region.")
                return

            print(f"\n🔍 Analyzing {len(findings)} security findings...")

            # Enrich findings with additional context
            enriched_findings = self.enrich_findings_with_context(findings)

            # Run comprehensive analysis
            stats = self.analyze_findings(enriched_findings)
            compliance_status = self.check_compliance_status(enriched_findings)

            # Generate executive dashboard
            dashboard_data = self.generate_executive_dashboard(enriched_findings, stats, compliance_status)

            # Display comprehensive report
            report = self.generate_comprehensive_report(enriched_findings, stats)
            print(report)

            # Generate remediation recommendations
            recommendations = self.generate_remediation_recommendations(enriched_findings)

            print("\n" + "="*80)
            print("AUTOMATED REMEDIATION RECOMMENDATIONS")
            print("="*80)

            # Show top 10 priority recommendations
            priority_recs = sorted(recommendations,
                                 key=lambda x: (x['severity'] == 'CRITICAL', x['automation_possible']),
                                 reverse=True)[:10]

            for i, rec in enumerate(priority_recs, 1):
                automation_icon = "🤖" if rec['automation_possible'] else "👥"
                severity_icon = "🔴" if rec['severity'] == 'CRITICAL' else "🟠" if rec['severity'] == 'HIGH' else "🟡"

                print(f"\n{i}. {severity_icon} {automation_icon} {rec['title']}")
                print(f"   Severity: {rec['severity']} | Effort: {rec['estimated_effort']}")

                if rec.get('aws_cli_commands'):
                    print(f"   Quick Fix: {rec['aws_cli_commands'][0]}")

            # Export comprehensive analysis
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')

            # Export detailed JSON report
            comprehensive_report = {
                'metadata': {
                    'timestamp': datetime.utcnow().isoformat(),
                    'region': self.region,
                    'analyzer_version': '2.0.0',
                    'total_findings_analyzed': len(enriched_findings)
                },
                'executive_summary': dashboard_data,
                'findings_analysis': stats,
                'compliance_status': compliance_status,
                'remediation_recommendations': recommendations,
                'detailed_findings': enriched_findings[:50]  # Limit for file size
            }

            json_filename = f'security_hub_comprehensive_analysis_{timestamp}.json'
            with open(json_filename, 'w') as f:
                json.dump(comprehensive_report, f, indent=2, default=str)

            print(f"\n📊 Comprehensive analysis exported to: {json_filename}")

            # Export findings in multiple formats
            csv_filename = self.export_findings(enriched_findings, format='csv')
            print(f"📈 Findings exported to CSV: {csv_filename}")

            # Export high priority findings separately
            critical_findings = [f for f in enriched_findings
                               if f.get('Severity', {}).get('Label') == 'CRITICAL']

            if critical_findings:
                critical_filename = self.export_findings(critical_findings, format='json',
                                                       output_file=f'critical_findings_{timestamp}.json')
                print(f"🚨 Critical findings exported to: {critical_filename}")

            print(f"\n✅ Analysis complete. {len(enriched_findings)} findings processed.")
            print(f"🎯 Focus on {len(critical_findings)} critical findings for immediate action.")

        except Exception as e:
            logger.error(f"Error running comprehensive analysis: {str(e)}")
            import traceback
            traceback.print_exc()
            return 1

        return 0

    def generate_comprehensive_report(self, findings, stats):
        """Generate a comprehensive security report with recommendations"""
        compliance_status = self.check_compliance_status(findings)
        remediation_recommendations = self.generate_remediation_recommendations(findings)
        dashboard_data = self.generate_executive_dashboard(findings, stats, compliance_status)

        report = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                        AWS SECURITY ASSESSMENT REPORT                        ║
║                      Comprehensive Security Analysis                         ║
╚══════════════════════════════════════════════════════════════════════════════╝

Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC
Region: {self.region}
Analysis Period: Last 30 days

EXECUTIVE SUMMARY
═══════════════════════════════════════════════════════════════════════════════
Total Active Findings: {stats['total_findings']}
Risk Level: {dashboard_data['summary']['risk_level']}
Risk Score: {dashboard_data['summary']['risk_score']}/100

Critical Findings: {dashboard_data['summary']['critical_findings']}
High Severity Findings: {dashboard_data['summary']['high_findings']}

FINDINGS BY SEVERITY
═══════════════════════════════════════════════════════════════════════════════"""

        for severity, count in sorted(stats['by_severity'].items()):
            status_icon = "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🟡" if severity == "MEDIUM" else "🟢"
            report += f"\n{status_icon} {severity}: {count}"

        report += f"""

COMPLIANCE STATUS
═══════════════════════════════════════════════════════════════════════════════"""

        for framework, data in compliance_status.items():
            framework_name = framework.replace('_', ' ').title()
            score = data['score']
            status_icon = "✅" if score >= 90 else "⚠️" if score >= 70 else "❌"
            report += f"\n{status_icon} {framework_name}: {score:.1f}% ({data['passed']} passed, {data['failed']} failed)"

        report += f"""

TOP AFFECTED RESOURCE TYPES
═══════════════════════════════════════════════════════════════════════════════"""

        for resource_type, count in sorted(stats['by_resource'].items(), key=lambda x: x[1], reverse=True)[:10]:
            report += f"\n• {resource_type}: {count} findings"

        report += f"""

PRIORITY REMEDIATION ACTIONS
═══════════════════════════════════════════════════════════════════════════════"""

        # Top 5 critical recommendations
        critical_recs = [r for r in remediation_recommendations if r['severity'] == 'CRITICAL'][:5]
        for i, rec in enumerate(critical_recs, 1):
            report += f"""
{i}. {rec['title']}
   Severity: {rec['severity']} | Automation: {'Yes' if rec['automation_possible'] else 'No'}
   Steps: {'; '.join(rec['remediation_steps'])}
"""

        report += f"""

SECURITY RECOMMENDATIONS
═══════════════════════════════════════════════════════════════════════════════
1. Immediate Actions:
   • Address all {dashboard_data['summary']['critical_findings']} critical findings within 24 hours
   • Review and update security groups with overly permissive rules
   • Enable MFA for all IAM users and root accounts

2. Short-term (1-2 weeks):
   • Implement automated security scanning in CI/CD pipelines
   • Enable AWS Config rules for continuous compliance monitoring
   • Set up CloudWatch alarms for security-related events

3. Long-term (1-3 months):
   • Implement Infrastructure as Code with security best practices
   • Establish regular security training for development teams
   • Create incident response procedures and test regularly

NEXT STEPS
═══════════════════════════════════════════════════════════════════════════════
1. Review this report with security team
2. Prioritize remediation based on risk levels
3. Implement automated monitoring for continuous assessment
4. Schedule regular security reviews and assessments

For detailed remediation instructions and automation scripts,
use: --export-remediation flag with this tool.
"""

        return report

def main():
    parser = argparse.ArgumentParser(
        description='AWS Security Hub Enterprise Analyzer - Comprehensive security analysis with automated remediation recommendations'
    )
    parser.add_argument('--region', default='eu-west-2', help='AWS region (default: eu-west-2)')
    parser.add_argument('--config', help='Configuration file path (YAML format)')
    parser.add_argument('--severity', nargs='+', default=['HIGH', 'CRITICAL'],
                       choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
                       help='Severity levels to include (default: HIGH, CRITICAL)')
    parser.add_argument('--days', type=int, default=30, help='Days back to analyze (default: 30)')
    parser.add_argument('--output', choices=['comprehensive', 'simple', 'json'], default='comprehensive',
                       help='Output format (default: comprehensive)')
    parser.add_argument('--export-format', choices=['json', 'csv', 'yaml'], default='json',
                       help='Export format for findings (default: json)')
    parser.add_argument('--include-suppressed', action='store_true',
                       help='Include suppressed findings in analysis')
    parser.add_argument('--compliance-only', action='store_true',
                       help='Focus only on compliance-related findings')
    parser.add_argument('--auto-remediate', action='store_true',
                       help='Enable automatic remediation (dry-run mode)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')

    args = parser.parse_args()

    # Configure logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    print(f"🚀 AWS Security Hub Enterprise Analyzer v2.0.0")
    print(f"📍 Region: {args.region}")
    print(f"📅 Analysis Period: Last {args.days} days")
    print(f"🔍 Severity Filter: {', '.join(args.severity)}")
    print("-" * 60)

    try:
        # Initialize analyzer with configuration
        analyzer = SecurityHubAnalyzer(region=args.region, config_file=args.config)

        if args.output == 'comprehensive':
            # Run full enterprise analysis
            return analyzer.run_comprehensive_analysis()

        else:
            # Run legacy simple analysis for backward compatibility
            findings = analyzer.get_findings(severity=args.severity, days_back=args.days)
            stats = analyzer.analyze_findings(findings)

            if args.output == 'json':
                output = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'region': args.region,
                    'stats': dict(stats),
                    'findings_count': len(findings)
                }
                print(json.dumps(output, indent=2, default=str))
            else:
                # Simple text output
                print(f"\nSecurity Hub Findings Summary:")
                print(f"Total findings: {stats['total_findings']}")
                print(f"By severity: {dict(stats['by_severity'])}")
                print(f"By type: {dict(list(stats['by_type'].items())[:5])}")

            # Export findings if requested
            if args.export_format:
                filename = analyzer.export_findings(findings, format=args.export_format)
                print(f"\n📄 Findings exported to: {filename}")

    except KeyboardInterrupt:
        print("\n⚠️  Analysis interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

    return 0

if __name__ == '__main__':
    exit(main())