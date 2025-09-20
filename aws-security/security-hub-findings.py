#!/usr/bin/env python3
"""
AWS Security Hub Findings Analyzer
Retrieves and analyzes Security Hub findings with filtering and reporting capabilities.
"""

import boto3
import json
import argparse
from datetime import datetime, timedelta
from collections import defaultdict

class SecurityHubAnalyzer:
    def __init__(self, region='us-east-1'):
        self.securityhub = boto3.client('securityhub', region_name=region)
        self.region = region

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

        return stats

    def generate_report(self, findings, stats):
        """Generate a formatted security report."""
        report = f"""
=== AWS Security Hub Findings Report ===
Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC
Region: {self.region}

SUMMARY:
Total Active Findings: {stats['total_findings']}

FINDINGS BY SEVERITY:
"""
        for severity, count in sorted(stats['by_severity'].items()):
            report += f"  {severity}: {count}\n"

        report += "\nTOP FINDING TYPES:\n"
        for finding_type, count in sorted(stats['by_type'].items(), key=lambda x: x[1], reverse=True)[:10]:
            report += f"  {finding_type}: {count}\n"

        report += "\nTOP AFFECTED RESOURCE TYPES:\n"
        for resource_type, count in sorted(stats['by_resource'].items(), key=lambda x: x[1], reverse=True)[:10]:
            report += f"  {resource_type}: {count}\n"

        if stats['by_compliance']:
            report += "\nCOMPLIANCE STANDARDS:\n"
            for standard, count in sorted(stats['by_compliance'].items()):
                report += f"  {standard}: {count}\n"

        return report

def main():
    parser = argparse.ArgumentParser(description='Analyze AWS Security Hub findings')
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    parser.add_argument('--severity', nargs='+', default=['HIGH', 'CRITICAL'],
                       choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
                       help='Severity levels to include')
    parser.add_argument('--days', type=int, default=7, help='Days back to analyze')
    parser.add_argument('--output', choices=['text', 'json'], default='text', help='Output format')

    args = parser.parse_args()

    try:
        analyzer = SecurityHubAnalyzer(region=args.region)
        print(f"Retrieving Security Hub findings for region: {args.region}")

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
            report = analyzer.generate_report(findings, stats)
            print(report)

    except Exception as e:
        print(f"Error: {str(e)}")
        return 1

    return 0

if __name__ == '__main__':
    exit(main())