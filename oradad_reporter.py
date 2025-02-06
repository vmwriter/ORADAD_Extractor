from typing import List, Dict
import json
from datetime import datetime, timedelta
import plotly.graph_objects as go
from jinja2 import Template
from .oradad_extractor import OradadExtractor
from .oradad_structures import UserFlags, TrustDirection, TrustType
import os
import csv
import itertools

class OradadReporter:
    def __init__(self, extractor: OradadExtractor):
        self.extractor = extractor

    def generate_summary_stats(self) -> Dict:
        """Generate summary statistics for all domains."""
        stats = {
            'domains': len(self.extractor.domains),
            'total_users': len(self.extractor.all_users),
            'total_groups': len(self.extractor.all_groups),
            'total_computers': len(self.extractor.all_computers),
            'disabled_users': sum(1 for u in self.extractor.all_users if not u.enabled),
            'password_never_expires': sum(1 for u in self.extractor.all_users if u.password_never_expires),
            'inactive_computers': sum(1 for c in self.extractor.all_computers 
                                   if (datetime.now() - c.last_logon).days > 90)
        }
        
        # Add per-domain statistics
        stats['domain_stats'] = {}
        for domain_name, domain in self.extractor.domains.items():
            stats['domain_stats'][domain_name] = {
                'users': len(domain.users),
                'groups': len(domain.groups),
                'computers': len(domain.computers),
                'ous': len(domain.ous),
                'gpos': len(domain.gpos),
                'trusts': len(domain.trusts)
            }
            
        return stats

    def analyze_privileged_access(self) -> Dict:
        """Analyze privileged access in the domain."""
        privileged_groups = {
            'S-1-5-32-544': 'Administrators',
            'S-1-5-32-548': 'Account Operators',
            'S-1-5-32-549': 'Server Operators',
            'S-1-5-32-550': 'Print Operators',
            'S-1-5-32-551': 'Backup Operators',
            'S-1-5-32-552': 'Replicators',
        }
        
        analysis = {
            'privileged_users': [],
            'nested_groups': [],
            'privileged_stats': {
                'total_admins': 0,
                'disabled_admins': 0,
                'nested_groups': 0
            }
        }
        
        # Build group membership map
        group_map = {group.sid: group for group in self.extractor.groups}
        user_map = {user.sid: user for user in self.extractor.users}
        
        def get_nested_members(group_sid: str, seen=None):
            if seen is None:
                seen = set()
            if group_sid in seen:
                return set()
            seen.add(group_sid)
            
            members = set()
            group = group_map.get(group_sid)
            if not group:
                return members
            
            for member in group.members:
                if member in group_map:
                    members.update(get_nested_members(member, seen))
                else:
                    members.add(member)
            return members
        
        # Analyze each privileged group
        for group_sid, group_name in privileged_groups.items():
            if group_sid not in group_map:
                continue
            
            group = group_map[group_sid]
            all_members = get_nested_members(group_sid)
            
            for member_sid in all_members:
                if member_sid in user_map:
                    user = user_map[member_sid]
                    analysis['privileged_users'].append({
                        'name': user.sam_account_name,
                        'group': group_name,
                        'enabled': user.enabled,
                        'last_logon': user.last_logon
                    })
                    analysis['privileged_stats']['total_admins'] += 1
                    if not user.enabled:
                        analysis['privileged_stats']['disabled_admins'] += 1
        
        return analysis

    def generate_security_report(self) -> Dict:
        """Generate a comprehensive security report."""
        report = {
            'high_risk_users': [],
            'stale_computers': [],
            'privileged_groups': [],
            'security_stats': {
                'users_password_never_expires': 0,
                'users_password_not_required': 0,
                'users_smartcard_required': 0,
                'users_trusted_for_delegation': 0,
                'computers_old_os': 0,
                'computers_inactive': 0
            }
        }
        
        # Analyze users
        for user in self.extractor.users:
            if user.user_flags & UserFlags.DONT_EXPIRE_PASSWORD:
                report['security_stats']['users_password_never_expires'] += 1
                
            if user.user_flags & UserFlags.PASSWD_NOTREQD:
                report['security_stats']['users_password_not_required'] += 1
                report['high_risk_users'].append({
                    'name': user.sam_account_name,
                    'risk': 'Password not required'
                })
                
            if user.user_flags & UserFlags.TRUSTED_FOR_DELEGATION:
                report['security_stats']['users_trusted_for_delegation'] += 1
                report['high_risk_users'].append({
                    'name': user.sam_account_name,
                    'risk': 'Trusted for delegation'
                })

        # Analyze computers
        for computer in self.extractor.computers:
            if (datetime.now() - computer.last_logon_timestamp).days > 90:
                report['security_stats']['computers_inactive'] += 1
                report['stale_computers'].append(computer.name)
                
            if computer.operating_system and 'windows' in computer.operating_system.lower():
                if 'xp' in computer.operating_system.lower() or \
                   'server 2003' in computer.operating_system.lower():
                    report['security_stats']['computers_old_os'] += 1

        # Add privileged access analysis
        priv_analysis = self.analyze_privileged_access()
        report['privileged_access'] = priv_analysis
        
        return report

    def generate_html_report(self) -> str:
        """Generate HTML report with visualizations."""
        template = Template('''
            <!DOCTYPE html>
            <html>
            <head>
                <title>ORADAD Analysis Report</title>
                <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
                <style>
                    .risk-high { color: #dc3545; }
                    .risk-medium { color: #ffc107; }
                    .risk-low { color: #28a745; }
                    .summary-card {
                        margin: 10px;
                        padding: 15px;
                        border-radius: 5px;
                        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1 class="mt-4 mb-4">Active Directory Analysis Report</h1>
                    
                    <!-- Summary Statistics -->
                    <div class="row">
                        {% for stat, value in summary_stats.items() %}
                        <div class="col-md-4">
                            <div class="summary-card">
                                <h4>{{ stat|replace('_', ' ')|title }}</h4>
                                <h2>{{ value }}</h2>
                            </div>
                        </div>
                        {% endfor %}
                    </div>

                    <!-- Security Findings -->
                    <h2 class="mt-4">Security Findings</h2>
                    <div class="row">
                        <div class="col-md-6">
                            <h3>High Risk Users</h3>
                            <ul class="list-group">
                            {% for user in security_report.high_risk_users %}
                                <li class="list-group-item">
                                    <strong>{{ user.name }}</strong>
                                    <span class="risk-high">{{ user.risk }}</span>
                                </li>
                            {% endfor %}
                            </ul>
                        </div>
                        <div class="col-md-6">
                            <h3>Stale Computers</h3>
                            <ul class="list-group">
                            {% for computer in security_report.stale_computers %}
                                <li class="list-group-item">{{ computer }}</li>
                            {% endfor %}
                            </ul>
                        </div>
                    </div>

                    <!-- Privileged Access -->
                    <h2 class="mt-4">Privileged Access Analysis</h2>
                    <div class="row">
                        <div class="col-md-12">
                            <table class="table">
                                <thead>
                                    <tr>
                                        <th>Username</th>
                                        <th>Privileged Group</th>
                                        <th>Status</th>
                                        <th>Last Logon</th>
                                    </tr>
                                </thead>
                                <tbody>
                                {% for user in security_report.privileged_access.privileged_users %}
                                    <tr>
                                        <td>{{ user.name }}</td>
                                        <td>{{ user.group }}</td>
                                        <td>{{ "Enabled" if user.enabled else "Disabled" }}</td>
                                        <td>{{ user.last_logon }}</td>
                                    </tr>
                                {% endfor %}
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <!-- Charts -->
                    <div id="userStats"></div>
                    <div id="computerStats"></div>
                </div>

                <script>
                    // User Statistics Chart
                    var userStats = {{ user_stats|tojson|safe }};
                    Plotly.newPlot('userStats', [{
                        values: Object.values(userStats),
                        labels: Object.keys(userStats),
                        type: 'pie',
                        title: 'User Account Statistics'
                    }]);

                    // Computer Statistics Chart
                    var computerStats = {{ computer_stats|tojson|safe }};
                    Plotly.newPlot('computerStats', [{
                        x: Object.keys(computerStats),
                        y: Object.values(computerStats),
                        type: 'bar',
                        title: 'Computer Statistics'
                    }]);
                </script>
            </body>
            </html>
        ''')

        # Prepare data for the template
        summary_stats = self.generate_summary_stats()
        security_report = self.generate_security_report()
        
        # Prepare chart data
        user_stats = {
            'Active Users': len(self.extractor.users) - summary_stats['disabled_users'],
            'Disabled Users': summary_stats['disabled_users'],
            'Password Never Expires': summary_stats['password_never_expires']
        }
        
        computer_stats = {
            'Active': len(self.extractor.computers) - security_report['security_stats']['computers_inactive'],
            'Inactive': security_report['security_stats']['computers_inactive'],
            'Old OS': security_report['security_stats']['computers_old_os']
        }

        return template.render(
            summary_stats=summary_stats,
            security_report=security_report,
            user_stats=user_stats,
            computer_stats=computer_stats
        )

    def generate_json_report(self) -> str:
        """Generate JSON report."""
        report = {
            'summary': self.generate_summary_stats(),
            'security': self.generate_security_report(),
            'privileged_access': self.analyze_privileged_access()
        }
        return json.dumps(report, default=str, indent=2)

    def export_to_csv(self, output_dir: str):
        """Export data to CSV files."""
        os.makedirs(output_dir, exist_ok=True)
        
        # Export users
        with open(os.path.join(output_dir, 'users.csv'), 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Username', 'Enabled', 'Password Never Expires', 'Last Logon'])
            for user in self.extractor.users:
                writer.writerow([
                    user.sam_account_name,
                    user.enabled,
                    user.password_never_expires,
                    user.last_logon
                ])
        
        # Export computers
        with open(os.path.join(output_dir, 'computers.csv'), 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Name', 'OS', 'Last Logon', 'Enabled'])
            for computer in self.extractor.computers:
                writer.writerow([
                    computer.name,
                    computer.operating_system,
                    computer.last_logon,
                    computer.enabled
                ])
        
        # Export groups
        with open(os.path.join(output_dir, 'groups.csv'), 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Name', 'Member Count', 'Group Type', 'Group Scope'])
            for group in self.extractor.groups:
                writer.writerow([
                    group.name,
                    group.member_count,
                    group.group_category,
                    group.group_scope
                ]) 