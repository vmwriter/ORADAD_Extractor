from typing import List, Dict
from datetime import datetime
from .oradad_extractor import OradadExtractor

class SchemaAnalyzer:
    def __init__(self, extractor: OradadExtractor):
        self.extractor = extractor

    def analyze_schema_changes(self) -> Dict:
        """Analyze schema modifications across all domains."""
        analysis = {
            'total_modifications': 0,
            'recent_changes': [],
            'custom_classes': [],
            'custom_attributes': [],
            'domains': {}
        }

        for domain_name, domain in self.extractor.domains.items():
            domain_analysis = self._analyze_domain_schema(domain)
            analysis['domains'][domain_name] = domain_analysis
            analysis['total_modifications'] += domain_analysis['total_changes']
            analysis['recent_changes'].extend(domain_analysis['recent_changes'])
            analysis['custom_classes'].extend(domain_analysis['custom_classes'])
            analysis['custom_attributes'].extend(domain_analysis['custom_attributes'])

        # Sort recent changes by date
        analysis['recent_changes'].sort(key=lambda x: x['modified'], reverse=True)
        
        return analysis

    def _analyze_domain_schema(self, domain) -> Dict:
        """Analyze schema modifications for a single domain."""
        analysis = {
            'total_changes': len(domain.schema),
            'recent_changes': [],
            'custom_classes': [],
            'custom_attributes': []
        }

        thirty_days_ago = datetime.now() - timedelta(days=30)

        for schema_entry in domain.schema:
            # Track recent changes
            if schema_entry['modified'] > thirty_days_ago:
                analysis['recent_changes'].append({
                    'name': schema_entry['name'],
                    'modified': schema_entry['modified'],
                    'type': 'class' if 'subClassOf' in schema_entry else 'attribute'
                })

            # Track custom schema elements
            if self._is_custom_schema(schema_entry):
                if 'subClassOf' in schema_entry:
                    analysis['custom_classes'].append(schema_entry)
                else:
                    analysis['custom_attributes'].append(schema_entry)

        return analysis

    def _is_custom_schema(self, schema_entry: Dict) -> bool:
        """Determine if a schema entry is custom (non-default)."""
        # Check for common Microsoft OIDs
        if 'schemaIDGUID' in schema_entry:
            oid = schema_entry['schemaIDGUID']
            return not (oid.startswith('1.2.840.113556.1.5') or  # Default classes
                       oid.startswith('1.2.840.113556.1.4'))     # Default attributes
        return False

    def generate_schema_report(self) -> str:
        """Generate a detailed schema analysis report."""
        analysis = self.analyze_schema_changes()
        
        report = []
        report.append("# Schema Analysis Report\n")
        
        report.append(f"Total Schema Modifications: {analysis['total_modifications']}\n")
        
        if analysis['recent_changes']:
            report.append("\n## Recent Changes (Last 30 Days)\n")
            for change in analysis['recent_changes']:
                report.append(f"- {change['name']} ({change['type']}) - "
                            f"Modified: {change['modified'].strftime('%Y-%m-%d')}")

        for domain_name, domain_analysis in analysis['domains'].items():
            report.append(f"\n## Domain: {domain_name}\n")
            report.append(f"Total Changes: {domain_analysis['total_changes']}\n")
            
            if domain_analysis['custom_classes']:
                report.append("\n### Custom Classes\n")
                for cls in domain_analysis['custom_classes']:
                    report.append(f"- {cls['name']}")
            
            if domain_analysis['custom_attributes']:
                report.append("\n### Custom Attributes\n")
                for attr in domain_analysis['custom_attributes']:
                    report.append(f"- {attr['name']}")

        return '\n'.join(report) 