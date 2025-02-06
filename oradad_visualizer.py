import networkx as nx
from pyvis.network import Network
from typing import Dict
from .oradad_extractor import OradadExtractor, DomainInfo

class OradadVisualizer:
    def __init__(self, extractor: OradadExtractor):
        self.extractor = extractor

    def generate_forest_visualization(self, output_file: str):
        """Generate interactive visualization of the domain forest."""
        # Create network
        net = Network(height="750px", width="100%", bgcolor="#ffffff", 
                     font_color="black")
        
        # Add domains as nodes
        for domain_name, domain in self.extractor.domains.items():
            net.add_node(domain_name, 
                        label=domain_name,
                        title=self._generate_domain_tooltip(domain),
                        color="#97c2fc",
                        size=30)

        # Add trust relationships
        for domain_name, domain in self.extractor.domains.items():
            for trust in domain.trusts:
                if trust.trust_direction in [1, 3]:  # Inbound or Bidirectional
                    net.add_edge(trust.trusted_domain, domain_name,
                               title="Trust Relationship",
                               arrows="to")
                if trust.trust_direction in [2, 3]:  # Outbound or Bidirectional
                    net.add_edge(domain_name, trust.trusted_domain,
                               title="Trust Relationship",
                               arrows="to")

        # Save visualization
        net.save_graph(output_file)

    def generate_ou_tree(self, domain_name: str, output_file: str):
        """Generate OU tree visualization for a specific domain."""
        domain = self.extractor.domains.get(domain_name)
        if not domain:
            return

        net = Network(height="750px", width="100%", bgcolor="#ffffff",
                     font_color="black", directed=True)

        # Add OUs as nodes
        for ou in domain.ous:
            net.add_node(ou.distinguished_name,
                        label=ou.name,
                        title=self._generate_ou_tooltip(ou),
                        color="#97c2fc",
                        size=20)

            # Add parent-child relationships
            parent_dn = self._get_parent_dn(ou.distinguished_name)
            if parent_dn:
                net.add_edge(parent_dn, ou.distinguished_name,
                            arrows="to")

        net.save_graph(output_file)

    def _generate_domain_tooltip(self, domain: DomainInfo) -> str:
        """Generate tooltip content for domain nodes."""
        return f"""
        <b>{domain.name}</b><br>
        Users: {len(domain.users)}<br>
        Computers: {len(domain.computers)}<br>
        Groups: {len(domain.groups)}<br>
        OUs: {len(domain.ous)}<br>
        GPOs: {len(domain.gpos)}<br>
        Trusts: {len(domain.trusts)}
        """

    def _generate_ou_tooltip(self, ou) -> str:
        """Generate tooltip content for OU nodes."""
        return f"""
        <b>{ou.name}</b><br>
        Description: {ou.description or 'N/A'}<br>
        GPO Links: {len(ou.gpo_links)}<br>
        Protected: {'Yes' if ou.protected_from_deletion else 'No'}
        """

    def _get_parent_dn(self, dn: str) -> str:
        """Extract parent DN from distinguished name."""
        parts = dn.split(',')
        if len(parts) > 1:
            return ','.join(parts[1:])
        return None 