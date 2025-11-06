#!/usr/bin/env python3
"""
SecretHound - BloodHound OpenGraph Extension for Secrets

SecretHound converts secret scanning results from various sources (NoseyParker, TruffleHog, Nemesis)
into BloodHound OpenGraph format for attack path visualization and analysis.

GitHub: https://github.com/C0KERNEL/SecretHound
"""

import json
import hashlib
import logging
import argparse
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field

try:
    from bhopengraph.OpenGraph import OpenGraph
    from bhopengraph.Node import Node
    from bhopengraph.Edge import Edge
    from bhopengraph.Properties import Properties
except ImportError:
    print("Error: bhopengraph library not found. Install with: pip install bhopengraph")
    exit(1)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class SecretMapping:
    """Configuration for mapping secrets to BloodHound nodes"""
    pattern: str  # Regex pattern or rule name to match
    node_kind: str  # BloodHound node kind (e.g., AWSBase, AZBase, GCPBase, GHBase)
    color: Optional[str] = None  # Icon color for BloodHound visualization


@dataclass
class SecretFinding:
    """Represents a discovered secret"""
    secret_type: str
    secret_value: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    repository: Optional[str] = None
    commit: Optional[str] = None
    author: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class SecretsParser(ABC):
    """Abstract base class for parsing secret scanner output"""
    
    def __init__(self, redact_secrets: bool = True, custom_mappings: Optional[List[SecretMapping]] = None):
        """
        Initialize the parser
        
        Args:
            redact_secrets: If True, redact actual secret values in output
            custom_mappings: Custom mappings from secret types to BloodHound nodes
        """
        self.redact_secrets = redact_secrets
        self.custom_mappings = custom_mappings or []
        self.default_mappings = self._get_default_mappings()
        
    def _get_default_mappings(self) -> List[SecretMapping]:
        """Get default secret type to node kind mappings (empty unless custom mappings provided via -c)"""
        return []
    
    def get_node_kind_for_secret(self, secret_type: str) -> str:
        """
        Determine the appropriate BloodHound node kind for a secret type

        Args:
            secret_type: The type of secret discovered

        Returns:
            BloodHound node kind string
        """
        import re

        # Check custom mappings first (only applies when -c flag is used)
        for mapping in self.custom_mappings:
            if re.search(mapping.pattern, secret_type, re.IGNORECASE):
                return mapping.node_kind

        # Default to Secret if no match
        return "Secret"
    
    def redact_value(self, value: str) -> str:
        """Redact a secret value while keeping some context"""
        if not self.redact_secrets:
            return value
        
        if len(value) <= 8:
            return "***REDACTED***"
        
        # Show first 4 and last 4 characters
        return f"{value[:4]}...{value[-4:]}"
    
    def generate_node_id(self, *components: str) -> str:
        """Generate a unique node ID from components"""
        combined = "|".join(str(c) for c in components)
        return hashlib.sha256(combined.encode()).hexdigest()
    
    @abstractmethod
    def parse_file(self, file_path: Path) -> List[SecretFinding]:
        """
        Parse a secret scanner output file
        
        Args:
            file_path: Path to the scanner output file
            
        Returns:
            List of SecretFinding objects
        """
        pass
    
    @abstractmethod
    def parse_json(self, data: Dict[str, Any]) -> List[SecretFinding]:
        """
        Parse JSON data from the scanner
        
        Args:
            data: JSON data dictionary
            
        Returns:
            List of SecretFinding objects
        """
        pass




class BloodHoundGraphBuilder:
    """Builds BloodHound OpenGraph from secret findings"""

    def __init__(self, source_kind: str = "StargateNetwork"):
        """
        Initialize the graph builder

        Args:
            source_kind: Source kind for the OpenGraph
        """
        self.graph = OpenGraph(source_kind=source_kind)
        self.created_nodes: Set[str] = set()
        self.created_repositories: Set[str] = set()

    def _is_github_repository(self, repository_path: str) -> bool:
        """Determine if a repository path is a GitHub repository"""
        if not repository_path:
            return False
        return 'github.com' in repository_path.lower()

    def _get_repository_name(self, repository_path: str) -> str:
        """Extract a clean repository name from the path"""
        if not repository_path:
            return "unknown"

        # Handle GitHub URLs
        if 'github.com/' in repository_path:
            parts = repository_path.split('github.com/')
            if len(parts) > 1:
                return parts[1].strip('/')

        # Handle local paths - just take the last part
        return repository_path.split('/')[-1]

    def _get_repository_id(self, repository_path: str) -> str:
        """Get repository node ID from path"""
        return hashlib.sha256(repository_path.encode()).hexdigest()

    def _create_repository_node(self, repository_path: str) -> str:
        """
        Create a repository node and return its ID

        Args:
            repository_path: Path or URL to the repository

        Returns:
            Repository node ID
        """
        if not repository_path:
            return None

        repo_id = self._get_repository_id(repository_path)

        # If repository node already exists, just return the ID
        if repository_path in self.created_repositories:
            return repo_id

        # Determine node kinds based on repository type
        is_github = self._is_github_repository(repository_path)
        if is_github:
            node_kinds = ["GHBase", "GHRepository"]
        else:
            node_kinds = ["Repository"]

        # Create repository node
        repo_name = self._get_repository_name(repository_path)
        props_dict = {
            'objectid': repo_id,
            'name': repo_name,
            'displayname': repo_name,
            'repository_path': repository_path,
        }

        repo_node = Node(
            id=repo_id,
            kinds=node_kinds,
            properties=Properties(**props_dict)
        )

        self.graph.add_node(repo_node)
        self.created_repositories.add(repository_path)
        logger.debug(f"Created repository node: {repo_id} ({', '.join(node_kinds)})")

        return repo_id

    def add_secret_finding(self, finding: SecretFinding, parser: SecretsParser):
        """
        Add a secret finding to the BloodHound graph

        Args:
            finding: SecretFinding object
            parser: SecretsParser instance for mapping logic
        """
        # Generate secret node ID
        secret_id = parser.generate_node_id(
            finding.secret_type,
            finding.secret_value if not parser.redact_secrets else "redacted",
            finding.repository or "",
            finding.file_path or ""
        )

        # Create secret node if it doesn't exist
        if secret_id not in self.created_nodes:
            # Prepare node properties
            props_dict = {
                'objectid': secret_id,
                'name': f"{finding.secret_type}_{secret_id[:8]}",
                'displayname': f"{finding.secret_type}",
                'secret_type': finding.secret_type,
            }

            # Add non-sensitive metadata
            if finding.file_path:
                props_dict['file_path'] = finding.file_path
            if finding.repository:
                props_dict['repository'] = finding.repository
            if finding.commit:
                props_dict['commit'] = finding.commit
            if finding.author:
                props_dict['author'] = finding.author
            if finding.line_number:
                props_dict['line_number'] = finding.line_number

            # Add metadata
            for key, value in finding.metadata.items():
                if key not in ['password', 'secret', 'token', 'key']:
                    props_dict[key] = str(value)

            # Add redacted or full secret value based on configuration
            if not parser.redact_secrets:
                props_dict['secret_value'] = finding.secret_value
            else:
                props_dict['secret_value_redacted'] = parser.redact_value(finding.secret_value)

            # Determine node kind based on mappings (if -c flag was used)
            node_kind = parser.get_node_kind_for_secret(finding.secret_type)

            # Build kinds list - always include "Secret", plus the mapped kind if different
            if node_kind == "Secret":
                kinds = ["Secret"]
            else:
                kinds = ["Secret", node_kind]

            # Create secret node
            secret_node = Node(
                id=secret_id,
                kinds=kinds,
                properties=Properties(**props_dict)
            )

            self.graph.add_node(secret_node)
            self.created_nodes.add(secret_id)
            logger.debug(f"Created secret node: {secret_id}")

        # Create repository node and edge if repository information exists
        if finding.repository:
            repo_id = self._create_repository_node(finding.repository)

            if repo_id:
                # Create edge from repository to secret
                edge = Edge(
                    start_node=repo_id,
                    end_node=secret_id,
                    kind="ContainsCredentialsFor"
                )

                self.graph.add_edge(edge)
                logger.debug(f"Created edge: {repo_id} -> {secret_id}")
        
    def save_to_file(self, output_path: Path):
        """
        Save the graph to a JSON file

        Args:
            output_path: Path to output JSON file
        """
        logger.info(f"Saving BloodHound graph to {output_path}")

        # Use export_to_file method from bhopengraph
        self.graph.export_to_file(str(output_path))

        total_nodes = len(self.created_nodes) + len(self.created_repositories)
        logger.info(f"Successfully saved graph with {len(self.created_repositories)} repositories, "
                   f"{len(self.created_nodes)} secrets ({total_nodes} total nodes)")


def load_custom_mappings(config_path: Path) -> List[SecretMapping]:
    """
    Load custom secret mappings from a JSON config file
    
    Args:
        config_path: Path to JSON configuration file
        
    Returns:
        List of SecretMapping objects
    """
    logger.info(f"Loading custom mappings from {config_path}")
    
    with open(config_path, 'r') as f:
        config = json.load(f)
    
    mappings = []
    for item in config.get('mappings', []):
        mapping = SecretMapping(
            pattern=item['pattern'],
            node_kind=item['node_kind'],
            color=item.get('color')
        )
        mappings.append(mapping)

    return mappings


def main():
    """Main entry point"""
    # Import parsers here to avoid circular import issues
    from parsers import GitHubSecretScannerParser, NoseyParkerParser, TruffleHogParser, NemesisParser

    parser = argparse.ArgumentParser(
        description='SecretHound - Convert secret scanner output to BloodHound OpenGraph format',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
SecretHound is a BloodHound OpenGraph extension for secrets.

Examples:
  # Fetch and parse GitHub Secret Scanning alerts (requires GitHub token)
  python secrethound.py -t github --github-owner myorg --github-repo myrepo -o secrets.json

  # Parse GitHub Secret Scanning JSON export
  python secrethound.py -t github -i github_alerts.json -o secrets.json

  # Parse NoseyParker output
  python secrethound.py -t noseyparker -i noseyparker_report.json -o secrets.json

  # Parse TruffleHog output without redaction
  python secrethound.py -t trufflehog -i trufflehog_output.jsonl -o secrets.json --no-redact

  # Use custom mappings
  python secrethound.py -t noseyparker -i report.json -o output.json -c mappings.json

  # Parse Nemesis export
  python secrethound.py -t nemesis -i nemesis_export.json -o secrets.json

Compatible with various OpenGraph extensions.
Visit https://github.com/C0KERNEL/SecretHound for more information.
        """
    )

    parser.add_argument(
        '-t', '--type',
        choices=['github', 'noseyparker', 'trufflehog', 'nemesis'],
        required=True,
        help='Type of secret scanner output'
    )
    
    parser.add_argument(
        '-i', '--input',
        type=Path,
        help='Input file path (JSON or JSONL) - not required for GitHub API mode'
    )

    parser.add_argument(
        '-o', '--output',
        type=Path,
        required=True,
        help='Output BloodHound JSON file path'
    )
    
    parser.add_argument(
        '-c', '--config',
        type=Path,
        help='Custom mappings configuration file (JSON)'
    )
    
    parser.add_argument(
        '--no-redact',
        action='store_true',
        help='Do not redact secret values (DANGEROUS - use with caution!)'
    )
    
    parser.add_argument(
        '--source-kind',
        default='StargateNetwork',
        help='Source kind for BloodHound OpenGraph (default: StargateNetwork)'
    )
    
    parser.add_argument(
        '--nemesis-url',
        help='Nemesis API URL (for nemesis type)'
    )

    parser.add_argument(
        '--nemesis-api-key',
        help='Nemesis API key (for nemesis type)'
    )

    parser.add_argument(
        '--github-token',
        help='GitHub personal access token (for github type API mode, or GITHUB_TOKEN env var)'
    )

    parser.add_argument(
        '--github-owner',
        help='GitHub repository owner/organization (for github type API mode)'
    )

    parser.add_argument(
        '--github-repo',
        help='GitHub repository name (for github type API mode)'
    )

    parser.add_argument(
        '--github-include-locations',
        action='store_true',
        default=True,
        help='Include location details for GitHub alerts (default: True)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # Configure logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Load custom mappings if provided
    custom_mappings = None
    if args.config:
        custom_mappings = load_custom_mappings(args.config)
    
    # Create appropriate parser
    redact_secrets = not args.no_redact

    if args.type == 'github':
        # Check if using API mode or file mode
        github_token = args.github_token or os.environ.get('GITHUB_TOKEN')

        secret_parser = GitHubSecretScannerParser(
            github_token=github_token,
            redact_secrets=redact_secrets,
            custom_mappings=custom_mappings
        )
    elif args.type == 'noseyparker':
        secret_parser = NoseyParkerParser(
            redact_secrets=redact_secrets,
            custom_mappings=custom_mappings
        )
    elif args.type == 'trufflehog':
        secret_parser = TruffleHogParser(
            redact_secrets=redact_secrets,
            custom_mappings=custom_mappings
        )
    elif args.type == 'nemesis':
        secret_parser = NemesisParser(
            nemesis_url=args.nemesis_url,
            api_key=args.nemesis_api_key,
            redact_secrets=redact_secrets,
            custom_mappings=custom_mappings
        )
    else:
        logger.error(f"Unsupported scanner type: {args.type}")
        return 1

    try:
        # Handle GitHub API mode
        if args.type == 'github' and args.github_owner and args.github_repo:
            logger.info(f"Fetching GitHub Secret Scanning alerts from {args.github_owner}/{args.github_repo}")
            findings = secret_parser.fetch_from_github_api(
                owner=args.github_owner,
                repo=args.github_repo,
                include_locations=args.github_include_locations
            )
            logger.info(f"Found {len(findings)} secrets")
        # Handle file input mode
        elif args.input:
            logger.info(f"Processing {args.type} output from {args.input}")
            findings = secret_parser.parse_file(args.input)
            logger.info(f"Found {len(findings)} secrets")
        else:
            logger.error("Either --input file or (--github-owner and --github-repo) must be provided")
            return 1
        
        # Build BloodHound graph
        graph_builder = BloodHoundGraphBuilder(source_kind=args.source_kind)
        
        for finding in findings:
            graph_builder.add_secret_finding(finding, secret_parser)
        
        # Save output
        graph_builder.save_to_file(args.output)
        
        logger.info("Conversion completed successfully!")
        return 0
        
    except Exception as e:
        logger.error(f"Error during conversion: {e}", exc_info=True)
        return 1


if __name__ == '__main__':
    exit(main())
