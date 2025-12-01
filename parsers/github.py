import json
import logging
import base64
from pathlib import Path
from typing import Dict, List, Any

from secrethound import SecretsParser, SecretFinding

logger = logging.getLogger(__name__)


class GitHubSecretScannerParser(SecretsParser):
    """Parser for GitHub Secret Scanning API output"""

    def __init__(self, redact_secrets: bool = True, custom_mappings=None, taxonomy=None,
                 scanner_name: str = "github", organization_id: str = None):
        """
        Initialize the GitHub parser

        Args:
            redact_secrets: If True, redact actual secret values in output
            custom_mappings: Custom mappings from secret types to BloodHound nodes
            taxonomy: Taxonomy instance for rule ID lookups
            scanner_name: Name of scanner for taxonomy lookups
            organization_id: Optional GitHub organization ID for GitHound-compatible IDs
        """
        super().__init__(redact_secrets, custom_mappings, taxonomy, scanner_name)
        self.organization_id = organization_id

    def generate_githound_id(self, org_id: str, repo_node_id: str, alert_number: int) -> str:
        """
        Generate GitHound-compatible alert ID

        Matches the format from GitHound PowerShell:
        $alertId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("SSA_{org.id}_{repo.node_id}_{alert.number}"))

        Args:
            org_id: GitHub organization ID
            repo_node_id: Repository node_id (e.g., "MDEwOlJlcG9zaXRvcnk...")
            alert_number: Alert number

        Returns:
            Base64-encoded alert ID matching GitHound format
        """
        alert_string = f"SSA_{org_id}_{repo_node_id}_{alert_number}"
        return base64.b64encode(alert_string.encode('ascii')).decode('ascii')

    def parse_file(self, file_path: Path) -> List[SecretFinding]:
        """Parse GitHub Secret Scanning API JSON file"""
        logger.info(f"Parsing GitHub Secret Scanning output from {file_path}")

        with open(file_path, 'r') as f:
            data = json.load(f)

        # Handle both single alert and array of alerts
        if isinstance(data, list):
            findings = []
            for item in data:
                findings.extend(self.parse_json(item))
            return findings
        else:
            return self.parse_json(data)

    def parse_json(self, data: Dict[str, Any]) -> List[SecretFinding]:
        """
        Parse GitHub Secret Scanning API JSON data

        Expected format from GitHub API:
        {
          "number": 2,
          "created_at": "2020-11-06T18:48:51Z",
          "url": "https://api.github.com/repos/owner/repo/secret-scanning/alerts/2",
          "html_url": "https://github.com/owner/repo/security/secret-scanning/2",
          "state": "resolved",
          "secret_type": "adafruit_io_key",
          "secret_type_display_name": "Adafruit IO Key",
          "secret": "aio_XXXXXXXXXXXXXXXXXXXXXXXXXXXX",
          "repository": {  # Present in org-level alerts
            "id": 123456,
            "node_id": "MDEwOlJlcG9zaXRvcnkxMjM0NTY=",
            "name": "repo",
            "full_name": "owner/repo",
            "html_url": "https://github.com/owner/repo",
            ...
          },
          "first_location_detected": {
            "path": "/example/secrets.txt",
            "start_line": 1,
            "end_line": 1,
            "start_column": 1,
            "end_column": 64,
            "blob_sha": "af5626b4a114abcb82d63db7c8082c3c4756e51b",
            "commit_sha": "f14d7debf9775f957cf4f1e8176da0786431f72b"
          },
          ...
        }
        """
        findings = []

        # Extract alert metadata
        alert_number = data.get('number')
        # Use secret_type (machine-readable) for taxonomy lookup (e.g., "adafruit_io_key")
        secret_type = data.get('secret_type', 'unknown')
        # secret_type_display_name is human-readable (e.g., "Adafruit IO Key")
        secret_type_display_name = data.get('secret_type_display_name', '')
        secret_value = data.get('secret', '')
        state = data.get('state', 'unknown')
        created_at = data.get('created_at')
        html_url = data.get('html_url', '')

        # Extract repository information - prioritize repository object (org-level alerts)
        repository = None
        repo_node_id = None
        repo_id = None
        repo_object = data.get('repository', {})

        if repo_object:
            # Org-level alerts include full repository object
            repo_node_id = repo_object.get('node_id')
            repo_id = repo_object.get('id')
            repository = repo_object.get('html_url')
            logger.debug(f"Found repository object: node_id={repo_node_id}, id={repo_id}, url={repository}")
        elif html_url:
            # Repo-level alerts - extract from URL
            # Extract repo from URL like: https://github.com/owner/repo/security/secret-scanning/1
            parts = html_url.split('github.com/')
            if len(parts) > 1:
                repo_parts = parts[1].split('/security/')
                if repo_parts:
                    repository = f"https://github.com/{repo_parts[0]}"

        # Get first location detected
        first_location = data.get('first_location_detected', {})

        # Build metadata
        metadata = {
            'source': 'github_secret_scanner',
            'secret_type': secret_type,  # Store machine-readable type
            'secret_type_display_name': secret_type_display_name,  # Store human-readable name
            'alert_number': alert_number,
            'state': state,
            'created_at': created_at,
            'html_url': html_url,
            'resolution': data.get('resolution'),
            'resolved_at': data.get('resolved_at'),
            'validity': data.get('validity'),
            'publicly_leaked': data.get('publicly_leaked'),
            'multi_repo': data.get('multi_repo'),
        }

        # Add GitHound-related metadata if available
        if repo_node_id:
            metadata['repository_node_id'] = repo_node_id
        if repo_id:
            metadata['repository_id'] = repo_id

        # Extract organization ID from repository owner if available, or use provided org ID
        org_id = None
        if repo_object:
            owner = repo_object.get('owner', {})
            if owner:
                org_id = owner.get('id')
                if org_id:
                    metadata['organization_id'] = org_id

        # Use provided organization ID if not found in data
        if not org_id and self.organization_id:
            org_id = self.organization_id
            metadata['organization_id'] = org_id
            logger.debug(f"Using provided organization ID: {org_id}")

        # Generate GitHound-compatible ID if we have all required components
        if org_id and repo_node_id and alert_number:
            githound_id = self.generate_githound_id(str(org_id), repo_node_id, alert_number)
            metadata['githound_id'] = githound_id
            logger.debug(f"Generated GitHound ID: {githound_id} for alert {alert_number}")
        else:
            missing = []
            if not org_id:
                missing.append('organization_id')
            if not repo_node_id:
                missing.append('repository_node_id')
            if not alert_number:
                missing.append('alert_number')
            logger.debug(f"Cannot generate GitHound ID, missing: {', '.join(missing)}")

        # Add first location details if available
        if first_location:
            metadata.update({
                'blob_sha': first_location.get('blob_sha'),
                'blob_url': first_location.get('blob_url'),
                'start_column': first_location.get('start_column'),
                'end_column': first_location.get('end_column'),
                'end_line': first_location.get('end_line'),
            })

            finding = SecretFinding(
                secret_type=secret_type,
                secret_value=secret_value,
                file_path=first_location.get('path'),
                line_number=first_location.get('start_line'),
                repository=repository,
                commit=first_location.get('commit_sha'),
                metadata=metadata
            )
        else:
            # No location data - create a finding with what we have
            finding = SecretFinding(
                secret_type=secret_type,
                secret_value=secret_value,
                repository=repository,
                metadata=metadata
            )

        findings.append(finding)
        return findings
