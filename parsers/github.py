import json
import logging
from pathlib import Path
from typing import Dict, List, Any

from secrethound import SecretsParser, SecretFinding

logger = logging.getLogger(__name__)


class GitHubSecretScannerParser(SecretsParser):
    """Parser for GitHub Secret Scanning API output"""

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
        secret_type = data.get('secret_type_display_name') or data.get('secret_type', 'Unknown')
        secret_value = data.get('secret', '')
        state = data.get('state', 'unknown')
        created_at = data.get('created_at')
        html_url = data.get('html_url', '')

        # Extract repository information from URL
        repository = None
        if html_url:
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
