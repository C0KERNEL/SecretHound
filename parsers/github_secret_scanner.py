import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional

from secrethound import SecretsParser, SecretFinding

logger = logging.getLogger(__name__)


class GitHubSecretScannerParser(SecretsParser):
    """Parser for GitHub Secret Scanning API output"""

    def __init__(self, github_token: Optional[str] = None, *args, **kwargs):
        """
        Initialize GitHub Secret Scanner parser

        Args:
            github_token: GitHub personal access token for API access
        """
        super().__init__(*args, **kwargs)
        self.github_token = github_token

    def parse_file(self, file_path: Path) -> List[SecretFinding]:
        """Parse GitHub Secret Scanning API JSON file"""
        logger.info(f"Parsing GitHub Secret Scanning output from {file_path}")

        with open(file_path, 'r') as f:
            content = f.read().strip()

            # Try to parse as JSON array first
            try:
                data = json.loads(content)
                if isinstance(data, list):
                    findings = []
                    for item in data:
                        findings.extend(self.parse_json(item))
                    return findings
                else:
                    return self.parse_json(data)
            except json.JSONDecodeError:
                # Try parsing as JSONL
                findings = []
                for line in content.split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            findings.extend(self.parse_json(data))
                        except json.JSONDecodeError as e:
                            logger.warning(f"Failed to parse line: {e}")
                return findings

    def parse_json(self, data: Dict[str, Any]) -> List[SecretFinding]:
        """
        Parse GitHub Secret Scanning API JSON data

        Expected format from GitHub API:
        {
          "number": 1,
          "created_at": "2020-01-01T00:00:00Z",
          "url": "https://api.github.com/repos/owner/repo/secret-scanning/alerts/1",
          "html_url": "https://github.com/owner/repo/security/secret-scanning/1",
          "state": "open",
          "secret_type": "github_personal_access_token",
          "secret_type_display_name": "GitHub Personal Access Token",
          "secret": "ghp_xxxxx",
          "locations": [...]  # Optional, may be included
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

        # Check if locations are included in the response
        locations = data.get('locations', [])

        if locations:
            # Process each location
            for location in locations:
                location_type = location.get('type')
                details = location.get('details', {})

                if location_type == 'commit':
                    finding = SecretFinding(
                        secret_type=secret_type,
                        secret_value=secret_value,
                        file_path=details.get('path'),
                        line_number=details.get('start_line'),
                        repository=repository,
                        commit=details.get('commit_sha'),
                        metadata={
                            'source': 'github_secret_scanner',
                            'alert_number': alert_number,
                            'state': state,
                            'created_at': created_at,
                            'html_url': html_url,
                            'blob_sha': details.get('blob_sha'),
                            'start_column': details.get('start_column'),
                            'end_column': details.get('end_column'),
                        }
                    )
                    findings.append(finding)
        else:
            # No location data - create a finding with what we have
            finding = SecretFinding(
                secret_type=secret_type,
                secret_value=secret_value,
                repository=repository,
                metadata={
                    'source': 'github_secret_scanner',
                    'alert_number': alert_number,
                    'state': state,
                    'created_at': created_at,
                    'html_url': html_url,
                    'resolution': data.get('resolution'),
                    'resolved_at': data.get('resolved_at'),
                }
            )
            findings.append(finding)

        return findings

    def fetch_from_github_api(self, owner: str, repo: str,
                              include_locations: bool = True) -> List[SecretFinding]:
        """
        Fetch secret scanning alerts from GitHub API

        Args:
            owner: Repository owner (username or organization)
            repo: Repository name
            include_locations: Whether to fetch location details for each alert

        Returns:
            List of SecretFinding objects

        Raises:
            ImportError: If requests library is not installed
            ValueError: If GitHub token is not provided
        """
        if not self.github_token:
            raise ValueError("GitHub token required for API access. "
                           "Provide via github_token parameter or GITHUB_TOKEN environment variable")

        try:
            import requests
        except ImportError:
            raise ImportError("requests library required for GitHub API access. "
                            "Install with: pip install requests")

        logger.info(f"Fetching secret scanning alerts from GitHub: {owner}/{repo}")

        headers = {
            'Authorization': f'token {self.github_token}',
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28'
        }

        # Fetch all secret scanning alerts
        alerts_url = f"https://api.github.com/repos/{owner}/{repo}/secret-scanning/alerts"

        all_alerts = []
        page = 1
        per_page = 100

        while True:
            response = requests.get(
                alerts_url,
                headers=headers,
                params={'state': 'open', 'per_page': per_page, 'page': page}
            )
            response.raise_for_status()

            alerts = response.json()
            if not alerts:
                break

            # Optionally fetch locations for each alert
            if include_locations:
                for alert in alerts:
                    locations_url = alert.get('locations_url')
                    if locations_url:
                        loc_response = requests.get(locations_url, headers=headers)
                        if loc_response.status_code == 200:
                            alert['locations'] = loc_response.json()

            all_alerts.extend(alerts)

            # Check if there are more pages
            if len(alerts) < per_page:
                break
            page += 1

        logger.info(f"Fetched {len(all_alerts)} secret scanning alerts")

        # Parse all alerts
        findings = []
        for alert in all_alerts:
            findings.extend(self.parse_json(alert))

        return findings
