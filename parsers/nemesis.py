import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any

from secrethound import SecretsParser, SecretFinding

logger = logging.getLogger(__name__)


class NemesisParser(SecretsParser):
    """Parser for Nemesis API data via Jupyter notebook"""
    
    def __init__(self, nemesis_url: Optional[str] = None, 
                 api_key: Optional[str] = None,
                 *args, **kwargs):
        """
        Initialize Nemesis parser
        
        Args:
            nemesis_url: URL of the Nemesis API
            api_key: API key for authentication
        """
        super().__init__(*args, **kwargs)
        self.nemesis_url = nemesis_url
        self.api_key = api_key
    
    def parse_file(self, file_path: Path) -> List[SecretFinding]:
        """Parse Nemesis export JSON file"""
        logger.info(f"Parsing Nemesis output from {file_path}")
        
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        return self.parse_json(data)
    
    def parse_json(self, data: Dict[str, Any]) -> List[SecretFinding]:
        """Parse Nemesis JSON data"""
        findings = []

        # Nemesis returns a list of findings from the noseyparker enrichment module
        if isinstance(data, list):
            for item in data:
                findings.extend(self._parse_nemesis_item(item))
        elif isinstance(data, dict):
            # Single item
            findings.extend(self._parse_nemesis_item(data))

        return findings

    def _parse_nemesis_item(self, item: Dict[str, Any]) -> List[SecretFinding]:
        """Parse a single Nemesis finding item"""
        findings = []

        # Extract the raw_data which contains the match information
        raw_data = item.get('raw_data', {})
        match_data = raw_data.get('match', {})

        # Extract rule name (this maps to NoseyParker rule names)
        rule_name = match_data.get('rule_name', 'Unknown')

        # Extract the matched secret content
        matched_content = match_data.get('matched_content')

        if not matched_content:
            return findings

        # Extract location information
        location = match_data.get('location', {})
        line_number = location.get('line')
        column = location.get('column')

        # Extract file information from files_enriched
        files_enriched = item.get('files_enriched', {})
        file_path = files_enriched.get('path') or match_data.get('file_path')

        # Extract repository and project information
        repository = files_enriched.get('source')
        project = files_enriched.get('project')
        agent_id = files_enriched.get('agent_id')

        # Extract triage information (true_positive, false_positive, etc.)
        triage_histories = item.get('finding_triage_histories', [])
        triage_status = None
        if triage_histories:
            # Get the most recent triage
            latest_triage = triage_histories[-1]
            triage_status = latest_triage.get('value')

        finding = SecretFinding(
            secret_type=rule_name,
            secret_value=matched_content,
            file_path=file_path,
            line_number=line_number,
            repository=repository,
            metadata={
                'source': 'nemesis',
                'origin_name': item.get('origin_name', 'noseyparker'),
                'finding_id': item.get('finding_id'),
                'category': item.get('category'),
                'severity': item.get('severity'),
                'rule_type': match_data.get('rule_type'),
                'column': column,
                'project': project,
                'agent_id': agent_id,
                'git_commit': match_data.get('git_commit'),
                'triage_status': triage_status,
            }
        )

        findings.append(finding)
        return findings
    
    #TODO: nemesis users can change the triage_status. when this happens, it is no longer a true
    # positive and should not make it into our graph. graphql query in fetch_nemesis_findings.py
    # works for manual uploads. ideal state: 
    #     graphql subscription -> nemesis api -> secrethound processing -> bloodhound api
    # secrets should populate in real-time.
    # not sure how i want to do this yet...
    # ideas: 
    #  1 could use a unique id from nemesis as the node's object id in bloodhound.
    #  2 would be really cool to use nemesis eventing from triage_status 
    #  to create nodes initially and update kind when they get marked as true pos.
    #  initial state could be a gray secret; once it is marked true pos, make it gold.
    #  if it gets marked as needs review, that should also reflect in some way. 

    def fetch_from_api(self) -> List[SecretFinding]:
        """Fetch secrets from Nemesis API via graphql subscription"""
        if not self.nemesis_url or not self.api_key:
            raise ValueError("Nemesis URL and API key required for API access")
        
        try:
            import requests
        except ImportError:
            raise ImportError("requests library required for Nemesis API access")
        
        logger.info(f"Fetching data from Nemesis API: {self.nemesis_url}")
        
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
        
        #TODO: use graphql subscription to make a request like in fetch_nemesis_findings.py
        response = requests.get(
            f"{self.nemesis_url}/api/credentials",
            headers=headers,
            verify=True
        )
        response.raise_for_status()
        
        data = response.json()
        return self.parse_json(data)
