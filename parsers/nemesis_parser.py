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
        
        # Nemesis stores extracted credentials in various formats
        # This is a generalized parser - adjust based on actual Nemesis output
        
        if isinstance(data, list):
            for item in data:
                findings.extend(self._parse_nemesis_item(item))
        elif isinstance(data, dict):
            findings.extend(self._parse_nemesis_item(data))
        
        return findings
    
    def _parse_nemesis_item(self, item: Dict[str, Any]) -> List[SecretFinding]:
        """Parse a single Nemesis item"""
        findings = []
        
        # Handle different Nemesis data types
        credential_type = item.get('type', item.get('credential_type', 'Unknown'))
        
        # Extract credential data
        username = item.get('username', item.get('user'))
        password = item.get('password', item.get('secret'))
        domain = item.get('domain')
        source_file = item.get('source_file', item.get('file_path'))
        
        if password:
            finding = SecretFinding(
                secret_type=credential_type,
                secret_value=password,
                file_path=source_file,
                metadata={
                    'source': 'nemesis',
                    'username': username,
                    'domain': domain,
                    'credential_type': credential_type,
                    **{k: v for k, v in item.items() if k not in 
                       ['password', 'secret', 'username', 'user', 'type', 'credential_type']}
                }
            )
            findings.append(finding)
        
        return findings
    
    def fetch_from_api(self) -> List[SecretFinding]:
        """Fetch secrets from Nemesis API"""
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
        
        # Adjust endpoint based on Nemesis API structure
        #TODO: Use https://github.com/SpecterOps/Nemesis/blob/main/projects/jupyter/notebooks/2_triage_false_positive_findings.ipynb
        response = requests.get(
            f"{self.nemesis_url}/api/credentials",
            headers=headers,
            verify=True
        )
        response.raise_for_status()
        
        data = response.json()
        return self.parse_json(data)
