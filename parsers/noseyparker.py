import json
import logging
from pathlib import Path
from typing import Dict, List, Any

from secrethound import SecretsParser, SecretFinding

logger = logging.getLogger(__name__)


class NoseyParkerParser(SecretsParser):
    """Parser for NoseyParker JSON output"""
    
    def parse_file(self, file_path: Path) -> List[SecretFinding]:
        """Parse NoseyParker JSON file"""
        logger.info(f"Parsing NoseyParker output from {file_path}")
        
        with open(file_path, 'r') as f:
            # NoseyParker can output JSON or JSONL
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
        """Parse NoseyParker JSON data"""
        findings = []

        # NoseyParker format has a 'matches' array
        matches = data.get('matches', [])
        rule_name = data.get('rule_name', 'Unknown')

        for match in matches:
            # Extract provenance information
            provenance_list = match.get('provenance', [])

            # Get the secret value from snippet.matching
            secret_value = match.get('snippet', {}).get('matching', '')

            for prov in provenance_list:
                # Handle git_repo provenance kind
                if prov.get('kind') == 'git_repo':
                    repo_path = prov.get('repo_path', '')
                    first_commit = prov.get('first_commit', {})
                    commit_metadata = first_commit.get('commit_metadata', {})
                    blob_path = first_commit.get('blob_path', '')

                    finding = SecretFinding(
                        secret_type=rule_name,
                        secret_value=secret_value,
                        file_path=blob_path,
                        repository=repo_path,
                        commit=commit_metadata.get('commit_id'),
                        author=commit_metadata.get('author_email'),
                        metadata={
                            'source': 'noseyparker',
                            'rule': rule_name,
                            'rule_text_id': data.get('rule_text_id', ''),
                            'finding_id': data.get('finding_id', ''),
                            'committer_name': commit_metadata.get('committer_name'),
                            'committer_email': commit_metadata.get('committer_email'),
                        }
                    )
                    findings.append(finding)
                # Handle filesystem provenance kind
                elif prov.get('kind') == 'filesystem':
                    file_path = prov.get('path', '')
                    finding = SecretFinding(
                        secret_type=rule_name,
                        secret_value=secret_value,
                        file_path=file_path,
                        metadata={
                            'source': 'noseyparker',
                            'rule': rule_name,
                            'rule_text_id': data.get('rule_text_id', ''),
                            'finding_id': data.get('finding_id', ''),
                        }
                    )
                    findings.append(finding)

        return findings

