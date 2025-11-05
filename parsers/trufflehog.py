import json
import logging
from pathlib import Path
from typing import Dict, List, Any

from secrethound import SecretsParser, SecretFinding

logger = logging.getLogger(__name__)


class TruffleHogParser(SecretsParser):
    """Parser for TruffleHog JSON output"""
    
    def parse_file(self, file_path: Path) -> List[SecretFinding]:
        """Parse TruffleHog JSON/JSONL file"""
        logger.info(f"Parsing TruffleHog output from {file_path}")
        
        findings = []
        with open(file_path, 'r') as f:
            # TruffleHog outputs JSONL (one JSON object per line)
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                try:
                    data = json.loads(line)
                    findings.extend(self.parse_json(data))
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse line {line_num}: {e}")
        
        return findings
    
    def parse_json(self, data: Dict[str, Any]) -> List[SecretFinding]:
        """Parse TruffleHog JSON data"""
        findings = []
        
        # Extract detector information
        detector_name = data.get('DetectorName', data.get('DetectorType', 'Unknown'))
        
        # Extract source metadata
        source_metadata = data.get('SourceMetadata', {})
        source_data = source_metadata.get('Data', {})
        
        # Initialize common fields
        file_path = None
        repository = None
        commit = None
        author = None
        line_number = None
        
        # Handle different source types
        if 'Git' in source_data:
            git_data = source_data['Git']
            file_path = git_data.get('file')
            repository = git_data.get('repository')
            commit = git_data.get('commit')
            author = git_data.get('email')
            line_number = git_data.get('line')
        elif 'Filesystem' in source_data:
            fs_data = source_data['Filesystem']
            file_path = fs_data.get('file')
            line_number = fs_data.get('line')
        elif 'Github' in source_data:
            gh_data = source_data['Github']
            file_path = gh_data.get('file')
            repository = gh_data.get('repository')
            commit = gh_data.get('commit')
        
        # Extract the secret value
        secret_value = data.get('Raw', '')
        
        finding = SecretFinding(
            secret_type=detector_name,
            secret_value=secret_value,
            file_path=file_path,
            line_number=line_number,
            repository=repository,
            commit=commit,
            author=author,
            metadata={
                'source': 'trufflehog',
                'detector': detector_name,
                'verified': data.get('Verified', False),
                'source_type': data.get('SourceType'),
                'source_name': data.get('SourceName'),
            }
        )
        
        findings.append(finding)
        return findings

