import requests
import json
import urllib3
import argparse
from typing import Dict, List, Optional
# ignore cert warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def fetch_findings(api_key: str) -> tuple[Optional[List[Dict]], Optional[Dict[str, str]], Optional[str]]:
    """
    Fetch findings from Hasura GraphQL API
    Returns:
        tuple: (findings_list, triage_states_dict, error_message)
    """
    query = {
        "query": """
            query GetFindingsForSecretHound {
                findings(where: {finding_name: {_eq: "noseyparker_secret"}, finding_triage_histories: {value: {_eq: "true_positive"}}}, order_by: {finding_id: asc}) {
                    category
                    created_at
                    finding_id
                    finding_name
                    triage_id
                    updated_at
                    severity
                    origin_type
                    origin_name
                    object_id
                    files_enriched {
                        agent_id
                        created_at
                        source
                        size
                        project
                        timestamp
                        updated_at
                        path
                        mime_type
                        file_name
                        file_tags
                        extension
                    }
                    raw_data
                    finding_triage_histories(order_by: {timestamp: desc}, limit: 1) {
                        id
                        timestamp
                        true_positive_context
                        username
                        value
                        finding_id
                    }
                }
            }
        """
    }
    
    findings = None
    triage_states = {}
    error = None
    
    try:
        response = requests.post(
            'https://localhost:7443/hasura/v1/graphql',
            json=query,
            headers={
                'Content-Type': 'application/json',
                'x-hasura-admin-secret': api_key
            },
            verify=False
        )
        
        if not response.ok:
            raise Exception(f"Network response error: {response.status_code}")
        
        result = response.json()
        
        if 'errors' in result and result['errors']:
            raise Exception(result['errors'][0]['message'])
        
        # Filter findings to only include those with true_positive in triage history
        all_findings = result['data']['findings']
        filtered_findings = []
        
        for finding in all_findings:
            if (finding.get('finding_triage_histories') and 
                len(finding['finding_triage_histories']) > 0):
                triage_value = finding['finding_triage_histories'][0]['value']
                if triage_value == 'true_positive':
                    triage_states[finding['finding_id']] = triage_value
                    filtered_findings.append(finding)
        
        findings = filtered_findings
        
    except Exception as err:
        print(f'Error fetching findings: {err}')
        error = str(err)
    
    return findings, triage_states, error

# Example usage
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Fetch findings from Hasura GraphQL API')
    parser.add_argument('--api-key', required=True, help='Hasura admin secret key')
    args = parser.parse_args()
    
    findings, triage_states, error = fetch_findings(args.api_key)
    
    if error:
        print(f"An error occurred: {error}")
    else:
        print(json.dumps(findings, indent=2, default=str))