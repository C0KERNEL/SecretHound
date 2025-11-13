#!/usr/bin/env python3
"""
Custom Icons Cleanup for SecretHound
This script deletes custom node icons in BloodHound Community Edition.
"""
import requests
import urllib3
import argparse
import time

try:
    from taxonomy import Taxonomy
except ImportError:
    Taxonomy = None

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Default BloodHound API settings
DEFAULT_BASE_URL = "http://127.0.0.1:8080/api/v2/custom-nodes"
DEFAULT_TAXONOMY_FILE = "taxonomy/taxonomy.json"

def delete_icon(base_url, headers, icon_type):
    """Delete a custom icon from BloodHound"""
    url = f"{base_url}/{icon_type}"
    
    response = requests.delete(
        url,
        headers=headers,
        verify=False  # Disables SSL verification
    )
    
    print(f"Deleted icon for: {icon_type}")
    print("Status Code:", response.status_code)
    if response.status_code not in [200, 204]:
        print("Response Body:", response.text)
    print("---")
    
    return response.status_code in [200, 204]

def load_taxonomy_kinds(taxonomy_file):
    """Load all node kinds from taxonomy file"""
    if Taxonomy is None:
        print("Warning: taxonomy module not found. Cannot load taxonomy kinds.")
        return []
    
    taxonomy = Taxonomy(taxonomy_file)
    return list(taxonomy.get_all_colors().keys())

def main():
    parser = argparse.ArgumentParser(
        description='Delete custom icons from BloodHound',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Delete all icons from taxonomy
  python custom_icons_delete.py --token YOUR_TOKEN --all

  # Delete specific icons
  python custom_icons_delete.py --token YOUR_TOKEN --kind Secret AWSAccessKey GitHubToken

  # Use custom taxonomy file
  python custom_icons_delete.py --token YOUR_TOKEN --all --taxonomy taxonomy/taxonomy_minimal.json

  # Use custom BloodHound URL
  python custom_icons_delete.py --token YOUR_TOKEN --url http://bloodhound.local:8080/api/v2/custom-nodes --all
        """
    )
    
    parser.add_argument(
        '--token',
        required=True,
        help='BloodHound API token'
    )
    
    parser.add_argument(
        '--url',
        default=DEFAULT_BASE_URL,
        help=f'BloodHound API base URL (default: {DEFAULT_BASE_URL})'
    )
    
    parser.add_argument(
        '--kind',
        nargs='+',
        help='Node kind(s) to delete (e.g., Secret AWSAccessKey)'
    )
    
    parser.add_argument(
        '--all',
        action='store_true',
        help='Delete all icons from taxonomy (includes default Secret icon)'
    )
    
    parser.add_argument(
        '--taxonomy',
        default=DEFAULT_TAXONOMY_FILE,
        help=f'Path to taxonomy JSON file (default: {DEFAULT_TAXONOMY_FILE})'
    )
    
    args = parser.parse_args()
    
    if not args.kind and not args.all:
        parser.error("Either --kind or --all must be specified")
    
    headers = {
        "Authorization": f"Bearer {args.token}",
        "Content-Type": "application/json"
    }
    
    # Determine which kinds to delete
    if args.all:
        print(f"Loading taxonomy from {args.taxonomy}")
        taxonomy_kinds = load_taxonomy_kinds(args.taxonomy)
        kinds_to_delete = ["Secret"] + taxonomy_kinds
        print(f"Found {len(kinds_to_delete)} icons to delete (1 default + {len(taxonomy_kinds)} from taxonomy)\n")
    else:
        kinds_to_delete = args.kind
    
    # Delete icons with rate limiting
    success_count = 0
    for idx, kind in enumerate(kinds_to_delete, start=1):
        print(f"Deleting {kind} icon...")
        if delete_icon(args.url, headers, kind):
            success_count += 1
        
        # Sleep after every 55 requests
        if idx % 55 == 0 and idx < len(kinds_to_delete):
            print(f"\n[Rate limiting: sleeping 2 seconds after {idx} requests]\n")
            time.sleep(2)
    
    print(f"\nSuccessfully deleted {success_count}/{len(kinds_to_delete)} icons")

if __name__ == '__main__':
    main()