#!/usr/bin/env python3
"""
Custom Icons for SecretHound
This script registers custom node icons in BloodHound Community Edition
for secret types based on the technology taxonomy.
"""
import requests
import json
import urllib3
import argparse
from pathlib import Path

try:
    from taxonomy import Taxonomy
except ImportError:
    print("Error: taxonomy module not found. Ensure taxonomy package is available.")
    exit(1)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Default BloodHound API settings
DEFAULT_URL = "http://127.0.0.1:8080/api/v2/custom-nodes"
DEFAULT_TAXONOMY_FILE = "taxonomy/taxonomy.json"

def define_icons(url, headers, icon_definitions):
    """Define all custom icons in BloodHound with a single request"""
    payload = {"custom_types": icon_definitions}
    
    response = requests.post(
        url,
        headers=headers,
        json=payload,
        verify=False  # Disables SSL verification
    )
    
    print(f"Sent {len(icon_definitions)} icons in single request")
    print("Status Code:", response.status_code)
    if response.status_code != 200:
        print("Response Body:", response.text)
    print("---")
    
    return response.status_code == 200

def load_taxonomy_colors(taxonomy_file):
    """
    Load technology colors from taxonomy file
    Returns:
        Dict mapping node kinds to colors
    """
    taxonomy = Taxonomy(taxonomy_file)
    return taxonomy.get_all_colors()

def main():
    parser = argparse.ArgumentParser(
        description='Register custom icons in BloodHound for SecretHound',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Register icons from taxonomy
  python custom_icons.py --token YOUR_TOKEN

  # Use custom BloodHound URL
  python custom_icons.py --token YOUR_TOKEN --url http://bloodhound.local:8080/api/v2/custom-nodes
        """
    )

    parser.add_argument(
        '--token',
        required=True,
        help='BloodHound API token'
    )

    parser.add_argument(
        '--url',
        default=DEFAULT_URL,
        help=f'BloodHound API URL (default: {DEFAULT_URL})'
    )

    args = parser.parse_args()

    headers = {
        "Authorization": f"Bearer {args.token}",
        "Content-Type": "application/json"
    }

    # Load taxonomy colors
    print(f"Loading taxonomy from {DEFAULT_TAXONOMY_FILE}")
    node_colors = load_taxonomy_colors(Path(DEFAULT_TAXONOMY_FILE))
    print(f"Found {len(node_colors)} node kinds to register\n")
    
    # Build icon definitions dictionary
    icon_definitions = {}
    
    # Add default Secret icon (yellow)
    default_color = "#ffc800"
    icon_definitions["Secret"] = {
        "icon": {
            "type": "font-awesome",
            "name": "key",
            "color": default_color
        }
    }
    
    # Add icons for each node kind from taxonomy
    for node_kind, color in sorted(node_colors.items()):
        icon_definitions[node_kind] = {
            "icon": {
                "type": "font-awesome",
                "name": "key",
                "color": color
            }
        }
    
    # Register all icons in one request
    print(f"Registering {len(icon_definitions)} icons (1 default + {len(node_colors)} from taxonomy)...")
    if define_icons(args.url, headers, icon_definitions):
        print(f"\nSuccessfully registered all {len(icon_definitions)} icons")
    else:
        print("\nFailed to register icons")

if __name__ == '__main__':
    main()