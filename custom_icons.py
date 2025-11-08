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
    print("Error: taxonomy module not found. Ensure taxonomy.py is in the same directory.")
    exit(1)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Default BloodHound API settings
DEFAULT_URL = "http://127.0.0.1:8080/api/v2/custom-nodes"
DEFAULT_TAXONOMY_FILE = "taxonomy.json"

def define_icon(url, headers, icon_type, icon_name, icon_color):
    """Define a custom icon in BloodHound"""
    payload = {
        "custom_types": {
            icon_type: {
                "icon": {
                    "type": "font-awesome",
                    "name": icon_name,
                    "color": icon_color
                }
            }
        }
    }

    response = requests.post(
        url,
        headers=headers,
        json=payload,
        verify=False  # Disables SSL verification
    )

    print(f"Sent icon for: {icon_type} (color: {icon_color})")
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

  # Use minimal taxonomy
  python custom_icons.py --token YOUR_TOKEN --taxonomy taxonomy_minimal.json

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

    parser.add_argument(
        '--taxonomy',
        default=DEFAULT_TAXONOMY_FILE,
        type=Path,
        help=f'Path to taxonomy JSON file (default: {DEFAULT_TAXONOMY_FILE})'
    )

    args = parser.parse_args()

    headers = {
        "Authorization": f"Bearer {args.token}",
        "Content-Type": "application/json"
    }

    # Load taxonomy colors
    print(f"Loading taxonomy from {args.taxonomy}")
    node_colors = load_taxonomy_colors(args.taxonomy)

    print(f"Found {len(node_colors)} node kinds to register\n")

    # Register the default Secret icon (yellow)
    default_color = "#ffc800"
    print("Registering default Secret icon...")
    define_icon(args.url, headers, "Secret", "key", default_color)

    # Register icons for each node kind from taxonomy
    success_count = 0
    for node_kind, color in sorted(node_colors.items()):
        print(f"Registering {node_kind} icon...")
        if define_icon(args.url, headers, node_kind, "key", color):
            success_count += 1

    print(f"\nSuccessfully registered {success_count + 1} icons (1 default + {success_count} from taxonomy)")

if __name__ == '__main__':
    main()
