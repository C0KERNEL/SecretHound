#!/usr/bin/env python3
"""
Custom Icons for SecretHound

This script registers custom node icons in BloodHound Community Edition
for secret types based on the mappings defined in example_mappings.json.
"""

import requests
import json
import urllib3
import argparse
from pathlib import Path

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Default BloodHound API settings
DEFAULT_URL = "http://127.0.0.1:8080/api/v2/custom-nodes"
DEFAULT_MAPPINGS_FILE = "example_mappings.json"

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

def load_mappings(mappings_file):
    """Load secret mappings from JSON file"""
    with open(mappings_file, 'r') as f:
        return json.load(f)

def main():
    parser = argparse.ArgumentParser(
        description='Register custom icons in BloodHound for SecretHound',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Register icons with default settings
  python custom_icons.py --token YOUR_TOKEN

  # Use custom mappings file
  python custom_icons.py --token YOUR_TOKEN -m custom_mappings.json

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
        '-m', '--mappings',
        default=DEFAULT_MAPPINGS_FILE,
        type=Path,
        help=f'Path to mappings JSON file (default: {DEFAULT_MAPPINGS_FILE})'
    )

    args = parser.parse_args()

    headers = {
        "Authorization": f"Bearer {args.token}",
        "Content-Type": "application/json"
    }

    # Load mappings
    print(f"Loading mappings from {args.mappings}")
    config = load_mappings(args.mappings)

    default_color = config.get('default_color', '#ffc800')
    mappings = config.get('mappings', [])

    print(f"Found {len(mappings)} custom mappings\n")

    # Register the default Secret icon
    print("Registering default Secret icon...")
    define_icon(args.url, headers, "Secret", "key", default_color)

    # Register icons for each mapped node kind
    success_count = 0
    for mapping in mappings:
        node_kind = mapping.get('node_kind')
        color = mapping.get('color', default_color)

        if node_kind:
            print(f"Registering {node_kind} icon...")
            if define_icon(args.url, headers, node_kind, "key", color):
                success_count += 1

    print(f"\nSuccessfully registered {success_count + 1} icons (1 default + {success_count} custom)")

if __name__ == '__main__':
    main()
