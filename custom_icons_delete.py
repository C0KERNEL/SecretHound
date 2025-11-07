#!/usr/bin/env python3
"""
Custom Icons Cleanup for SecretHound
This script deletes custom node icons in BloodHound Community Edition.
"""
import requests
import urllib3
import argparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Default BloodHound API settings
DEFAULT_BASE_URL = "http://127.0.0.1:8080/api/v2/custom-nodes"

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

def main():
    parser = argparse.ArgumentParser(
        description='Delete custom icons from BloodHound',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Delete a single icon
  python custom_icons_delete.py --token YOUR_TOKEN --kind Secret
  
  # Delete multiple icons
  python custom_icons_delete.py --token YOUR_TOKEN --kind Secret AWSAccessKey GitHubToken
  
  # Use custom BloodHound URL
  python custom_icons_delete.py --token YOUR_TOKEN --url http://bloodhound.local:8080/api/v2/custom-nodes --kind Secret
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
        required=True,
        help='Node kind(s) to delete (e.g., Secret AWSAccessKey)'
    )
    
    args = parser.parse_args()
    
    headers = {
        "Authorization": f"Bearer {args.token}",
        "Content-Type": "application/json"
    }
    
    success_count = 0
    for kind in args.kind:
        print(f"Deleting {kind} icon...")
        if delete_icon(args.url, headers, kind):
            success_count += 1
    
    print(f"\nSuccessfully deleted {success_count}/{len(args.kind)} icons")

if __name__ == '__main__':
    main()