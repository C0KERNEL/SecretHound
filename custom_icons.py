import requests
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

url = "http://127.0.0.1:8080/api/v2/custom-nodes"

headers = {
    "Authorization": "Bearer eyJhbG...FYr_wRWWaMVw",
    "Content-Type": "application/json"
}

def define_icon(icon_type, icon_name, icon_color):
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

    print(f"🔹 Sent icon for: {icon_type}")
    print("Status Code:", response.status_code)
    print("Response Body:", response.text)
    print("---")

# Call function for each icon type you want to send
define_icon("Secret", "key", "#ffc800")
