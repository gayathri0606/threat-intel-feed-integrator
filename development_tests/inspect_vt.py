import os
import requests
from dotenv import load_dotenv


# -----------------------------
# LOAD API KEY
# -----------------------------

load_dotenv()

api_key = os.getenv("VIRUSTOTAL_API_KEY")


# -----------------------------
# TEST HASH
# -----------------------------

test_hash = "44d88612fea8a8f36de82e1278abb02f"

url = (
    "https://www.virustotal.com/api/v3/"
    f"files/{test_hash}"
)

headers = {
    "x-apikey": api_key
}


# -----------------------------
# REQUEST VIRUSTOTAL DATA
# -----------------------------

response = requests.get(
    url,
    headers=headers,
    timeout=15
)

print("Status Code:", response.status_code)


# -----------------------------
# DISPLAY USEFUL INFORMATION
# -----------------------------

if response.status_code == 200:

    data = response.json()

    attributes = data["data"]["attributes"]

    print("\n--- VirusTotal Context ---")

    print(
        "Meaningful Name:",
        attributes.get("meaningful_name", "Unknown")
    )

    print(
        "File Type:",
        attributes.get(
            "type_description",
            "Unknown"
        )
    )

    print(
        "Tags:",
        attributes.get("tags", [])
    )

    print(
        "Popular Threat Classification:",
        attributes.get(
            "popular_threat_classification",
            {}
        )
    )

else:

    print(
        "Unable to retrieve data from VirusTotal."
    )