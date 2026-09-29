import os
import requests
from datetime import datetime, timezone
from dotenv import load_dotenv
from pymongo import MongoClient

# -----------------------------
# LOAD ENVIRONMENT VARIABLES
# -----------------------------

load_dotenv()

api_key = os.getenv("VIRUSTOTAL_API_KEY")


# -----------------------------
# CONNECT TO MONGODB
# -----------------------------

client = MongoClient("mongodb://localhost:27017/")

db = client["threat_intel_db"]

collection = db["iocs"]


# -----------------------------
# GET IOC FROM USER
# -----------------------------

ip_address = input("Enter an IP address: ")


# -----------------------------
# VIRUSTOTAL API REQUEST
# -----------------------------

url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"

headers = {
    "x-apikey": api_key
}

response = requests.get(url, headers=headers)

print("Status Code:", response.status_code)


# -----------------------------
# PROCESS RESPONSE
# -----------------------------

if response.status_code == 200:

    data = response.json()

    attributes = data["data"]["attributes"]

    stats = attributes["last_analysis_stats"]

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    country = attributes.get("country", "Unknown")
    network_owner = attributes.get("as_owner", "Unknown")


    # -----------------------------
    # THREAT CLASSIFICATION
    # -----------------------------

    if malicious >= 5:
        threat_level = "MALICIOUS"

    elif malicious >= 1:
        threat_level = "SUSPICIOUS"

    else:
        threat_level = "CLEAN"


    # -----------------------------
    # DISPLAY REPORT
    # -----------------------------

    print("\n--- VirusTotal Threat Report ---")

    print("IP Address:", ip_address)
    print("Country:", country)
    print("Network Owner:", network_owner)

    print("\nSecurity Vendor Results:")

    print("Malicious:", malicious)
    print("Suspicious:", suspicious)
    print("Harmless:", harmless)
    print("Undetected:", undetected)

    print("\nThreat Classification:", threat_level)


    # -----------------------------
    # IOC DATA
    # -----------------------------

    ioc_document = {
        "ioc": ip_address,
        "type": "IP Address",
        "source": "VirusTotal",
        "country": country,
        "network_owner": network_owner,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "classification": threat_level,
        "last_checked": datetime.now(timezone.utc)
    }


    # -----------------------------
    # INSERT OR UPDATE IOC
    # -----------------------------

    result = collection.update_one(
        {"ioc": ip_address},
        {
            "$set": ioc_document,
            "$setOnInsert": {
                "first_seen": datetime.now(timezone.utc)
            }
        },
        upsert=True
    )


    # -----------------------------
    # RESULT
    # -----------------------------

    if result.upserted_id:

        print("\nNew IOC added to MongoDB!")
        print("Document ID:", result.upserted_id)

    else:

        print("\nIOC already exists.")
        print("Threat intelligence updated successfully!")


else:

    print("Unable to retrieve VirusTotal data.")