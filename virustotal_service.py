import os
import re
import base64
import ipaddress
import requests

from dotenv import load_dotenv


# -----------------------------
# SETUP
# -----------------------------

load_dotenv()

api_key = os.getenv("VIRUSTOTAL_API_KEY")


# -----------------------------
# DETECT IOC TYPE
# -----------------------------

def detect_ioc_type(ioc):

    try:
        ipaddress.ip_address(ioc)
        return "IP Address"

    except ValueError:
        pass

    if ioc.startswith("http://") or ioc.startswith("https://"):
        return "URL"

    if re.fullmatch(r"[a-fA-F0-9]{32}", ioc):
        return "MD5 Hash"

    if re.fullmatch(r"[a-fA-F0-9]{40}", ioc):
        return "SHA-1 Hash"

    if re.fullmatch(r"[a-fA-F0-9]{64}", ioc):
        return "SHA-256 Hash"

    if "." in ioc and " " not in ioc:
        return "Domain"

    return "Unknown"


# -----------------------------
# CREATE VIRUSTOTAL URL
# -----------------------------

def create_virustotal_url(ioc, ioc_type):

    if ioc_type == "IP Address":

        return (
            "https://www.virustotal.com/api/v3/"
            f"ip_addresses/{ioc}"
        )

    if ioc_type == "Domain":

        return (
            "https://www.virustotal.com/api/v3/"
            f"domains/{ioc}"
        )

    if ioc_type == "URL":

        url_id = base64.urlsafe_b64encode(
            ioc.encode()
        ).decode().rstrip("=")

        return (
            "https://www.virustotal.com/api/v3/"
            f"urls/{url_id}"
        )

    if ioc_type in [
        "MD5 Hash",
        "SHA-1 Hash",
        "SHA-256 Hash"
    ]:

        return (
            "https://www.virustotal.com/api/v3/"
            f"files/{ioc}"
        )

    return None


# -----------------------------
# CLASSIFY IOC
# -----------------------------

def classify_ioc(malicious):

    if malicious >= 5:
        return "MALICIOUS"

    if malicious >= 1:
        return "SUSPICIOUS"

    return "CLEAN"


# -----------------------------
# ANALYZE IOC WITH VIRUSTOTAL
# -----------------------------

def analyze_ioc(ioc):

    ioc_type = detect_ioc_type(ioc)

    if ioc_type == "Unknown":

        return {
            "success": False,
            "error": "Unknown IOC type"
        }

    if not api_key:

        return {
            "success": False,
            "error": "VirusTotal API key not configured"
        }

    vt_url = create_virustotal_url(
        ioc,
        ioc_type
    )

    headers = {
        "x-apikey": api_key
    }

    try:

        response = requests.get(
            vt_url,
            headers=headers,
            timeout=15
        )

    except requests.RequestException as error:

        return {
            "success": False,
            "error": f"Network error: {error}"
        }


    if response.status_code != 200:

        return {
            "success": False,
            "status_code": response.status_code,
            "error": (
                "VirusTotal request failed with "
                f"HTTP {response.status_code}"
            )
        }


    # -----------------------------
    # PROCESS VIRUSTOTAL RESPONSE
    # -----------------------------

    data = response.json()

    attributes = data["data"]["attributes"]

    stats = attributes.get(
        "last_analysis_stats",
        {}
    )

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    threat_level = classify_ioc(
        malicious
    )


    # -----------------------------
    # IP INFORMATION
    # -----------------------------

    country = "N/A"
    network_owner = "N/A"

    if ioc_type == "IP Address":

        country = attributes.get(
            "country",
            "Unknown"
        )

        network_owner = attributes.get(
            "as_owner",
            "Unknown"
        )


    # -----------------------------
    # THREAT INFORMATION
    # -----------------------------

    threat_info = attributes.get(
        "popular_threat_classification",
        {}
    )

    threat_label = threat_info.get(
        "suggested_threat_label",
        "N/A"
    )

    category_data = threat_info.get(
        "popular_threat_category",
        []
    )

    threat_categories = []

    for category in category_data:

        value = category.get("value")

        if value:
            threat_categories.append(value)


    # -----------------------------
    # FILE INFORMATION
    # -----------------------------

    meaningful_name = "N/A"
    file_type = "N/A"

    if ioc_type in [
        "MD5 Hash",
        "SHA-1 Hash",
        "SHA-256 Hash"
    ]:

        meaningful_name = attributes.get(
            "meaningful_name",
            "Unknown"
        )

        file_type = attributes.get(
            "type_description",
            "Unknown"
        )


    # -----------------------------
    # NORMALIZED RESULT
    # -----------------------------

    return {
        "success": True,
        "ioc": ioc,
        "type": ioc_type,
        "source": "VirusTotal",
        "country": country,
        "network_owner": network_owner,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "classification": threat_level,
        "threat_label": threat_label,
        "threat_categories": threat_categories,
        "vt_tags": attributes.get("tags", []),
        "meaningful_name": meaningful_name,
        "file_type": file_type
    }