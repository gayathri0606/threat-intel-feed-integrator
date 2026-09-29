import os
import time

from datetime import datetime, timezone

from dotenv import load_dotenv
from pymongo import MongoClient

from virustotal_service import analyze_ioc


# -----------------------------
# LOAD CONFIGURATION
# -----------------------------

load_dotenv()

mongodb_uri = os.getenv(
    "MONGODB_URI"
)

if not mongodb_uri:
    raise RuntimeError(
        "MONGODB_URI is missing from .env"
    )


# -----------------------------
# CONNECT TO MONGODB
# -----------------------------

client = MongoClient(
    mongodb_uri
)

db = client["threat_intel_db"]
collection = db["iocs"]


# -----------------------------
# REFRESH ONE IOC
# -----------------------------

def refresh_ioc(ioc):

    result = analyze_ioc(ioc)

    if not result["success"]:

        print(
            f"Failed to update {ioc}:",
            result.get(
                "error",
                "Unknown error"
            )
        )

        return


    ioc_document = result.copy()

    ioc_document.pop(
        "success",
        None
    )

    ioc_document["last_checked"] = (
        datetime.now(timezone.utc)
    )


    collection.update_one(
        {
            "ioc": ioc
        },
        {
            "$set": ioc_document
        }
    )


    print(
        f"Updated: {ioc} "
        f"→ {result['classification']}"
    )


# -----------------------------
# REFRESH ALL IOCS
# -----------------------------

def refresh_all_iocs():

    print(
        "\nStarting IOC refresh...\n"
    )

    stored_iocs = collection.find(
        {},
        {
            "_id": 0,
            "ioc": 1
        }
    )


    for document in stored_iocs:

        ioc = document.get(
            "ioc"
        )

        if ioc:

            print(
                "Checking:",
                ioc
            )

            refresh_ioc(
                ioc
            )

            # Space out external API requests
            time.sleep(16)


    print(
        "\nIOC refresh completed!\n"
    )


# -----------------------------
# MANUAL EXECUTION
# -----------------------------

if __name__ == "__main__":

    refresh_all_iocs()