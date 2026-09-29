import os

from datetime import datetime, timezone

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    jsonify,
    flash
)

from dotenv import load_dotenv
from pymongo import MongoClient
from bson.objectid import ObjectId
from bson.errors import InvalidId

from virustotal_service import analyze_ioc


# -----------------------------
# LOAD CONFIGURATION
# -----------------------------

load_dotenv()

flask_secret_key = os.getenv(
    "FLASK_SECRET_KEY"
)

mongodb_uri = os.getenv(
    "MONGODB_URI"
)


# -----------------------------
# VALIDATE CONFIGURATION
# -----------------------------

if not flask_secret_key:
    raise RuntimeError(
        "FLASK_SECRET_KEY is missing from .env"
    )

if not mongodb_uri:
    raise RuntimeError(
        "MONGODB_URI is missing from .env"
    )


# -----------------------------
# SETUP FLASK
# -----------------------------

app = Flask(__name__)

app.secret_key = flask_secret_key


# -----------------------------
# CONNECT TO MONGODB
# -----------------------------

client = MongoClient(
    mongodb_uri
)

db = client["threat_intel_db"]
collection = db["iocs"]


# -----------------------------
# DASHBOARD
# -----------------------------

@app.route("/")
def dashboard():

    iocs = list(collection.find())

    total_iocs = collection.count_documents({})

    clean_count = collection.count_documents({
        "classification": "CLEAN"
    })

    suspicious_count = collection.count_documents({
        "classification": "SUSPICIOUS"
    })

    malicious_count = collection.count_documents({
        "classification": "MALICIOUS"
    })

    return render_template(
        "dashboard.html",
        iocs=iocs,
        total_iocs=total_iocs,
        clean_count=clean_count,
        suspicious_count=suspicious_count,
        malicious_count=malicious_count
    )


# -----------------------------
# ANALYZE IOC
# -----------------------------

@app.route("/analyze", methods=["POST"])
def analyze():

    ioc = request.form.get(
        "ioc",
        ""
    ).strip()

    if not ioc:

        flash(
            "Please enter an IOC.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    result = analyze_ioc(ioc)


    # -----------------------------
    # HANDLE ERRORS
    # -----------------------------

    if not result["success"]:

        status_code = result.get(
            "status_code"
        )

        if status_code == 404:

            message = (
                "IOC was not found in VirusTotal."
            )

        elif status_code == 429:

            message = (
                "VirusTotal API rate limit reached. "
                "Please try again later."
            )

        elif status_code in [401, 403]:

            message = (
                "VirusTotal authentication or "
                "permission error."
            )

        else:

            message = result.get(
                "error",
                "Unable to analyze IOC."
            )

        flash(
            message,
            "error"
        )

        return redirect(
            url_for("dashboard")
        )


    # -----------------------------
    # PREPARE DATABASE DOCUMENT
    # -----------------------------

    ioc_document = result.copy()

    ioc_document.pop(
        "success",
        None
    )

    ioc_document["last_checked"] = (
        datetime.now(timezone.utc)
    )


    # -----------------------------
    # INSERT OR UPDATE IOC
    # -----------------------------

    database_result = collection.update_one(

        {
            "ioc": ioc
        },

        {
            "$set": ioc_document,

            "$setOnInsert": {
                "first_seen": datetime.now(
                    timezone.utc
                )
            }
        },

        upsert=True
    )


    # -----------------------------
    # SUCCESS MESSAGE
    # -----------------------------

    if database_result.upserted_id:

        flash(
            "IOC analyzed and added successfully.",
            "success"
        )

    else:

        flash(
            "IOC analyzed and updated successfully.",
            "success"
        )

    return redirect(
        url_for("dashboard")
    )


# =========================================================
# API - GET IOCS
# =========================================================

@app.route("/api/iocs", methods=["GET"])
def get_iocs():

    query = {}


    # -----------------------------
    # CLASSIFICATION FILTER
    # -----------------------------

    classification = request.args.get(
        "classification"
    )

    if classification:

        classification = classification.upper()

        allowed_classifications = [
            "CLEAN",
            "SUSPICIOUS",
            "MALICIOUS"
        ]

        if classification not in allowed_classifications:

            return jsonify({
                "error": (
                    "Invalid classification. "
                    "Use CLEAN, SUSPICIOUS, "
                    "or MALICIOUS."
                )
            }), 400

        query["classification"] = classification


    # -----------------------------
    # IOC TYPE FILTER
    # -----------------------------

    ioc_type = request.args.get(
        "type"
    )

    if ioc_type:

        allowed_types = [
            "IP Address",
            "Domain",
            "URL",
            "MD5 Hash",
            "SHA-1 Hash",
            "SHA-256 Hash"
        ]

        if ioc_type not in allowed_types:

            return jsonify({
                "error": "Invalid IOC type.",
                "allowed_types": allowed_types
            }), 400

        query["type"] = ioc_type


    # -----------------------------
    # QUERY DATABASE
    # -----------------------------

    documents = list(
        collection.find(
            query,
            {
                "_id": 0
            }
        )
    )

    return jsonify({
        "total": len(documents),

        "filters": {
            "classification": classification,
            "type": ioc_type
        },

        "iocs": documents
    })


# =========================================================
# API - GET ONE IOC
# =========================================================

@app.route(
    "/api/iocs/<ioc_id>",
    methods=["GET"]
)
def get_ioc_by_id(ioc_id):

    try:

        object_id = ObjectId(
            ioc_id
        )

    except InvalidId:

        return jsonify({
            "error": "Invalid IOC ID."
        }), 400


    document = collection.find_one({
        "_id": object_id
    })


    if not document:

        return jsonify({
            "error": "IOC not found."
        }), 404


    document["_id"] = str(
        document["_id"]
    )

    return jsonify(
        document
    )


# -----------------------------
# START APPLICATION
# -----------------------------

if __name__ == "__main__":

    app.run(debug=True)