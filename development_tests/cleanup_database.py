from pymongo import MongoClient


# -----------------------------
# CONNECT TO MONGODB
# -----------------------------

client = MongoClient("mongodb://localhost:27017/")

db = client["threat_intel_db"]
collection = db["iocs"]


# -----------------------------
# FIND DUPLICATE IOC VALUES
# -----------------------------

duplicates = collection.aggregate([
    {
        "$group": {
            "_id": "$ioc",
            "document_ids": {
                "$push": "$_id"
            },
            "count": {
                "$sum": 1
            }
        }
    },
    {
        "$match": {
            "count": {
                "$gt": 1
            }
        }
    }
])


duplicates_found = False


# -----------------------------
# REMOVE DUPLICATES
# -----------------------------

for duplicate in duplicates:

    duplicates_found = True

    ioc_value = duplicate["_id"]
    document_ids = duplicate["document_ids"]

    print(
        f"Duplicate found: {ioc_value} "
        f"({duplicate['count']} documents)"
    )

    # Keep the first document.
    # Delete the remaining duplicates.
    ids_to_delete = document_ids[1:]

    result = collection.delete_many({
        "_id": {
            "$in": ids_to_delete
        }
    })

    print(
        f"Removed {result.deleted_count} duplicate document(s)."
    )


if not duplicates_found:
    print("No duplicate IOCs found.")


# -----------------------------
# CREATE UNIQUE INDEX
# -----------------------------

collection.create_index(
    "ioc",
    unique=True,
    name="unique_ioc"
)

print("Unique IOC index created successfully!")


# -----------------------------
# SHOW FINAL COUNT
# -----------------------------

total = collection.count_documents({})

print("Total IOC documents:", total)