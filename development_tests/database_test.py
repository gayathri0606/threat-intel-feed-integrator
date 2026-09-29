from pymongo import MongoClient

# Connect to MongoDB running on this laptop
client = MongoClient("mongodb://localhost:27017/")

# Create/use our database
db = client["threat_intel_db"]

# Create/use our IOC collection
collection = db["iocs"]

# Test document
test_ioc = {
    "ioc": "8.8.8.8",
    "type": "IP Address",
    "source": "VirusTotal",
    "classification": "CLEAN"
}

# Insert the document into MongoDB
result = collection.insert_one(test_ioc)

print("IOC saved successfully!")
print("Document ID:", result.inserted_id)