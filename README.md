# Threat Intel Feed Integrator

A Python-based Cyber Threat Intelligence (CTI) application that analyzes Indicators of Compromise (IOCs) using VirusTotal, stores normalized threat intelligence in MongoDB, and provides a Flask-based dashboard and REST API for viewing and filtering the collected intelligence.

The project also includes automated IOC re-enrichment using APScheduler so previously stored indicators can be periodically checked for updated threat information.

---

## Features

- Analyze Indicators of Compromise using VirusTotal
- Automatically detect IOC type
- Support for:
  - IPv4 and IPv6 addresses
  - Domains
  - URLs
  - MD5 hashes
  - SHA-1 hashes
  - SHA-256 hashes
- Retrieve VirusTotal threat intelligence
- Classify IOCs as:
  - CLEAN
  - SUSPICIOUS
  - MALICIOUS
- Store IOC intelligence in MongoDB
- Prevent duplicate IOC records using upsert and a unique IOC index
- Preserve `first_seen` and update `last_checked`
- Display VirusTotal threat labels, categories, and tags
- Display IP country and network owner information when available
- Flask-based threat intelligence dashboard
- Threat classification visualization
- Search stored IOC intelligence
- Filter dashboard records by classification
- REST API for retrieving IOC data
- API filtering by IOC type and classification
- Automatic IOC refresh using APScheduler
- User-facing success and error messages
- Environment-variable based secret management

---

## Architecture

```text
                        User
                          |
                          v
                  Flask Dashboard
                          |
                          v
                 IOC Analysis Request
                          |
                          v
              virustotal_service.py
                 /                \
                /                  \
       IOC Type Detection      VirusTotal API
                \                  /
                 \                /
                  v              v
               Normalize Threat Data
                          |
                          v
                  Classification
                          |
                          v
                      MongoDB
                     /       \
                    /         \
                   v           v
             Dashboard      REST API


              scheduler.py
                   |
                   v
            refresh_iocs.py
                   |
                   v
        virustotal_service.py
                   |
                   v
             VirusTotal API
                   |
                   v
          Update MongoDB Records
```

---

## Technology Stack

### Backend
- Python
- Flask

### Threat Intelligence
- VirusTotal API

### Database
- MongoDB
- PyMongo

### Automation
- APScheduler

### HTTP/API Communication
- Requests

### Configuration
- python-dotenv

### Frontend
- HTML
- CSS
- JavaScript
- Jinja2 templates

---

## Project Structure

```text
threat-intel-feed-integrator/
|
|-- templates/
|   `-- dashboard.html
|
|-- development_tests/
|   |-- cleanup_database.py
|   |-- database_test.py
|   |-- inspect_vt.py
|   |-- ioc_analyzer.py
|   |-- test_api.py
|   `-- virustotal.py
|
|-- app.py
|-- virustotal_service.py
|-- refresh_iocs.py
|-- scheduler.py
|-- requirements.txt
|-- .env.example
|-- .gitignore
`-- README.md
```

The `development_tests` directory contains scripts that were used while developing and validating individual components of the project. They are not required for normal application execution.

---

## IOC Processing Workflow

When an IOC is submitted through the dashboard:

1. Flask receives the IOC.
2. The application determines the IOC type.
3. The correct VirusTotal API endpoint is selected.
4. A request is sent to VirusTotal.
5. The JSON response is parsed.
6. Relevant threat intelligence is normalized.
7. A project-level classification is assigned.
8. The IOC is inserted into or updated in MongoDB.
9. The dashboard displays the stored intelligence.

---

## IOC Classification

The project uses a simple classification rule based on the number of VirusTotal engines reporting an IOC as malicious.

```text
Malicious detections >= 5  -> MALICIOUS
Malicious detections >= 1  -> SUSPICIOUS
Malicious detections == 0  -> CLEAN
```

These thresholds are project-defined and are not official VirusTotal classifications.

A `CLEAN` result should not be interpreted as a guarantee that an IOC is safe. Threat intelligence can change over time, which is one reason the project periodically refreshes stored indicators.

---

## VirusTotal Intelligence

Depending on the IOC type and available VirusTotal data, the application stores information including:

- IOC value
- IOC type
- Source
- Malicious detections
- Suspicious detections
- Harmless detections
- Undetected results
- Project classification
- Threat label
- Threat categories
- VirusTotal tags
- Country
- Network owner
- Meaningful file name
- File type
- First seen time
- Last checked time

---

## REST API

### Get All IOCs

```http
GET /api/iocs
```

Example:

```text
http://127.0.0.1:5000/api/iocs
```

---

### Filter by Classification

```http
GET /api/iocs?classification=MALICIOUS
```

Supported classifications:

```text
CLEAN
SUSPICIOUS
MALICIOUS
```

---

### Filter by IOC Type

Example:

```http
GET /api/iocs?type=IP%20Address
```

Supported IOC types include:

```text
IP Address
Domain
URL
MD5 Hash
SHA-1 Hash
SHA-256 Hash
```

---

### Combine Filters

Example:

```http
GET /api/iocs?classification=CLEAN&type=IP%20Address
```

The API returns JSON data containing records matching both filters.

---

### Get an IOC by MongoDB ID

```http
GET /api/iocs/<ioc_id>
```

The endpoint returns the corresponding IOC document or an appropriate error response if the ID is invalid or does not exist.

---

## Automated Threat Intelligence Refresh

The project uses APScheduler to periodically refresh stored IOC intelligence.

The final local configuration runs the refresh job every:

```text
6 hours
```

Start the scheduler using:

```bash
python scheduler.py
```

The scheduler calls the refresh service, which retrieves stored IOCs from MongoDB, rechecks them through VirusTotal, and updates their intelligence.

The scheduler runs only while the Python scheduler process is active. A production deployment could instead use a managed background worker, operating-system service, containerized worker, or external scheduling system.

---

## Installation

### 1. Clone the repository

```bash
git clone <repository-url>
cd threat-intel-feed-integrator
```

### 2. Create a virtual environment

Windows:

```bash
python -m venv venv
```

Activate it:

```powershell
.\venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Install and start MongoDB

The project expects a MongoDB instance to be available.

The default development configuration is:

```text
mongodb://localhost:27017/
```

### 5. Configure environment variables

Copy `.env.example` to a new file named:

```text
.env
```

Configure:

```text
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
FLASK_SECRET_KEY=your_flask_secret_key_here
MONGODB_URI=mongodb://localhost:27017/
```

Never commit the real `.env` file.

### 6. Start the Flask application

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

### 7. Start the scheduler

In a separate terminal:

```bash
python scheduler.py
```

---

## Security Considerations

The project includes several basic security practices:

- VirusTotal API keys are stored in environment variables.
- Flask secret keys are not hard-coded in source code.
- `.env` is excluded through `.gitignore`.
- `.env.example` contains placeholders rather than real credentials.
- External API requests use a timeout.
- Invalid API filter values return HTTP 400 responses.
- VirusTotal authentication, not-found, rate-limit, and network errors are handled.
- Duplicate IOC records are prevented at the database level.

For a production deployment, additional controls would be required, including authentication, authorization, HTTPS, MongoDB authentication, stronger input validation, logging, monitoring, rate limiting, and secure deployment configuration.

---

## Dashboard

The dashboard provides:

- IOC submission
- Total IOC count
- Clean IOC count
- Suspicious IOC count
- Malicious IOC count
- Threat classification visualization
- IOC search
- Classification filtering
- Threat labels
- Threat categories
- VirusTotal tags
- IOC-specific contextual information

---

## Development and Testing

The application was manually tested with multiple IOC types, including:

- IP address
- Domain
- URL
- MD5 hash
- Invalid input

Testing also covered:

- MongoDB insertion and updating
- Duplicate prevention
- Dashboard search
- Dashboard filtering
- REST API responses
- REST API filtering
- Error handling
- Manual IOC refresh
- Scheduled IOC refresh

The EICAR test-file hash was used during development to safely validate malicious-file-hash intelligence without executing malware.

---

## Limitations

This project currently:

- Uses VirusTotal as its primary external threat intelligence source.
- Uses project-defined classification thresholds.
- Runs locally using Flask's development server.
- Requires the scheduler process to remain running for periodic refreshes.
- Uses relatively simple IOC validation.
- Does not currently provide user authentication or role-based access control.
- Does not replace a production SIEM, TIP, SOAR, or enterprise threat intelligence platform.

---

## Future Improvements

Possible future enhancements include:

- Integrating additional threat intelligence feeds such as AlienVault OTX or AbuseIPDB
- MISP integration
- More advanced IOC validation and normalization
- Authentication and role-based access control
- Server-side pagination
- Advanced IOC search
- Historical threat-score tracking
- Additional dashboard analytics
- IOC expiration and retention policies
- Structured application logging
- Docker containerization
- Unit and integration tests
- Production deployment
- SIEM/SOAR integration
- Exporting intelligence in formats such as STIX/TAXII

---

## Purpose

This project was developed as a cybersecurity portfolio project to gain hands-on experience with:

- Cyber Threat Intelligence
- Indicators of Compromise
- Threat intelligence APIs
- REST APIs
- HTTP and JSON
- Python backend development
- Flask
- MongoDB
- API integration
- Threat-data normalization
- Automation
- Secure configuration management

---

## Disclaimer

This project is intended for educational and defensive cybersecurity purposes.

Threat classifications generated by the application should be treated as contextual intelligence rather than definitive security verdicts.