# MailTrace

MailTrace is a local email forensics application. It ingests `.eml` evidence, analyzes message headers and authentication, inspects URLs and attachments, correlates indicators, calculates risk, and supports cases, alerts, reports, evidence checks, and audit history.

## Requirements

- Python 3.10 or later
- MongoDB
- Node.js and npm

Evidence is stored on the backend machine in `backend/evidence` by default. MongoDB stores normalized email data and analysis results. Docker and MinIO are not required.

## Run the backend

From the repository root in PowerShell:

```powershell
venv\Scripts\python.exe -m pip install -r backend\requirements.txt
venv\Scripts\python.exe -m uvicorn app.main:app --reload --app-dir backend
```

The backend reads optional settings from `backend/.env` and environment variables. At minimum, MongoDB must be reachable at the configured `MONGODB_URI`.

## Run the frontend

In another PowerShell window:

```powershell
cd frontend
npm install
npm run dev
```

The frontend uses `http://localhost:8000/api/v1` by default. Set `VITE_API_BASE_URL` in `frontend/.env` to use another backend URL.

## Offline and external intelligence

Analysis runs offline by default (`OFFLINE_MODE=true`). Local heuristics, DNS fixture data, and the configured GeoIP database work without provider credentials. Optional live lookups require `OFFLINE_MODE=false` and the relevant keys in `backend/.env`:

```dotenv
IPINFO_TOKEN=
ABUSEIPDB_API_KEY=
URLSCAN_API_KEY=
```

Live lookups send extracted public IP addresses and message URLs to those providers. Avoid enabling them for sensitive evidence unless that disclosure is acceptable. Without provider credentials, ASN, live IP reputation, and external URL verdicts remain unavailable.

## Threat-language analysis

MailTrace uses rule-based language checks for urgency, credential requests, payment requests, impersonation, secrecy, payment-detail changes, and sign-in link instructions. These findings are supporting forensic observations, not a standalone verdict. No local transformer model is downloaded or required.

## Experimental phishing-vs-nonspam baseline

The local dataset preparation includes 481 Nazario phishing messages and 1,652 SpamAssassin ham (non-spam) messages. This is not a verified phishing-vs-legitimate dataset. To train an offline TF-IDF + logistic regression experiment and evaluate a grouped held-out split:

```powershell
venv\Scripts\python.exe -m pip install -r backend\requirements-training.txt
venv\Scripts\python.exe backend\scripts\train_email_baseline.py
```

The script reads only subject and text body, groups repeated Message-IDs and exact text together across the split, and writes `model.joblib` and `evaluation.json` to the ignored `backend\models\email-classifier-proxy` directory. When that model file exists, Extended Forensics displays its raw corpus-class scores as a separate experiment. These are not calibrated real-world phishing probabilities and must not be used as email verdicts: the phishing and non-spam messages come from different, old corpora, so the model can learn source and era artifacts. The proxy is not used for the MailTrace risk score, alerts, or verdict. Rule-based language checks remain the only text-language contribution to the threat score. See `backend\data\datasets\email_classifier\DATASET_NOTES.txt` for provenance and caveats.

## Evidence retention

MailTrace retains evidence indefinitely by default. To opt into automatic deletion, set `RETENTION_DAYS` to a positive number in `backend/.env`; expired email records, analysis records, alerts and local evidence files are then deleted by the backend worker. Audit events remain available for review. `GET /api/v1/retention/status` shows whether deletion is enabled and how many records are due. Set `RETENTION_DAYS=0` to disable automatic deletion.

To enable local city geolocation, place a compatible `.mmdb` database at `backend/data/dbip-city-lite.mmdb`, or set `GEOIP_DATABASE_PATH` to its location.

## Analysis limits

- Threat-language scoring always uses transparent rules and patterns. The optional experimental corpus classifier may be unavailable and does not affect scores or verdicts.
- Risk scores are heuristic signals for triage and need analyst review.
- Infrastructure correlation reports shared indicators, not verified threat-actor attribution.
- The extended analysis page now shows a capped relationship graph connecting emails to shared sender details, URL domains, IP addresses extracted from normalized fields and `Received` headers, and attachment hashes. The full related-email list remains available below it.
- Risk explanations show each scoring input, source evidence, and its effect on the score. These explain the current scoring rules; they do not establish that an email is malicious.
- Analysts can label a reviewed email as legitimate or malicious. The evaluation endpoint calculates precision, recall, and false-positive rate at the existing score threshold of 40, deduplicates repeated indicators while showing their occurrence counts, and marks small evaluation samples as early indications. Metrics describe only manually reviewed emails with current saved scores; labels do not train or alter the local model.
- Evidence verification compares the stored SHA-256 with the local evidence file. Audit hashes make changes detectable in ordinary sequential use, but they are not a substitute for access-controlled, immutable storage or a transactional chain-of-custody system.
- New audit events use versioned SHA-256 hashes over UTC timestamps normalized to MongoDB's millisecond precision. Older unhashed events and hashes created with the prior timestamp format are reported as legacy and are not claimed as verified.
- Audit hashes detect changes in ordinary sequential use, but concurrent updates and direct database edits mean they are not a substitute for access-controlled, immutable storage or a transactional chain-of-custody system.
