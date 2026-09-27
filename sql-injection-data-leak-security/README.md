# Detecting Data Leaks / Preventing SQL Injection

End-to-end educational cloud security project matching Task 2. It prevents SQL injection using parameterized SQLAlchemy queries and an additional suspicious-input detector, protects sensitive reversible data with AES-256-GCM, hashes passwords with bcrypt, and uses short-lived HMAC capability codes to authorize protected profile access.

## Requirement mapping
- Secure user data against SQL injection: SQLAlchemy parameterized queries + validation/detection + least-privilege deployment guidance.
- AES-256: AESGCM with a 256-bit key for sensitive reversible fields. Passwords are intentionally hashed, not encrypted.
- Capability code: signed, short-lived HMAC token controls protected access. It does **not** inject SQL; SQL injection is never used as an authorization mechanism.
- Double layer: Layer 1 query/input security; Layer 2 encryption + authorization.
- Internet accessible/lightweight: FastAPI + Docker, deployable to Cloud Run with Cloud SQL.

## Run locally (Windows PowerShell)
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python -c "import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
# Put output into AES_KEY_BASE64 in .env and change CAPABILITY_SECRET
uvicorn app.main:app --reload
```
Open http://127.0.0.1:8000 or http://127.0.0.1:8000/docs.

## Production notes
Do not use the local key fallback or demo admin code in production. Put keys in GCP Secret Manager/KMS, use Cloud SQL with least-privilege credentials, enable logging/monitoring, rate limiting/WAF as appropriate, backups, and key rotation. Never concatenate user input into SQL.
