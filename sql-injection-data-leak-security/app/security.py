import base64, hashlib, hmac, os, re, time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from passlib.context import CryptContext
from .config import AES_KEY_BASE64, CAPABILITY_SECRET
pwd=CryptContext(schemes=["bcrypt"], deprecated="auto")
PATTERNS=[r"(?i)\bunion\s+select\b",r"(?i)\bor\s+['\"]?1['\"]?\s*=\s*['\"]?1",r"(?i)--",r"(?i)/\*",r"(?i)\bdrop\s+table\b"]
def suspicious(value:str)->bool:
    return any(re.search(p,value or "") for p in PATTERNS)
def hash_password(p): return pwd.hash(p)
def verify_password(p,h): return pwd.verify(p,h)
def _key():
    if AES_KEY_BASE64: return base64.urlsafe_b64decode(AES_KEY_BASE64)
    return hashlib.sha256(CAPABILITY_SECRET.encode()).digest() # local-dev fallback only
def encrypt_text(text):
    nonce=os.urandom(12); ct=AESGCM(_key()).encrypt(nonce,text.encode(),None)
    return base64.urlsafe_b64encode(nonce+ct).decode()
def decrypt_text(token):
    raw=base64.urlsafe_b64decode(token); return AESGCM(_key()).decrypt(raw[:12],raw[12:],None).decode()
def make_capability(username,ttl=300):
    exp=int(time.time())+ttl; msg=f"{username}:{exp}"
    sig=hmac.new(CAPABILITY_SECRET.encode(),msg.encode(),hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{msg}:{sig}".encode()).decode()
def verify_capability(token,username):
    try:
        raw=base64.urlsafe_b64decode(token).decode(); u,exp,sig=raw.rsplit(":",2)
        msg=f"{u}:{exp}"; expected=hmac.new(CAPABILITY_SECRET.encode(),msg.encode(),hashlib.sha256).hexdigest()
        return u==username and int(exp)>=int(time.time()) and hmac.compare_digest(sig,expected)
    except Exception: return False
