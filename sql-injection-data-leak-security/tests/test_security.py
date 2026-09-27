import os,base64
os.environ.setdefault("CAPABILITY_SECRET","test-secret")
os.environ.setdefault("AES_KEY_BASE64",base64.urlsafe_b64encode(b"1"*32).decode())
from app.security import encrypt_text,decrypt_text,suspicious,make_capability,verify_capability
def test_aes_roundtrip():
    assert decrypt_text(encrypt_text("secret@example.com"))=="secret@example.com"
def test_detector():
    assert suspicious("' OR 1=1 --")
def test_capability():
    t=make_capability("alice"); assert verify_capability(t,"alice")
