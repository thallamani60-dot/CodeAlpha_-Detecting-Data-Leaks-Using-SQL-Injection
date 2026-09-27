import os
from dotenv import load_dotenv
load_dotenv()
DATABASE_URL=os.getenv("DATABASE_URL","sqlite:///./security.db")
AES_KEY_BASE64=os.getenv("AES_KEY_BASE64","")
CAPABILITY_SECRET=os.getenv("CAPABILITY_SECRET","dev-only-change-me")
