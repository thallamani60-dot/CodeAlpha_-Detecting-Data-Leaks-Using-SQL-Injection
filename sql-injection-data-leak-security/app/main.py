from fastapi import FastAPI,Depends,Form,HTTPException,Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from .database import Base,engine,get_db
from .models import User,SecurityEvent
from .security import suspicious,hash_password,verify_password,encrypt_text,decrypt_text,make_capability,verify_capability
Base.metadata.create_all(bind=engine)
app=FastAPI(title="SQL Injection Data Leak Security")
app.mount("/static",StaticFiles(directory="static"),name="static")
templates=Jinja2Templates(directory="templates")
@app.get("/",response_class=HTMLResponse)
def home(request:Request): return templates.TemplateResponse("index.html",{"request":request})
@app.post("/register")
def register(username:str=Form(...),password:str=Form(...),email:str=Form(...),db:Session=Depends(get_db)):
    if suspicious(username) or suspicious(email):
        db.add(SecurityEvent(source="register",reason="Suspicious SQL-like input")); db.commit(); raise HTTPException(400,"Suspicious input blocked")
    if db.query(User).filter(User.username==username).first(): raise HTTPException(409,"Username exists")
    # ORM equality filter is parameterized; password is hashed, sensitive email is AES-256-GCM encrypted.
    db.add(User(username=username,password_hash=hash_password(password),email_encrypted=encrypt_text(email))); db.commit()
    return {"message":"Registered securely"}
@app.post("/login")
def login(username:str=Form(...),password:str=Form(...),db:Session=Depends(get_db)):
    if suspicious(username): raise HTTPException(400,"Suspicious input blocked")
    user=db.query(User).filter(User.username==username).first()
    if not user or not verify_password(password,user.password_hash): raise HTTPException(401,"Invalid credentials")
    return {"message":"Login successful","capability_code":make_capability(username),"expires_in_seconds":300}
@app.get("/protected-profile")
def protected_profile(username:str,capability_code:str,db:Session=Depends(get_db)):
    if not verify_capability(capability_code,username): raise HTTPException(403,"Invalid/expired capability code")
    user=db.query(User).filter(User.username==username).first()
    if not user: raise HTTPException(404,"User not found")
    return {"username":user.username,"email":decrypt_text(user.email_encrypted)}
@app.get("/security-events")
def events(admin_code:str,db:Session=Depends(get_db)):
    if admin_code!="demo-admin-change-me": raise HTTPException(403,"Forbidden")
    return [{"source":x.source,"reason":x.reason,"time":str(x.created_at)} for x in db.query(SecurityEvent).order_by(SecurityEvent.id.desc()).limit(50)]
@app.get("/health")
def health(): return {"status":"ok"}
