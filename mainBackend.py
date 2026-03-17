from sqlalchemy import create_engine,Column,String
from sqlalchemy.orm import declarative_base,sessionmaker,Session
from fastapi import FastAPI,Depends
from pydantic import BaseModel
from passlib.context import CryptContext
from fastapi.middleware.cors import CORSMiddleware
import random
import smtplib
from email.message import EmailMessage
Base=declarative_base()
VerificationCodes={}
class User(Base):
	__tablename__="users"
	email=Column(String,primary_key=True)
	password=Column(String)
class VerificationCodeModel(BaseModel):
		verification_code:str
		email:str
class EmailModel(BaseModel):
		email: str
engine=create_engine("sqlite:///./Users.db",connect_args={"check_same_thread": False})
SessionLocal=sessionmaker(autocommit=False,autoflush=False,bind=engine)
Base.metadata.create_all(bind=engine)
app=FastAPI()
app.add_middleware(
	CORSMiddleware,
	allow_origins=["*"],
	allow_credentials=True,
	allow_methods=["*"],
	allow_headers=["*"],)
def GenerateVerificationCode()->str:
	tempVerificationCode=""
	for i in range(6):
		Digit=random.randint(48,57)
		CapitalLetter=random.randint(65,90)
		SmallLetter=random.randint(97,122)
		RealCharacter=random.randint(1,3)
		if RealCharacter==1:
			tempVerificationCode+=chr(Digit)
		elif RealCharacter==2:
			tempVerificationCode+=chr(CapitalLetter)
		elif RealCharacter==3:
			tempVerificationCode+=chr(SmallLetter)
	return tempVerificationCode
pwd_context=CryptContext(schemes=["bcrypt"],deprecated="auto")
class UserModel(BaseModel):
	email: str
	password: str
def get_db():
	db=SessionLocal()
	try:
		yield db
	finally:
		db.close()
def hash_string(string:str)->str:
	truncated_string=string[:min(len(string),72)]
	return pwd_context.hash(truncated_string)
def verify_password(entered_password:str,stored_hashed_password:str)->bool:
	truncated_password=entered_password[:min(len(entered_password),72)]
	return pwd_context.verify(truncated_password,stored_hashed_password)
@app.post("/signup/")
def signup(user:EmailModel,db:Session=Depends(get_db)):
	db_user=db.query(User).filter(User.email==user.email).first()
	if db_user:
		return {"message":f"{user.email} Already Used","statusCode":-1}
	return {"message":"Account Created Successfully","statusCode":0}
@app.post("/login/")
def login(user:UserModel,db:Session=Depends(get_db)):
	db_user=db.query(User).filter(User.email==user.email).first()
	if not db_user:
		return {"message":"Email is not Exist","statusCode":-1}
	if not verify_password(user.password,db_user.password):
		return {"message":"Incorrect Password","statusCode":-2}
	return {"message":"Email Successfully Login","statusCode":0}
@app.post("/send_verification_code/")
def send_verification_code(data:EmailModel,db:Session=Depends(get_db)):
	email=data.email
	db_user=db.query(User).filter(User.email==email).first()
	if not db_user:
		return {"message":f"Email {email} is not Exist","statusCode":-1}
	VerificationCodes[email]=GenerateVerificationCode()
	msg=EmailMessage()
	msg["Subject"]="Verification Code"
	msg["From"]="Fire Fighter Drone<ffighterdrone@gmail.com>"
	msg["To"]=email
	msg.set_content(f"Your Verification Code is {VerificationCodes[email]}")
	msg.add_alternative(f"Your Verification Code is <b>{VerificationCodes[email]}</b>",subtype="html")
	try:
		with smtplib.SMTP_SSL("smtp.gmail.com",465) as smtp:
			smtp.login("ffighterdrone@gmail.com","xxtr omic rxtl clda")
			smtp.send_message(msg)
	except:
		return {"message":f"Cannot Send Verification Code to {email}","statusCode":-2}
	return {"message":f"Successfuly Sent Verification Code to {email}","statusCode":0}
@app.post("/set_verification_code/")
def set_verification_code(data:VerificationCodeModel):
	global VerificationCodes
	if data.verification_code!=VerificationCodes[data.email]:
		return{"message":"Error in Verification Code","statusCode":-1}
	return{"message":"Successful Verification","statusCode":0}
@app.post("/create_new_password/")
def create_new_password(user:UserModel,db:Session=Depends(get_db)):
	email=user.email
	new_password=user.email
	db_user=db.query(User).filter(User.email==email).first()
	if not db_user:
		return {"message":"Email is not Exist","statusCode":-1}
	hashed_password=hash_string(new_password)
	db_user.password=hashed_password
	db.commit()
	return {"message":"Password Changed Successfully","statusCode":0}