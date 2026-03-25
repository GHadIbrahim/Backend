from sqlalchemy import create_engine,Column,String
from sqlalchemy.orm import declarative_base,sessionmaker,Session
from pydantic import BaseModel
from passlib.context import CryptContext
from fastapi import FastAPI,Depends,WebSocket,WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import random
import smtplib
import os
from email.message import EmailMessage
from threading import Lock
import asyncio
import socket
from zeroconf import Zeroconf,ServiceBrowser,ServiceListener
import requests
import cv2
import numpy
import json
DeviceData={}
Clients=[]
class DeviceListener(ServiceListener):
	def __init__(self,devices_dict,lock):
		self.devices=devices_dict
		self.lock=lock
	def add_service(self,zeroconf,type,name):
		info=zeroconf.get_service_info(type,name)
		print("service added")
		if info:
			ip=socket.inet_ntoa(info.addresses[0])
			hostname=info.server.rstrip(".")
			mac=info.properties.get(b"MAC",b"").decode().upper()
			Port=info.port
			LAT=float(info.properties.get(b"LAT",b"0").decode())
			LON=float(info.properties.get(b"LON",b"0").decode())
			isDeviceConnected=bool(info.properties.get(b"isDeviceConnected",b"0").decode())
			with self.lock:
				self.devices[mac]={"IP":ip,
											 "HOSTNAME":hostname,
											 "ServiceName":name,
											 "PORT":Port,
											 "LAT":LAT,
											 "LON":LON,
											 "isDeviceConnected":isDeviceConnected,}
	def remove_service(self,zeroconf,type,name):
		with self.lock:
			to_remove=[k for k,v in self.devices.items() if v["ServiceName"]==name]
			for k in to_remove:
				del self.devices[k]
		print("service removed")
	def update_service(self,zeroconf,type,name):
		print("service updated")
		self.add_service(zeroconf,type,name)
EMAIL=os.getenv("EMAIL")
EMAIL_KEY=os.getenv("EMAIL_KEY")
Base=declarative_base()
VerificationCodes={}
DevicesLock=Lock()
Devices={}
zeroconf=Zeroconf()
listener=DeviceListener(Devices,DevicesLock)
browser=ServiceBrowser(zeroconf,"_http._tcp.local.",listener)
class User(Base):
	__tablename__="users"
	email=Column(String,primary_key=True)
	password=Column(String)
class VerificationCodeModel(BaseModel):
	verification_code:str
	email:str
class EmailModel(BaseModel):
	email: str
class DeviceModel(BaseModel):
	Device_MAC:str
	Device_NAME:str
class ControlStatementModel(BaseModel):
	Device_MAC:str
	Statement:str
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
	if db_user and db_user.password!="":
		return {"message":f"{user.email} Already Used","statusCode":-1}
	return {"message":"","statusCode":0}
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
	msg["From"]=f"Fire Fighter Drone<{EMAIL}>"
	msg["To"]=email
	msg.set_content(f"Your Verification Code is {VerificationCodes[email]}")
	msg.add_alternative(f"Your Verification Code is <b>{VerificationCodes[email]}</b>",subtype="html")
	try:
		with smtplib.SMTP_SSL("smtp.gmail.com",465) as smtp:
			smtp.login(EMAIL,EMAIL_KEY)
			smtp.send_message(msg)
	except:
		return {"message":f"Cannot Send Verification Code to {email}","statusCode":-2}
	return {"message":f"Successfuly Sent Verification Code to {email}","statusCode":0}
@app.post("/set_verification_code/")
def set_verification_code(data:VerificationCodeModel):
	global VerificationCodes
	if data.verification_code!=VerificationCodes[data.email]:
		return{"message":"Error in Verification Code","statusCode":-1}
	del VerificationCodes[data.email]
	return{"message":"Successful Verification","statusCode":0}
@app.post("/create_password/")
def create_password(user:UserModel,db:Session=Depends(get_db)):
	email=user.email
	new_password=user.password
	db_user=db.query(User).filter(User.email==email).first()
	old_password=db_user.password
	hashed_password=hash_string(new_password)
	db_user.password=hashed_password
	db.commit()
	if old_password!="":
		return {"message":f"Password of {email} is Changed Successfully","statusCode":0}
	else:
		return {"message":f"Your email ({email}) has been successfully registered","statusCode":0}
@app.websocket("/ws/devices")
async def devices_websocket(websocket:WebSocket):
	await websocket.accept()
	try:
		while True:
			with DevicesLock:
				await websocket.send_json(Devices)
			await asyncio.sleep(1)
	except:
		pass
@app.post("/connect_device/")
def connect_device(data:DeviceModel):
	Device_NAME=data.Device_NAME
	Device_MAC=data.Device_MAC
	with DevicesLock:
		if not Device_MAC in list(Devices.keys()):
			return {"message":f"Connection to {Device_NAME} Failed","statusCode":-1}
		IP=Devices[Device_MAC]["IP"]
		PORT=Devices[Device_MAC]["PORT"]
		ENCODED_MAC=Device_MAC.replace(":","-")
	try:
		response=requests.get(f"http://{IP}:{PORT}/connect/{ENCODED_MAC}/",timeout=3)
		print(response)
		if response.status_code==200:
			if response.text=="Device Connected Successfully":
				return {"message":response.text,"statusCode":0}
			else:
				return {"message":response.text,"statusCode":-1}
		else:
			return {"message": f"Connection to {Device_NAME} denied","statusCode":-2}
	except Exception as e:
		return {"message": f"Connection to {Device_NAME} Failed {e}","statusCode":-3}
@app.post("/disconnect_device/")
def disconnect_device(data:DeviceModel):
	Device_NAME=data.Device_NAME
	Device_MAC=data.Device_MAC
	with DevicesLock:
		if not Device_MAC in list(Devices.keys()):
			return {"message":f"Connection to {Device_NAME} Failed","statusCode":-1}
		IP=Devices[Device_MAC]["IP"]
		PORT=Devices[Device_MAC]["PORT"]
		ENCODED_MAC=Device_MAC.replace(":","-")
	try:
		response=requests.get(f"http://{IP}:{PORT}/disconnect/{ENCODED_MAC}/",timeout=3)
		print(response)
		if response.status_code==200:
			if response.text=="Device disconnected Successfully":
				return {"message":response.text,"statusCode":0}
			else:
				return {"message":response.text,"statusCode":-1}
		else:
			return {"message": f"{Device_NAME} Connection denied","statusCode":-2}
	except Exception as e:
		return {"message": f"Connection to {Device_NAME} Failed","statusCode":-3}
@app.websocket("/ws/receive_information/{device_mac}/")
async def receive_information(websocket: WebSocket,device_mac:str):
	await websocket.accept()
	try:
		while True:
			data=await websocket.receive()
			if "bytes" in data:
				np_array=numpy.frombuffer(data["bytes"],numpy.uint8)
				frame=cv2.imdecode(np_array,cv2.IMREAD_COLOR)
				if frame is not None:
					cv2.imshow("Recieved Frame",frame)
					cv2.waitKey(1)
				if device_mac not in DeviceData:
					DeviceData[device_mac]={}
				DeviceData[device_mac]["frame"]=data["bytes"]
			elif "text" in data:
				info=json.loads(data["text"])
				if device_mac not in DeviceData:
						DeviceData[device_mac] = {}
				DeviceData[device_mac]["info"]=info
	except WebSocketDisconnect:
		print("Client disconnected")
		cv2.destroyAllWindows()
@app.websocket("/ws/send_information/")
async def send_information(websocket: WebSocket):
	await websocket.accept()
	Clients.append(websocket)
	try:
		while True:
			await asyncio.sleep(0.03)
			for mac,data in DeviceData.items():
				if "info" in data:
					await websocket.send_json({
							"mac":mac,
							"info":data["info"]
					})
				if "frame" in data:
					await websocket.send_bytes(data["frame"])
	except:
		Clients.remove(websocket)
@app.post("/control_statement/")
def control_statement(controlStatement:ControlStatementModel):
	Device_MAC=controlStatement.Device_MAC
	Statement=controlStatement.Statement
	with DevicesLock:
		if not Device_MAC in list(Devices.keys()):
			return {"message":"cannot send Control Statement","statusCode":-1}
		IP=Devices[Device_MAC]["IP"]
		PORT=Devices[Device_MAC]["PORT"]
		Device_NAME=Devices[Device_MAC]["HOSTNAME"]
		ENCODED_MAC=Device_MAC.replace(":","-")
	try:
		response=requests.get(f'http://{IP}:{PORT}/control/{ENCODED_MAC}/',params={"ControlStatement":Statement},timeout=3)
		print(response)
		if response.status_code==200:
			return {"message":"","statusCode":0}
		else:
			return {"message":"cannot send Control Statement","statusCode":-2}
	except Exception as e:
		return {"message": f"Connection to {Device_NAME} Failed","statusCode":-3}