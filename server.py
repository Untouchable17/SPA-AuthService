import hmac, hashlib, base64, json
from typing import Optional

from fastapi import FastAPI, Form, Cookie, Body
from fastapi.responses import Response


app = FastAPI()

SECRET_KEY = "3a118242fc5fdee1ce7fc5de35a97d46a816c18f2f15b8ad8ac3b33d2bba5bf59bccda5b70eb3e"
PASSWORD_SOLT = "d5bf8348c6576779215d3f4bdb52a0e0f5ddc3cc12c415e3e2b5bb8348c65e"


users = {
	"secdet@blasthack.net": {
		"id": 13,
		"username": "secdet",
		"password": "068d46c79d0fc796ac0f64b6b45c534e8811f5f34e7684a9dc952d33e0620108",
		"balance": 730_000
	},
	"krypton@blasthack.net": {
		"id": 17,
		"username": "krypton",
		"password": "c875d99823c53d867f7842622aaf9ca8b6b6d0f8209803fa8168bd8c49f93fef",
		"balance": 100_050
	},
}


def sign_data(data: str) -> str:

	return hmac.new(
		SECRET_KEY.encode(),
		msg=data.encode(),
		digestmod=hashlib.sha256
	).hexdigest().upper()


def get_username_from_signed_string(username_signed: str) -> Optional[str]:

	username_base64, sign = username_signed.split(".")
	username = base64.b64decode(username_base64.encode()).decode()
	valid_sign = sign_data(username)

	if hmac.compare_digest(valid_sign, sign):
		return username


def verify_password(username: str, password: str) -> bool:

	password_hash = hashlib.sha256((password + PASSWORD_SOLT).encode()).hexdigest().lower()
	stored_password_hash = users[username]["password"].lower()
	
	return password_hash == stored_password_hash





@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
	with open("templates/login.html", "r", encoding="utf-8") as file:
		login_page = file.read()

	if not username:
		return Response(login_page, media_type="text/html")
	
	valid_username = get_username_from_signed_string(username)

	if not valid_username:
		response = Response(login_page, media_type="text/html")
		response.delete_cookie(key="username")
		return response

	try:
		user = users[valid_username]
	except KeyError:
		response = Response(login_page, media_type="text/html")
		response.delete_cookie(key="username")
		return response 
	return Response(f"Welcome, {users[username]['username']}")



@app.post("/login")
def process_login_page(data: dict = Body(...)):
	print(f"[DATA] {data}")
	
	username = data["username"]
	password = data["password"]

	user = users.get(username, None)

	if not user or not verify_password(username, password):
		return Response(
			json.dumps({
				"success": False, 
				"message": "Error in login or password"
			}), 
			media_type="application/json"
		)

	response = Response(
		json.dumps({
			"success": True, 
			"message": f"Welcome, {user['username']}. Your balance: {user['balance']}"
		}), 
		media_type="application/json"
	)
	username_signed = base64.b64encode(username.encode()).decode() + "." + sign_data(username)
	response.set_cookie(key="username", value=username_signed)

	return response