from datetime import datetime, timedelta, timezone
import bcrypt
from bson import ObjectId
import certifi
from fastapi import Request, Response
import jwt
from pymongo import MongoClient
from app.helpers.exception import UserException
from app.models.userBaseModel import LoginData, RegisterData
from app.core.config import settings
from app.helpers.validator import Validator

class UserService:
    def __init__(self):
      self.client = MongoClient(settings.MONGODB_URI, tlsCAFile=certifi.where())
      self.db = self.client[settings.DB_NAME]
      self.collection = self.db[settings.COLLECTION_NAME]

    def registerUser(self, userRegister : RegisterData):
        try:
            userData = userRegister.model_dump()
            if self.collection.find_one({"email" : userData["email"]}):
                raise UserException(400, "Email already exists")
            
            if not Validator.validateEmail(userData["email"]):
                raise UserException(400, "Invalid email format")
            
            if (len(userData["password"]) < 6):
                raise UserException(400, "Password should be atleast 6 characters long")
            
            if (userData["password"] != userData["confirmedPassword"]):
                raise UserException(400, "Password mismatched")
            
            if not Validator.validatePhoneNumber(userData["phoneNumber"]):
                raise UserException(400, "Invalid phone number format")
            
            hashedPassword = bcrypt.hashpw(userData["password"].encode('utf-8'), bcrypt.gensalt())
            userData["hashedPassword"] = hashedPassword
            del userData["password"]
            del userData["confirmedPassword"]

            result = self.collection.insert_one(userData)

            return {"statusCode": 201, "userId": str(result.inserted_id)}

        except UserException as e:
            raise e
        except Exception as e:
            raise UserException(500, f"Error creating user: {str(e)}")
        
    def loginUser(self, data : LoginData, response: Response):
        
        user = self.collection.find_one({"email": data.email})

        if not user:
            raise Exception("User not found.")

        storedPassword = user.get("hashedPassword")

        if bcrypt.checkpw(data.password.encode('utf-8'), storedPassword):
            token = self.createJwtToken(user["_id"])

            expirationTime = datetime.now(timezone.utc) + timedelta(hours=100)

            response.set_cookie(
                key="jwt_token",
                value=token,
                httponly=True,  
                secure=True,
                samesite="Lax",
                expires=expirationTime
            )

            return {
                "statusCode" : 200,
                "message": "Login successful",
                "userId": str(user["_id"]),
                "token" : token,
                "response" : response
            }
    
    def createJwtToken(self, userId):
        try:
            expirationTime = datetime.now(timezone.utc) + timedelta(hours=10)
            payload = {
                "userId": str(userId),
                "exp": expirationTime
            }
            token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
            return token
        
        except Exception as e:
            raise UserException(500, f"Error jwt token: {str(e)}") 

    def verifyJwtToken(self, request: Request):
        try:
            token = request.cookies.get("jwt_token")  
            if not token:
                raise UserException(status_code=401, detail="User not logged in. Please log in.")
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])            
            return {"statusCode" : 200,"userId" : payload["userId"]}
        except UserException as e:
            raise e
        except Exception as e:
            raise UserException(500, f"Error verifying user: {str(e)}")
        