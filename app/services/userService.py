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
        
    def loginUser(self, userLogin : LoginData, response: Response):
        
        try:
            userData = userLogin.model_dump()
            user = self.collection.find_one({"email" : userData["email"]})

            if not user:
                raise UserException(400, f"user not found")
                
            stored_password = user.get("hashedPassword")

            if bcrypt.checkpw(userData["password"].encode('utf-8'), stored_password):
                token = self.createJwtToken(user["_id"])
                
                expiration_time = datetime.now(timezone.utc) + timedelta(hours=1)
                response.set_cookie(
                    key="jwt_token",
                    value=token,
                    httponly=True,  
                    secure=True,    
                    samesite="Lax",
                    expires=expiration_time
                )
                return {"statusCode" : 200, "message": "Login successful", "userId": str(user["_id"]), "token" : token}
        except UserException as e:
            raise e
        except Exception as e:
            raise UserException(500, f"Error creating user: {str(e)}")
    
    def createJwtToken(self, userId):
        try:
            expiration_time = datetime.now(timezone.utc) + timedelta(hours=10)
            payload = {
                "userId": str(userId),
                "exp": expiration_time
            }
            token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
            return {"statusCode" : 200, "token" : token}
        
        except Exception as e:
            raise UserException(500, f"Error creating user: {str(e)}") 

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
            raise UserException(500, f"Error creating user: {str(e)}")
        