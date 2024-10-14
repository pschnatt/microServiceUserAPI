from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from app.helpers.exception import UserException
from app.models.userBaseModel import LoginData, RegisterData
from app.services.userService import UserService

router = APIRouter()

userService = UserService()

@router.post("/register")
async def registerUser(registerData : RegisterData):
    try:
      response = userService.registerUser(registerData)
      return JSONResponse(status_code=response["statusCode"], content={"message": "User created successfully", "userId": response["userId"]})
    except UserException as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)

@router.post("/login")
async def loginUser(loginData : LoginData, response : Response):
    try:

        result = userService.loginUser(loginData, response=response)
        
        return JSONResponse(
            status_code=result["statusCode"], 
            content={"message": "User successfully login", "userId": result["userId"], "token": result["token"]},
            headers=dict(response.headers))
    
    except UserException as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)

@router.get("/verify")
async def verifyUser(request: Request):
    try:
        response = userService.verifyJwtToken(request)
        return JSONResponse(status_code=response["statusCode"], content={"message": "Verify successfully", "userId": response["userId"]})
    except UserException as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)
