from fastapi.testclient import TestClient
from unittest.mock import patch
from app.services.userService import UserService
from app.helpers.exception import UserException
from main import app

client = TestClient(app)

user_service = UserService()

def test_registerUser_ReturnSuccess():
    mockResponse = {"statusCode": 201, "userId": "user123"}
    
    with patch.object(UserService, 'registerUser', return_value=mockResponse):
        userData = {
            "email": "user123@example.com",
            "password": "password123",
            "confirmedPassword": "password123",
            "phoneNumber": "+12345678901"
        }
        response = client.post("/api/user/register", json=userData)

    assert response.status_code == 201
    assert response.json() == {
        "message": "User created successfully",
        "userId": "user123"
    }

def test_registerUser_UsernameExists_ReturnError():
    mockException = UserException(400, "Username already exists")
    
    with patch.object(UserService, 'registerUser', side_effect=mockException):
        userData = {
            "username": "existingUser",
            "email": "existingUser@example.com",
            "password": "password123",
            "confirmedPassword": "password123",
            "phoneNumber": "+12345678901"
        }
        response = client.post("/api/user/register", json=userData)

    assert response.status_code == 400
    assert response.json() == {"detail": "Username already exists"}

def test_loginUser_ReturnSuccess():
    mockResponse = {"statusCode": 200, "message": "Login successful", "userId": "user123", "token": "token123"}

    with patch.object(UserService, 'loginUser', return_value=mockResponse):
        loginData = {
            "email": "user123@example.com",
            "password": "password123"
        }
        response = client.post("/api/user/login", json=loginData)

    assert response.status_code == 200
    assert response.json() == {
        "message": "User successfully login",
        "userId": "user123",
        "token": "token123"
    }

def test_loginUser_InvalidCredentials_ReturnError():
    mockException = UserException(400, "user not found")
    
    with patch.object(UserService, 'loginUser', side_effect=mockException):
        loginData = {
            "email": "invalid@example.com",
            "password": "password123"
        }
        response = client.post("/api/user/login", json=loginData)

    assert response.status_code == 400
    assert response.json() == {"detail": "user not found"}

def test_verifyJwtToken_ReturnSuccess():
    mockResponse = {"statusCode": 200, "userId": "user123"}

    with patch.object(UserService, 'verifyJwtToken', return_value=mockResponse):
        response = client.get("/api/user/verify")

    assert response.status_code == 200
    assert response.json() == {
        "message": "Verify successfully",
        "userId": "user123"
    }

def test_verifyJwtToken_NotLoggedIn_ReturnError():
    mockException = UserException(401, "User not logged in. Please log in.")
    
    with patch.object(UserService, 'verifyJwtToken', side_effect=mockException):
        response = client.get("/api/user/verify")

    assert response.status_code == 401
    assert response.json() == {"detail": "User not logged in. Please log in."}
