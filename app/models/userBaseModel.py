from datetime import datetime
from typing import Optional
from pydantic import BaseModel
from enum import Enum

class RegisterData(BaseModel):
  email : str
  phoneNumber : str
  password : str
  confirmedPassword : str

class LoginData(BaseModel):
  email : str
  password : str

