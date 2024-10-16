import os
from dotenv import load_dotenv
from pydantic_settings import BaseSettings
load_dotenv()

class Settings(BaseSettings):
    MONGODB_URI: str = os.getenv("MONGODB_URI", "mongodb+srv://schnatr:vcS0AQDhqKWSi6Tc@clusterzero.6uzvv.mongodb.net/?retryWrites=true&w=majority&appName=ClusterZero")
    DB_NAME: str = os.getenv("DB_NAME", "USER")
    COLLECTION_NAME: str = os.getenv("COLLECTION_NAME", "USER")
    SECRET_KEY : str = os.getenv("SECRET_KEY", "testtest")

settings = Settings()
