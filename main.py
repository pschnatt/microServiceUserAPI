from fastapi import FastAPI
from app.controllers.userController import router as userController

app = FastAPI()
app.include_router(userController, prefix="/api/user")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8002, reload=True)
