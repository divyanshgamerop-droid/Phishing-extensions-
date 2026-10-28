from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from services.url_scanner import scan_url


app = FastAPI()


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class URLRequest(BaseModel):
    url: str


@app.get("/")
def home():

    return {
        "message": "Phishing Protection API is running"
    }


@app.post("/scan-url")
def scan_url_endpoint(request: URLRequest):

    result = scan_url(request.url)

    return result