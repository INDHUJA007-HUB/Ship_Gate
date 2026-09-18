import os

from flask import Flask, request

app = Flask(__name__)
API_KEY = os.environ["PHOTO_API_KEY"]


@app.post("/photos")
def upload_photo():
    payload = request.get_json()
    return {"filename": payload["filename"]}, 201
