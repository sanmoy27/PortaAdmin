import os
os.chdir("C:/F/Project-Start-up/flaskapp")
import numpy as np
import pandas as pd
import datetime
import math
from twilio.rest import Client
import requests
from flask import jsonify
import json
from flask_mail import Mail, Message
with open('config.json', 'r') as json_data_file:
    config = json.load(json_data_file)

URL = config["SMS_URL"]
API_KEY = config["SMS_API_KEY"]
TEMPLATE_ID = config['TEMPLATE_ID']
# the following line needs your Twilio Account SID and Auth Token
#client = Client("AC1fb054295459a660813b55cb0c3289b3", "9b61543c03c401c86497eb6a8facdefe")
#client.messages.create(to="+918317021769", 
#                       from_="+18507572201",
#                       body="Hello from Python!")
#

def sendOTP_SMS(pHNo, otp):
    print("sendOTP_SMS==================")
    payload = "sender_id=FSTSMS&language=english&route=qt&numbers="+str(pHNo)+"&message="+str(TEMPLATE_ID)+"&variables={#BB#}&variables_values="+str(otp)
    headers = {
        'authorization': API_KEY,
        'cache-control': "no-cache",
        'content-type': "application/x-www-form-urlencoded"
        }
    
    response = requests.request("POST", URL, data=payload, headers=headers)
    return json.loads(response.text)

def sendEMAIL(app, emailid, subject, msgBody):
    print("sendEMAIL==================")
    mail = Mail(app)
    
    msg = Message(
            subject=subject,
            recipients=[emailid],
            body=msgBody,
            cc=['sanmoy.nmims@gmail.com'],
            bcc=[],
            attachments=[]
            )
    mail.send(msg)
    return "email sent!!!!"
