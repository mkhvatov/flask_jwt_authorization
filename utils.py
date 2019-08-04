import random
import re
import sys

import requests

from settings import PASSWORD_COMPLEXITY, MSISDN_LENGTH, SEND_SMS_SERVICE_URL


def gen_password(length=PASSWORD_COMPLEXITY):
    password = str()

    for i in range(length):
        char = random.randint(0, 9)
        password += str(char)
    return password


def is_msisdn_valid(msisdn):
    if re.match(r'[7]{1}[0-9]{10}', msisdn) and len(msisdn) == MSISDN_LENGTH:
        return True


def send_password_sms_to_user(password, msisdn):

    params = {
        'username': 'xxx',
        'from': 'xxx',
        'dlr-mask': 123,
        'text': password,
        'smsc': 'xxx',
        'to': msisdn,
        'password': 'xxx',
        'charset': 'UTF-8',
        'coding': 123,
        'rip': 123,
    }

    try:
        send_sms_req = requests.get(SEND_SMS_SERVICE_URL, params=params)
        send_sms_response = {'status_code': send_sms_req.status_code, 'headers': send_sms_req.headers}
    except Exception as error:
        print(error, file=sys.stderr)
