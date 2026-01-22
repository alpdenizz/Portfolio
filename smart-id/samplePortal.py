#pip install Flask
from flask import Flask
from flask import request, Response
from flask import jsonify
import os
from jwcrypto.common import json_encode

app = Flask(__name__)

def genCookie():
    return 'JSESSIONID='+os.urandom(16).hex().upper()

cookie = genCookie()

@app.route('/api/providers', methods=['GET'])
def getProviders():
    global cookie
    args = request.args
    print('[+] isHierarchical:',args.get('isHierarchical'))
    print('[+] type:',args.get('type'))
    print('[+] clientApp:',args.get('clientApp'))
    print('[+] clientLib:',args.get('clientLib'))
    print('[+] clientDevice:',args.get('clientDevice'))
    print('[+] clientPlatform:',args.get('clientPlatform'))

    resp = {
    "data": {
        "deviceRestriction": {
            "ADVANCED": "OFF",
            "QUALIFIED": "OFF"
        },
        "isProxy": False,
        "order": [
            {
                "country": "EE",
                "types": [
                    {
                        "type": "MOBILEID"
                    },
                    {
                        "type": "IDCARD"
                    },
                    {
                        "groups": [
                            {
                                "group": "Swedbank",
                                "providers": [
                                    "Swedbank-BANKOFFICE"
                                ]
                            },
                            {
                                "group": "SEB",
                                "providers": [
                                    "SEB-BANKOFFICE"
                                ]
                            },
                            {
                                "group": "Luminor",
                                "providers": [
                                    "Luminor-BANKOFFICE"
                                ]
                            }
                        ],
                        "type": "BANK"
                    },
                    {
                        "type": "REMOTE_ONBOARDING"
                    }
                ]
            },
            {
                "country": "LV",
                "types": [
                    {
                        "groups": [
                            {
                                "group": "Swedbank",
                                "providers": [
                                    "Swedbank-LV",
                                    "Swedbank-BANKOFFICE"
                                ]
                            },
                            {
                                "group": "SEB",
                                "providers": [
                                    "SEB-LV",
                                    "SEB-BANKOFFICE"
                                ]
                            },
                            {
                                "group": "Luminor",
                                "providers": [
                                    "Luminor-DNB-LV",
                                    "Luminor-Nordea-LV",
                                    "Luminor-BANKOFFICE"
                                ]
                            }
                        ],
                        "type": "BANK"
                    },
                    {
                        "type": "IDCARD"
                    },
                    {
                        "type": "REMOTE_ONBOARDING"
                    }
                ]
            },
            {
                "country": "LT",
                "types": [
                    {
                        "groups": [
                            {
                                "group": "Swedbank",
                                "providers": [
                                    "Swedbank-LT",
                                    "Swedbank-BANKOFFICE"
                                ]
                            },
                            {
                                "group": "SEB",
                                "providers": [
                                    "SEB-LT",
                                    "SEB-BANKOFFICE"
                                ]
                            },
                            {
                                "group": "Luminor",
                                "providers": [
                                    "Luminor-DNB-LT",
                                    "Luminor-Nordea-LT",
                                    "Luminor-BANKOFFICE"
                                ]
                            },
                            {
                                "group": "Šiaulių Bankas",
                                "providers": [
                                    "SB-LT"
                                ]
                            },
                            {
                                "group": "Medicinos Bankas",
                                "providers": [
                                    "Medicinos",
                                    "Medicinos-BANKOFFICE"
                                ]
                            }
                        ],
                        "type": "BANK"
                    },
                    {
                        "type": "MOBILEID"
                    },
                    {
                        "type": "IDCARD"
                    },
                    {
                        "type": "REMOTE_ONBOARDING"
                    }
                ]
            }
        ],
        "providers": [
            {
                "countries": [
                    "EE",
                    "LT"
                ],
                "isGeoRestricted": False,
                "name": "Mobile-ID",
                "otpStatus": "ENABLE",
                "proxyRestriction": {
                    "android": "OFF",
                    "ios": "OFF"
                },
                "rootRestriction": {
                    "android": "BLOCK",
                    "ios": "BLOCK"
                },
                "type": "MOBILEID",
                "url": "/api/mobileid/authenticate"
            },
            {
                "countries": [
                    "EE",
                    "LV",
                    "LT"
                ],
                "isGeoRestricted": False,
                "name": "ID-Card",
                "portalSecondaryUrl": "https://rega.smart-id.com",
                "portalUrl": "https://reg.smart-id.com",
                "primaryUrlChances": {
                    "ee": "1",
                    "lt": "0",
                    "lv": "0"
                },
                "proxyRestriction": {
                    "android": "OFF",
                    "ios": "OFF"
                },
                "rootRestriction": {
                    "android": "BLOCK",
                    "ios": "BLOCK"
                },
                "type": "IDCARD"
            },
            {
                "country": "LV",
                "displayName": "Swedbank",
                "group": "Swedbank",
                "isGeoRestricted": False,
                "name": "Swedbank-LV",
                "proxyRestriction": {
                    "android": "BLOCK",
                    "ios": "BLOCK"
                },
                "rootRestriction": {},
                "type": "BANKLINK",
                "url": "/api/banklink/authenticate?provider=Swedbank-LV"
            },
            {
                "country": "LT",
                "displayName": "Swedbank",
                "group": "Swedbank",
                "isGeoRestricted": False,
                "name": "Swedbank-LT",
                "proxyRestriction": {
                    "android": "BLOCK",
                    "ios": "BLOCK"
                },
                "rootRestriction": {},
                "type": "BANKLINK",
                "url": "/api/banklink/authenticate?provider=Swedbank-LT"
            },
            {
                "country": "LT",
                "displayName": "SEB",
                "group": "SEB",
                "isGeoRestricted": False,
                "name": "SEB-LT",
                "proxyRestriction": {
                    "android": "BLOCK",
                    "ios": "BLOCK"
                },
                "rootRestriction": {},
                "type": "BANKLINK",
                "url": "/api/banklink/authenticate?provider=SEB-LT"
            },
            {
                "country": "LV",
                "displayName": "SEB",
                "group": "SEB",
                "isGeoRestricted": False,
                "name": "SEB-LV",
                "proxyRestriction": {
                    "android": "BLOCK",
                    "ios": "BLOCK"
                },
                "rootRestriction": {},
                "type": "BANKLINK",
                "url": "/api/banklink/authenticate?provider=SEB-LV"
            },
            {
                "countries": [
                    "EE",
                    "LV",
                    "LT"
                ],
                "group": "Swedbank",
                "isGeoRestricted": False,
                "name": "Swedbank-BANKOFFICE",
                "proxyRestriction": {
                    "android": "OFF",
                    "ios": "OFF"
                },
                "rootRestriction": {},
                "type": "BANKOFFICE"
            },
            {
                "countries": [
                    "EE",
                    "LV",
                    "LT"
                ],
                "group": "SEB",
                "isGeoRestricted": False,
                "name": "SEB-BANKOFFICE",
                "proxyRestriction": {
                    "android": "OFF",
                    "ios": "OFF"
                },
                "rootRestriction": {},
                "type": "BANKOFFICE"
            },
            {
                "country": "LT",
                "displayName": "Luminor | DNB online",
                "group": "Luminor",
                "isGeoRestricted": False,
                "name": "Luminor-DNB-LT",
                "proxyRestriction": {
                    "android": "BLOCK",
                    "ios": "BLOCK"
                },
                "rootRestriction": {},
                "type": "BANKLINK",
                "url": "/api/banklink/authenticate?provider=Luminor-DNB-LT"
            },
            {
                "country": "LV",
                "displayName": "Luminor | DNB online",
                "group": "Luminor",
                "isGeoRestricted": False,
                "name": "Luminor-DNB-LV",
                "proxyRestriction": {
                    "android": "BLOCK",
                    "ios": "BLOCK"
                },
                "rootRestriction": {},
                "type": "BANKLINK",
                "url": "/api/banklink/authenticate?provider=Luminor-DNB-LV"
            },
            {
                "country": "LT",
                "displayName": "Šiaulių Bankas",
                "group": "Šiaulių Bankas",
                "isGeoRestricted": False,
                "name": "SB-LT",
                "proxyRestriction": {
                    "android": "OFF",
                    "ios": "OFF"
                },
                "rootRestriction": {},
                "type": "BANKLINK",
                "url": "/api/banklink/authenticate?provider=SB-LT"
            },
            {
                "country": "LT",
                "displayName": "Medicinos Bankas",
                "group": "Medicinos Bankas",
                "isGeoRestricted": False,
                "name": "Medicinos",
                "proxyRestriction": {
                    "android": "OFF",
                    "ios": "OFF"
                },
                "rootRestriction": {},
                "type": "BANKLINK",
                "url": "/api/banklink/authenticate?provider=Medicinos"
            },
            {
                "country": "LV",
                "displayName": "Luminor | Nordea online",
                "group": "Luminor",
                "isGeoRestricted": False,
                "name": "Luminor-Nordea-LV",
                "proxyRestriction": {
                    "android": "BLOCK",
                    "ios": "BLOCK"
                },
                "rootRestriction": {},
                "type": "BANKLINK",
                "url": "/api/banklink/authenticate?provider=Luminor-Nordea-LV"
            },
            {
                "country": "LT",
                "displayName": "Luminor | Nordea online",
                "group": "Luminor",
                "isGeoRestricted": False,
                "name": "Luminor-Nordea-LT",
                "proxyRestriction": {
                    "android": "BLOCK",
                    "ios": "BLOCK"
                },
                "rootRestriction": {},
                "type": "BANKLINK",
                "url": "/api/banklink/authenticate?provider=Luminor-Nordea-LT"
            },
            {
                "countries": [
                    "LT"
                ],
                "group": "Medicinos Bankas",
                "isGeoRestricted": False,
                "name": "Medicinos-BANKOFFICE",
                "proxyRestriction": {
                    "android": "OFF",
                    "ios": "OFF"
                },
                "rootRestriction": {},
                "type": "BANKOFFICE"
            },
            {
                "countries": [
                    "EE",
                    "LV",
                    "LT"
                ],
                "group": "Luminor",
                "isGeoRestricted": False,
                "name": "Luminor-BANKOFFICE",
                "proxyRestriction": {
                    "android": "OFF",
                    "ios": "OFF"
                },
                "rootRestriction": {},
                "type": "BANKOFFICE"
            }
        ],
        "rootRestriction": {
            "ADVANCED": "WARN",
            "QUALIFIED": "WARN"
        }
    },
    "error": None,
    "status": "SUCCESS"
}
    
    body = json_encode(resp)
    response = Response(body, 200)
    response.headers['Set-Cookie'] = cookie+'; Path=/'
    response.headers['Content-Type'] = 'application/json'
    return response

@app.route('/api/mobileid/authenticate', methods=['POST'])
def midAuth():
    global cookie
    reqCookie = request.headers['Cookie']
    print('[+] cookie:',cookie)
    print('[+] reqCookie:',reqCookie)
    if cookie != reqCookie:
        return jsonify({'message': 'Unauthorized'}), 401
    
    
    data = request.form.to_dict()
    for k,v in data.items():
        print('[+] '+k+': '+v)
    
    cookie = genCookie()
    resp = {
    "data": {
        "statusUrl": "/api/mobileid/status",
        "verificationCode": "0110"
    },
    "error": None,
    "status": "SUCCESS"
    }

    body = json_encode(resp)
    response = Response(body, 200)
    response.headers['Set-Cookie'] = cookie+'; Path=/'
    response.headers['Content-Type'] = 'application/json'
    return response

@app.route('/api/log/event', methods=['POST'])
def logEvent():
    resp = {
    "data": {
        "status": "OK"
    },
    "error": None,
    "status": "SUCCESS"
    }

    body = json_encode(resp)
    response = Response(body, 200)
    response.headers['Content-Type'] = 'application/json'
    return response

@app.route('/api/mobileid/status', methods=['GET'])
def getMidStatus():
    global cookie
    reqCookie = request.headers['Cookie']
    if cookie != reqCookie:
        return jsonify({'message': 'Unauthorized'}), 401
    
    cookie = genCookie()
    resp = {
    "data": {
        "isMinor": False,
        "registerUserUrl": "/api/mobileid/register-user",
        "status": "USER_AUTHENTICATED"
    },
    "error": None,
    "status": "SUCCESS"
    }

    body = json_encode(resp)
    response = Response(body, 200)
    response.headers['Set-Cookie'] = cookie+'; Path=/'
    response.headers['Content-Type'] = 'application/json'
    return response

@app.route('/api/mobileid/otp/create', methods=['POST'])
def createOTP():
    global cookie
    reqCookie = request.headers['Cookie']
    if cookie != reqCookie:
        return jsonify({'message': 'Unauthorized'}), 401
    
    resp = {
    "data": {
        "message": "OK",
        "ttl": 300
    },
    "error": None,
    "status": "SUCCESS"
    }

    data = request.form.to_dict()
    for k,v in data.items():
        print('[+] '+k+': '+v)

    body = json_encode(resp)
    response = Response(body, 200)
    response.headers['Content-Type'] = 'application/json'
    return response

@app.route('/api/mobileid/otp/verify', methods=['POST'])
def verifyOTP():
    global cookie
    reqCookie = request.headers['Cookie']
    if cookie != reqCookie:
        return jsonify({'message': 'Unauthorized'}), 401
    
    resp = {
    "data": {
        "message": "OK"
    },
    "error": None,
    "status": "SUCCESS"
    }

    data = request.form.to_dict()
    for k,v in data.items():
        print('[+] '+k+': '+v)

    body = json_encode(resp)
    response = Response(body, 200)
    response.headers['Content-Type'] = 'application/json'
    return response

@app.route('/api/mobileid/register-user', methods=['POST'])
def registerUser():
    global cookie
    reqCookie = request.headers['Cookie']
    if cookie != reqCookie:
        return jsonify({'message': 'Unauthorized'}), 401
    
    resp = {
    "data": {
        "identityToken": "identityTestTokenForExperiment",
        "isMinor": False,
        "signApplicationUrl": "/api/mobileid/sign-application"
    },
    "error": None,
    "status": "SUCCESS"
    }

    body = json_encode(resp)
    response = Response(body, 200)
    response.headers['Content-Type'] = 'application/json'
    return response

@app.route('/api/mobileid/sign-application', methods=['POST'])
def signApplication():
    global cookie
    reqCookie = request.headers['Cookie']
    if cookie != reqCookie:
        return jsonify({'message': 'Unauthorized'}), 401
    
    resp = {
    "data": {
        "statusUrl": "/api/mobileid/sign-status",
        "verificationCode": "1001"
    },
    "error": None,
    "status": "SUCCESS"
    }

    body = json_encode(resp)
    response = Response(body, 200)
    response.headers['Content-Type'] = 'application/json'
    return response

@app.route('/api/mobileid/sign-status', methods=['GET'])
def getSignStatus():
    global cookie
    reqCookie = request.headers['Cookie']
    if cookie != reqCookie:
        return jsonify({'message': 'Unauthorized'}), 401
    
    resp = {
    "data": {
        "getSignedDocDataUrl": "/api/mobileid/get-signed-doc-data",
        "status": "SIGNATURE"
    },
    "error": None,
    "status": "SUCCESS"
    }

    body = json_encode(resp)
    response = Response(body, 200)
    response.headers['Content-Type'] = 'application/json'
    return response

@app.route('/api/mobileid/get-signed-doc-data', methods=['POST'])
def getSignedData():
    global cookie
    reqCookie = request.headers['Cookie']
    if cookie != reqCookie:
        return jsonify({'message': 'Unauthorized'}), 401
    
    resp = {
    "data": {
        "completeUrl": "/api/mobileid/complete",
        "signedDocData": None
    },
    "error": None,
    "status": "SUCCESS"
    }

    body = json_encode(resp)
    response = Response(body, 200)
    response.headers['Content-Type'] = 'application/json'
    return response