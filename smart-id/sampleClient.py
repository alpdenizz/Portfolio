#pip install pycryptodome
from Crypto.PublicKey import RSA
from Crypto.Util.asn1 import *

#pip install jwcrypto
from jwcrypto.common import json_encode, json_decode
from jwcrypto import jwk, jws, jwe

#pip install pyDH
import pyDH

#default python3 modules
from base64 import urlsafe_b64encode, b64encode, b64decode
from math import ceil
from random import getrandbits
from time import sleep
from codecs import encode,decode
import hashlib
import requests
import json
import KeyGeneration
import argparse
import re, os


authFreshnessToken = ''
authOneTimePassword = ''
authKeyUUID = ''
authTEK = ''
authCompositeModulusBits = 0
authModulus = 0
authDhKeyPair = None

signFreshnessToken = ''
signOneTimePassword = ''
signKeyUUID = ''
signTEK = ''
signCompositeModulusBits = 0
signModulus = 0
signDhKeyPair = None

accountUUID = ''
appInstanceUUID = ''
password = ''

def genRequestId():
    i = getrandbits(32)
    b = i.to_bytes(4,'big')
    return b.hex()

def getBase64EncodedStr(intValue):
    return b64encode(intValue.to_bytes(ceil(intValue.bit_length() / 8), 'big')).decode()

def getIntValue(base64EncStr):
    return int.from_bytes(b64decode(base64EncStr),'big')

def getHeader():
    return {'X-Smart-ID-UI': '18.4.177', 'Content-type': 'application/json-rpc', 'User-Agent': 'okhttp/3.12.2', 'X-Smart-ID-Library': '14.1.120-sk-release', 'Accept-Charset': 'utf-8', 'X-Smart-ID-Platform': 'Android', 'Accept': None, 'Accept-Encoding': 'gzip', 'Connection': 'Keep-Alive'}

def getRegTokenNonce():
    header = getHeader()
    algorithm = 'MODULI-WITH-NONCE-SHA256'
    clientAuthModulus = getBase64EncodedStr(authModulus)
    clientSignModulus = getBase64EncodedStr(signModulus)
    registrationMethod = 'KEYTOKEN'
    body = {'id': genRequestId(), 'jsonrpc': '2.0', 'method':'getRegTokenNonce', 'params': {'algorithm': algorithm, 'clientAuthModulus': clientAuthModulus, 'clientSignModulus': clientSignModulus, 'registrationMethod': registrationMethod}}
    url = HOST + '/v2/public'
    #proxies = {
    #    "http": "PROXY ADDRESS",
    #    "https": "PROXY ADDRESS",
    #}
    #set proxies=proxies and verify=False to see the requests in the proxy easily
    r = requests.post(url, json=body, headers=header)
    
    print('[+] Request Header:',r.request.headers)
    print('[+] Request Body:',r.request.body)
    
    print('[+] Status:',r.status_code)
    responseBody = r.json()
    print('[+] Response Body:',responseBody)

    print('[+] nonce:', responseBody['result']['nonce'])
    print('[+] token:', responseBody['result']['token'])
    return responseBody['result']['nonce']

def registerDevice(token,tokenMethod='KEYTOKEN'):
    header = getHeader()
    clientAuthDhPublicKey = getBase64EncodedStr(authDhKeyPair.gen_public_key())
    clientAuthModulus = getBase64EncodedStr(authModulus)
    clientSignDhPublicKey = getBase64EncodedStr(signDhKeyPair.gen_public_key())
    clientSignModulus = getBase64EncodedStr(signModulus)
    knownServerKeys = ["KTKQ-2018"]
    registrationTokenAlgorithm = "MODULI-WITH-NONCE-SHA256"
    registrationTokenFromBackend = token
    registrationType = tokenMethod

    body = {'id': genRequestId(), 'jsonrpc':'2.0', 'method':'registerDevice', 'params': {'accountRegistrationData':{
        'clientAuthDhPublicKey': clientAuthDhPublicKey,
        'clientAuthModulus': clientAuthModulus,
        'clientSignDhPublicKey': clientSignDhPublicKey,
        'clientSignModulus': clientSignModulus,
        'knownServerKeys': knownServerKeys,
        'registrationTokenAlgorithm': registrationTokenAlgorithm,
        'registrationTokenFromBackend': registrationTokenFromBackend,
        'registrationType': registrationType
    }, 'deviceData': {
        "appPackageName": "com.smart_id",
            "appVersion": "18.4.177",
            "platform": "Android",
            "properties": {
                "apiVersion": "24",
                "capabilityList": [
                    "dev-keys",
                    "x86",
                    "LTR",
                    "NFC_unsupported"
                ],
                "deviceCodeName": "revolver",
                "deviceFingerprint": genRequestId()+genRequestId(),
                "hwCryptoTest": {
                    "aesKeyStore": "sw",
                    "attestationRoot": "failedCheckValidity",
                    "attestedAppDigest": "failedCheckValidity",
                    "attestedAppPackageName": "failedCheckValidity",
                    "attestedAppVersion": "failedCheckValidity",
                    "attestedKeymaster": "failedCheckValidity",
                    "attestedVerifiedBootState": "failedCheckValidity",
                    "ecKeyStore": "sw",
                    "rsaKeyStore": "sw"
                },
                "manufacturer": "Google",
                "modelName": "LG-770R",
                "platformVersion": "7.0",
                "prngTestResult": [
                    {
                        "failCount": 0,
                        "name": "FIPS 140-1 Monobit test",
                        "successCount": 25
                    },
                    {
                        "failCount": 0,
                        "name": "FIPS 140-1 Poker test",
                        "successCount": 25
                    },
                    {
                        "failCount": 0,
                        "name": "FIPS 140-1 Runs test",
                        "successCount": 25
                    },
                    {
                        "failCount": 0,
                        "name": "FIPS 140-1 Long Runs test",
                        "successCount": 25
                    }
                ],
                "productCodeName": "revolver"
            },
            "pushNotificationChannel": "PUSH_CHANNEL_GCM_DEFAULT",
            "serviceLibraryVersion": "14.1.120-sk-release",
            "tseVersion": "10.3.3_RELEASE"
    } }}
    url = HOST + '/v2/public'
    #proxies = {
    #    "http": "PROXY ADDRESS",
    #    "https": "PROXY ADDRESS",
    #}
    #set proxies=proxies and verify=False to see the requests in the proxy easily
    r = requests.post(url, json=body, headers=header)
    return r.status_code, r.json()
    
    print('[+] Status:',r.status_code)
    responseBody = r.json()
    print('[+] Response Body:',responseBody)

def handleRegisterDeviceResponse(response):
    global accountUUID
    global appInstanceUUID
    global password
    result = response['result']
    accountUUID = result['accountUUID']
    appInstanceUUID = result['appInstanceUUID']
    password = result['password']
    authKeyResponse = result['authKey']
    signKeyResponse = result['signKey']
    
    handleKeyResponse(True,authKeyResponse)
    handleKeyResponse(False,signKeyResponse)

def deriveTEK(dhKeyPair, otherPartyDhPublicKey):
    otherPubInt = int.from_bytes(b64decode(bytes(otherPartyDhPublicKey, 'utf-8')),'big')
    #print('ClientDhPublicKey:', otherPubInt)
    privateKey = dhKeyPair.get_private_key()
    prime = dhKeyPair.p
    sharedKey = pow(otherPubInt, privateKey, prime)
    sharedKeyBytes = sharedKey.to_bytes(ceil(sharedKey.bit_length() / 8), 'big')
    initializationVector = 'A128CBC-HS256CLIENTSERVER'.encode('utf-8')
    itoOSPBytes = bytes([0,0,0,1])
    hasher = hashlib.sha256()
    hasher.update(itoOSPBytes)
    hasher.update(sharedKeyBytes)
    hasher.update(initializationVector)
    return urlsafe_b64encode(hasher.digest()).decode()

def testResponseData(dhDerivedKeyId, dhDerivedKey):
    oneTimePassword = b64encode(getrandbits(128).to_bytes(16,'big')).decode()
    jwePayloadContent = json_encode({'oneTimePassword': oneTimePassword}).encode('utf-8')
    jweKey = jwk.JWK.from_json(json_encode({'k': dhDerivedKey, 'kty':'oct'}))
    jwePayload = jwe.JWE(jwePayloadContent, json_encode({"aud":"CLIENT","enc":"A128CBC-HS256","alg":"dir","keyUUID":dhDerivedKeyId,"kid":dhDerivedKeyId}))
    jwePayload.add_recipient(jweKey)
    message = jwePayload.serialize(True)
    return message

def extractOneTimePasswordFromResponseData(responseData, tek):
    jwktek = jwk.JWK.from_json(json_encode({'k': tek, 'kty':'oct'}))
    jweDecrypted = jwe.JWE()
    jweDecrypted.deserialize(responseData)
    jweDecrypted.decrypt(jwktek)
    oneTimePasswordJson = json.loads(jweDecrypted.payload)
    oneTimePassword = oneTimePasswordJson['oneTimePassword']
    #print('oneTimePassword:',oneTimePassword)
    return oneTimePassword

def verifyServerDhMessageAndSetKeyUUID(serverDhMessage, serverDhPublicKey, clientDhPublicKey, tek):
    jwktek = jwk.JWK.from_json(json_encode({'k': tek, 'kty':'oct'}))
    jweDecrypted = jwe.JWE()
    jweDecrypted.deserialize(serverDhMessage)
    jweDecrypted.decrypt(jwktek)
    jwsObject = jweDecrypted.payload
    
    #jwsObjectHeader = json_decode(jwsObject)['header']
    #keyUUID = jwsObjectHeader['keyUUID'] #access keyUUID for auth or sign (depending on which key)

    ktk = jwk.JWK.from_pem(ktkKeyCert)
    jwsContainer = jws.JWS()
    jwsContainer.deserialize(jwsObject.decode())
    jwsContainer.verify(ktk)
    
    jwsObjectHeader = jwsContainer.jose_header
    #keyUUID = jwsObjectHeader['keyUUID'] #access keyUUID for auth or sign (depending on which key)
    res = json_encode({'clientDhPublicKey': clientDhPublicKey, 'serverDhPublicKey': serverDhPublicKey}).encode('utf-8') == jwsContainer.payload
    if not res:
        raise Exception('Server response is not verified! - Encryption/Decryption Failure')
    else: 
        return jwsObjectHeader['keyUUID']

def handleKeyResponse(isAuthKey, keyResponse):
    global authTEK
    global authOneTimePassword
    global authFreshnessToken
    global authCompositeModulusBits
    global signTEK
    global signOneTimePassword
    global signFreshnessToken
    global signCompositeModulusBits
    global authKeyUUID
    global signKeyUUID
    # set freshness token
    freshnessToken = keyResponse['freshnessToken']
    compositeModulus = keyResponse['compositeModulusBits']
    if isAuthKey:
        authFreshnessToken = freshnessToken
        authCompositeModulusBits = compositeModulus
    else:
        signFreshnessToken = freshnessToken
        signCompositeModulusBits = compositeModulus
    # construct tek
    serverDhPublicKey = keyResponse['serverDhPublicKey']
    tek = ''
    if isAuthKey:
        authTEK = deriveTEK(authDhKeyPair, serverDhPublicKey)
    else:
        signTEK = deriveTEK(signDhKeyPair, serverDhPublicKey)
    # extract oneTimePassword from responseData
    responseData =  keyResponse['responseData']
    if isAuthKey:
        authOneTimePassword = extractOneTimePasswordFromResponseData(responseData,authTEK)
    else:
        signOneTimePassword = extractOneTimePasswordFromResponseData(responseData,signTEK)
    # verify serverDhMessage and extract keyUUID
    serverDhMessage = keyResponse['serverDhMessage']
    if isAuthKey:
        clientDhPublicKey = getBase64EncodedStr(authDhKeyPair.gen_public_key())
        authKeyUUID = verifyServerDhMessageAndSetKeyUUID(serverDhMessage, serverDhPublicKey, clientDhPublicKey, authTEK)
    else:
        clientDhPublicKey = getBase64EncodedStr(signDhKeyPair.gen_public_key())
        signKeyUUID = verifyServerDhMessageAndSetKeyUUID(serverDhMessage, serverDhPublicKey, clientDhPublicKey, signTEK)

def getAuthorization(appInstanceUUID, password):
    token = urlsafe_b64encode((appInstanceUUID+':'+password).encode('utf-8'))
    return 'Basic '+token.decode()

def getHeaderWithAuthorization(hasSplitKeyTrigger, appInstanceUUID, password):
    if hasSplitKeyTrigger:
        return {'X-Smart-ID-UI': '18.4.177', 'Content-type': 'application/json-rpc', 'User-Agent': 'okhttp/3.12.2', 'X-Smart-ID-Library': '14.1.120-sk-release', 'Accept-Charset': 'utf-8', 'X-Smart-ID-Platform': 'Android', 'Accept': None, 'Accept-Encoding': 'gzip', 'Connection': 'Keep-Alive', 'X-SplitKey-Trigger': 'external', 'Authorization': getAuthorization(appInstanceUUID, password)}
    return {'X-Smart-ID-UI': '18.4.177', 'Content-type': 'application/json-rpc', 'User-Agent': 'okhttp/3.12.2', 'X-Smart-ID-Library': '14.1.120-sk-release', 'Accept-Charset': 'utf-8', 'X-Smart-ID-Platform': 'Android', 'Accept': None, 'Accept-Encoding': 'gzip', 'Connection': 'Keep-Alive', 'Authorization': getAuthorization(appInstanceUUID, password)}

def submitServersPartOfPrivateKey(isAuth, freshnessToken, oneTimePassword, privateKeyServerPart, keyUUID, tek, clientModulus):
    header = getHeaderWithAuthorization(True, appInstanceUUID, password)
    
    jweKTK = jwk.JWK.from_pem(ktkKeyCert)
    jwePayloadContent = privateKeyServerPart.to_bytes(ceil(privateKeyServerPart.bit_length() / 8), 'big')
    jwePayload = jwe.JWE(jwePayloadContent, json_encode({"enc":"A128CBC-HS256","alg":"RSA-OAEP","kid":"KTKQ-2018","aud":"SERVER","purpose":"CLIENT2NDPART"}))
    jwePayload.add_recipient(jweKTK)
    jweContainingD1PrimePrime = jwePayload.serialize(True)

    jweTEK = jwk.JWK.from_json(json_encode({'k': tek, 'kty':'oct'}))
    retransmitNonce = getBase64EncodedStr(getrandbits(128))
    jwePayloadContent = json_encode({"client2ndPart": jweContainingD1PrimePrime,"client2ndPartEncoding":"JWE","clientModulus": clientModulus, "retransmitNonce": retransmitNonce,"oneTimePassword": oneTimePassword}
    ).encode('utf-8')
    jwePayload = jwe.JWE(jwePayloadContent, json_encode({"enc":"A128CBC-HS256","alg":"dir","keyUUID":keyUUID,"kid":keyUUID,"aud":"SERVER"}))
    print('tek:',tek)
    jwePayload.add_recipient(jweTEK)
    requestData = jwePayload.serialize(True)

    params = {'freshnessToken': freshnessToken, 'requestData': requestData, 'requestDataEncoding': 'JWE'}
    body = {'id': genRequestId(), 'jsonrpc':'2.0', 'method':'submitClient2ndPart', 'params': params}
    url = HOST + '/v2/protected'
    #proxies = {
    #    "http": "PROXY ADDRESS",
    #    "https": "PROXY ADDRESS",
    #}
    #set proxies=proxies and verify=False to see the requests in the proxy easily
    r = requests.post(url, json=body, headers=header)
    return r.status_code, r.json()

def handleSubmitClient2ndPartResponse(submitClient2ndPartResponse, tek):
    csrTransactionUUID = submitClient2ndPartResponse['result']['csrTransactionUUID']
    oneTimePassword = extractOneTimePasswordFromResponseData(submitClient2ndPartResponse['result']['responseData'], tek)
    return csrTransactionUUID, oneTimePassword

def getTransaction(transactionUUID):
    header = getHeaderWithAuthorization(False, appInstanceUUID, password)
    params = {'transactionUUID': transactionUUID}
    body = {'id': genRequestId(), 'jsonrpc':'2.0', 'method':'getTransaction', 'params': params}
    
    url = HOST + '/v2/protected'
    #proxies = {
    #    "http": "PROXY ADDRESS",
    #    "https": "PROXY ADDRESS",
    #}
    #set proxies=proxies and verify=False to see the requests in the proxy easily
    r = requests.post(url, json=body, headers=header)
    return r.status_code, r.json()

def handleGetTransaction(getTransactionResponse):
    result = getTransactionResponse['result']
    freshnessToken = result['freshnessToken']
    transaction = result['transaction']
    digest = transaction['hash']
    digestType = transaction['hashType']
    return digest, digestType, freshnessToken

def getObjectIdentifierFromDigestAlgorithm(digestAlgorithm):
    if digestAlgorithm == 'SHA256':
        return '2.16.840.1.101.3.4.2.1'
    if digestAlgorithm == 'SHA512':
        return '2.16.840.1.101.3.4.2.3'
    return ''

def applyPKCS1_5padding(toBePadded, expectedLen):
    digestLen = len(toBePadded)
    padLen = expectedLen - digestLen - 3
    return bytes([0,1]) + padLen * b'\xff' + bytes([0]) + toBePadded

def submitSignature(d1prime, tek, clientModulus, compositeModulusBits, oneTimePassword, keyUUID, digest, digestType, freshnessToken, transactionUUID):
    header = getHeaderWithAuthorization(True, appInstanceUUID, password)

    hashBytes = b64decode(digest)
    digestInfoDer = DerSequence([DerSequence([DerObjectId(getObjectIdentifierFromDigestAlgorithm(digestType)).encode(),DerNull().encode()]).encode(),DerOctetString(hashBytes)])
    paddedDer = applyPKCS1_5padding(digestInfoDer.encode(),(compositeModulusBits + 7) // 8)
    paddedDerInt = int.from_bytes(paddedDer,'big')
    clientSignatureShare = pow(paddedDerInt,d1prime,clientModulus)
    jweKTK = jwk.JWK.from_pem(ktkKeyCert)
    jwePayloadContent = clientSignatureShare.to_bytes(ceil(clientSignatureShare.bit_length() / 8), 'big')
    jwePayload = jwe.JWE(jwePayloadContent, json_encode({"enc":"A128CBC-HS256","alg":"RSA-OAEP","kid":"KTKQ-2018","aud":"SERVER","purpose":"CLIENTSIGNATURESHARE"}))
    jwePayload.add_recipient(jweKTK)
    jweContainingClientSignatureShare = jwePayload.serialize(True)

    retransmitNonce = getBase64EncodedStr(getrandbits(128))
    jweTEK = jwk.JWK.from_json(json_encode({'k': tek, 'kty':'oct'}))
    jwePayloadContent = json_encode({"digest":digest,"digestAlgorithm":digestType,"signatureShare":jweContainingClientSignatureShare,"signatureShareEncoding":"JWE","retransmitNonce":retransmitNonce,"oneTimePassword":oneTimePassword}).encode('utf-8')
    jwePayload = jwe.JWE(jwePayloadContent, json_encode({"enc":"A128CBC-HS256","alg":"dir","keyUUID":keyUUID,"kid":keyUUID,"aud":"SERVER"}))
    jwePayload.add_recipient(jweTEK)
    requestData = jwePayload.serialize(True)

    params = {'accountUUID': accountUUID, 'freshnessToken': freshnessToken, 'requestData': requestData, 'requestDataEncoding':'JWE', 'transactionUUID': transactionUUID}
    body = {'id': genRequestId(), 'jsonrpc':'2.0', 'method': 'submitSignature', 'params': params}
    print('[+] Request Body:', body)
    url = HOST + '/v2/protected'
    #proxies = {
    #    "http": "PROXY ADDRESS",
    #    "https": "PROXY ADDRESS",
    #}
    #set proxies=proxies and verify=False to see the requests in the proxy easily
    r = requests.post(url, json=body, headers=header)
    return r.status_code, r.json()

def handleSubmitSignatureResponse(submitSignatureResponse, tek):
    oneTimePassword = extractOneTimePasswordFromResponseData(submitSignatureResponse['result']['responseData'], tek)
    return oneTimePassword

def getAccountStatus(accountUUID, appInstanceUUID, password):
    header = getHeaderWithAuthorization(False, appInstanceUUID, password)
    params = {'accountUUID': accountUUID}
    body = {'id': genRequestId(), 'jsonrpc':'2.0', 'method': 'getAccountStatus', 'params': params}
    
    url = HOST + '/v2/protected'
    #proxies = {
    #    "http": "PROXY ADDRESS",
    #    "https": "PROXY ADDRESS",
    #}
    #set proxies=proxies and verify=False to see the requests in the proxy easily
    r = requests.post(url, json=body, headers=header)
    return r.status_code, r.json()

def handleGetAccountStatusResponse(getAccountStatusResponse):
    result = getAccountStatusResponse['result']
    authKeyResponse = result['keys'][0]
    signKeyResponse = result['keys'][1]
    authReady = 'certificate' in authKeyResponse
    signReady = 'certificate' in signKeyResponse
    return authReady and signReady

def getPendingTransaction(accountUUID, appInstanceUUID, password):
    header = getHeaderWithAuthorization(False, appInstanceUUID, password)
    params = {'accountUUID': accountUUID}
    body = {'id': genRequestId(), 'jsonrpc':'2.0', 'method': 'getPendingOperation', 'params': params}
    print('[+] Request Body:', body)
    url = HOST + '/v2/protected'
    #proxies = {
    #    "http": "PROXY ADDRESS",
    #    "https": "PROXY ADDRESS",
    #}
    #set proxies=proxies and verify=False to see the requests in the proxy easily
    r = requests.post(url, json=body, headers=header)
    return r.status_code, r.json()

def handleGetPendingTransactionResponse(getPendingTransactionResponse):
    if 'rpRequest' in getPendingTransactionResponse['result']:
        rpRequestUUID = getPendingTransactionResponse['result']['rpRequest']['rpRequestUUID']
        requestType = getPendingTransactionResponse['result']['rpRequest']['requestType']
        print('[+] rpRequestUUID:',rpRequestUUID)
        print('[+] requestType:',requestType)
        print()
        return rpRequestUUID, requestType
    return None, None

def createTransactionForRpRequest(accountUUID, appInstanceUUID, password, rpRequestUUID):
    header = getHeaderWithAuthorization(False, appInstanceUUID, password)
    params = {'accountUUID': accountUUID, 'rpRequestUUID':rpRequestUUID}
    body = {'id': genRequestId(), 'jsonrpc':'2.0', 'method': 'createTransactionForRpRequest', 'params': params}
    print('[+] Request Body:', body)
    url = HOST + '/v2/protected'
    #proxies = {
    #    "http": "PROXY ADDRESS",
    #    "https": "PROXY ADDRESS",
    #}
    #set proxies=proxies and verify=False to see the requests in the proxy easily
    r = requests.post(url, json=body, headers=header)
    return r.status_code, r.json()

def handleCreateTransactionForRpRequestResponse(createTransactionForRpRequestResponse):
    result = createTransactionForRpRequestResponse['result']
    freshnessToken = result['freshnessToken']
    transaction = result['transaction']
    digest = transaction['hash']
    digestType = transaction['hashType']
    transactionUUID = transaction['transactionUUID']
    return digest, digestType, transactionUUID, freshnessToken

def registerNewAccount(method='ID-Card', tokenMethod='KEYTOKEN', token='TTTTT', beforeSubmitSignature=None, params=None, cookie=None):
    global authModulus
    global signModulus
    global authDhKeyPair
    global signDhKeyPair
    global authFreshnessToken
    global signFreshnessToken
    
    global authOneTimePassword
    global authKeyUUID
    global authTEK
    global authCompositeModulusBits
    
    global signOneTimePassword
    global signKeyUUID
    global signTEK
    global signCompositeModulusBits

    global accountUUID
    global appInstanceUUID
    global password

    authPrivateKeyClientPart, authPrivateKeyServerPart, authModulus = KeyGeneration.generatePQAndCreateKeyShare(3072, 65537)
    authDhKeyPair = pyDH.DiffieHellman()

    signPrivateKeyClientPart, signPrivateKeyServerPart, signModulus = KeyGeneration.generatePQAndCreateKeyShare(3072, 65537)
    signDhKeyPair = pyDH.DiffieHellman()

    if method == 'ID-Card':
        print('[+] Getting Registration Token Nonce')
        token = getRegTokenNonce()
        print()
        print('[+] Registering Device, Key Enrolment')
        statusCode,registerDeviceResponse = registerDevice(token)

        print('[+] Status:',statusCode)
        print('[+] Response Body:',registerDeviceResponse)
        print()

        while statusCode != 200:
            sleep(10)
            statusCode,registerDeviceResponse = registerDevice(token)
            print('[+] Status:',statusCode)
            print('[+] Response Body:',registerDeviceResponse)
            print()

        handleRegisterDeviceResponse(registerDeviceResponse)
    
    else:
        print('[+] Registering Device, Key Enrolment')
        statusCode,registerDeviceResponse = registerDevice(token, 'IDENTITYTOKEN')

        print('[+] Status:',statusCode)
        print('[+] Response Body:',registerDeviceResponse)
        print()

        while statusCode != 200:
            sleep(10)
            statusCode,registerDeviceResponse = registerDevice(token, 'IDENTITYTOKEN')
            print('[+] Status:',statusCode)
            print('[+] Response Body:',registerDeviceResponse)
            print()

        handleRegisterDeviceResponse(registerDeviceResponse)

    print('[+] Submitting server\'s part of private key for AUTHENTICATION key')
    statusCode,submitClient2ndPartResponse = submitServersPartOfPrivateKey(True, authFreshnessToken, authOneTimePassword, authPrivateKeyServerPart, authKeyUUID, authTEK, getBase64EncodedStr(authModulus))
    print('[+] Status:',statusCode)
    print('[+] Response Body:',submitClient2ndPartResponse)
    print()

    authCsrTransactionUUID, authOneTimePassword = handleSubmitClient2ndPartResponse(submitClient2ndPartResponse, authTEK)
    print('[+] authCsrTransactionUUID:',authCsrTransactionUUID)
    print()

    print('[+] Submitting server\'s part of private key for SIGNATURE key')
    statusCode,submitClient2ndPartResponse = submitServersPartOfPrivateKey(False, signFreshnessToken, signOneTimePassword, signPrivateKeyServerPart, signKeyUUID, signTEK, getBase64EncodedStr(signModulus))
    print('[+] Status:',statusCode)
    print('[+] Response Body:',submitClient2ndPartResponse)
    print()

    signCsrTransactionUUID, signOneTimePassword = handleSubmitClient2ndPartResponse(submitClient2ndPartResponse, signTEK)
    print('[+] signCsrTransactionUUID:',signCsrTransactionUUID)
    print()

    print('[+] Getting CSR Transaction for AUTHENTICATION key')
    statusCode, getTransactionResponse = getTransaction(authCsrTransactionUUID)
    print('[+] Status:',statusCode)
    print('[+] Response Body:',getTransactionResponse)
    print()

    authDigest, authDigestType, authFreshnessToken = handleGetTransaction(getTransactionResponse)

    print('[+] Getting CSR Transaction for SIGNATURE key')
    statusCode, getTransactionResponse = getTransaction(signCsrTransactionUUID)
    print('[+] Status:',statusCode)
    print('[+] Response Body:',getTransactionResponse)
    print()

    signDigest, signDigestType, signFreshnessToken = handleGetTransaction(getTransactionResponse)

    if beforeSubmitSignature != None: 
        beforeSubmitSignature(params, cookie)

    print('[+] Submitting client\'s signature share for AUTHENTICATION key')
    statusCode, submitSignatureResponse = submitSignature(authPrivateKeyClientPart, authTEK, authModulus, authCompositeModulusBits, authOneTimePassword, authKeyUUID, authDigest, authDigestType, authFreshnessToken, authCsrTransactionUUID)
    print('[+] Status:',statusCode)
    print('[+] Response Body:',submitSignatureResponse)
    print()

    authOneTimePassword = handleSubmitSignatureResponse(submitSignatureResponse, authTEK)

    print('[+] Submitting client\'s signature share for SIGNATURE key')
    statusCode, submitSignatureResponse = submitSignature(signPrivateKeyClientPart, signTEK, signModulus, signCompositeModulusBits, signOneTimePassword, signKeyUUID, signDigest, signDigestType, signFreshnessToken, signCsrTransactionUUID)
    print('[+] Status:',statusCode)
    print('[+] Response Body:',submitSignatureResponse)
    print()

    signOneTimePassword = handleSubmitSignatureResponse(submitSignatureResponse, signTEK)

    ## keep asking account status until cert is ready
    print('[+] Getting Account Status')
    statusCode, getAccountStatusResponse = getAccountStatus(accountUUID, appInstanceUUID, password)
    print('[+] Status:',statusCode)
    print('[+] Response Body:',getAccountStatusResponse)
    print()

    isReady = handleGetAccountStatusResponse(getAccountStatusResponse)
    while not isReady:
        sleep(5)
        print('[+] Getting Account Status')
        statusCode, getAccountStatusResponse = getAccountStatus(accountUUID, appInstanceUUID, password)
        print('[+] Status:',statusCode)
        print('[+] Response Body:',getAccountStatusResponse)
        print()
        isReady = handleGetAccountStatusResponse(getAccountStatusResponse)
    
    ### write account information to a json file
    open('account_'+accountUUID, 'w').write(json_encode({"accountUUID": accountUUID, "appInstanceUUID": appInstanceUUID, "password": password, 
    "authPrivateKeyClientPart": authPrivateKeyClientPart, "authModulus": authModulus, "authFreshnessToken": authFreshnessToken, "authOneTimePassword": authOneTimePassword,
    "authKeyUUID": authKeyUUID, "authTEK": authTEK, "authCompositeModulusBits": authCompositeModulusBits, 
    "signPrivateKeyClientPart": signPrivateKeyClientPart, "signModulus": signModulus, "signFreshnessToken": signFreshnessToken, "signOneTimePassword": signOneTimePassword,
    "signKeyUUID": signKeyUUID, "signTEK": signTEK, "signCompositeModulusBits": signCompositeModulusBits}))

def loadAccountInformation(accUUID):
    global authOneTimePassword
    global authKeyUUID
    global authTEK
    global authCompositeModulusBits
    global authModulus

    global signOneTimePassword
    global signKeyUUID
    global signTEK
    global signCompositeModulusBits
    global signModulus

    global accountUUID
    global appInstanceUUID
    global password
    
    info = open('account_'+accUUID, 'r')
    if info is None:
        raise Exception('Account is not found or some problem else!')
    
    accountInfo = json.loads(info.read())
    authOneTimePassword = accountInfo['authOneTimePassword']
    authKeyUUID = accountInfo['authKeyUUID']
    authTEK = accountInfo['authTEK']
    authCompositeModulusBits = accountInfo['authCompositeModulusBits']
    authModulus = accountInfo['authModulus']
    
    signOneTimePassword = accountInfo['signOneTimePassword']
    signKeyUUID = accountInfo['signKeyUUID']
    signTEK = accountInfo['signTEK']
    signCompositeModulusBits = accountInfo['signCompositeModulusBits']
    signModulus = accountInfo['signModulus']

    accountUUID = accountInfo['accountUUID']
    appInstanceUUID = accountInfo['appInstanceUUID']
    password = accountInfo['password']
    return accountInfo

def updateAccountInformation(accountUUID, accountInformation):
    os.remove('account_'+accountUUID)
    open('account_'+accountUUID, 'w').write(accountInformation)

def checkAccountState(accountUUID, appInstanceUUID, password):
    print('[+] Getting Account Status')
    statusCode, getAccountStatusResponse = getAccountStatus(accountUUID, appInstanceUUID, password)
    print('[+] Status:',statusCode)
    #print('[+] Response Body:',getAccountStatusResponse)
    print()

    isReady = handleGetAccountStatusResponse(getAccountStatusResponse)
    return isReady

def checkPendingOperation(accountUUID, appInstanceUUID, password):
    print('[+] Getting Pending Transaction')
    statusCode, getPendingTransactionResponse = getPendingTransaction(accountUUID, appInstanceUUID, password) 
    print('[+] Status:',statusCode)
    print('[+] Response Body:',getPendingTransactionResponse)
    print()
    if ('result' in getPendingTransactionResponse):
        return getPendingTransactionResponse
    return None

def invokeRequest(verb, url, header, params, data):
    if verb == 'GET':
        return requests.get(url, headers=header, params=params)
    if verb == 'POST':
        return requests.post(url, data=data, headers=header, params=params)
    return None

def extractResponse(r):
    return r.status_code, r.json(), r.headers

params = {'clientApp': '18.4.177', 'clientLib': '14.1.120-sk-release', 'clientDevice': 'samsung SM-G900FD', 'clientPlatform': 'Android 6.0.1'}
officialPortal = 'https://portal.smart-id.com'
customPortal = 'http://127.0.0.1:5000'
portalUrl = officialPortal

def registerNewAccountMobileID():
    #get api providers and store response cookie
    statusCode, responseBody, responseHeader = extractResponse(invokeRequest('GET', portalUrl+'/api/providers', {}, params, None))
    print(responseHeader)
    cookie = responseHeader['Set-Cookie'].split(';')[0]
    print('[+] Get Providers status:',statusCode)
    print('[+] Cookie:', cookie)
    print()
    
    #post api/mobileid/authenticate and store response cookie
    form = {'email': '', 'phoneNumber': '+37253049722', 'countryCode': 'EE', 'personalCode': '39401010067', 'mobileIdPhoneNumber': '+37253049722', 'language': 'ENG'}
    statusCode, responseBody, responseHeader = extractResponse(invokeRequest('POST', portalUrl+'/api/mobileid/authenticate', {'Content-Type':'application/x-www-form-urlencoded; charset=utf-8', 'Cookie': cookie}, params, form))
    print('[+] MobileId Authenticate status:',statusCode)
    print('[+] MobileId Authenticate response:',responseBody)
    cookie = responseHeader['Set-Cookie'].split(';')[0]
    print('[+] Cookie:', cookie)
    print('[+] Status URL:',responseBody['data']['statusUrl'])
    print('[+] Verification code:',responseBody['data']['verificationCode'])
    print()
    
    #get api/mobileid/status until auth is successful if so store response cookie
    statusCode, responseBody, responseHeader = extractResponse(invokeRequest('GET', portalUrl+'/api/mobileid/status', {'Cookie': "cookie"}, params, None))
    print('[+] MobileId Authenticate status:',statusCode)
    print('[+] MobileId Authenticate response:',responseBody)
    while(not ('Set-Cookie' in responseHeader)):
        sleep(5)
        statusCode, responseBody, responseHeader = extractResponse(invokeRequest('GET', portalUrl+'/api/mobileid/status', {'Cookie': cookie}, params, None))
    cookie = responseHeader['Set-Cookie'].split(';')[0]
    print('[+] MobileId Authenticate check status:',statusCode)
    print('[+] Cookie:', cookie)
    print('[+] RegisterUser URL:',responseBody['data']['registerUserUrl'])
    print('[+] Status:',responseBody['data']['status'])
    print()

    '''#post api/mobileid/otp/create
    form = {'appPackageName':'com.smart_id'}
    statusCode, responseBody, responseHeader = extractResponse(invokeRequest('POST', portalUrl+'/api/mobileid/otp/create', {'Content-Type':'application/x-www-form-urlencoded; charset=utf-8', 'Cookie': cookie}, params, form))
    print('[+] OTP Create:',statusCode)
    print('[+] Message:',responseBody['data']['message'])
    print('[+] Status:',responseBody['status'])
    print()
    
    #post api/mobileid/otp/verify
    form = {'otp':'wohoo'}
    statusCode, responseBody, responseHeader = extractResponse(invokeRequest('POST', portalUrl+'/api/mobileid/otp/verify', {'Content-Type':'application/x-www-form-urlencoded; charset=utf-8', 'Cookie': cookie}, params, form))
    print('[+] OTP Verify:',statusCode)
    print('[+] Message:',responseBody['data']['message'])
    print('[+] Status:',responseBody['status'])
    print()'''
    
    #post api/mobileid/register-user and store identityToken and use it with IDENTITYTOKEN in the registration process
    form = None
    statusCode, responseBody, responseHeader = extractResponse(invokeRequest('POST', portalUrl+'/api/mobileid/register-user', {'Cookie': cookie}, params, form))
    print('[+] MobileID Register User:',statusCode)
    print('[+] Identity token:',responseBody['data']['identityToken'])
    print('[+] SignApplicationUrl:',responseBody['data']['signApplicationUrl'])
    print()
    
    def beforeSubmitSignature(params, cookie):
        #post api/mobileid/sign-application
        form = None
        statusCode, responseBody, responseHeader = extractResponse(invokeRequest('POST', portalUrl+'/api/mobileid/sign-application', {'Cookie': cookie}, params, form))
        print('[+] MobileID Sign Application:',statusCode)
        print('[+] Status Url:',responseBody['data']['statusUrl'])
        print('[+] Verification code:',responseBody['data']['verificationCode'])
        print()
        
        #get api/mobileid/sign-status until status SIGNATURE
        form = None
        statusCode, responseBody, responseHeader = extractResponse(invokeRequest('GET', portalUrl+'/api/mobileid/sign-status', {'Cookie': cookie}, params, form))
        print('[+] MobileID Sign Status:', statusCode)
        print('[+] Status:',responseBody['data']['status'])
        
        while((not ('getSignedDocDataUrl' in responseBody['data'])) or (responseBody['data']['status'] != 'SIGNATURE')):
            statusCode, responseBody, responseHeader = extractResponse(invokeRequest('GET', portalUrl+'/api/mobileid/sign-status', {'Cookie': cookie}, params, form))
            print('[+] MobileID Sign Status:', statusCode)
            print('[+] Status:',responseBody['data']['status'])
        
        print('[+] Get Signed Doc Url:',responseBody['data']['getSignedDocDataUrl'])
        print('[+] Status:',responseBody['data']['status'])
        print()
        
        #post api/mobileid/get-signed-doc-data and check signedDocData is null
        form = None
        statusCode, responseBody, responseHeader = extractResponse(invokeRequest('POST', portalUrl+'/api/mobileid/get-signed-doc-data', {'Cookie': cookie}, params, form))
        print('[+] MobileID Sign Status:', statusCode)
        print('[+] Completed Url:',responseBody['data']['completeUrl'])
        print('[+] Signed Doc Data:',responseBody['data']['signedDocData'])
        print()
    
    #register process until submitSignature
    registerNewAccount('Mobile-ID', 'IDENTITYTOKEN', responseBody['data']['identityToken'], beforeSubmitSignature, params, cookie)

officialCert = b'-----BEGIN CERTIFICATE-----\nMIIEHDCCAoQCCQDF3v7I7R+Q2zANBgkqhkiG9w0BAQUFADBQMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMREwDwYDVQQLDAhTTUFSVC1JRDERMA8GA1UEAwwIS1RLUTIwMTgwHhcNMTgwNjI4MDgxNzE0WhcNMTkwNjI4MDgxNzE0WjBQMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMREwDwYDVQQLDAhTTUFSVC1JRDERMA8GA1UEAwwIS1RLUTIwMTgwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCsWWBh1mokq7IIcR2zQoWa88yrGkUp1wePStB1qGo3wcp/IEeMHW3B13bskHjT58gO6iTIZlf15u3wigalExetDkHi3uA2pFxEmGhiw1w36MxvoN0R1PDkS58Twsmqmvg2i0eoxLJOYComGm1vV8KM1TzjW9eiq3/FQun5a3XTrFXh3ju8LrRqmFb6ax2OYtA8YYDoE2Yf9/sqJTeawdW5PURX1L37A8k5YpHuO8wxI2X/yFbSaHtrivsBOLiMSaSU59DcVvCAVkzDJBSJIoeekrLlcN+DahLP3HcjCR7Tyf2Xtzn+x3f809tPloZhSFVogyhMo8VQ3D+YraO79evGjjRv37kz1xertqSxkNx1VbR2KNPl8Zhgf9552BUg8YEx6WN4Bk2gYQ27QYa2vnyipLDbHD3tPnqbBozg3iPw6uNyuc7uPZJYJgT5zymoYx3Oil8pAP/NxXVxZScl8UROiTzjCnUALmYVWMpT5prjJmQDCt5sGp4F8ds3/Q0QArkCAwEAATANBgkqhkiG9w0BAQUFAAOCAYEAKodWRP1/PIdIlArc/ckrFYQSF2H+dXfeOSbIGWAXIjvupcbANneW62eldBkhN5Xy4LJAtp3wG9iyWAl0XINa6hoVWPi6GCl5z10OUj0deYbrgH8SFWWR76RteiqYw0RiSoeFPQS7tLQnVZPsaOzdhDWpxA2nV/w/8Xh2gqyz0jczZHTjKUsjtHPhP0D533CDau60wzjWA+EHeQui/7qhsNBpKQQ2JvX0MszmrAJnSXfDmyCie1aIbioHC8iuNQD3D6W7C9WzPx/28WI30XYguJcy+Mcgar5Cug8bFIRPlUyx49T11HageELs6gIMUqq6+s9s+rKFGT+w4sK7bsa/kgob+PQIGpYVyYGU23AmyBQNb0LFMB1yOLfnEtsUUEaWBAC2cBbvKKd49mVKN5hdxOphAR3+H1ZkSpWiK/puzdj1hgxz0fvf5ydswwXZRQb3jz9bm/iv9o8vct0jyCR9gkpFXvVknVzvJW/hgR89n1CJVPcEVpseqRNxoGc79IkV\n-----END CERTIFICATE-----\n'
officialHost = 'https://mobile-api.smart-id.com'

customCert = b'-----BEGIN CERTIFICATE-----\nMIID7jCCAlagAwIBAgIUb+uCAh8t+lCvQQZMXYp+9YwiscAwDQYJKoZIhvcNAQELBQAwGjEYMBYGA1UEAwwPY3J5cHRvZ3JhcGh5LmlvMB4XDTIwMDgwNDEzNDc1NloXDTIwMTExMzEzNDc1NlowGjEYMBYGA1UEAwwPY3J5cHRvZ3JhcGh5LmlvMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAqho4uPS8ic/H1TS4hAjsnTNEVGwSy6SeH7jbrxDMPv0EY7ECgUkdElXYmm+gAgiJvZQulgk2L9MLo7Iv4o06Wannb+jfcUD7zKF4ZX3YR8p684rTrqFq0ly8lz11/Stug/WaDmvEuSVHMsqkeGRuPxR6/A/Aco+x96GsiANy4fNPFdHbFZi4Iw3Okpuup7teI0rI7rmxI9+f1CqaxmokgYOQh0/0VMUE7guq+rNDAIe933GIu2ffMVKkaUd+ipHtPDum7339RRPA96TKMrTXqgYd0x2WZf4x85eFzvm53bu2kWFmxEC8lApivplgu7nshKVgp0yrr1jPknUb2G6XAVYntFMO4QfPb4++lziuRKBQ4QSUa9YqRmBiJvq639z+hNyEqUvQ8kZNr0vKrBcopKMPF03ZmZCsBwMNWGhGzKCBPTZpU2OmMW+deQBIuN4S7UZX/b3YI4RuJy/LfCP2zL7s0hItv5cnpusYja2PZw6X8YPWl4N5tn4GaaRaBdh/AgMBAAGjLDAqMBoGA1UdEQQTMBGCD2NyeXB0b2dyYXBoeS5pbzAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBgQAzc/rnKf53sqH4ZCKt4yreI8EPgCpVr7DMIxpsRD+uFATzTwrAuMitHGMJK6FVi+znMJdLHV2Deb202Ob+wngVu4bz5U/bgLNzW1M72TsySXFCAU9X16ftkilmOKEoOT1JFE0FnHFrotO2tnu+l9HyKlsi9v0qYCZuY0TlB8H17XRtgwbZm38EJZAEiHog5WbSY7orQVsbTomb7RtSeJ9iY+CRsr/xod/sdG0dYPsyH4EUbLDnWypHbKDc+1VkhzzJ89ToWrKHuq3Kp1LWU6rMDij1k/Z7LKaJJuadtmlvcd1L6wwlkXkbLrWQoUZnPjIC0pzz3mdxwKpveS9UhBhoFEccC5HIW4N95PEPLDEnTbFgsFgjTkGqvfCgoIBWU8ItOU0LaK9kYn+aL6zCMvSojWLnJOxGOMOl+4I5ChIOhFv4NczWypeFSq2vMP9XdEq1LxKhw1mCmb9JFy7qaBZ+tVLnkWmARPT0L++L8S1WvmUHXgY51n2nu4rQFar+ypU=\n-----END CERTIFICATE-----\n'
customHost = 'http://127.0.0.1:6000'

ktkKeyCert = officialCert
HOST = officialHost

parser = argparse.ArgumentParser(prog='sampleClient')
parser.add_argument('--accountUUID', help='Smart-ID accountUUID for the account.')
parser.add_argument('--registrationMethod', help='Registration method to Smart-ID')
args = parser.parse_args()

if args.registrationMethod == 'ID-Card' and (args.accountUUID is None or re.match("\\b[0-9a-f]{8}\\b-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-\\b[0-9a-f]{12}\\b", args.accountUUID) is None):
    registerNewAccount()
elif args.registrationMethod == 'Mobile-ID':
    registerNewAccountMobileID()
else:
    accountInformation = loadAccountInformation(args.accountUUID)
    state = checkAccountState(accountUUID, appInstanceUUID, password)
    if state:
       pendingOperation = checkPendingOperation(accountUUID, appInstanceUUID, password)
       if pendingOperation:
           rpRequestUUID, requestType = handleGetPendingTransactionResponse(pendingOperation)
           if requestType == 'AUTHENTICATION':
                print('[+] Creating transaction for rpRequest')
                statusCode, createTransactionForRpRequestResponse = createTransactionForRpRequest(accountUUID, appInstanceUUID, password, rpRequestUUID)
                print('[+] Status:',statusCode)
                print('[+] Response Body:',createTransactionForRpRequestResponse)
                print()
                digest, digestType, transactionUUID, authFreshnessToken = handleCreateTransactionForRpRequestResponse(createTransactionForRpRequestResponse)
                print('[+] Submit signature for authentication')
                statusCode, submitSignatureResponse = submitSignature(accountInformation['authPrivateKeyClientPart'], accountInformation['authTEK'], accountInformation['authModulus'], 
                accountInformation['authCompositeModulusBits'], accountInformation['authOneTimePassword'], accountInformation['authKeyUUID'], digest, digestType, authFreshnessToken, transactionUUID)
               
                print('[+] Status:',statusCode)
                print('[+] Response Body:',submitSignatureResponse)
                print()
                authOneTimePassword = handleSubmitSignatureResponse(submitSignatureResponse, accountInformation['authTEK'])
                accountInformation['authOneTimePassword'] = authOneTimePassword
                updateAccountInformation(accountInformation['accountUUID'], json_encode(accountInformation))
           elif requestType != None:
                print('[+] Creating transaction for rpRequest')
                statusCode, createTransactionForRpRequestResponse = createTransactionForRpRequest(accountUUID, appInstanceUUID, password, rpRequestUUID)
                print('[+] Status:',statusCode)
                print('[+] Response Body:',createTransactionForRpRequestResponse)
                print()
                digest, digestType, transactionUUID, signFreshnessToken = handleCreateTransactionForRpRequestResponse(createTransactionForRpRequestResponse)

                statusCode, submitSignatureResponse = submitSignature(accountInformation['signPrivateKeyClientPart'], accountInformation['signTEK'], accountInformation['signModulus'],
                accountInformation['signCompositeModulusBits'], accountInformation['signOneTimePassword'], accountInformation['signKeyUUID'], digest, digestType, signFreshnessToken, transactionUUID)
               
                print('[+] Status:',statusCode)
                print('[+] Response Body:',submitSignatureResponse)
                print()
                signOneTimePassword = handleSubmitSignatureResponse(submitSignatureResponse, accountInformation['signTEK'])
                accountInformation['signOneTimePassword'] = signOneTimePassword
                updateAccountInformation(accountInformation['accountUUID'], json_encode(accountInformation))
           else:
                pendingTransaction = pendingOperation['result']['transaction']
                if pendingTransaction['transactionType'] == 'AUTHENTICATION':
                    statusCode, submitSignatureResponse = submitSignature(accountInformation['authPrivateKeyClientPart'], accountInformation['authTEK'], accountInformation['authModulus'],
                    accountInformation['authCompositeModulusBits'], accountInformation['authOneTimePassword'], accountInformation['authKeyUUID'], 
                    pendingTransaction['hash'], pendingTransaction['hashType'], pendingOperation['result']['freshnessToken'], pendingTransaction['transactionUUID'])
               
                    print('[+] Status:',statusCode)
                    print('[+] Response Body:',submitSignatureResponse)
                    print()
                    authOneTimePassword = handleSubmitSignatureResponse(submitSignatureResponse, accountInformation['authTEK'])
                    accountInformation['authOneTimePassword'] = authOneTimePassword
                    updateAccountInformation(accountInformation['accountUUID'], json_encode(accountInformation))
                else:
                    statusCode, submitSignatureResponse = submitSignature(accountInformation['signPrivateKeyClientPart'], accountInformation['signTEK'], accountInformation['signModulus'],
                    accountInformation['signCompositeModulusBits'], accountInformation['signOneTimePassword'], accountInformation['signKeyUUID'], 
                    pendingTransaction['hash'], pendingTransaction['hashType'], pendingOperation['result']['freshnessToken'], pendingTransaction['transactionUUID'])
               
                    print('[+] Status:',statusCode)
                    print('[+] Response Body:',submitSignatureResponse)
                    print()
                    signOneTimePassword = handleSubmitSignatureResponse(submitSignatureResponse, accountInformation['signTEK'])
                    accountInformation['signOneTimePassword'] = signOneTimePassword
                    updateAccountInformation(accountInformation['accountUUID'], json_encode(accountInformation))