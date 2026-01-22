#pip install Flask
from flask import Flask
from flask import request
from flask import jsonify

#pip install pycryptodome
from Crypto.PublicKey import RSA
from Crypto.Util.number import size
from Crypto.Util.asn1 import *

#pip install jwcrypto
from jwcrypto import jwk, jws, jwe
from jwcrypto.common import json_encode

#default python3 modules
from codecs import encode,decode
from random import getrandbits
from base64 import urlsafe_b64encode, b64encode, b64decode
from math import ceil
from sampleAccount import Account, KeyInfo, Transaction, RpRequest
import re
import pyDH
import hashlib
import json
import os, pickle
app = Flask(__name__)

# find jwe library, prepare serverDhMessage and responseData, test it with Smart-ID Android client, see the app for building jwe objects (double encrypting) submitClient2ndPart, submitSignature

serverPrivateKey = b'-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----\n'
privateKeyPartAuth = 0
privateKeyPartSign = 0

def loadList(filename):
    exists = os.path.isfile(filename)
    if exists:
        return pickle.load(open(filename, 'rb'))
    return []

def saveList(l, filename):
    pickle.dump(l, open(filename, 'wb'))

accounts = loadList('accounts.p')
transactions = loadList('transactions.p')
rpRequests = loadList('rprequests.p')

def genUUID():
    i = getrandbits(128)
    b = i.to_bytes(16,'big')
    hb = b.hex()
    return hb[0:8]+'-'+hb[8:12]+'-'+hb[12:16]+'-'+hb[16:20]+'-'+hb[20:32]

def doesTokenExist(basicToken):
    decoded = b64decode(basicToken[6:])
    loc = decoded.find(b':')
    appI = decoded[0:loc].decode()
    password = decoded[loc+1:].decode()
    for a in accounts:
        if a.password == password:
            return a
    return None

def doesAccountExist(accountUUID):
    for a in accounts:
        if a.accountUUID == accountUUID:
            return a
    return None

def removeAccount(account):
    accounts.remove(account)
    saveList(accounts, 'accounts.p')
    return

def removeRpRequest(rpRequest):
    rpRequests.remove(rpRequest)
    saveList(rpRequests, 'rprequests.p')
    return

def removeTransaction(transaction):
    transactions.remove(transaction)
    saveList(transactions, 'transactions.p')
    return

def doesTransactionExist(transactionUUID):
    for t in transactions:
        if t.transactionUUID == transactionUUID:
            return t
    return None

def hasPendingOperation(accountUUID):
    for rpr in rpRequests:
        if rpr.accountUUID == accountUUID:
            return rpr
    return None

def deleteRPRequest(rpName):
    if rpName is not None:
        req = None
        for rpr in rpRequests:
            if rpr.rpName == rpName:
                req = rpr
        if req is not None:
            rpRequests.remove(req)
            saveList(rpRequests, 'rprequests.p')
    return

def calculateCompositeModulusAndBits(keyInfo, clientModulus):
    keyInfo.setClientModulus(clientModulus)
    serverModulus = keyInfo.serverModulus
    clientModulus = int.from_bytes(b64decode(clientModulus), 'big')
    compositeModulus = serverModulus * clientModulus
    keyInfo.setCompositeModulus(compositeModulus)
    compositeModulusBitSize = compositeModulus.bit_length()
    compositeModulusBytes = compositeModulus.to_bytes(ceil(compositeModulusBitSize / 8), 'big')
    compositeModulusBytesBase64 = b64encode(compositeModulusBytes)
    return compositeModulusBytesBase64.decode(), compositeModulusBitSize 

def calculateConcatKDF(dhKeyPair, otherPartyDhPublicKey):
    otherPubInt = int.from_bytes(b64decode(bytes(otherPartyDhPublicKey, 'utf-8')),'big')
    privateKey = dhKeyPair.get_private_key()
    prime = dhKeyPair.p
    sharedKey = pow(otherPubInt, privateKey, prime)
    sharedKeyBytes = sharedKey.to_bytes(ceil(sharedKey.bit_length() / 8), 'big')
    print('sharedKeyBase64:', b64encode(sharedKeyBytes))
    initializationVector = 'A128CBC-HS256CLIENTSERVER'.encode('utf-8')
    itoOSPBytes = bytes([0,0,0,1])
    hasher = hashlib.sha256()
    hasher.update(itoOSPBytes)
    hasher.update(sharedKeyBytes)
    hasher.update(initializationVector)
    return urlsafe_b64encode(hasher.digest())

def test_calculateConcatKDF(privateKey, prime, otherPartyDhPublicKey):
    otherPubInt = int.from_bytes(b64decode(bytes(otherPartyDhPublicKey, 'utf-8')),'big')
    sharedKey = pow(otherPubInt, privateKey, prime)
    sharedKeyBytes = sharedKey.to_bytes(ceil(sharedKey.bit_length() / 8), 'big')
    initializationVector = 'A128CBC-HS256CLIENTSERVER'.encode('utf-8')
    itoOSPBytes = bytes([0,0,0,1])
    hasher = hashlib.sha256()
    hasher.update(itoOSPBytes)
    hasher.update(sharedKeyBytes)
    hasher.update(initializationVector)
    return urlsafe_b64encode(hasher.digest())

def test_calculateConcatKDF_inverse(privateKey, prime, otherPartyDhPublicKey):
    otherPubInt = int.from_bytes(b64decode(bytes(otherPartyDhPublicKey, 'utf-8')),'big')
    sharedKey = pow(otherPubInt, privateKey, prime)
    sharedKeyBytes = sharedKey.to_bytes(ceil(sharedKey.bit_length() /8), 'big')
    initializationVector = 'A128CBC-HS256CLIENTSERVER'.encode('utf-8')
    itoOSPBytes = bytes([0,0,0,1])
    hasher = hashlib.sha256()
    hasher.update(initializationVector)
    hasher.update(sharedKeyBytes)
    hasher.update(itoOSPBytes)
    return urlsafe_b64encode(hasher.digest())

def extractAndSetPrivateKeyPartAuth(requestData, authKeyInfo):
    derivedDhKey = authKeyInfo.derivedDhKey
    jweKey = jwk.JWK.from_json(json_encode({'k': derivedDhKey.decode(), 'kty':'oct'}))
    jweContent = jwe.JWE()
    jweContent.deserialize(requestData)
    jweContent.decrypt(jweKey)
    payload = json.loads(jweContent.payload)
    header = jweContent.jose_header
    if header['enc'] != 'A128CBC-HS256' or header['alg'] != 'dir' or header['aud'] != 'SERVER' or len(header['keyUUID']) == 0 or len(header['kid']) == 0:
        return False
    oneTimePassword = payload['oneTimePassword']
    if oneTimePassword != authKeyInfo.oneTimePassword:
        print('oneTimePassword in payload:',oneTimePassword)
        print('authKeyInfo oneTimePassword:',authKeyInfo.oneTimePassword)
        return False
    else:
        privateKeyPartJwe = payload['client2ndPart']
        modulus = payload['clientModulus']
        print('modulusInt:',int.from_bytes(b64decode(modulus),'big'))
        jweServerKey = jwk.JWK.from_pem(serverPrivateKey)
        jweSecondPart = jwe.JWE()
        jweSecondPart.deserialize(privateKeyPartJwe, jweServerKey)
        header = jweSecondPart.jose_header
        if header['enc'] != 'A128CBC-HS256' or header['alg'] != 'RSA-OAEP' or header['aud'] != 'SERVER' or header['purpose'] != 'CLIENT2NDPART' or len(header['kid']) == 0:
            return False
        secondPart = jweSecondPart.payload
        print('privateKeyPartAuth:',secondPart)
        privateKeyPartAuth = int.from_bytes(secondPart,'big')
        authKeyInfo.setPrivateKeyPart(privateKeyPartAuth)
        return True

def extractAndSetPrivateKeyPartSign(requestData, signKeyInfo):
    derivedDhKey = signKeyInfo.derivedDhKey
    jweKey = jwk.JWK.from_json(json_encode({'k': derivedDhKey.decode(), 'kty':'oct'}))
    jweContent = jwe.JWE()
    jweContent.deserialize(requestData)
    jweContent.decrypt(jweKey)
    payload = json.loads(jweContent.payload)
    oneTimePassword = payload['oneTimePassword']
    header = jweContent.jose_header
    if header['enc'] != 'A128CBC-HS256' or header['alg'] != 'dir' or header['aud'] != 'SERVER' or len(header['keyUUID']) == 0 or len(header['kid']) == 0:
        return False
    if oneTimePassword != signKeyInfo.oneTimePassword:
        return False
    else:
        privateKeyPartJwe = payload['client2ndPart']
        jweServerKey = jwk.JWK.from_pem(serverPrivateKey)
        jweSecondPart = jwe.JWE()
        jweSecondPart.deserialize(privateKeyPartJwe, jweServerKey)
        header = jweSecondPart.jose_header
        if header['enc'] != 'A128CBC-HS256' or header['alg'] != 'RSA-OAEP' or header['aud'] != 'SERVER' or header['purpose'] != 'CLIENT2NDPART' or len(header['kid']) == 0:
            return False
        secondPart = jweSecondPart.payload
        privateKeyPartSign = int.from_bytes(secondPart, 'big')
        signKeyInfo.setPrivateKeyPart(privateKeyPartSign)
        return True

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

def removePKCS1_5padding(toBeRemoved):
    secondZeroByte = toBeRemoved.find(b'\x00',1)
    return toBeRemoved[secondZeroByte+1:]

def getCoefficients(n1, n2):
    (old_r, r) = (n1, n2)
    (old_s, s) = (1, 0)
    (old_t, t) = (0, 1)
    
    while r:
        quotient = old_r // r
        (old_r, r) = (r, old_r - quotient * r)
        (old_s, s) = (s, old_s - quotient * s)
        (old_t, t) = (t, old_t - quotient * t)
    
    c1, c2 = old_s, old_t
    gcd = old_r
    if gcd == 1:
        return c1,c2
    raise Exception("Moduli n1 and n2 are not co-prime!")

def verifySignature(requestData, keyInfo):
    derivedDhKey = keyInfo.derivedDhKey
    privateKeyPartAuth = keyInfo.privateKeyPart
    compositeAuthModulus = keyInfo.compositeModulus
    otp = keyInfo.oneTimePassword
    clientAuthModulus = keyInfo.clientModulus
    jweKey = jwk.JWK.from_json(json_encode({'k': derivedDhKey.decode(), 'kty':'oct'}))
    jweContent = jwe.JWE()
    jweContent.deserialize(requestData)
    jweContent.decrypt(jweKey)
    payload = jweContent.payload
    payloadJSON = json.loads(payload)
    oneTimePassword = payloadJSON['oneTimePassword']
    header = jweContent.jose_header
    print('[+] First header for SubmitSignature:',header)
    if header['enc'] != 'A128CBC-HS256' or header['alg'] != 'dir' or header['aud'] != 'SERVER' or len(header['keyUUID']) == 0 or len(header['kid']) == 0:
        return False, 'JWE Header is not valid!'
    if oneTimePassword != otp:
        return False, 'OneTimePassword is not correct!'
    signatureShareJwe = payloadJSON['signatureShare']
    digest = payloadJSON['digest']
    digestAlgorithm = payloadJSON['digestAlgorithm']
    jweServerKey = jwk.JWK.from_pem(serverPrivateKey)
    jweSignatureShare = jwe.JWE()
    jweSignatureShare.deserialize(signatureShareJwe, jweServerKey)
    header = jweSignatureShare.jose_header
    print('[+] Second header for SubmitSignature:',header)
    if header['enc'] != 'A128CBC-HS256' or header['alg'] != 'RSA-OAEP' or header['aud'] != 'SERVER' or header['purpose'] != 'CLIENTSIGNATURESHARE' or len(header['kid']) == 0:
        return False, 'JWE Header is not valid!'
    signatureShare = jweSignatureShare.payload
    #print('digest:',digest)
    #print('digestAlgorithm:',digestAlgorithm)
    print('signatureShare:',signatureShare)
    digest = b64decode(digest)
    digestInfoDer = DerSequence([DerSequence([DerObjectId(getObjectIdentifierFromDigestAlgorithm(digestAlgorithm)).encode(),DerNull().encode()]).encode(),DerOctetString(digest)]) #complete this object according to Crypto.Util.asn1.DerObjects ...
    paddedDer = applyPKCS1_5padding(digestInfoDer.encode(),(compositeAuthModulus.bit_length() + 7) // 8)
    paddedDerInt = int.from_bytes(paddedDer,'big')
    print('EncodedMessage Integer Value:',paddedDerInt)
    authModulus = int.from_bytes(b64decode(clientAuthModulus),'big')
    print('authModulus:',authModulus)
    print('privateKeyPartAuth_d1primeprime:',privateKeyPartAuth)
    serverSignatureShare = pow(paddedDerInt,privateKeyPartAuth,authModulus)
    #print('serverSignatureShare:',serverSignatureShare)
    signatureShareInt = int.from_bytes(signatureShare,'big')
    #print('clientSignatureShare:',signatureShareInt)
    completeSignature = (signatureShareInt * serverSignatureShare) % authModulus
    toBeVerified = pow(completeSignature, 65537, authModulus)
    print('toBeVerified:',toBeVerified)
    if toBeVerified == (paddedDerInt % authModulus):
        print('[+] First signature verification passed!') 
        serverSignature = pow(paddedDerInt,keyInfo.serverD,keyInfo.serverModulus)
        c1,c2 = getCoefficients(authModulus, keyInfo.serverModulus)
        S = (c2 * keyInfo.serverModulus * completeSignature + c1 * authModulus * serverSignature) % compositeAuthModulus
        M = pow(S,65537,compositeAuthModulus)
        if M == paddedDerInt:
            print('[+] Second signature verification passed!')
            return True, ''
    return False, 'Signature is not verified!'
    #apply padding to digestInfoDer PCKS 1.5 crypto notlarinda var araya 0xff koyulandan
    #calculate signature m,d,n pow(paddedDerInt,d1primeprime,clientAuthModulus) = serverSignatureShare
    #compute (signatureShare * serverSignatureShare) mod n1
    #verify complete signatureShare to clientAuthModulus,65537(exponent)
    #calculate signature m,d2,n2 (servers keys)
    #S = β * n2 * s1 + α * n1 * s2 mod n. (euclid coefficients extented algorithm)
    #verify S against composite public key (n1*n2,e=65537)
    #all ok => true, otherwise => false   
    
def calculateDhMessageAndPublicKey(clientDhPublicKey, keyInfo):
    serverDhKeyPair = pyDH.DiffieHellman()
    serverDhPublicKey = serverDhKeyPair.gen_public_key()
    serverDhPublicKeyEncoded = b64encode(serverDhPublicKey.to_bytes(ceil(serverDhPublicKey.bit_length() / 8), 'big')).decode()
    derivedDhKey = calculateConcatKDF(serverDhKeyPair, clientDhPublicKey)
    derivedDhKeyId = genUUID()
    keyInfo.setDerivedDhKeyInfo(derivedDhKeyId, derivedDhKey)
    jwsSignKey = jwk.JWK.from_pem(serverPrivateKey)
    jwsPayload = jws.JWS(json_encode({'clientDhPublicKey': clientDhPublicKey, 'serverDhPublicKey': serverDhPublicKeyEncoded}).encode('utf-8'))
    jwsPayload.add_signature(jwsSignKey, None, json_encode({"aud":"CLIENT","purpose":"DH","alg":"RS256","keyUUID":derivedDhKeyId,"kid":"KTKQ-2018"}))
    jwePayloadContent = jwsPayload.serialize(True).encode('utf-8')
    jweKey = jwk.JWK.from_json(json_encode({'k': derivedDhKey.decode(), 'kty':'oct'}))
    jwePayload = jwe.JWE(jwePayloadContent, json_encode({"aud":"CLIENT","enc":"A128CBC-HS256","alg":"dir","keyUUID":derivedDhKeyId,"kid":derivedDhKeyId}))
    jwePayload.add_recipient(jweKey)
    message = jwePayload.serialize(True)
    return message, serverDhPublicKeyEncoded

def calculateResponseData(keyInfo, isAuth):
    global accounts
    if isAuth:
        authOneTimePassword = b64encode(getrandbits(128).to_bytes(16,'big')).decode()
        keyInfo.setOneTimePassword(authOneTimePassword)
        saveList(accounts, 'accounts.p')
    else:
        signOneTimePassword = b64encode(getrandbits(128).to_bytes(16,'big')).decode()
        keyInfo.setOneTimePassword(signOneTimePassword)
        saveList(accounts, 'accounts.p')
    oneTimePassword = keyInfo.oneTimePassword
    dhDerivedKey = keyInfo.derivedDhKey
    jwePayloadContent = json_encode({'oneTimePassword': oneTimePassword}).encode('utf-8')
    jweKey = jwk.JWK.from_json(json_encode({'k': dhDerivedKey.decode(), 'kty':'oct'}))
    jwePayload = jwe.JWE(jwePayloadContent, json_encode({"aud":"CLIENT","enc":"A128CBC-HS256","alg":"dir","keyUUID":keyInfo.derivedDhKeyId,"kid":keyInfo.derivedDhKeyId}))
    jwePayload.add_recipient(jweKey)
    message = jwePayload.serialize(True)
    return message

def calculateFreshnessToken(keyInfo, isAuth):
    global accounts
    if isAuth:
        authFreshnessToken = b64encode(getrandbits(128).to_bytes(16,'big')).decode()
        keyInfo.setFreshnessToken(authFreshnessToken)
        saveList(accounts, 'accounts.p')
        return authFreshnessToken
    else:
        signFreshnessToken = b64encode(getrandbits(128).to_bytes(16,'big')).decode()
        keyInfo.setFreshnessToken(signFreshnessToken)
        saveList(accounts, 'accounts.p')
        return signFreshnessToken
    
@app.route('/v2/public', methods=['POST'])
def publicMethods():
    global accounts
    reqData = request.data
    reqJson = json.loads(reqData)
    id = reqJson['id']
    jsonrpc = reqJson['jsonrpc']
    method = reqJson['method']
    params = reqJson['params']
    print('method:', method)
    if method == 'getRegTokenNonce':
        resp = {
            "id": id,
            "jsonrpc": jsonrpc,
            "result": {
                 "nonce": "LssSYMrfYcVnX2EL+w3y7Q==",
                 "timeToLiveSec": 900,
                 "token": "NW9PL"
            }
        }
        return jsonify(resp), 200
    elif method == 'registerDevice':
        accountRegistrationData = params['accountRegistrationData']
        clientAuthDhPublicKey = accountRegistrationData['clientAuthDhPublicKey']
        clientSignDhPublicKey = accountRegistrationData['clientSignDhPublicKey']
        authRsa = RSA.generate(3072)
        signRsa = RSA.generate(3072)
        authKeyInfo = KeyInfo()
        signKeyInfo = KeyInfo()
        authKeyInfo.setRsaKeyPair(authRsa)
        signKeyInfo.setRsaKeyPair(signRsa)
        authComposite, authBits = calculateCompositeModulusAndBits(authKeyInfo, accountRegistrationData['clientAuthModulus'])
        signComposite, signBits = calculateCompositeModulusAndBits(signKeyInfo, accountRegistrationData['clientSignModulus'])
        messageAuth, dhAuthPublicKey = calculateDhMessageAndPublicKey(clientAuthDhPublicKey, authKeyInfo)
        print('derivedDhAuthKey:', authKeyInfo.derivedDhKey)
        messageSign, dhSignPublicKey = calculateDhMessageAndPublicKey(clientSignDhPublicKey, signKeyInfo)
        print('derivedDhSignKey:', signKeyInfo.derivedDhKey)
        authResponseData = calculateResponseData(authKeyInfo, True)
        signResponseData = calculateResponseData(signKeyInfo, False)
        accountUUID = genUUID()
        appInstanceUUID = genUUID()
        password = genUUID().replace('-','')
        resp = {
    "id": id,
    "jsonrpc": jsonrpc,
    "result": {
        "accountUUID": accountUUID,
        "appInstanceUUID": appInstanceUUID,
        "authKey": {
            "compositeModulus": authComposite,
            "compositeModulusBits": authBits,
            "freshnessToken": calculateFreshnessToken(authKeyInfo, True),
            "responseData": authResponseData,
            "responseDataEncoding": "JWE",
            "serverDhMessage": messageAuth,
            "serverDhMessageEncoding": "JWE",
            "serverDhPublicKey": dhAuthPublicKey
        },
        "identityData": {
            "givenName": "DENIZALP",
            "govID": {
                "code": "39401010067",
                "country": "EE"
            },
            "id": {
                "issuer": "EE",
                "personSemanticID": "PNOEE-39401010067",
                "scheme": "ETSI_PNO",
                "value": "39401010067"
            },
            "surname": "KAPISIZ"
        },
        "password": password,
        "signKey": {
            "compositeModulus": signComposite,
            "compositeModulusBits": signBits,
            "freshnessToken": calculateFreshnessToken(signKeyInfo, False),
            "responseData": signResponseData,
            "responseDataEncoding": "JWE",
            "serverDhMessage": messageSign,
            "serverDhMessageEncoding": "JWE",
            "serverDhPublicKey": dhSignPublicKey
        }
    }
}
        acc = Account(accountUUID, appInstanceUUID, password, authKeyInfo, signKeyInfo)
        accounts.append(acc)
        saveList(accounts, 'accounts.p')
        return jsonify(resp), 200
        

@app.route('/rpRequest', methods=['POST'])
def addRpRequest():
    global rpRequests
    reqJson = json.loads(request.data)
    uuid = reqJson['rpRequestUUID']
    reqType = reqJson['requestType']
    rpName = reqJson['relyingParty']
    accountUUID = reqJson['accountUUID']
    ttl = reqJson['ttl']
    rpr = RpRequest(reqType, rpName, uuid, ttl, accountUUID)
    rpRequests.append(rpr)
    saveList(rpRequests, 'rprequests.p')
    return jsonify({"message": "OK"}), 200

@app.route('/v2/protected', methods=['POST'])
def protectedMethods():
    global transactions
    global accounts
    reqHeaders = request.headers
    account = doesTokenExist(reqHeaders['Authorization'])
    reqData = request.data
    reqJson = json.loads(reqData)
    id = reqJson['id']
    jsonrpc = reqJson['jsonrpc']
    method = reqJson['method']
    params = reqJson['params']
    print('[+] Received Method:',method)
    print('[+] Its Parameters:',params)
    if account is None:
        resp = {
            "id": id,
            "jsonrpc": jsonrpc,
            "error": {
                "code": -31000,
                "message": "Unauthorized!"
            }
        }
        return jsonify(resp), 401
    if method == 'submitClient2ndPart':
        freshnessToken = params['freshnessToken']
        if freshnessToken != account.authKeyInfo.freshnessToken and freshnessToken != account.signKeyInfo.freshnessToken:
            resp = {
                "id": id,
                "jsonrpc": jsonrpc,
                "error": {
                    "code": -31006,
                    "message": "Invalid freshness token"
                }
            }
            return jsonify(resp), 400
        elif freshnessToken == account.authKeyInfo.freshnessToken:
            submitClient2ndPartCalled = True
            authRequestData = params['requestData']
            isSuccessful = extractAndSetPrivateKeyPartAuth(authRequestData, account.authKeyInfo)
            if isSuccessful:
                authResponseData = calculateResponseData(account.authKeyInfo, True)
                transactionUUID = genUUID()
                resp = {
                    "id": id,
                    "jsonrpc": jsonrpc,
                    "result": {
                    "csrTransactionUUID": transactionUUID,
                    "responseData": authResponseData,
                    "responseDataEncoding": "JWE"
                    }
                }
                transaction = Transaction(transactionUUID, account.accountUUID, 'AUTHENTICATION')
                transaction.setTransactionSource('CSR')
                i = getrandbits(256)
                transaction.setHashAndHashType(b64encode(i.to_bytes(32, 'big')).decode(),'SHA256')
                transactions.append(transaction)
                saveList(transactions, 'transactions.p')
            else:
                resp = {
                    "id": id,
                    "jsonrpc": jsonrpc,
                    "error": {
                        "code": -31023,
                        "message": "Clone detected!"
                        }
                    }
                return jsonify(resp), 400
            return jsonify(resp), 200
        elif freshnessToken == account.signKeyInfo.freshnessToken:
            submitClient2ndPartCalled = True
            signRequestData = params['requestData']
            isSuccessful = extractAndSetPrivateKeyPartSign(signRequestData, account.signKeyInfo)
            if isSuccessful:
                signResponseData = calculateResponseData(account.signKeyInfo, False)
                transactionUUID = genUUID()
                resp = {
                    "id": id,
                    "jsonrpc": jsonrpc,
                    "result": {
                    "csrTransactionUUID": transactionUUID,
                    "responseData": signResponseData,
                    "responseDataEncoding": "JWE"
                    }
                }
                transaction = Transaction(transactionUUID, account.accountUUID, 'SIGNATURE')
                transaction.setTransactionSource('CSR')
                i = getrandbits(256)
                transaction.setHashAndHashType(b64encode(i.to_bytes(32, 'big')).decode(),'SHA256')
                transactions.append(transaction)
                saveList(transactions, 'transactions.p')
            else:
                resp = {
                    "id": id,
                    "jsonrpc": jsonrpc,
                    "error": {
                        "code": -31023,
                        "message": "Clone detected!"
                        }
                    }
                return jsonify(resp), 400
            return jsonify(resp), 200
        
        else:
            resp = {
                    "id": id,
                    "jsonrpc": jsonrpc,
                    "error": {
                        "code": -31000,
                        "message": "Unknown Error"
                        }
                    }
            return jsonify(resp), 400
    
    elif method == 'registerAccount':
        accountRegistrationData = params['accountRegistrationData']
        clientAuthDhPublicKey = accountRegistrationData['clientAuthDhPublicKey']
        clientSignDhPublicKey = accountRegistrationData['clientSignDhPublicKey']
        authRsa = RSA.generate(3072)
        signRsa = RSA.generate(3072)
        authKeyInfo = KeyInfo()
        signKeyInfo = KeyInfo()
        authKeyInfo.setRsaKeyPair(authRsa)
        signKeyInfo.setRsaKeyPair(signRsa)
        authComposite, authBits = calculateCompositeModulusAndBits(authKeyInfo, accountRegistrationData['clientAuthModulus'])
        signComposite, signBits = calculateCompositeModulusAndBits(signKeyInfo, accountRegistrationData['clientSignModulus'])
        messageAuth, dhAuthPublicKey = calculateDhMessageAndPublicKey(clientAuthDhPublicKey, authKeyInfo)
        print('derivedDhAuthKey:', authKeyInfo.derivedDhKey)
        messageSign, dhSignPublicKey = calculateDhMessageAndPublicKey(clientSignDhPublicKey, signKeyInfo)
        print('derivedDhSignKey:', signKeyInfo.derivedDhKey)
        authResponseData = calculateResponseData(authKeyInfo, True)
        signResponseData = calculateResponseData(signKeyInfo, False)
        accountUUID = genUUID()
        resp = {
    "id": id,
    "jsonrpc": jsonrpc,
    "result": {
        "accountUUID": accountUUID,
        "authKey": {
            "compositeModulus": authComposite,
            "compositeModulusBits": authBits,
            "freshnessToken": calculateFreshnessToken(authKeyInfo, True),
            "responseData": authResponseData,
            "responseDataEncoding": "JWE",
            "serverDhMessage": messageAuth,
            "serverDhMessageEncoding": "JWE",
            "serverDhPublicKey": dhAuthPublicKey
        },
        "identityData": {
            "givenName": "DENIZALP",
            "govID": {
                "code": "39401010067",
                "country": "EE"
            },
            "id": {
                "issuer": "EE",
                "personSemanticID": "PNOEE-39401010067",
                "scheme": "ETSI_PNO",
                "value": "39401010067"
            },
            "surname": "KAPISIZ"
        },
        "signKey": {
            "compositeModulus": signComposite,
            "compositeModulusBits": signBits,
            "freshnessToken": calculateFreshnessToken(signKeyInfo, False),
            "responseData": signResponseData,
            "responseDataEncoding": "JWE",
            "serverDhMessage": messageSign,
            "serverDhMessageEncoding": "JWE",
            "serverDhPublicKey": dhSignPublicKey
        }
    }
}
        account.updateKeyInfo(accountUUID, authKeyInfo, signKeyInfo)
        saveList(accounts, 'accounts.p')
        return jsonify(resp), 200

    elif method == 'getAccountStatus':
        authKeyStatus = 'IN_PREPARATION'
        if account.authKeyInfo.certificate is not None:
            authKeyStatus = 'OK'
        
        signKeyStatus = 'IN_PREPARATION'
        if account.signKeyInfo.certificate is not None:
            signKeyStatus = 'OK'

        missingApproval = 'RA_PORTAL'
        state = 'CSRS_CREATED'
        resultCode = None

        if authKeyStatus == 'OK' and authKeyStatus == signKeyStatus:
            missingApproval = None
            state = 'COMPLETE'
            resultCode = 'OK'
    
        resp = {
            "id": id,
            "jsonrpc": jsonrpc,
            "result": {
                "accountUUID": account.accountUUID,
                "keys": [
                {
                    "certificate": account.authKeyInfo.certificate,
                    "documentCreationTime": "2020-06-19T08:19:54.132Z",
                    "documentNumber": "PNOEE-39401010067-B6BJ-Q",
                    "keyType": "AUTHENTICATION",
                    "keyUUID": account.authKeyInfo.derivedDhKeyId,
                    "lockInfo": {
                        "nextLockDurationSec": 10911,
                        "pinAttemptsLeft": 3,
                        "pinAttemptsLeftInTotal": 9,
                        "wrongAttempts": 0
                    },
                    "status": authKeyStatus
                },
                {
                    "certificate": account.signKeyInfo.certificate,
                    "documentCreationTime": "2020-06-19T08:19:54.132Z",
                    "documentNumber": "PNOEE-39401010067-B6BJ-Q",
                    "keyType": "SIGNATURE",
                    "keyUUID": account.signKeyInfo.derivedDhKeyId,
                    "lockInfo": {
                        "nextLockDurationSec": 10911,
                        "pinAttemptsLeft": 3,
                        "pinAttemptsLeftInTotal": 9,
                        "wrongAttempts": 0
                },
                    "status": signKeyStatus
                }
        ],
        "numberOfAccounts": 2,
        "registration": {
            "documentNumber": "PNOEE-39401010067-B6BJ-Q",
            "missingApproval": missingApproval,
            "state": state,
            "resultCode": resultCode
        },
        "status": "ENABLED"
    }
}
        return jsonify(resp), 200
        
    elif method == 'getTransaction':
        transactionUUID = params['transactionUUID']
        t = doesTransactionExist(transactionUUID)
        isAuth = t.isAuthentication()
        if t is not None:
            authRegisterHash = t.hash
            authRegisterHashType = t.hashType
            ft = ''
            if isAuth:
                ft = calculateFreshnessToken(account.authKeyInfo, True)
            else:
                ft = calculateFreshnessToken(account.signKeyInfo, False)
            resp = {
    "id": id,
    "jsonrpc": jsonrpc,
    "result": {
        "freshnessToken": ft,
        "transaction": {
            "accountUUID": t.accountUUID,
            "hash": authRegisterHash,
            "hashType": authRegisterHashType,
            "state": t.state,
            "transactionSource": t.source,
            "transactionType": t.type,
            "transactionUUID": t.transactionUUID,
            "ttlSec": 899
        }
    }
}
            return jsonify(resp), 200
        else:
            resp = {
                    "id": id,
                    "jsonrpc": jsonrpc,
                    "error": {
                       "code": -31001,
                       "message": "Could not find transaction with UUID: "+transactionUUID
                    }
                }
            return jsonify(resp), 400
    elif method == 'submitSignature':
        transactionUUID = params['transactionUUID']
        t = doesTransactionExist(transactionUUID)
        if t is not None and t.isAuthentication():
            authRequestData = params['requestData']
            freshnessToken = params['freshnessToken']
            if freshnessToken != account.authKeyInfo.freshnessToken:
                resp = {
                    "id": id,
                    "jsonrpc": jsonrpc,
                    "error": {
                       "code": -31006,
                       "message": "Invalid freshness token"
                    }
                }
                return jsonify(resp), 400
            else:
                signatureVerified, errorMessage = verifySignature(authRequestData, account.authKeyInfo)
                if signatureVerified:
                    authResponseData = calculateResponseData(account.authKeyInfo, True)
                    resp = {
                   "id": id,
                   "jsonrpc": jsonrpc,
                   "result": {
                       "responseData": authResponseData,
                       "responseDataEncoding": "JWE",
                       "result": "OK"
                    }
                }
                else:
                    resp = {
                    "id": id,
                    "jsonrpc": jsonrpc,
                    "error": {
                       "code": -31000,
                       "message": errorMessage
                    }
                }
                    return jsonify(resp), 400
            certificate = {
                    "qscd": 0,
                    "subject": {
                        "C": "EE",
                        "CN": "KAPISIZ\\,DENIZALP\\,PNOEE-39401010067",
                        "GN": "DENIZALP",
                        "O": None,
                        "OU": None,
                        "SN": "KAPISIZ",
                        "serialNumber": "PNOEE-39401010067"
                    },
                    "type": "QUALIFIED",
                    "validSince": "2020-06-19T08:20:27Z",
                    "validUntil": "2023-06-19T08:20:27Z",
                    "value": "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"
                }
            account.authKeyInfo.setCertificate(certificate)
            t.setCompleted()
            deleteRPRequest(t.rpName)
            saveList(accounts, 'accounts.p')
            saveList(transactions, 'transactions.p')
            return jsonify(resp), 200
        elif t is not None and not t.isAuthentication():
            authRequestData = params['requestData']
            freshnessToken = params['freshnessToken']
            if freshnessToken != account.signKeyInfo.freshnessToken:
                resp = {
                    "id": id,
                    "jsonrpc": jsonrpc,
                    "error": {
                       "code": -31006,
                       "message": "Invalid freshness token"
                    }
                }
                return jsonify(resp), 400
            else:
                signatureVerified, errorMessage = verifySignature(authRequestData, account.signKeyInfo)
                if signatureVerified:
                    signResponseData = calculateResponseData(account.signKeyInfo, False)
                    resp = {
                    "id": id,
                    "jsonrpc": jsonrpc,
                    "result": {
                         "responseData": signResponseData,
                         "responseDataEncoding": "JWE",
                         "result": "OK"
                        }
                    }
                else:
                    resp = {
          "id": id,
          "jsonrpc": jsonrpc,
        "error": {
            "code": -31000,
            "message": errorMessage
           }
        }
                    return jsonify(resp), 400
            certificate = {
                    "qscd": 1,
                    "subject": {
                        "C": "EE",
                        "CN": "KAPISIZ\\,DENIZALP\\,PNOEE-39401010067",
                        "GN": "DENIZALP",
                        "O": None,
                        "OU": None,
                        "SN": "KAPISIZ",
                        "serialNumber": "PNOEE-39401010067"
                    },
                    "type": "QUALIFIED",
                    "validSince": "2020-06-19T08:20:40Z",
                    "validUntil": "2023-06-19T08:20:40Z",
                    "value": "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"
                }
            account.signKeyInfo.setCertificate(certificate)
            t.setCompleted()
            deleteRPRequest(t.rpName)
            saveList(accounts, 'accounts.p')
            saveList(transactions, 'transactions.p')
            return jsonify(resp), 200
        else:
            resp = {
                    "id": id,
                    "jsonrpc": jsonrpc,
                    "error": {
                       "code": -31001,
                       "message": "Could not find transaction with UUID: "+transactionUUID
                    }
                }
            return jsonify(resp), 400
    elif method == 'getPendingOperation':
        accountUUID = params['accountUUID']
        rpr = hasPendingOperation(accountUUID)
        if rpr is not None:
            resp = {
                "id": id,
                "jsonrpc": jsonrpc,
            "result": {
                "rpRequest": {
                "requestType": rpr.requestType,
                "rpName": rpr.rpName,
                "rpRequestUUID": rpr.rpRequestUUID,
                "ttlSec": rpr.ttl
                }
            }
        }
            return jsonify(resp), 200
        else:
            resp = {
            "error": {
                "code": -31001,
                "message": "Could not find running transaction for account with UUID: "+accountUUID
            },
            "id": id,
            "jsonrpc": jsonrpc
        }
            return jsonify(resp), 400
    elif method == 'createTransactionForRpRequest':
        accountUUID = params['accountUUID']
        rpRequestUUID = params['rpRequestUUID']
        rpr = hasPendingOperation(accountUUID)
        if rpr is not None:
            isAuthentication = rpr.requestType == 'AUTHENTICATION'
            ft = ''
            if isAuthentication:
                ft = calculateFreshnessToken(account.authKeyInfo, isAuthentication)
            else:
                ft = calculateFreshnessToken(account.signKeyInfo, False)
            transaction = Transaction(genUUID(), accountUUID, rpr.requestType)
            i = getrandbits(512)
            transaction.setHashAndHashType(b64encode(i.to_bytes(64, 'big')).decode(),'SHA512')
            transaction.setTransactionSource(rpr.requestType)
            transaction.setRpName(rpr.rpName)
            transactions.append(transaction)
            saveList(transactions, 'transactions.p')
            resp = {
                "id": id,
                "jsonrpc": jsonrpc,
                "result": {
                "freshnessToken": ft,
                "transaction": {
                    "accountUUID": accountUUID,
                    "displayText": "Log in to SMART-ID portal",
                    "hash": transaction.hash,
                    "hashType": transaction.hashType,
                    "rpName": transaction.rpName,
                    "state": transaction.state,
                    "transactionSource": transaction.source,
                    "transactionType": transaction.type,
                    "transactionUUID": transaction.transactionUUID,
                    "ttlSec": 89
                }
            }
        }
            return jsonify(resp), 200
        else:
            resp = {
            "error": {
                "code": -31001,
                "message": "Could not find running transaction for account with UUID: "+accountUUID
            },
            "id": id,
            "jsonrpc": jsonrpc
        }
            return jsonify(resp), 400
    
    elif method == 'getFreshnessToken':
        keyType = params['keyType']
        if keyType not in ['AUTHENTICATION', 'SIGNATURE']:
            resp = {
                "jsonrpc": jsonrpc,
                "id": id,
                "error": {
                    "code": -32602,
                    "message": "Invalid method parameters"
                }
            }
            return jsonify(resp), 400
        else:
            freshnessToken = ''
            if keyType == 'AUTHENTICATION':
                freshnessToken = calculateFreshnessToken(account.authKeyInfo, True)
            else:
                freshnessToken = calculateFreshnessToken(account.signKeyInfo, False)
            resp = {
                "id": id,
                "jsonrpc": jsonrpc,
                "result": {
                    "freshnessToken": freshnessToken
                }
            }
            return jsonify(resp), 200
    elif method == 'deleteAccount':
        accountUUID = params['accountUUID']
        acc = doesAccountExist(accountUUID)
        if acc is None:
            resp = {
                "error": {
                    "code": -31002,
                    "message": "Account was already DISABLED: "+accountUUID
                    },
                "id": id,
                "jsonrpc": jsonrpc
            }
            return jsonify(resp), 400
        else:
            acc.deleteKeyInfo()
            saveList(accounts, 'accounts.p')
            resp = {
                "result": {
                    "message": "OK"
                    },
                "id": id,
                "jsonrpc": jsonrpc
            }
            return jsonify(resp), 200
    elif method == 'cancelRpRequest':
        rpr = hasPendingOperation(params['accountUUID'])
        if rpr is not None:
            removeRpRequest(rpr)
            resp = {
            "id": id,
            "jsonrpc": jsonrpc,
            "result": {
                "message": "OK"
            }
            }
            return jsonify(resp), 200
        else:
            resp = {
                "error": {
                    "code": -31000,
                    "message": "No RP Request found for "+accountUUID
                    },
                "id": id,
                "jsonrpc": jsonrpc
            }
            return jsonify(resp), 400
    elif method == 'cancelTransaction':
        transaction = doesTransactionExist(params['transactionUUID'])
        if transaction is not None:
            removeTransaction(transaction)
            resp = {
            "id": id,
            "jsonrpc": jsonrpc,
            "result": {
                "message": "OK"
            }
            }
            return jsonify(resp), 200
        else:
            resp = {
                "error": {
                    "code": -31000,
                    "message": "No Transaction found for "+transactionUUID
                    },
                "id": id,
                "jsonrpc": jsonrpc
            }
            return jsonify(resp), 400
    else:
        resp = {
            "jsonrpc": jsonrpc,
            "id": id,
            "error": {
                "code": -32601,
                "message": "method not found"
            }
        }
        return jsonify(resp), 404