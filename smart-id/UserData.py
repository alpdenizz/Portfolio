import xml.etree.ElementTree as ET
import os, re, json
import hashlib, hmac
import argparse
from jwcrypto.common import json_encode, json_decode
from base64 import b64decode

class KeyInfo:
    def __init__(self, compositeBits, privateKeyPart, dhDerivedKey, dhDerivedKeyId, modulus):
        self.compositeBits = compositeBits
        self.privateKeyPart = privateKeyPart
        self.dhDerivedKey = dhDerivedKey
        self.dhDerivedKeyId = dhDerivedKeyId
        self.modulus = modulus
    
    def setOneTimePassword(self, otp):
        self.otp = otp

class AccountInfo:
    def __init__(self, accountUUID, appInstanceUUID, password, authKeyInfo, signKeyInfo):
        self.accountUUID = accountUUID
        self.appInstanceUUID = appInstanceUUID
        self.password = password
        self.authKeyInfo = authKeyInfo
        self.signKeyInfo = signKeyInfo

def getIntValue(base64EncStr):
    return int.from_bytes(b64decode(base64EncStr),'big')

def strToList(str):
    l = []
    for c in str:
        l.append(bytes([c]))
    return l

def F(myHmac, salt, iterations, arr1, arr2, i):
    if salt is not None:
        myHmac.update(salt)
    myHmac.update(b''.join(arr1))
    res = myHmac.digest()
    arr2[i:] = strToList(res)

def generateDerivedKey(pin,salt,iterations):
    j = 20
    k = (32 + j - 1) // j
    arrayOfByte1 = [b'\x00',b'\x00',b'\x00',b'\x00']
    arrayOfByte2 = [b'\x00']*k*j
    myHmac = hmac.new(pin, digestmod='sha1')
    paramInt = 1
    i = 0

    arrayOfByte1 = [b'\x00',b'\x00',b'\x00',b'\x01']
    F(myHmac, salt, iterations, arrayOfByte1, arrayOfByte2, i)
    i = i + j
    paramInt = paramInt + 1

    myHmac = hmac.new(pin, digestmod='sha1')
    arrayOfByte1 = [b'\x00',b'\x00',b'\x00',b'\x02']
    F(myHmac, salt, iterations, arrayOfByte1, arrayOfByte2, i)
    i = i + j
    paramInt = paramInt + 1

    return arrayOfByte2

from Crypto.Cipher import AES
def decryptClientKeyPart(enc, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    dec = cipher.decrypt(enc)
    return int.from_bytes(dec, 'big')

def getPrivateKeyPart(enc, pin):
    arr = generateDerivedKey(pin, b'\x00', 1)
    key = b''.join(arr[0:16])
    iv = b''.join(arr[16:32])
    encrypted = b64decode(enc)
    return decryptClientKeyPart(encrypted, key, iv)

def getKeyInfo(keyData, pin):
    compositeBits = keyData['compositeModulusBits']
    privateKeyPart = getPrivateKeyPart(keyData['d1Prime']['keyShare'], pin)
    dhDerivedKey = keyData['dhDerivedKey']
    dhDerivedKeyId = keyData['dhDerivedKeyId']
    modulus = getIntValue(keyData['n1'])
    return KeyInfo(compositeBits, privateKeyPart, dhDerivedKey, dhDerivedKeyId, modulus)

def getAccountInformation(p1, p2):
    pin1 = p1.encode('utf-8')
    pin2 = p2.encode('utf-8')
    xmlFiles = os.listdir('userdata')
    #print(xmlFiles)

    uuidPattern = "\\b[0-9a-f]{8}\\b-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-\\b[0-9a-f]{12}\\b"
    fingerprint = "\\b[0-9a-f]{16}\\b"
    starter = 'ee.cyber.smartid.cryptolib.STORAGE_ee.cyber.smartid.'

    patterns = {
'ACCOUNT_STATE': 'ACCOUNT_STATES', 
'INSTANCE_ID': 'INSTANCE_ID_DATA', 
'KEY_DATA_AUTH': starter+'APP_KEY_DATA_AUTHENTICATION', 
'KEY_DATA_SIGN': starter+'APP_KEY_DATA_SIGNATURE', 
'KEY_STATE_AUTH': starter+'APP_KEY_STATE_FOR_KEY_ID_ee.cyber.smartid.APP_KEY_DATA_AUTHENTICATION', 
'KEY_STATE_SIGN': starter+'APP_KEY_STATE_FOR_KEY_ID_ee.cyber.smartid.APP_KEY_DATA_SIGNATURE', 
'PASSWORD': 'APP_PASSWORD_DATA'}

    neededFiles = {'ACCOUNT_STATE': '', 'INSTANCE_ID': '', 'KEY_DATA_AUTH': '', 'KEY_DATA_SIGN': '', 'KEY_STATE_AUTH': '', 'KEY_STATE_SIGN': '', 'PASSWORD': ''}

    for prop, pattern in patterns.items():
        for xmlFile in xmlFiles:
            if pattern in xmlFile:
                neededFiles[prop] = xmlFile

    #account state
    parseFile = '.\\userdata\\'+neededFiles['ACCOUNT_STATE']
    tree = ET.parse(parseFile)
    root = tree.getroot()
    accountState = json.loads(root[0].text)
    #print('[+] Account Info:',accountState)

    #instance id
    parseFile = '.\\userdata\\'+neededFiles['INSTANCE_ID']
    tree = ET.parse(parseFile)
    root = tree.getroot()
    instanceID = root[0].text
    instanceID = instanceID[1:-1]
    #print('[+] App Instance UUID:',instanceID)

    #key data auth
    parseFile = '.\\userdata\\'+neededFiles['KEY_DATA_AUTH']
    tree = ET.parse(parseFile)
    root = tree.getroot()
    keyDataAuth = json.loads(root[0].text)
    #print('[+] Key Data Auth:',keyDataAuth)
    authKeyInfo = getKeyInfo(keyDataAuth, pin1)

    #key data sign
    parseFile = '.\\userdata\\'+neededFiles['KEY_DATA_SIGN']
    tree = ET.parse(parseFile)
    root = tree.getroot()
    keyDataSign = json.loads(root[0].text)
    #print('[+] Key Data Sign:',keyDataSign)
    signKeyInfo = getKeyInfo(keyDataSign, pin2)

    #key state auth
    parseFile = '.\\userdata\\'+neededFiles['KEY_STATE_AUTH']
    tree = ET.parse(parseFile)
    root = tree.getroot()
    keyStateAuth = json.loads(root[0].text)
    #print('[+] Key State Auth:',keyStateAuth)
    authKeyInfo.setOneTimePassword(keyStateAuth['oneTimePassword'])
    accountUUID = keyStateAuth['accountUUID']

    #key state sign
    parseFile = '.\\userdata\\'+neededFiles['KEY_STATE_SIGN']
    tree = ET.parse(parseFile)
    root = tree.getroot()
    keyStateSign = json.loads(root[0].text)
    #print('[+] Key State Sign:',keyStateSign)
    signKeyInfo.setOneTimePassword(keyStateSign['oneTimePassword'])

    #password
    parseFile = '.\\userdata\\'+neededFiles['PASSWORD']
    tree = ET.parse(parseFile)
    root = tree.getroot()
    password = root[0].text
    password = password[1:-1]
    #print('[+] Password:',password)
    
    open('account_'+accountUUID, 'w').write(json_encode({"accountUUID": accountUUID, "appInstanceUUID": instanceID, "password": password, 
    "authPrivateKeyClientPart": authKeyInfo.privateKeyPart, "authModulus": authKeyInfo.modulus, "authOneTimePassword": authKeyInfo.otp,
    "authKeyUUID": authKeyInfo.dhDerivedKeyId, "authTEK": authKeyInfo.dhDerivedKey, "authCompositeModulusBits": authKeyInfo.compositeBits, 
    "signPrivateKeyClientPart": signKeyInfo.privateKeyPart, "signModulus": signKeyInfo.modulus, "signOneTimePassword": signKeyInfo.otp,
    "signKeyUUID": signKeyInfo.dhDerivedKeyId, "signTEK": signKeyInfo.dhDerivedKey, "signCompositeModulusBits": signKeyInfo.compositeBits}))

parser = argparse.ArgumentParser(prog='UserData')
parser.add_argument('--PIN1', help='PIN1 of the account')
parser.add_argument('--PIN2', help='PIN2 of the account')
args = parser.parse_args()

getAccountInformation(args.PIN1, args.PIN2)