class Account:
    def __init__(self, accountUUID, appInstanceUUID, password, authKeyInfo, signKeyInfo):
        self.accountUUID = accountUUID
        self.appInstanceUUID = appInstanceUUID
        self.password = password
        self.authKeyInfo = authKeyInfo
        self.signKeyInfo = signKeyInfo
    
    def deleteKeyInfo(self):
        self.accountUUID = None
        self.authKeyInfo = None
        self.signKeyInfo = None
    
    def updateKeyInfo(self, accountUUID, authKeyInfo, signKeyInfo):
        self.accountUUID = accountUUID
        self.authKeyInfo = authKeyInfo
        self.signKeyInfo = signKeyInfo

class KeyInfo:
    def __init__(self):
        self.certificate = None

    def setDerivedDhKeyInfo(self, derivedDhKeyId, derivedDhKey):
        self.derivedDhKeyId = derivedDhKeyId
        self.derivedDhKey = derivedDhKey
    
    def setFreshnessToken(self, token):
        self.freshnessToken = token
    
    def setOneTimePassword(self, password):
        self.oneTimePassword = password
    
    def setPrivateKeyPart(self, privateKeyPart):
        self.privateKeyPart = privateKeyPart
    
    def setRsaKeyPair(self, rsaKeyPair):
        self.serverModulus = rsaKeyPair.n
        self.serverD = rsaKeyPair.d
        self.serverE = rsaKeyPair.e
    
    def setCompositeModulus(self, compositeModulus):
        self.compositeModulus = compositeModulus

    def setClientModulus(self, clientModulus):
        self.clientModulus = clientModulus
    
    def setCertificate(self, certificate):
        self.certificate = certificate

class Transaction:
    def __init__(self, transactionUUID, accountUUID, typeT):
        self.transactionUUID = transactionUUID
        self.accountUUID = accountUUID
        self.state = 'RUNNING'
        self.type = typeT if typeT == 'AUTHENTICATION' else 'SIGNATURE'
        self.rpName = None
    
    def setHashAndHashType(self, hashV, hashType):
        self.hash = hashV
        self.hashType = hashType
    
    def setTransactionSource(self, source):
        self.source = source
    
    def isAuthentication(self):
        return self.type == 'AUTHENTICATION'
    
    def setCompleted(self):
        self.state = 'COMPLETED'
    
    def setRpName(self, rpName):
        self.rpName = rpName

class RpRequest:
    def __init__(self, requestType, rpName, rpRequestUUID, ttl, accountUUID):
        self.requestType = requestType
        self.rpName = rpName
        self.rpRequestUUID = rpRequestUUID
        self.ttl = ttl
        self.accountUUID = accountUUID