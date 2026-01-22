from random import getrandbits, randint
from math import log2, ceil, gcd
from os import urandom
import hashlib, hmac

class GenerationParams:
    def __init__(self, param1Int, param1BigInteger):
        if param1Int == 2048 or param1Int == 3072:
            self.nlen = param1Int
            self.e = param1BigInteger
            if param1Int == 2048:
                self.securityStrength = 0x70
            else:
                self.securityStrength = 0x80
            if param1Int == 2048:
                self.xP1PrimLen = 0x1a0
            else:
                self.xP1PrimLen = 0x280
            if param1Int == 2048:
                self.xP1PrimPrimLen = 0xa0
            else:
                self.xP1PrimPrimLen = 0xc0
            if param1Int == 2048:
                self.xP2Len = 0x1a0
            else:
                self.xP2Len = 0x280
            if param1Int == 2048:
                self.mrIterations = 56
            else:
                self.mrIterations = 64
        else:
            raise Exception("Only 2048 and 3072 are supported!")
    def clear(self):
        self.nlen = 0
        self.e = None
        self.securityStrength = 0
        self.xP1PrimLen = 0
        self.xP1PrimPrimLen = 0
        self.xP2Len = 0
        self.mrIterations = 0

def hasAnySmallFactors(paramBigInteger):
    i = paramBigInteger % 223092870
    if i % 2 != 0 and i % 3 != 0 and i % 5 != 0 and i % 7 != 0 and i % 11 != 0 and  i % 13 != 0 and  i % 17 != 0 and i % 19 != 0:
        if i % 23 == 0:
            return True
        i = paramBigInteger % 58642669
        if i % 29 != 0 and i % 31 != 0 and i % 37 != 0 and i % 41 != 0:
            if i % 43 == 0:
                return True
            i = paramBigInteger % 600662303
            if i % 47 != 0 and i % 53 != 0 and i % 59 != 0 and i % 61 != 0:
                if i % 67 == 0:
                    return True
                i = paramBigInteger % 33984931
                if i % 71 != 0 and i % 73 != 0 and i % 79 != 0:
                    if i % 83 == 0:
                        return True
                    i = paramBigInteger % 89809099
                    if i % 89 != 0 and i % 97 != 0 and i % 101 != 0:
                        if i % 103 == 0:
                            return True
                        i = paramBigInteger % 167375713
                        if i % 107 != 0 and i % 109 != 0 and i % 113 != 0:
                            if i % 127 == 0:
                                return True
                            i = paramBigInteger % 371700317
                            if i % 131 != 0 and i % 137 != 0 and i % 139 != 0:
                                if i % 149 == 0:
                                    return True
                                i = paramBigInteger % 645328247
                                if i % 151 != 0 and i % 157 != 0 and i % 163 != 0:
                                    if i % 167 == 0:
                                        return True
                                    i = paramBigInteger % 1070560157
                                    if i % 173 != 0 and i % 179 != 0 and i % 181 != 0:
                                        if i % 191 == 0:
                                            return True
                                        i = paramBigInteger % 1596463769
                                        if i % 193 != 0 and i % 197 != 0 and i % 199 != 0:
                                            return (i % 211 == 0)
    return True

def getLowestSetBit(paramBigInteger):
    if paramBigInteger == 0:
        return -1
    return int(log2(paramBigInteger & (-1 * paramBigInteger)))

def createRandomInRange(paramBigInteger1, paramBigInteger2):
    if paramBigInteger1 > paramBigInteger2:
        raise Exception('min may not be greater than max!')
    if paramBigInteger1 == paramBigInteger2:
        return paramBigInteger1
    if paramBigInteger1.bit_length() > (paramBigInteger2.bit_length() // 2):
        paramBigInteger2 = createRandomInRange(0, paramBigInteger2-paramBigInteger1)
        return paramBigInteger2 + paramBigInteger1
    for _ in range(0,1000,1):
        bigInteger = getrandbits(paramBigInteger2.bit_length())
        if bigInteger >= paramBigInteger1 and bigInteger <= paramBigInteger2:
            return bigInteger
    diff = paramBigInteger2 - paramBigInteger1
    paramBigInteger2 = getrandbits(diff.bit_length() - 1)
    return paramBigInteger2 + paramBigInteger1

def mrProbablePrimeToBase(paramBigInteger1, paramBigInteger2, paramBigInteger3, paramInt, paramBigInteger4):
    paramBigInteger3 = pow(paramBigInteger4, paramBigInteger3, paramBigInteger1)
    bool1 = (paramBigInteger3 == 1)
    bool2 = True
    if not bool1:
        if paramBigInteger3 == paramBigInteger2:
            return True
        for _ in range(1, paramInt, 1):
            paramBigInteger3 = pow(paramBigInteger3, 2, paramBigInteger1)
            if paramBigInteger3 == paramBigInteger2:
                return True
            if paramBigInteger3 == 1:
                return False
        bool2 = False
    return bool2

def isMRProbablePrime(paramBigInteger, paramInt):
    if paramInt > 0:
        if paramBigInteger.bit_length() == 2:
            return True
        if not (paramBigInteger & 1):
            return False
        bigInteger1 = paramBigInteger - 1
        bigInteger2 = paramBigInteger - 2
        j = getLowestSetBit(bigInteger1)
        bigInteger3 = bigInteger1 >> j
        for _ in range(0, paramInt, 1):
            if not mrProbablePrimeToBase(paramBigInteger, bigInteger1, bigInteger3, j, createRandomInRange(2, bigInteger2)):
                return False
        return True

def aa(paramBigInteger, paramInt):
    return (not hasAnySmallFactors(paramBigInteger)) and isMRProbablePrime(paramBigInteger, paramInt)

def a(paramInt1, paramInt2):
    bigInteger1 = getrandbits(paramInt1) | 1
    bigInteger2 = 2
    while(not aa(bigInteger1, paramInt2)):
        bigInteger1 = bigInteger1 + bigInteger2
    return bigInteger1

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b%a,a)
    return (g, x - (b//a) * y, y)

def modInverse(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('No modular inverse')
    return x%m

def generateProbablePrimeFromAuxiliaryPrimes(paramGenerationParams):
    bigInteger2 = a(paramGenerationParams.xP1PrimLen, paramGenerationParams.mrIterations)
    #print('[+] Generated bit length:',bigInteger2.bit_length())
    bigInteger3 = a(paramGenerationParams.xP1PrimPrimLen, paramGenerationParams.mrIterations)
    #print('[+] Generated bit length:',bigInteger3.bit_length())
    bigInteger4 = a(paramGenerationParams.xP2Len, paramGenerationParams.mrIterations)
    #print('[+] Generated bit length:',bigInteger4.bit_length())
    bigInteger5 = bigInteger2 * bigInteger3
    j = paramGenerationParams.nlen
    bigInteger6 = paramGenerationParams.e
    k = paramGenerationParams.mrIterations
    bigInteger7 = 2
    bigInteger1 = 1414213562373095048801688724209698078569671875376948073176679737990732478462107038850387534327641572735013846230912297024924836055850737212644121497099935831413222665927505592755799950501152782060571470109559971605970274534596862014728517418640889198609552329230484308714321450839762603627995251407989687253396546331808829640620615258352395054745750287759961729835575220337531857011354374603408498847160386899970699004815030544027790316454247823068492936918621580578463111596668713013015618568987237235288509264861249497715421833420428568606014682472077143585487415565706967765372022648544701585880162075847492265722600208558446652145839889394437092659180031138824646815708263010059485870400318648034219489727829064104507263688131373985525611732204024509122770022694112757362728049573810896750401836986836845072579936472906076299694138047565482372899718032680247442062926912485905218100445984215059112024944134172853147810580360337107730918286931471017111168391658172688941975871658215212822951848847208969463386289156288276595263514054226765323969461751129160240871
    bigInteger8 = 10 ** 1065
    i = bigInteger5.bit_length()
    i1 = bigInteger4.bit_length()
    m = j // 2
    n = m - 1
    if (i + i1) > (m - ceil(log2(n)) - 6):
        return None
    if not (gcd(bigInteger5 * bigInteger7, bigInteger4) == 1):
        return None
    bigInteger9 = (modInverse(bigInteger4, bigInteger5 * bigInteger7))*bigInteger4 - (modInverse(bigInteger5*bigInteger7, bigInteger4))*bigInteger5*bigInteger7
    if bigInteger9 % (bigInteger5 * bigInteger7) == 1:
        if (bigInteger9 + 1) % bigInteger4 != 0:
            return None
        while True:
            #print('[+] Applying Chinese Remainder...')
            bigInteger = createRandomInRange((bigInteger7**n) * bigInteger1 // bigInteger8, (bigInteger7 ** m) - 1)
            bigInteger3 = bigInteger + ((bigInteger9 - bigInteger) % (bigInteger7 * bigInteger5 * bigInteger4))
            bigInteger2 = bigInteger1
            if (bigInteger3 - 1) % bigInteger5 == 0:
                bigInteger2 = bigInteger1
                if (bigInteger3 + 1) % bigInteger4 == 0:
                    i = 0
                    bigInteger2 = bigInteger3
                    while (bigInteger2 < (bigInteger7 ** m)):
                        if gcd(bigInteger6, bigInteger2 - 1) == 1 and aa(bigInteger2, k):
                            res = []
                            res.append(bigInteger2)
                            res.append(bigInteger)
                            return res
                        i = i + 1
                        if i >= (j * 5 // 2):
                            return None
                        bigInteger2 = bigInteger2 + (bigInteger7 * bigInteger5 * bigInteger4)
                    bigInteger2 = bigInteger1
            bigInteger1 = bigInteger2
    return None
                        

def aaa(modulus, privateExponent, phi):
    arrayOfByte = urandom(modulus.bit_length() // 8)
    bigInteger = None
    while True:
        if bigInteger is None or (0 == bigInteger) or (privateExponent == bigInteger) or (phi == bigInteger):
            bigInteger = int.from_bytes(arrayOfByte, 'big')
            arrayOfByte = urandom(modulus.bit_length() // 8)
            continue
        dprimeprime = (privateExponent - bigInteger) % phi
        return bigInteger, dprimeprime, modulus 

def generatePQAndCreateKeyShare(paramInt, paramBigInteger):
    if paramBigInteger is None:
        raise Exception("Parameter e cannot be null!")
    while True:
        if paramBigInteger is None:
            raise Exception("Parameter e cannot be null!")
        if paramInt == 2048 or paramInt == 3072:
            if paramBigInteger % 2 != 0:
                if paramBigInteger > 2 ** 16:
                    if paramBigInteger < 2**256:
                        i = None
                        bigInteger1 = None
                        arrayOfBigInteger = None
                        bigInteger2 = None
                        generationParams = GenerationParams(paramInt, paramBigInteger)
                        while True:
                            arrayOfBigInteger1 = generateProbablePrimeFromAuxiliaryPrimes(generationParams)
                            if arrayOfBigInteger1 is not None:
                                #print('[+] P and XP are generated.')
                                bigInteger1 = arrayOfBigInteger1[0]
                                bigInteger2 = arrayOfBigInteger1[1]
                                while True:
                                    arrayOfBigInteger2 = generateProbablePrimeFromAuxiliaryPrimes(generationParams)
                                    if arrayOfBigInteger2 is not None:
                                        #print('[+] Q and XQ are generated.')
                                        bool1 = False
                                        bool2 = False
                                        bigInteger3 = arrayOfBigInteger2[0]
                                        bigInteger4 = arrayOfBigInteger2[1]
                                        bigInteger5 = 2
                                        i = paramInt // 2
                                        bigInteger5 = bigInteger5 ** (i - 100)
                                        if abs(bigInteger2 - bigInteger4) > bigInteger5:
                                            bool1 = True
                                        else:
                                            bool1 = False
                                        if abs(bigInteger1 - bigInteger3) > bigInteger5:
                                            bool2 = True
                                        else:
                                            bool2 = False
                                        if (not bool1) or (not bool2):
                                            continue
                                        generationParams.clear()
                                        b1 = (bigInteger1 - 1) * (bigInteger3 - 1)
                                        b2 = modInverse(paramBigInteger, b1)
                                        if (b2.bit_length() > i):
                                            return aaa(bigInteger1 * bigInteger3, b2, b1)
                                        continue
                                    continue
                                continue
                            continue
                        continue
                    raise Exception("e can't be >= 2^256!")
                raise Exception("e can't be <= 2^16")
            raise Exception("e must be odd!")
        raise Exception("Only 2048 or 3072 are supported!")

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

def generateDerivedKeyAlt(pin,salt,iterations):
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

def generateDerivedKey(pin,salt,iterations):
    j = 20
    k = (32 + j - 1) // j
    arrayOfByte1 = [b'\x00',b'\x00',b'\x00',b'\x00']
    arrayOfByte2 = [b'\x00']*k*j
    myHmac = hmac.new(pin, digestmod='sha1')
    paramInt = 1
    i = 0
    while paramInt <= k:
        m = 3
        while True:
            add1 = (int.from_bytes(arrayOfByte1[m],'big') + 1) % 256
            b = add1.to_bytes(1,'big')
            arrayOfByte1[m] = b
            if b == b'\x00':
                m = m - 1
                continue
            else:
                break
        F(myHmac, salt, iterations, arrayOfByte1, arrayOfByte2, i)
        i = i + j
        paramInt = paramInt + 1
    return arrayOfByte2

from Crypto.Cipher import AES
def decryptClientKeyPart(enc, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    dec = cipher.decrypt(enc)
    return int.from_bytes(dec, 'big')