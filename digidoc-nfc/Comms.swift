//
//  Comms.swift
//  MoppApp
//
//  Created by Denizalp Kapisiz on 04.08.2025.
//

import Foundation
import CoreNFC
import Security
import CryptoKit
import CommonCrypto
import SwiftECC
import BigInt
import CryptoSwift

func stringToBytes(_ string: String) -> [UInt8]? {
    let length = string.count
    if length & 1 != 0 {
        return nil
    }
    var bytes = [UInt8]()
    bytes.reserveCapacity(length/2)
    var index = string.startIndex
    for _ in 0..<length/2 {
        let nextIndex = string.index(index, offsetBy: 2)
        if let b = UInt8(string[index..<nextIndex], radix: 16) {
            bytes.append(b)
        } else {
            return nil
        }
        index = nextIndex
    }
    return bytes
}
func bytesConvertToHexstring(byte : [UInt8]) -> String {
    var string = ""
    
    if byte.isEmpty {
        return "<empty bytes>"
    }

    for val in byte {
        //getBytes(&byte, range: NSMakeRange(i, 1))
        string = string + String(format: "%02X", val)
    }

    return string
}
extension CryptoKit.Digest {
    var bytes: [UInt8] { Array(makeIterator()) }
    var data: Data { Data(bytes) }

    var hexStr: String {
        bytes.map { String(format: "%02X", $0) }.joined()
    }
}
struct QCCError: Error {
    var code: CCCryptorStatus
}

extension QCCError {
    init(code: Int) {
        self.init(code: CCCryptorStatus(code))
    }
}
class Comms {
    static let selectMaster: [UInt8] = stringToBytes("00a4040c10a000000077010800070000fe00000100")!
    static let selectPersonalDF: [UInt8] = stringToBytes("00a4010c025000")!
    static let readBinary: [UInt8] = stringToBytes("00b0000000")!
    static let MSESetAT: [UInt8] = stringToBytes("0022c1a40f800a04007f0007020204020483010200")!
    static let GAGetNonce: [UInt8] = stringToBytes("10860000027c0000")!
    static let GAMapNonceIncomplete: [UInt8] = stringToBytes("10860000457c438141")!
    static let GAKeyAgreementIncomplete = stringToBytes("10860000457c438341")!
    static let GAMutualAuthenticationIncomplete = stringToBytes("008600000c7c0a8508")!
    static let dataForMACIncomplete = stringToBytes("7f494f060a04007f000702020402048641")!
    static let selectFile = stringToBytes("0ca4010c1d871101")!
        //read binary: 00 b0 00 00 00
    static let readFile = stringToBytes("0cb000000d970100")!
        //empty pin1 verify: 00 20 00 01 00
    static let emptyPIN1 = stringToBytes("0c2000010d970100")!
    static let emptyPIN2 = stringToBytes("0c2000850d970100")!
    static let emptyPUK = stringToBytes("0c2000020d970100")!
    static let verifyPIN1 = stringToBytes("0c2000011d871101")!
    static let verifyPUK = stringToBytes("0c2000021d871101")!
    static let verifyPIN2 = stringToBytes("0c2000851d871101")!
    static let ChangePIN1 = stringToBytes("0c2400011d871101")!
    static let ChangePIN2 = stringToBytes("0c2400851d871101")!
    static let ChangePUK = stringToBytes("0c2400021d871101")!
    static let ResetPIN1 = stringToBytes("0c2c02011d871101")!
    static let ResetPIN2 = stringToBytes("0c2c02851d871101")!
        //sign env: 002241B6
    static let DSSetEnv = stringToBytes("0c2241B61d871101")!
    static let MSESetEnv = stringToBytes("0c2241A41d871101")!
        //sign setenv: 8004FF15080084019F
    static let DSEnv = stringToBytes("8004FF15080084019F")!
        //auth setenv: 8004FF200800840181
    static let Env = stringToBytes("8004FF200800840181")!
        //regular internalauth: 00880000<challengebytes>00
    static let InternalAuthenticate = stringToBytes("0c8800001d871101")!
        //Find correct value for this, currently it is InternalAuthenticate
        //regular digitalsignature: 002a9e9a<hashbytes>00
    static let DigitalSignature = stringToBytes("0c2a9e9a1d871101")!
    static let IASECCFID = [UInt8(0x3f), UInt8(0x00)]
    static let personalDF = [UInt8(0x50), UInt8(0x00)]
    static let AWP = [UInt8(0xad), UInt8(0xf1)]
    static let QSCD = [UInt8(0xad), UInt8(0xf2)]
    static let authCert = [UInt8(0x34), UInt8(0x01)]
    static let signCert = [UInt8(0x34), UInt8(0x1f)]
    
    static let DecryptAid = stringToBytes("E828BD080FF2504F5420415750")!
    static let DecryptSelect = stringToBytes("0ca4040c1d871101")!
    static let DecryptSetEnv = stringToBytes("0c2241B81d871101")!
    static let DecryptEnv = stringToBytes("8004FF300400840181")!
    static let Decrypt = stringToBytes("0c2A80861d871101")!
    static let DecryptChain = stringToBytes("1c2A80861d871101")!
    
    var idCard: NFCISO7816Tag?
    var keyEnc: [UInt8]?
    var keyMac: [UInt8]?
    var ssc: UInt8 = 0
    var CAN: String = ""
    
    init(idCard: NFCISO7816Tag? = nil, CAN: String) {
        self.idCard = idCard
        self.CAN = CAN
    }
    
    private func prepareSSC() -> [UInt8] {
        var bytes: [UInt8] = []
        var initial = self.ssc
        for _ in 0..<16 {
            bytes = [UInt8(initial & 0b11111111)] + bytes
            initial = initial >> 8
        }
        return bytes
    }
    
    func decryptNonce(input: [UInt8], CAN: [UInt8]) -> [UInt8] {
        let padded = CAN + [0x00,0x00,0x00,0x03]
        let hash = SHA256.hash(data: padded)
        var plaintext = [UInt8](repeating: 0, count: input.count)
        var plaintextCount = 0
        let err = CCCrypt(
            CCOperation(kCCDecrypt),
            CCAlgorithm(kCCAlgorithmAES),CCOptions(),
            hash.bytes, hash.bytes.count,
            [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
            input, input.count,
            &plaintext, plaintext.count,
            &plaintextCount
        )
        guard err == kCCSuccess else {
            //printLog("[NFC] [-] Error during AES decryption: returning empty")
            //printLog("[NFC] [-] Error during AES decryption: \(err)")
            return []
        }
        return plaintext
    }
    
    func createSecureAPDU(encrypted: Bytes, template: Bytes) -> Bytes {
        //////print("[+] Data bytes to be encrypted: \(encrypted.toHexString())")
        //////print("[+] Command template to be prepared: \(template.toHexString())")
        self.ssc = self.ssc + 1
        let length = 16 * (1 + encrypted.count >> 4)
        var macData = [UInt8](repeating: 0x00, count: (encrypted.count > 0 ? (48+length) : 48))
        var ciphertext: [UInt8] = []
        macData[15] = ssc
        
        macData[16] = template[0]
        macData[17] = template[1]
        macData[18] = template[2]
        macData[19] = template[3]
        
        macData[20] = 0x80
        
        macData[32] = template[5]
        macData[33] = template[6]
        macData[34] = template[7]
        if encrypted.count > 0 {
            var paddedData = encrypted + [UInt8](repeating: 0x00, count: (length - encrypted.count))
            paddedData[encrypted.count] = 0x80
            ciphertext = [UInt8](repeating: 0, count: paddedData.count)
            var ciphertextCount = 0
            
            let IV = prepareSSC()
            do {
                let aes = try AES(key: self.keyEnc!, blockMode: CryptoSwift.ECB())
                let encIV = try aes.encrypt(IV)
                let err = CCCrypt(
                    CCOperation(kCCEncrypt),
                    CCAlgorithm(kCCAlgorithmAES),CCOptions(),
                    self.keyEnc!, self.keyEnc!.count,
                    encIV,
                    paddedData, paddedData.count,
                    &ciphertext, ciphertext.count,
                    &ciphertextCount
                )
                guard err == kCCSuccess else {
                    //printLog("[NFC] [-] Error during AES encryption: returning empty")
                    //printLog("[NFC] [-] Error during AES encryption: \(err)")
                    return []
                }
                for pos in 0...(ciphertext.count-1) {
                    macData[35+pos] = ciphertext[pos]
                }
            } catch let error {
                //printLog("[-] something went wrong during creating secure APDU: \(error)")
            }
        }
        macData[35 + ciphertext.count] = 0x80
        //calculate MAC of macData
        do {
            let cmacBytes = try CMAC.init(key: self.keyMac!).authenticate(macData)
            let cmacBytesTrimmed = cmacBytes.prefix(upTo: 8)
            var APDU = template + [UInt8](repeating: 0x00, count: (ciphertext.count + 11))
            if ciphertext.count > 0 {
                for pos in 0...(ciphertext.count - 1) {
                    APDU[template.count + pos] = ciphertext[pos]
                }
            }
            APDU[template.count + ciphertext.count] = 0x8E
            APDU[template.count + ciphertext.count + 1] = 0x08
            for pos in 0...7 {
                APDU[template.count + ciphertext.count + 2 + pos] = cmacBytesTrimmed[pos]
            }
            self.ssc = self.ssc + 1
            return APDU
        } catch let error {
            //printLog("[NFC] [-] Error during CMAC: returning empty, reason: \(error)")
            return []
        }
    }
    
    func getResponse(command: NFCISO7816APDU, purpose: String) async -> (Bytes?,NSError?) {
        let result: (Data, UInt8, UInt8)?
        do {
            //printLog("[NFC] START [+] \(purpose)...")
            result = try await self.idCard?.sendCommand(apdu: command)
            //printLog("[NFC] END [+] \(purpose)...")
            let output = [UInt8](result!.0)
            let sw1 = result!.1
            let sw2 = result!.2
            if sw1 != UInt8(0x90) || sw2 != UInt8(0x00) {
                //printLog("[NFC] [-] Got response: \(bytesConvertToHexstring(byte: output))")
                //printLog("[NFC] [-] Got status: \(sw1) \(sw2)")
                let nfcCommandError: NSError = NSError.init(domain: "MoppLib", code: Int(MoppLibError.Code.general.rawValue), userInfo: [NSLocalizedDescriptionKey: "NFC command error"])
                return (nil,nfcCommandError)
            }
            //printLog("[NFC] [+] Got response: \(bytesConvertToHexstring(byte: output))")
            return (output,nil)
        }catch let error {
            //printLog("[NFC] [-] Something went wrong in APDU communication: \(error)")
            ////print("[NFC] [-] Something went wrong in APDU communication: \(error)")
            //self.idCard?.session?.invalidate(errorMessage: "Something went wrong during NFC communication")
            return (nil,error as NSError?)
        }
    }
    
    func getResponseWithStatus(command: NFCISO7816APDU, purpose: String) async -> ((Bytes, UInt8, UInt8)?,NSError?) {
        let result: (Data, UInt8, UInt8)?
        do {
            //printLog("[NFC] START [+] \(purpose)...")
            result = try await self.idCard?.sendCommand(apdu: command)
            //printLog("[NFC] END [+] \(purpose)...")
            let output = [UInt8](result!.0)
            let sw1 = result!.1
            let sw2 = result!.2
            return ((output,sw1,sw2),nil)
        }catch let error {
            //printLog("[NFC] [-] Something went wrong in APDU communication: \(error)")
            //self.idCard?.session?.invalidate(errorMessage: "Something went wrong during NFC communication")
            return (nil,error as NSError?)
        }
    }
    
    func decryptEncryptedResponse(encrypted: [UInt8]) -> [UInt8]? {
        var plaintext = [UInt8](repeating: 0, count: encrypted.count)
        var plaintextCount = 0
        
        //Obtain correct IV
        let IV = self.prepareSSC()
        do {
            let aes = try AES(key: self.keyEnc!, blockMode: CryptoSwift.ECB())
            let encIV = try aes.encrypt(IV)
            let err = CCCrypt(
                CCOperation(kCCDecrypt),
                CCAlgorithm(kCCAlgorithmAES),CCOptions(),
                self.keyEnc!, self.keyEnc!.count,
                encIV,
                encrypted, encrypted.count,
                &plaintext, plaintext.count,
                &plaintextCount
            )
            if err == kCCSuccess {
                return plaintext
            }
            else {
                //printLog("[NFC] [-] Error during AES decryption: returning empty")
                //printLog("[NFC] [-] Error during AES decryption: \(err)")
                return nil
            }
        } catch let error {
            //printLog("[NFC] [-] Error during IV prep: \(error)")
            return nil
        }
    }
    
    func obtainPersonalData(encrypted: [UInt8]) -> String? {
        var plaintext = [UInt8](repeating: 0, count: encrypted.count)
        var plaintextCount = 0
        
        //Obtain correct IV
        let IV = self.prepareSSC()
        do {
            let aes = try AES(key: self.keyEnc!, blockMode: CryptoSwift.ECB())
            let encIV = try aes.encrypt(IV)
            let err = CCCrypt(
                CCOperation(kCCDecrypt),
                CCAlgorithm(kCCAlgorithmAES),CCOptions(),
                self.keyEnc!, self.keyEnc!.count,
                encIV,
                encrypted, encrypted.count,
                &plaintext, plaintext.count,
                &plaintextCount
            )
            if err == kCCSuccess {
                //////print("[+] Derive personal data from: \(plaintext.toHexString())")
                for pos in (0...plaintext.count-1).reversed() {
                    if plaintext[pos] == 0x80 {
                        //////print("[+] Parsed plaintext: \(plaintext.prefix(upTo: pos))")
                        let dataBytes = Array(plaintext.prefix(upTo: pos))
                        let dataString = String(bytes: dataBytes, encoding: .utf8)
                        return dataString
                    }
                }
                ////print("[-] could not obtain the last 80 byte...")
                return nil
            }
            else {
                ////print("[-] Error during AES decryption: returning empty")
                ////print("[-] Error during AES decryption: \(err)")
                return nil
            }
        } catch let err {
            ////print("[-] Error during IV prep: \(err)")
            return nil
        }
    }
    
    func readPersonalDataAsync(lastBytes: [UInt8]) async -> [String]? {
        var command = self.createSecureAPDU(encrypted: Comms.IASECCFID, template: Comms.selectFile)
        if command.isEmpty {
            //printLog("[-] Could not create secure APDU, leaving...")
            return nil
        }
        //////print("[+] Selecting IASECCFID...")
        var (response,_) = await getResponse(command: NFCISO7816APDU(data: Data(command))!, purpose: "Selecting IASECCFID")
        if response == nil {
            //printLog("[-] Something went wrong in Selecting IASECCFID")
            return nil
        }
        command = self.createSecureAPDU(encrypted: Comms.personalDF, template: Comms.selectFile)
        if command.isEmpty {
            //printLog("[-] Could not create secure APDU, leaving...")
            return nil
        }
        //////print("[+] Selecting Personal Data File...")
        (response,_) = await getResponse(command: NFCISO7816APDU(data: Data(command))!, purpose: "Selecting Personal Data File")
        if response == nil {
            //printLog("[-] Something went wrong in Selecting Personal Data File")
            return nil
        }
        var personalData: [String] = []
        for pos in 0..<lastBytes.count {
            let data = [UInt8(0x50), lastBytes[pos]]
            command = self.createSecureAPDU(encrypted: data, template: Comms.selectFile)
            if command.isEmpty {
                //printLog("[-] Could not create secure APDU, leaving...")
                return nil
            }
            //////print("[+] Reading personal data 1...")
            (response,_) = await getResponse(command: NFCISO7816APDU(data: Data(command))!, purpose: "Selecting Personal Data")
            if response == nil {
                //printLog("[-] Something went wrong in Selecting Personal Data")
                return nil
            }
            command = self.createSecureAPDU(encrypted: [], template: Comms.readFile)
            if command.isEmpty {
                //printLog("[-] Could not create secure APDU, leaving...")
                return nil
            }
            (response,_) = await getResponse(command: NFCISO7816APDU(data: Data(command))!, purpose: "Reading Personal Data")
            if response == nil {
                //printLog("[-] Something went wrong in Reading Personal Data")
                return nil
            }
            let str = self.obtainPersonalData(encrypted: Array(response![3..<19]))
            if str == nil {
                //printLog("[-] Could not obtain personal data")
                return nil
            }
            personalData.append(str!)
        }
        return personalData
    }
    
    func getAuthCertificate() -> Data {
        func checkStatus(sw1: UInt8, sw2: UInt8) {
            if sw1 != UInt8(0x90) || sw2 != UInt8(0x00) {
                //printLog("[NFC] [-] Got status: \(sw1) \(sw2)")
                self.idCard?.session?.invalidate()
                return
            }
        }
        var authCertificate = Data()
        let dg: DispatchGroup = DispatchGroup()
        dg.enter()
        var command = self.createSecureAPDU(encrypted: Comms.IASECCFID, template: Comms.selectFile)
        if command.isEmpty {
            ////print("[-] Could not create secure APDU, leaving...")
            return authCertificate
        }
        self.idCard?.sendCommand(apdu: NFCISO7816APDU(data: Data(command))!) { response, sw1, sw2, err in
            checkStatus(sw1: sw1, sw2: sw2)
            command = self.createSecureAPDU(encrypted: (Comms.AWP), template: Comms.selectFile)
            if command.isEmpty {
                ////print("[-] Could not create secure APDU, leaving...")
                return
            }
            self.idCard?.sendCommand(apdu: NFCISO7816APDU(data: Data(command))!) { response, sw1, sw2, err in
                checkStatus(sw1: sw1, sw2: sw2)
                command = self.createSecureAPDU(encrypted: (Comms.authCert), template: Comms.selectFile)
                if command.isEmpty {
                    ////print("[-] Could not create secure APDU, leaving...")
                    return
                }
                self.idCard?.sendCommand(apdu: NFCISO7816APDU(data: Data(command))!) { response, sw1, sw2, err in
                    checkStatus(sw1: sw1, sw2: sw2)
                    var certificate: [UInt8] = []
                    var readCert: [UInt8] = [UInt8].init(repeating: 0, count: Comms.readFile.count)
                    var readingFinished = false
                    for pos in 0..<readCert.count {
                        readCert[pos] = Comms.readFile[pos]
                    }
                    for _ in 0..<16 {
                        readCert[2] = UInt8(certificate.count >> 8)
                        readCert[3] = UInt8(certificate.count % 256)
                        command = self.createSecureAPDU(encrypted: [], template: readCert)
                        if command.isEmpty {
                            ////print("[-] Could not create secure APDU, leaving...")
                            return
                        }
                        let dispatchGroup: DispatchGroup = DispatchGroup()
                        dispatchGroup.enter()
                        self.idCard?.sendCommand(apdu: NFCISO7816APDU(data: Data(command))!) { response, sw1, sw2, err in
                            let responseBytes = [UInt8](response)
                            let start: Int = responseBytes[2] == UInt8(0x01) ? 3 : 4
                            let end: Int = start + ((Int(responseBytes[start - 2]) + 256) % 256) - 1
                            let decrypted = self.decryptEncryptedResponse(encrypted: Array(responseBytes[start..<end]))
                            for pos in (0...decrypted!.count-1).reversed() {
                                if decrypted![pos] == 0x80 {
                                    //////print("[+] Parsed plaintext: \(plaintext.prefix(upTo: pos))")
                                    certificate.append(contentsOf: decrypted!.prefix(upTo: pos))
                                    break
                                    //////print("[+] Cert len becomes: \(certificate.count)")
                                }
                            }
                            if sw1 == UInt8(0x90) && sw2 == UInt8(0x00) {
                                readingFinished = true
                            }
                            dispatchGroup.leave()
                        }
                        dispatchGroup.wait()
                        if readingFinished {
                            authCertificate = Data(certificate)
                            dg.leave()
                            break
                        }
                    }
                }
            }
        }
        dg.wait()
        return authCertificate
    }
    
    func getCertificateAsync(isAuthCert: Bool) async -> [UInt8]? {
        var command = self.createSecureAPDU(encrypted: Comms.IASECCFID, template: Comms.selectFile)
        if command.isEmpty {
            ////print("[-] Could not create secure APDU, leaving...")
            return nil
        }
        var (response,_) = await getResponse(command: NFCISO7816APDU(data: Data(command))!, purpose: "Selecting IASECCFID")
        if response == nil {
            ////print("[-] Something went wrong in Selecting IASECCFID")
            return nil
        }
        command = self.createSecureAPDU(encrypted: (isAuthCert ? Comms.AWP : Comms.QSCD), template: Comms.selectFile)
        if command.isEmpty {
            ////print("[-] Could not create secure APDU, leaving...")
            return nil
        }
        (response,_) = await getResponse(command: NFCISO7816APDU(data: Data(command))!, purpose: "Selecting AWP or QSCD")
        if response == nil {
            ////print("[-] Something went wrong in Selecting AWP or QSCD")
            return nil
        }
        command = self.createSecureAPDU(encrypted: (isAuthCert ? Comms.authCert : Comms.signCert), template: Comms.selectFile)
        if command.isEmpty {
            ////print("[-] Could not create secure APDU, leaving...")
            return nil
        }
        (response,_) = await getResponse(command: NFCISO7816APDU(data: Data(command))!, purpose: "Selecting auth or sign certificate")
        if response == nil {
            ////print("[-] Something went wrong in Selecting auth or sign certificate")
            return nil
        }
        var certificate: [UInt8] = []
        var readCert: [UInt8] = [UInt8].init(repeating: 0, count: Comms.readFile.count)
        for pos in 0..<readCert.count {
            readCert[pos] = Comms.readFile[pos]
        }
        for _ in 0..<16 {
            readCert[2] = UInt8(certificate.count >> 8)
            readCert[3] = UInt8(certificate.count % 256)
            command = self.createSecureAPDU(encrypted: [], template: readCert)
            if command.isEmpty {
                ////print("[-] Could not create secure APDU, leaving...")
                return nil
            }
            let (responseWithStatus,_) = await getResponseWithStatus(command: NFCISO7816APDU(data: Data(command))!, purpose: "Reading certificate")
            if responseWithStatus == nil {
                ////print("[-] Something went wrong in Reading certificate...")
                return nil
            }
            let responseBytes = responseWithStatus!.0
            let sw1 = responseWithStatus!.1
            let sw2 = responseWithStatus!.2
            
            let start: Int = responseBytes[2] == UInt8(0x01) ? 3 : 4
            let end: Int = start + ((Int(responseBytes[start - 2]) + 256) % 256) - 1
            let decrypted = self.decryptEncryptedResponse(encrypted: Array(responseBytes[start..<end]))
            for pos in (0...decrypted!.count-1).reversed() {
                if decrypted![pos] == 0x80 {
                    //////print("[+] Parsed plaintext: \(plaintext.prefix(upTo: pos))")
                    certificate.append(contentsOf: decrypted!.prefix(upTo: pos))
                    break
                    //////print("[+] Cert len becomes: \(certificate.count)")
                }
            }
            if sw1 == UInt8(0x90) && sw2 == UInt8(0x00) {
                break
            }
        }
        return certificate
    }
    
    func verifyPIN(PIN: [UInt8], IsPIN2: Bool) async -> NSError? {
        //////print("[+] PIN to be verified: \(PIN)")
        let nfcGeneralError: NSError = NSError.init(domain: "MoppLib", code: Int(MoppLibError.Code.general.rawValue), userInfo: [NSLocalizedDescriptionKey: "NFC command error"])
        
        var command = self.createSecureAPDU(encrypted: Comms.IASECCFID, template: Comms.selectFile)
        if command.isEmpty {
            ////print("[-] Could not create secure APDU, leaving...")
            return nfcGeneralError
        }
        var (response,err) = await getResponse(command: NFCISO7816APDU(data: Data(command))!, purpose: "Selecting IASECCFID")
        if response == nil {
            ////print("[-] Something went wrong in Selecting IASECCFID")
            return err
        }
        if IsPIN2 {
            command = self.createSecureAPDU(encrypted: Comms.QSCD, template: Comms.selectFile)
            if command.isEmpty {
                ////print("[-] Could not create secure APDU, leaving...")
                return nfcGeneralError
            }
            (response,err) = await getResponse(command: NFCISO7816APDU(data: Data(command))!, purpose: "Selecting QSCD")
            if response == nil {
                ////print("[-] Something went wrong in Selecting QSCD")
                return err
            }
        }
        var paddedPIN = [UInt8].init(repeating: 0xff, count: 12)
        for i in 0..<PIN.count {
            paddedPIN[i] = PIN[i]
        }
        command = self.createSecureAPDU(encrypted: paddedPIN, template: (IsPIN2 ? Comms.verifyPIN2 : Comms.verifyPIN1))
        let pinString = IsPIN2 ? "PIN2" : "PIN1"
        if command.isEmpty {
            ////print("[-] Could not create secure APDU, leaving...")
            return nfcGeneralError
        }
        let (responseWithStatus,error) = await getResponseWithStatus(command: NFCISO7816APDU(data: Data(command))!, purpose: "Verifying PIN")
        if responseWithStatus == nil {
            ////print("[-] Something went wrong in Verifying PIN")
            return error
        }
        let sw1 = responseWithStatus!.1
        let sw2 = responseWithStatus!.2
        if sw1 != UInt8(0x90) || sw2 != UInt8(0x00) {
            if sw1 == UInt8(0x69) && sw2 == UInt8(0x83) {
                ////print("[-] PIN blocked")
                let nfcPinBlockedError : NSError = NSError.init(domain: "MoppLib", code: Int(MoppLibError.Code.pinBlocked.rawValue), userInfo: [NSLocalizedDescriptionKey: "\(pinString) blocked"])
                return nfcPinBlockedError
            }
            else if sw1 == UInt8(0x63) && sw2 != UInt8(0x00) {
                let left = sw2 - UInt8(0xc0)
                ////print("[-] Invalid PIN value, attempts left: \(left)")
                let nfcPinWrongError : NSError = NSError.init(domain: "MoppLib", code: Int(MoppLibError.Code.wrongPin.rawValue), userInfo: ["kMoppLibRetryCount": left, NSLocalizedDescriptionKey: "Wrong \(pinString)"])
                return nfcPinWrongError
            } else {
                return nfcGeneralError
            }
        } else {
            ////print("[+] PIN verified")
            return nil
        }
    }
    
    func calculateSignatureSync(PIN: String, signedData: [UInt8], success: @escaping (Data) -> Void, failure: @escaping (NSError) -> Void) {
        
        let PIN2 = Array(PIN.utf8)
        let nfcCommandError: NSError = NSError.init(domain: "MoppLib", code: Int(MoppLibError.Code.general.rawValue), userInfo: [NSLocalizedDescriptionKey: "NFC command error"])
        
        var command = self.createSecureAPDU(encrypted: Comms.IASECCFID, template: Comms.selectFile)
        if command.isEmpty {
            ////print("[-] Could not create secure APDU, leaving...")
            failure(nfcCommandError)
            
            //self.idCard?.session?.invalidate()
            return
        }
        //printLog("[NFC] [+] START calculate signature #1")
        self.idCard?.sendCommand(apdu: NFCISO7816APDU(data: Data(command))!) { response, sw1, sw2, err in
            if let error = err as NSError? {
                failure(error)
                return
            }
            if sw1 != UInt8(0x90) || sw2 != UInt8(0x00) {
                //printLog("[NFC] [-] Got response: \(bytesConvertToHexstring(byte: [UInt8](response)))")
                //printLog("[NFC] [-] Got status: \(sw1) \(sw2)")
                failure(nfcCommandError)
                
                //self.idCard?.session?.invalidate()
                return
            }
            //printLog("[NFC] [+] END calculate signature #1")
            command = self.createSecureAPDU(encrypted: Comms.QSCD, template: Comms.selectFile)
            if command.isEmpty {
                ////print("[-] Could not create secure APDU, leaving...")
                failure(nfcCommandError)
                
                //self.idCard?.session?.invalidate()
                return
            }
            //printLog("[NFC] [+] START calculate signature #2")
            self.idCard?.sendCommand(apdu: NFCISO7816APDU(data: Data(command))!) { response, sw1, sw2, err in
                if let error = err as NSError? {
                    failure(error)
                    return
                }
                if sw1 != UInt8(0x90) || sw2 != UInt8(0x00) {
                    //printLog("[NFC] [-] Got response: \(bytesConvertToHexstring(byte: [UInt8](response)))")
                    //printLog("[NFC] [-] Got status: \(sw1) \(sw2)")
                    failure(nfcCommandError)
                    
                    //self.idCard?.session?.invalidate()
                    return
                }
                //printLog("[NFC] [+] END calculate signature #2")
            }
            var paddedPIN = [UInt8].init(repeating: 0xff, count: 12)
            for i in 0..<PIN2.count {
                paddedPIN[i] = PIN2[i]
            }
            command = self.createSecureAPDU(encrypted: paddedPIN, template: Comms.verifyPIN2)
            if command.isEmpty {
                ////print("[-] Could not create secure APDU, leaving...")
                failure(nfcCommandError)
                
                //self.idCard?.session?.invalidate()
                return
            }
            //printLog("[NFC] [+] START calculate signature #3 verify pin2")
            self.idCard?.sendCommand(apdu: NFCISO7816APDU(data: Data(command))!) { response, sw1, sw2, err in
                if let error = err as NSError? {
                    failure(error)
                    return
                }
                if sw1 != UInt8(0x90) || sw2 != UInt8(0x00) {
                    if sw1 == UInt8(0x69) && sw2 == UInt8(0x83) {
                        ////print("[-] PIN blocked")
                        let nfcPinBlockedError : NSError = NSError.init(domain: "MoppLib", code: Int(MoppLibError.Code.pinBlocked.rawValue), userInfo: [NSLocalizedDescriptionKey: "PIN2 blocked"])
                        failure(nfcPinBlockedError)
                        //self.idCard?.session?.invalidate()
                        return
                    }
                    else if sw1 == UInt8(0x63) && sw2 != UInt8(0x00) {
                        let left = sw2 - UInt8(0xc0)
                        ////print("[-] Wrong PIN2, remaining: \(left)")
                        let nfcPinWrongError : NSError = NSError.init(domain: "MoppLib", code: Int(MoppLibError.Code.wrongPin.rawValue), userInfo: ["kMoppLibRetryCount": left, NSLocalizedDescriptionKey: "Wrong PIN2"])
                        failure(nfcPinWrongError)
                        //self.idCard?.session?.invalidate()
                        return
                    } else {
                        failure(nfcCommandError)
                        return
                    }
                } else {
                    //printLog("[NFC] [+] END calculate signature #3 verify pin2")
                    command = self.createSecureAPDU(encrypted: Comms.DSEnv, template: Comms.DSSetEnv)
                    if command.isEmpty {
                        ////print("[-] Could not create secure APDU, leaving...")
                        failure(nfcCommandError)
                        //self.idCard?.session?.invalidate()
                        return
                    }
                    //printLog("[NFC] [+] START calculate signature #4")
                    self.idCard?.sendCommand(apdu: NFCISO7816APDU(data: Data(command))!) { response, sw1, sw2, err in
                        if let error = err as NSError? {
                            failure(error)
                            return
                        }
                        if sw1 != UInt8(0x90) || sw2 != UInt8(0x00) {
                            //printLog("[NFC] [-] Got response: \(bytesConvertToHexstring(byte: [UInt8](response)))")
                            //printLog("[NFC] [-] Got status: \(sw1) \(sw2)")
                            failure(nfcCommandError)
                            //self.idCard?.session?.invalidate()
                            return
                        }
                        //printLog("[NFC] [+] END calculate signature #4")
                        var digitalSignature = Comms.DigitalSignature
                        digitalSignature[4] = UInt8(0x1d + 16 * (signedData.count >> 4))
                        digitalSignature[6] = UInt8(0x11 + 16 * (signedData.count >> 4))
                        command = self.createSecureAPDU(encrypted: signedData, template: digitalSignature)
                        if command.isEmpty {
                            ////print("[-] Could not create secure APDU, leaving...")
                            failure(nfcCommandError)
                            //self.idCard?.session?.invalidate()
                            return
                        }
                        //printLog("[NFC] [+] START calculate signature #5")
                        self.idCard?.sendCommand(apdu: NFCISO7816APDU(data: Data(command))!) { response, sw1, sw2, err in
                            if let error = err as NSError? {
                                failure(error)
                                return
                            }
                            if sw1 != UInt8(0x90) || sw2 != UInt8(0x00) {
                                //printLog("[NFC] [-] Got response: \(bytesConvertToHexstring(byte: [UInt8](response)))")
                                //printLog("[NFC] [-] Got status: \(sw1) \(sw2)")
                                failure(nfcCommandError)
                                //self.idCard?.session?.invalidate()
                                return
                            }
                            //printLog("[NFC] [+] END calculate signature #5")
                            let decrypted = self.decryptEncryptedResponse(encrypted: Array([UInt8](response)[3..<115]))
                            for pos in (0...decrypted!.count-1).reversed() {
                                if decrypted![pos] == 0x80 {
                                    //////print("[+] Parsed plaintext: \(plaintext.prefix(upTo: pos))")
                                    //printLog("[NFC] [+] signature calculated, invalidating session and calling success function...")
                                    //self.idCard?.session?.alertMessage = "Signing completed"
                                    //self.idCard?.session?.invalidate()
                                    let result = Data(Array(decrypted!.prefix(upTo: pos)))
                                    //printLog("[NFC] [+] signature bytes: \(bytesConvertToHexstring(byte: [UInt8](result)))")
                                    //printLog("[NFC] [+] End Calculate Signature")
                                    success(result)
                                    return
                                }
                            }
                            ////print("[NFC] [-] could not decrypt response")
                            failure(nfcCommandError)
                            //self.idCard?.session?.invalidate()
                            return
                        }
                    }
                }
            }
        }
    }
    
    func calculateSignatureAsync(PIN2: String, signedData: [UInt8]) async throws -> [UInt8]? {
        let nfcGeneralError: NSError = NSError.init(domain: "MoppLib", code: Int(MoppLibError.Code.general.rawValue), userInfo: [NSLocalizedDescriptionKey: "NFC communication got interrupted"])
        let verified = await self.verifyPIN(PIN: Array(PIN2.utf8), IsPIN2: true)
        if verified != nil {
            throw verified!
        }
        var command = self.createSecureAPDU(encrypted: Comms.DSEnv, template: Comms.DSSetEnv)
        if command.isEmpty {
            ////print("[-] Could not create secure APDU, leaving...")
            throw nfcGeneralError
        }
        var (response,error) = await getResponse(command: NFCISO7816APDU(data: Data(command))!, purpose: "Selecting Digital Signature environment")
        if response == nil {
            ////print("[-] Something went wrong in Selecting Digital Signature environment")
            throw error!
        }
        var digitalSignature = Comms.DigitalSignature
        digitalSignature[4] = UInt8(0x1d + 16 * (signedData.count >> 4))
        digitalSignature[6] = UInt8(0x11 + 16 * (signedData.count >> 4))
        command = self.createSecureAPDU(encrypted: signedData, template: digitalSignature)
        if command.isEmpty {
            ////print("[-] Could not create secure APDU, leaving...")
            throw nfcGeneralError
        }
        (response,error) = await getResponse(command: NFCISO7816APDU(data: Data(command))!, purpose: "Calculating digital signature")
        if response == nil {
            ////print("[-] Something went wrong in Calculating digital signature")
            throw error!
        }
        let decrypted = self.decryptEncryptedResponse(encrypted: Array(response![3..<115]))
        for pos in (0...decrypted!.count-1).reversed() {
            if decrypted![pos] == 0x80 {
                ////print("[+] Parsed plaintext: \(plaintext.prefix(upTo: pos))")
                return Array(decrypted!.prefix(upTo: pos))
            }
        }
        throw nfcGeneralError
    }
    
    func unblockAndChangePINCode(pukCode: String, type: MyeIDChangeCodesModel.ActionType, newCode: String) async -> NSError? {
        let nfcCommandError: NSError = NSError.init(domain: "MoppLib", code: Int(MoppLibError.Code.general.rawValue), userInfo: [NSLocalizedDescriptionKey: "NFC command error"])
        //verify PUK
        var command = self.createSecureAPDU(encrypted: Comms.IASECCFID, template: Comms.selectFile)
        if command.isEmpty {
            ////print("[-] Could not create secure APDU, leaving...")
            return nfcCommandError
        }
        var (response,error) = await getResponse(command: NFCISO7816APDU(data: Data(command))!, purpose: "Selecting IASECCFID")
        if response == nil {
            ////print("[-] Something went wrong in Selecting IASECCFID")
            return error
        }
        let PIN = pukCode.bytes
        var paddedPIN = [UInt8].init(repeating: 0xff, count: 12)
        for i in 0..<PIN.count {
            paddedPIN[i] = PIN[i]
        }
        command = self.createSecureAPDU(encrypted: paddedPIN, template: Comms.verifyPUK)
        if command.isEmpty {
            ////print("[-] Could not create secure APDU, leaving...")
            return nfcCommandError
        }
        let (responseWithStatus,err) = await getResponseWithStatus(command: NFCISO7816APDU(data: Data(command))!, purpose: "Verifying PUK")
        if responseWithStatus == nil {
            ////print("[-] Something went wrong in Verifying PIN")
            return err
        }
        let sw1 = responseWithStatus!.1
        let sw2 = responseWithStatus!.2
        if sw1 != UInt8(0x90) || sw2 != UInt8(0x00) {
            if sw1 == UInt8(0x69) && sw2 == UInt8(0x83) {
                ////print("[-] PUK blocked")
                let nfcPinBlockedError : NSError = NSError.init(domain: "MoppLib", code: Int(MoppLibError.Code.pinBlocked.rawValue), userInfo: [NSLocalizedDescriptionKey: "PUK blocked"])
                return nfcPinBlockedError
            }
            else if sw1 == UInt8(0x63) && sw2 != UInt8(0x00) {
                let left = sw2 - UInt8(0xc0)
                ////print("[+] Invalid PUK value, attempts left: \(left)")
                let nfcPinWrongError : NSError = NSError.init(domain: "MoppLib", code: Int(MoppLibError.Code.wrongPin.rawValue), userInfo: ["kMoppLibUserInfoRetryCount": left, NSLocalizedDescriptionKey: "Wrong PUK"])
                return nfcPinWrongError
            } else {
                return nfcCommandError
            }
        } else {
            if type == .unblockPin2 {
                command = self.createSecureAPDU(encrypted: Comms.QSCD, template: Comms.selectFile)
                if command.isEmpty {
                    ////print("[-] Could not create secure APDU, leaving...")
                    return nfcCommandError
                }
                (response,error) = await getResponse(command: NFCISO7816APDU(data: Data(command))!, purpose: "Selecting QSCD")
                if response == nil {
                    ////print("[-] Something went wrong in Selecting QSCD")
                    return error
                }
            }
            let newPIN = newCode.bytes
            var paddedNewPIN = [UInt8].init(repeating: 0xff, count: 12)
            for i in 0..<newPIN.count {
                paddedNewPIN[i] = newPIN[i]
            }
            if type == .unblockPin1 {
                command = self.createSecureAPDU(encrypted: paddedNewPIN, template: Comms.ResetPIN1)
                if command.isEmpty {
                    ////print("[-] Could not create secure APDU, leaving...")
                    return nfcCommandError
                }
                let (responseWithStatus,err2) = await getResponseWithStatus(command: NFCISO7816APDU(data: Data(command))!, purpose: "Unblock and change PIN1")
                if responseWithStatus == nil {
                    ////print("[-] Something went wrong in Verifying PIN")
                    return err2
                }
                let sw1 = responseWithStatus!.1
                let sw2 = responseWithStatus!.2
                if sw1 != UInt8(0x90) || sw2 != UInt8(0x00) {
                    ////print("[-] something went wrong during reset command...")
                    return nfcCommandError
                } else {
                    ////print("[+] PIN unblocked and changed")
                    return nil
                }
            }
            if type == .unblockPin2 {
                command = self.createSecureAPDU(encrypted: paddedNewPIN, template: Comms.ResetPIN2)
                if command.isEmpty {
                    ////print("[-] Could not create secure APDU, leaving...")
                    return nil
                }
                let (responseWithStatus,err3) = await getResponseWithStatus(command: NFCISO7816APDU(data: Data(command))!, purpose: "Unblock and change PIN2")
                if responseWithStatus == nil {
                    ////print("[-] Something went wrong in Verifying PIN")
                    return err3
                }
                let sw1 = responseWithStatus!.1
                let sw2 = responseWithStatus!.2
                if sw1 != UInt8(0x90) || sw2 != UInt8(0x00) {
                    ////print("[-] something went wrong during reset command...")
                    return nfcCommandError
                } else {
                    ////print("[+] PIN unblocked and changed")
                    return nil
                }
            }
            return nfcCommandError
        }
        //switch to QSCD if PIN2
        //pad newCode
        //send resetPIN1 or resetPIN2
    }
    
    func changePINCode(prev: String, curr: String, type: MyeIDChangeCodesModel.ActionType) async -> NSError? {
        let nfcCommandError: NSError = NSError.init(domain: "MoppLib", code: Int(MoppLibError.Code.general.rawValue), userInfo: [NSLocalizedDescriptionKey: "NFC command error"])
        var command = self.createSecureAPDU(encrypted: Comms.IASECCFID, template: Comms.selectFile)
        if command.isEmpty {
            ////print("[-] Could not create secure APDU, leaving...")
            return nfcCommandError
        }
        var (response,error) = await getResponse(command: NFCISO7816APDU(data: Data(command))!, purpose: "Selecting IASECCFID")
        if response == nil {
            ////print("[-] Something went wrong in Selecting IASECCFID")
            return error
        }
        if type == .changePin2 {
            command = self.createSecureAPDU(encrypted: Comms.QSCD, template: Comms.selectFile)
            if command.isEmpty {
                ////print("[-] Could not create secure APDU, leaving...")
                return nfcCommandError
            }
            (response,error) = await getResponse(command: NFCISO7816APDU(data: Data(command))!, purpose: "Selecting QSCD")
            if response == nil {
                ////print("[-] Something went wrong in Selecting QSCD")
                return error
            }
        }
        var paddedOldPIN = [UInt8](repeating: 0xff, count: 12)
        var paddedNewPIN = [UInt8](repeating: 0xff, count: 12)
        let oldBytes = [UInt8](Data(prev.utf8))
        let newBytes = [UInt8](Data(curr.utf8))
        for pos in 0..<oldBytes.count {
            paddedOldPIN[pos] = oldBytes[pos]
        }
        for pos in 0..<newBytes.count {
            paddedNewPIN[pos] = newBytes[pos]
        }
        let input = paddedOldPIN + paddedNewPIN
        var template = Comms.ChangePIN1
        var codeStr = "PIN1"
        if type == .changePin1 {
            template = Comms.ChangePIN1
        }
        if type == .changePin2 {
            template = Comms.ChangePIN2
            codeStr = "PIN2"
        }
        if type == .changePuk {
            template = Comms.ChangePUK
            codeStr = "PUK"
        }
        template[4] = UInt8(0x1d + 16 * (input.count >> 4))
        template[6] = UInt8(0x11 + 16 * (input.count >> 4))
        command = self.createSecureAPDU(encrypted: input, template: template)
        if command.isEmpty {
            ////print("[-] Could not create secure APDU, leaving...")
            return nfcCommandError
        }
        let (responseWithStatus,err) = await getResponseWithStatus(command: NFCISO7816APDU(data: Data(command))!, purpose: "Change \(codeStr)")
        if responseWithStatus == nil {
            ////print("[-] Something went wrong in Verifying PIN")
            return err
        }
        let sw1 = responseWithStatus!.1
        let sw2 = responseWithStatus!.2
        if sw1 != UInt8(0x90) || sw2 != UInt8(0x00) {
            if sw1 == UInt8(0x69) && sw2 == UInt8(0x83) {
                ////print("[-] PIN blocked")
                let nfcPinBlockedError : NSError = NSError.init(domain: "MoppLib", code: Int(MoppLibError.Code.pinBlocked.rawValue), userInfo: [NSLocalizedDescriptionKey: "\(codeStr) blocked"])
                return nfcPinBlockedError
                //return MoppLibError.error(.pinBlocked)
            }
            else {
                let left = sw2 - UInt8(0xc0)
                ////print("[+] Invalid PIN value, attempts left: \(left)")
                let nfcPinWrongError : NSError = NSError.init(domain: "MoppLib", code: Int(MoppLibError.Code.wrongPin.rawValue), userInfo: ["kMoppLibUserInfoRetryCount": left, NSLocalizedDescriptionKey: "Wrong \(codeStr)"])
                return nfcPinWrongError
            }
        } else {
            ////print("[+] \(codeStr) verified")
            return nil
        }
    }
    
    func authenticateAsync(PIN1: String, authData: [UInt8], failure: @escaping (NSError) -> Void) async -> [UInt8]? {
        let nfcGeneralError: NSError = NSError.init(domain: "MoppLib", code: Int(MoppLibError.Code.general.rawValue), userInfo: [NSLocalizedDescriptionKey: "NFC communication got interrupted"])
        let verified = await self.verifyPIN(PIN: Array(PIN1.utf8), IsPIN2: false)
        if verified != nil {
            ////print("[-] pin error during auth: \(verified!)")
            failure(verified!)
            return nil
        }
        var command = self.createSecureAPDU(encrypted: Comms.AWP, template: Comms.selectFile)
        if command.isEmpty {
            ////print("[-] Could not create secure APDU, leaving...")
            failure(nfcGeneralError)
            return nil
        }
        var (response,error) = await getResponse(command: NFCISO7816APDU(data: Data(command))!, purpose: "Selecting AWP")
        if response == nil {
            ////print("[-] Something went wrong in Selecting AWP")
            failure(error!)
            return nil
        }
        
        command = self.createSecureAPDU(encrypted: Comms.Env, template: Comms.MSESetEnv)
        if command.isEmpty {
            ////print("[-] Could not create secure APDU, leaving...")
            failure(nfcGeneralError)
            return nil
        }
        (response,error) = await getResponse(command: NFCISO7816APDU(data: Data(command))!, purpose: "Selecting Authenticate environment")
        if response == nil {
            ////print("[-] Something went wrong in Selecting Digital Signature environment")
            failure(error!)
            return nil
        }
        var digitalSignature = Comms.InternalAuthenticate
        digitalSignature[4] = UInt8(0x1d + 16 * (authData.count >> 4))
        digitalSignature[6] = UInt8(0x11 + 16 * (authData.count >> 4))
        command = self.createSecureAPDU(encrypted: authData, template: digitalSignature)
        if command.isEmpty {
            ////print("[-] Could not create secure APDU, leaving...")
            failure(nfcGeneralError)
            return nil
        }
        (response,error) = await getResponse(command: NFCISO7816APDU(data: Data(command))!, purpose: "Authenticating data")
        if response == nil {
            ////print("[-] Something went wrong in Authenticating data")
            failure(error!)
            return nil
        }
        let decrypted = self.decryptEncryptedResponse(encrypted: Array(response![3..<115]))
        for pos in (0...decrypted!.count-1).reversed() {
            if decrypted![pos] == 0x80 {
                //////print("[+] Parsed plaintext: \(plaintext.prefix(upTo: pos))")
                return Array(decrypted!.prefix(upTo: pos))
            }
        }
        ////print("[-] could not decrypt response")
        failure(nfcGeneralError)
        return nil
    }
    
    func decryptSync(PIN1: String, ecPubKey: [UInt8]) -> Data {
        func checkStatus(sw1: UInt8, sw2: UInt8) -> Bool {
            if sw1 != UInt8(0x90) || sw2 != UInt8(0x00) {
                ////printLog("[NFC] [-] Got status: \(sw1) \(sw2)")
                self.idCard?.session?.invalidate()
                return true
            }
            return false
        }
        var sharedSecret = Data()
        var exception: NSException? = nil
        ////printLog("[NFC] [+] decryptSync calling...")
        let dg: DispatchGroup = DispatchGroup()
        dg.enter()
        //printLog("[NFC] [+] PIN to be verified: \(PIN1)")
        let PIN = Array(PIN1.utf8)
        var command = self.createSecureAPDU(encrypted: Comms.IASECCFID, template: Comms.selectFile)
        if command.isEmpty {
            ////print("[-] Could not create secure APDU, leaving...")
            exception = NSException(name: NSExceptionName("Decryption failed"), reason:"Decryption failed", userInfo:[NSLocalizedDescriptionKey: "Decryption failed"])
            exception?.raise()
            return sharedSecret
        }
        //printLog("[NFC] [+] BEGIN decrypt #1")
        self.idCard?.sendCommand(apdu: NFCISO7816APDU(data: Data(command))!) { response, sw1, sw2, err in
            if (err as NSError?) != nil {
                exception = NSException(name: NSExceptionName("nfc_read_error"), reason:"nfc_read_error", userInfo:[NSLocalizedDescriptionKey: "NFC communication got interrupted"])
                dg.leave()
                //exception?.raise()
                return
            }
            if checkStatus(sw1: sw1, sw2: sw2) {
                exception = NSException(name: NSExceptionName("Decryption failed"), reason:"Decryption failed", userInfo:[NSLocalizedDescriptionKey: "Decryption failed"])
                //exception?.raise()
                dg.leave()
                return
            }
            //printLog("[NFC] [+] END decrypt #1")
            //pin command
            var paddedPIN = [UInt8].init(repeating: 0xff, count: 12)
            for i in 0..<PIN.count {
                paddedPIN[i] = PIN[i]
            }
            command = self.createSecureAPDU(encrypted: paddedPIN, template: Comms.verifyPIN1)
            if command.isEmpty {
                exception = NSException(name: NSExceptionName("Decryption failed"), reason:"Decryption failed", userInfo:[NSLocalizedDescriptionKey: "Decryption failed"])
                dg.leave()
                return
            }
            //send verifypin
            //printLog("[NFC] [+] BEGIN decrypt #2 verify pin1")
            self.idCard?.sendCommand(apdu: NFCISO7816APDU(data: Data(command))!) { response, sw1, sw2, err in
                if (err as NSError?) != nil {
                    exception = NSException(name: NSExceptionName("nfc_read_error"), reason:"nfc_read_error", userInfo:[NSLocalizedDescriptionKey: "NFC communication got interrupted"])
                    dg.leave()
                    //exception?.raise()
                    return
                }
                if sw1 != UInt8(0x90) || sw2 != UInt8(0x00) {
                    if sw1 == UInt8(0x69) && sw2 == UInt8(0x83) {
                        ////print("[+] PIN blocked")
                        exception = NSException(name: NSExceptionName("pin_blocked"), reason:"pin_blocked", userInfo:[NSLocalizedDescriptionKey: "PIN1 blocked"])
                        dg.leave()
                        return
                    }
                    else if sw1 == UInt8(0x63) && sw2 != UInt8(0x00) {
                        let left = sw2 - UInt8(0xc0)
                        ////print("[-] Wrong PIN1 for decryption, attempts left: \(left)")
                        exception = NSException(name: NSExceptionName("wrong_pin \(left)"), reason:"wrong_pin \(left)", userInfo:[NSLocalizedDescriptionKey: "Wrong PIN1"])
                        dg.leave()
                        return
                    } else {
                        exception = NSException(name: NSExceptionName("Decryption failed"), reason:"Decryption failed", userInfo:[NSLocalizedDescriptionKey: "Decryption failed"])
                        dg.leave()
                        return
                    }
                } else {
                    //printLog("[NFC] [+] END decrypt #2 verify pin1")
                    //set AWP environment
                    command = self.createSecureAPDU(encrypted: Comms.AWP, template: Comms.selectFile)
                    if command.isEmpty {
                        ////print("[-] Could not create secure APDU, leaving...")
                        exception = NSException(name: NSExceptionName("Decryption failed"), reason:"Decryption failed", userInfo:[NSLocalizedDescriptionKey: "Decryption failed"])
                        dg.leave()
                        return
                    }
                    //printLog("[NFC] [+] BEGIN decrypt #3")
                    self.idCard?.sendCommand(apdu: NFCISO7816APDU(data: Data(command))!) { response, sw1, sw2, err in
                        if (err as NSError?) != nil {
                            exception = NSException(name: NSExceptionName("nfc_read_error"), reason:"nfc_read_error", userInfo:[NSLocalizedDescriptionKey: "NFC communication got interrupted"])
                            dg.leave()
                            //exception?.raise()
                            return
                        }
                        if checkStatus(sw1: sw1, sw2: sw2) {
                            exception = NSException(name: NSExceptionName("Decryption failed"), reason:"Decryption failed", userInfo:[NSLocalizedDescriptionKey: "Decryption failed"])
                            //exception?.raise()
                            dg.leave()
                            return
                        }
                        //printLog("[NFC] [+] END decrypt #3")
                        //set sec env
                        command = self.createSecureAPDU(encrypted: Comms.DecryptEnv, template: Comms.DecryptSetEnv)
                        if command.isEmpty {
                            ////print("[-] Could not create secure APDU, leaving...")
                            exception = NSException(name: NSExceptionName("Decryption failed"), reason:"Decryption failed", userInfo:[NSLocalizedDescriptionKey: "Decryption failed"])
                            dg.leave()
                            return
                        }
                        //printLog("[NFC] [+] BEGIN decrypt #4")
                        self.idCard?.sendCommand(apdu: NFCISO7816APDU(data: Data(command))!) { response, sw1, sw2, err in
                            if (err as NSError?) != nil {
                                exception = NSException(name: NSExceptionName("nfc_read_error"), reason:"nfc_read_error", userInfo:[NSLocalizedDescriptionKey: "NFC communication got interrupted"])
                                dg.leave()
                                //exception?.raise()
                                return
                            }
                            if checkStatus(sw1: sw1, sw2: sw2) {
                                exception = NSException(name: NSExceptionName("Decryption failed"), reason:"Decryption failed", userInfo:[NSLocalizedDescriptionKey: "Decryption failed"])
                                //exception?.raise()
                                dg.leave()
                                return
                            }
                            //printLog("[NFC] [+] END decrypt #4")
                            
                            let enc = [UInt8(0x00)] + ecPubKey
                            var decrypt = Comms.Decrypt
                            decrypt[4] = UInt8(0x1d + 16 * (enc.count >> 4))
                            decrypt[6] = UInt8(0x11 + 16 * (enc.count >> 4))
                            
                            command = self.createSecureAPDU(encrypted: enc, template: decrypt)
                            if command.isEmpty {
                                ////print("[-] Could not create secure APDU, leaving...")
                                exception = NSException(name: NSExceptionName("Decryption failed"), reason:"Decryption failed", userInfo:[NSLocalizedDescriptionKey: "Decryption failed"])
                                dg.leave()
                                return
                            }
                            
                            //printLog("[NFC] [+] BEGIN decrypt #5")
                            self.idCard?.sendCommand(apdu: NFCISO7816APDU(data: Data(command))!) { response, sw1, sw2, err in
                                if (err as NSError?) != nil {
                                    exception = NSException(name: NSExceptionName("nfc_read_error"), reason:"nfc_read_error", userInfo:[NSLocalizedDescriptionKey: "NFC communication got interrupted"])
                                    dg.leave()
                                    //exception?.raise()
                                    return
                                }
                                if checkStatus(sw1: sw1, sw2: sw2) {
                                    exception = NSException(name: NSExceptionName("Decryption failed"), reason:"Decryption failed", userInfo:[NSLocalizedDescriptionKey: "Decryption failed"])
                                    //exception?.raise()
                                    dg.leave()
                                    return
                                }
                                //printLog("[NFC] [+] END decrypt #5")
                                
                                let decrypted = self.decryptEncryptedResponse(encrypted: Array(response[3..<67]))
                                for pos in (0...decrypted!.count-1).reversed() {
                                    if decrypted![pos] == 0x80 {
                                        //////print("[+] Parsed plaintext: \(plaintext.prefix(upTo: pos))")
                                        sharedSecret = Data(Array(decrypted!.prefix(upTo: pos)))
                                        //printLog("[NFC] [+] End Decrypt")
                                        dg.leave()
                                        break
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        dg.wait()
        if exception == nil {
            return sharedSecret
        } else {
            exception!.raise()
            return sharedSecret
        }
    }
    
    func pinRetryCountsAsync() async -> [Int]? {
        var counts: [Int] = [0,0,0]
        var command = self.createSecureAPDU(encrypted: Comms.IASECCFID, template: Comms.selectFile)
        if command.isEmpty {
            ////print("[-] Could not create secure APDU, leaving...")
            return nil
        }
        var (response,_) = await getResponse(command: NFCISO7816APDU(data: Data(command))!, purpose: "Selecting IASECCFID")
        if response == nil {
            ////print("[-] Something went wrong in Selecting IASECCFID")
            return nil
        }
        command = self.createSecureAPDU(encrypted: [], template: Comms.emptyPIN1)
        if command.isEmpty {
            ////print("[-] Could not create secure APDU, leaving...")
            return nil
        }
        var (responseWithStatus,_) = await getResponseWithStatus(command: NFCISO7816APDU(data: Data(command))!, purpose: "PIN1 retry count")
        if responseWithStatus == nil {
            ////print("[-] Something went wrong in PIN1 retry count")
            return nil
        }
        counts[0] = Int(responseWithStatus!.2 & 0x0f);
        
        command = self.createSecureAPDU(encrypted: [], template: Comms.emptyPUK)
        if command.isEmpty {
            ////print("[-] Could not create secure APDU, leaving...")
            return nil
        }
        (responseWithStatus,_) = await getResponseWithStatus(command: NFCISO7816APDU(data: Data(command))!, purpose: "PUK retry count")
        if responseWithStatus == nil {
            ////print("[-] Something went wrong in PUK retry count")
            return nil
        }
        counts[2] = Int(responseWithStatus!.2 & 0x0f);
        
        command = self.createSecureAPDU(encrypted: Comms.QSCD, template: Comms.selectFile)
        if command.isEmpty {
            ////print("[-] Could not create secure APDU, leaving...")
            return nil
        }
        (response,_) = await getResponse(command: NFCISO7816APDU(data: Data(command))!, purpose: "Selecting QSCD")
        if response == nil {
            ////print("[-] Something went wrong in Selecting QSCD")
            return nil
        }
        
        command = self.createSecureAPDU(encrypted: [], template: Comms.emptyPIN2)
        if command.isEmpty {
            ////print("[-] Could not create secure APDU, leaving...")
            return nil
        }
        (responseWithStatus,_) = await getResponseWithStatus(command: NFCISO7816APDU(data: Data(command))!, purpose: "PIN2 retry count")
        if responseWithStatus == nil {
            ////print("[-] Something went wrong in PIN2 retry count")
            return nil
        }
        counts[1] = Int(responseWithStatus!.2 & 0x0f);
        return counts
    }
    
    /*func decryptAsync(PIN1: String, encryptedData: [UInt8]) async -> [UInt8]? {
        await self.verifyPIN(PIN: Array(PIN1.utf8), IsPIN2: false)
        
        var command = self.createSecureAPDU(encrypted: Comms.AWP, template: Comms.selectFile)
        if command.isEmpty {
            ////print("[-] Could not create secure APDU, leaving...")
            return nil
        }
        var response = await getResponse(command: NFCISO7816APDU(data: Data(command))!, purpose: "Selecting AWP")
        if response == nil {
            ////print("[-] Something went wrong in Selecting AWP")
            return nil
        }
        
        if encryptedData.count <= 128 {
            let enc = [UInt8(0x00)] + encryptedData
            var decrypt = Comms.Decrypt
            decrypt[4] = UInt8(0x1d + 16 * (encryptedData.count >> 4))
            decrypt[6] = UInt8(0x11 + 16 * (encryptedData.count >> 4))
            
            command = self.createSecureAPDU(encrypted: enc, template: decrypt)
            if command.isEmpty {
                ////print("[-] Could not create secure APDU, leaving...")
                return nil
            }
            response = await getResponse(command: NFCISO7816APDU(data: Data(command))!, purpose: "Decrypting data")
            if response == nil {
                ////print("[-] Something went wrong in Decrypting data")
                return nil
            }
            let decrypted = self.decryptEncryptedResponse(encrypted: Array(response![3..<115]))
            for pos in (0...decrypted!.count-1).reversed() {
                if decrypted![pos] == 0x80 {
                    //////print("[+] Parsed plaintext: \(plaintext.prefix(upTo: pos))")
                    return Array(decrypted!.prefix(upTo: pos))
                }
            }
        }
        ////print("[-] not supporting bigger than 128 bytes for now")
        return nil
    }*/
    
    func performPACEAsync() async -> NSError? {
        let can = Array(self.CAN.utf8)
        let nfcGeneralError: NSError = NSError.init(domain: "MoppLib", code: Int(MoppLibError.Code.general.rawValue), userInfo: [NSLocalizedDescriptionKey: "NFC communication got interrupted"])
        
        var (response,error) = await getResponse(command: NFCISO7816APDU(data: Data(Comms.selectMaster))!, purpose: "Selecting Master")
        if response == nil {
            //printLog("[NFC] [-] Something went wrong in Selecting Master")
            ////print("[NFC] [-] Something went wrong in Selecting Master")
            //self.idCard?.session?.invalidate(errorMessage: "Could not establish a secure environment with your card")
            return error
        }
        (response,error) = await getResponse(command: NFCISO7816APDU(data: Data(Comms.MSESetAT))!, purpose: "Selecting Security Parameters")
        if response == nil {
            //printLog("[NFC] [-] Something went wrong in Selecting Security Parameters")
            ////print("[NFC] [-] Something went wrong in Selecting Security Parameters")
            //self.idCard?.session?.invalidate(errorMessage: "Could not establish a secure environment with your card")
            return error
        }
        (response,error) = await getResponse(command: NFCISO7816APDU(data: Data(Comms.GAGetNonce))!, purpose: "Getting Encrypted Nonce Value")
        if response == nil {
            //printLog("[NFC] [-] Something went wrong in Getting Encrypted Nonce Value")
            ////print("[NFC] [-] Something went wrong in Getting Encrypted Nonce Value")
            //self.idCard?.session?.invalidate(errorMessage: "Could not establish a secure environment with your card")
            return error
        }
        let decryptedNonce = self.decryptNonce(input: Array(response!.suffix(from: 4)), CAN: can)
        let domain = Domain.instance(curve: .EC256r1)
        let (publicKey,privateKey) = domain.makeKeyPair()
        let pubKeyBytes: [UInt8]
        do {
            pubKeyBytes = try domain.encodePoint(publicKey.w)
            //printLog("[NFC] [+] Got pubkey bytes: \(bytesConvertToHexstring(byte:pubKeyBytes))")
            let commandBytes = [0x10, 0x86, 0x00, 0x00, 0x45, 0x7C, 0x43, 0x81, 0x41] + pubKeyBytes + [0x00]
            //printLog("[NFC] [+] Got APDU command: \(bytesConvertToHexstring(byte:commandBytes))")
            (response,error) = await getResponse(command: NFCISO7816APDU(data: Data(commandBytes))!, purpose: "Sending public key to card")
            if response == nil {
                //printLog("[NFC] [-] Something went wrong in Sending public key to card")
                ////print("[NFC] [-] Something went wrong in Sending public key to card")
                //self.idCard?.session?.invalidate(errorMessage: "Could not establish a secure environment with your card")
                return error
            }
            let cardPubKey: Point
            let sharedPoint: Point
            let mappedECBasePoint: Point
            do {
                cardPubKey = try domain.decodePoint(Array(response!.suffix(from: 4)))
                sharedPoint = try domain.multiplyPoint(cardPubKey, privateKey.s)
                mappedECBasePoint = try domain.addPoints(domain.multiplyPoint(domain.g, BigInt.BInt(magnitude: decryptedNonce)), sharedPoint)
                let privKey = (domain.order - BInt.ONE).randomLessThan() + BInt.ONE
                let pubPoint = try domain.multiplyPoint(mappedECBasePoint, privKey)
                
                let newPubKeyBytes = try domain.encodePoint(pubPoint)
                //printLog("[NFC] [+] Got pubkey bytes: \(bytesConvertToHexstring(byte: newPubKeyBytes))")
                let commandBytes = [0x10, 0x86, 0x00, 0x00, 0x45, 0x7C, 0x43, 0x83, 0x41] + newPubKeyBytes + [0x00]
                //printLog("[NFC] [+] Got APDU command: \(bytesConvertToHexstring(byte: commandBytes))")
                (response,error) = await getResponse(command: NFCISO7816APDU(data: Data(commandBytes))!, purpose: "Sending agreed point to card")
                if response == nil {
                    //printLog("[NFC] [-] Something went wrong in Sending agreed point to card")
                    ////print("[NFC] [-] Something went wrong in Sending agreed point to card")
                    //self.idCard?.session?.invalidate(errorMessage: "Could not establish a secure environment with your card")
                    return error
                }
                do {
                    let fromCardPubKey = try domain.decodePoint(Array(response!.suffix(from: 4)))
                    let secret = try BInt.asMagnitudeBytes(domain.multiplyPoint(fromCardPubKey, privKey).x)()
                    //printLog("[NFC] [+] secret byte length: \(secret.count)")
                    
                    let kEnc = [UInt8] (secret) + [0x00,0x00,0x00,0x01]
                    let kEncHash = SHA256.hash(data: kEnc)
                    
                    let kMac = [UInt8] (secret) + [0x00,0x00,0x00,0x02]
                    let kMacHash = SHA256.hash(data: kMac)
                    
                    let apduBytes = Comms.dataForMACIncomplete + (try domain.encodePoint(fromCardPubKey))
                    let cmacBytes = try CMAC.init(key: kMacHash.bytes).authenticate(apduBytes)
                    let cmacBytesTrimmed = cmacBytes.prefix(upTo: 8)
                    let commandBytes = Comms.GAMutualAuthenticationIncomplete + cmacBytesTrimmed + [0x00]
                    let (responseWS,er) = await getResponseWithStatus(command: NFCISO7816APDU(data: Data(commandBytes))!, purpose: "Completing mutual authentication with card")
                    if responseWS == nil {
                        //printLog("[NFC] [-] Something went wrong in Completing mutual authentication with card, communication error")
                        ////print("[NFC] [-] Something went wrong in Completing mutual authentication with card, communication error")
                        //self.idCard?.session?.invalidate(errorMessage: "Could not establish a secure environment with your card")
                        return er
                    }
                    let (sw1,sw2) = (responseWS!.1,responseWS!.2)
                    if sw1 != UInt8(0x90) || sw2 != UInt8(0x00) {
                        if sw1 == UInt8(0x63) && sw2 == UInt8(0x00) {
                            //printLog("[NFC] [-] Something went wrong in Completing mutual authentication with card, wrong can")
                            ////print("[NFC] [-] Something went wrong in Completing mutual authentication with card, wrong can")
                            let nfcCANError: NSError = NSError.init(domain: "MoppLib", code: Int(MoppLibError.Code.general.rawValue), userInfo: [NSLocalizedDescriptionKey: "Wrong CAN"])
                            return nfcCANError
                        }
                        //printLog("[NFC] [-] Something went wrong in Completing mutual authentication with card, different error than wrong can")
                        ////print("[NFC] [-] Something went wrong in Completing mutual authentication with card, different error than wrong can")
                        return nfcGeneralError
                    }
                    do {
                        let apduBytes = Comms.dataForMACIncomplete + newPubKeyBytes
                        let cmacBytes = try CMAC.init(key: kMacHash.bytes).authenticate(apduBytes).prefix(upTo: 8)
                        let r = responseWS!.0.suffix(from: 4)
                        if cmacBytes.elementsEqual(r) {
                            //printLog("[NFC] [+] MAC established, returning keys...")
                            //After PACE is established, read personal data using Secure APDU
                            self.keyEnc = kEncHash.bytes
                            self.keyMac = kMacHash.bytes
                            return nil
                            //self.idCard?.session?.invalidate()
                        } else {
                            //printLog("[NFC] [-] MAC failed, check the code...")
                            //self.idCard?.session?.invalidate(errorMessage: "Could not establish a secure environment with your card")
                            return nfcGeneralError
                        }
                    }catch {
                        //printLog("[NFC] [-] Error during point operations")
                        ////print("[NFC] [-] Error during point operations")
                        //self.idCard?.session?.invalidate(errorMessage: "Could not establish a secure environment with your card")
                        return nfcGeneralError
                    }
                }
            }
        } catch {
            //printLog("[NFC] [-] Error during EC key operations...")
            ////print("[NFC] [-] Error during EC key operations...")
            //self.idCard?.session?.invalidate(errorMessage: "Could not establish a secure environment with your card")
            return nfcGeneralError
        }
    }
    
    func performPACE(can: [UInt8]) {
        func createAPDU(template: [UInt8], data: [UInt8]) -> [UInt8] {
            return template+data
        }
        ////print("[+] Selecting Master...")
        self.idCard?.sendCommand(apdu: NFCISO7816APDU(data: Data(Comms.selectMaster))!, completionHandler: { response, sw1, sw2, error in
            guard error == nil else {
                ////print("[-] Error during APDU communication")
                ////print("[-] Error: \(error.debugDescription)")
                self.idCard?.session?.invalidate()
                return
            }
            if sw1 != UInt8(0x90) || sw2 != UInt8(0x00) {
                ////print("[-] Got response: \(bytesConvertToHexstring(byte: [UInt8](response)))")
                ////print("[-] Got status: \(sw1) \(sw2)")
                self.idCard?.session?.invalidate()
                return
            }
            let output = [UInt8](response)
            ////print("[+] Got response: \(bytesConvertToHexstring(byte: output))")
            ////print("[+] Got status: \(sw1) \(sw2)")
            ////print("[+] Selecting Security Parameters...")
            self.idCard?.sendCommand(apdu: NFCISO7816APDU(data: Data(Comms.MSESetAT))!, completionHandler: { response, sw1, sw2, error in
                guard error == nil else {
                    ////print("[-] Error during APDU communication")
                    ////print("[-] Error: \(error.debugDescription)")
                    self.idCard?.session?.invalidate()
                    return
                }
                if sw1 != UInt8(0x90) || sw2 != UInt8(0x00) {
                    ////print("[-] Got response: \(bytesConvertToHexstring(byte: [UInt8](response)))")
                    ////print("[-] Got status: \(sw1) \(sw2)")
                    self.idCard?.session?.invalidate()
                    return
                }
                let output = [UInt8](response)
                ////print("[+] Got response: \(bytesConvertToHexstring(byte: output))")
                ////print("[+] Got status: \(sw1) \(sw2)")
                ////print("[+] Obtain encrypted nonce from card...")
                self.idCard?.sendCommand(apdu: NFCISO7816APDU(data: Data(Comms.GAGetNonce))!, completionHandler: { response, sw1, sw2, error in
                    guard error == nil else {
                        ////print("[-] Error during APDU communication")
                        ////print("[-] Error: \(error.debugDescription)")
                        self.idCard?.session?.invalidate()
                        return
                    }
                    if sw1 != UInt8(0x90) || sw2 != UInt8(0x00) {
                        ////print("[-] Got response: \(bytesConvertToHexstring(byte: [UInt8](response)))")
                        ////print("[-] Got status: \(sw1) \(sw2)")
                        self.idCard?.session?.invalidate()
                        return
                    }
                    let output = [UInt8](response)
                    ////print("[+] Got response: \(bytesConvertToHexstring(byte: output))")
                    ////print("[+] Got status: \(sw1) \(sw2)")
                    //continue from here, decryptNonce implement, also use extra functions not to repeat some lines
                    let decryptedNonce = self.decryptNonce(input: Array(output.suffix(from: 4)), CAN: can)
                    if decryptedNonce.isEmpty {
                        ////print("[-] Terminating...")
                        self.idCard?.session?.invalidate()
                        return
                    }
                    let domain = Domain.instance(curve: .EC256r1)
                    let (publicKey,privateKey) = domain.makeKeyPair()
                    //let apduInput = createAPDU(template: Comms.GAMapNonceIncomplete, data: [UInt8] (publicKey.rawRepresentation))
                
                    //////print("[+] EC public key: \(publicKey.der)")
                    //////print("[+] Got APDU to send: \(bytesConvertToHexstring(byte: apduInput))")
                    let pubKeyBytes: [UInt8]
                    do {
                        pubKeyBytes = try domain.encodePoint(publicKey.w)
                        ////print("[+] Got pubkey bytes: \(bytesConvertToHexstring(byte:pubKeyBytes))")
                        let commandBytes = [0x10, 0x86, 0x00, 0x00, 0x45, 0x7C, 0x43, 0x81, 0x41] + pubKeyBytes + [0x00]
                        ////print("[+] Got APDU command: \(bytesConvertToHexstring(byte:commandBytes))")
                        ////print("[+] Sending public key to card...")
                        self.idCard?.sendCommand(apdu: NFCISO7816APDU(data: Data(commandBytes))!, completionHandler: { response, sw1, sw2, error in
                            guard error == nil else {
                                ////print("[-] Error during APDU communication")
                                ////print("[-] Error: \(error.debugDescription)")
                                self.idCard?.session?.invalidate()
                                return
                            }
                            if sw1 != UInt8(0x90) || sw2 != UInt8(0x00) {
                                ////print("[-] Got response: \(bytesConvertToHexstring(byte: [UInt8](response)))")
                                ////print("[-] Got status: \(sw1) \(sw2)")
                                self.idCard?.session?.invalidate()
                                return
                            }
                            let output = [UInt8](response)
                            ////print("[+] Got response: \(bytesConvertToHexstring(byte: output))")
                            ////print("[+] Got status: \(sw1) \(sw2)")
                            //continue from here, decryptNonce implement, also use extra functions not to repeat some lines
                            let cardPubKey: Point
                            let sharedPoint: Point
                            let mappedECBasePoint: Point
                            do {
                                cardPubKey = try domain.decodePoint(Array(output.suffix(from: 4)))
                                sharedPoint = try domain.multiplyPoint(cardPubKey, privateKey.s)
                                //let nonceData = Data(bytes: decryptedNonce)
                                //let nonceValue = UInt8(bigEndian: nonceData.withUnsafeBytes {$0.pointee})
                                mappedECBasePoint = try domain.addPoints(domain.multiplyPoint(domain.g, BigInt.BInt(magnitude: decryptedNonce)), sharedPoint)
                                let privKey = (domain.order - BInt.ONE).randomLessThan() + BInt.ONE
                                let pubPoint = try domain.multiplyPoint(mappedECBasePoint, privKey)
                                
                                let newPubKeyBytes = try domain.encodePoint(pubPoint)
                                ////print("[+] Got pubkey bytes: \(bytesConvertToHexstring(byte: newPubKeyBytes))")
                                let commandBytes = [0x10, 0x86, 0x00, 0x00, 0x45, 0x7C, 0x43, 0x83, 0x41] + newPubKeyBytes + [0x00]
                                ////print("[+] Got APDU command: \(bytesConvertToHexstring(byte: commandBytes))")
                                ////print("[+] Sending agreed point to card...")
                                self.idCard?.sendCommand(apdu: NFCISO7816APDU(data: Data(commandBytes))!, completionHandler: { response, sw1, sw2, error in
                                    guard error == nil else {
                                        ////print("[-] Error during APDU communication")
                                        ////print("[-] Error: \(error.debugDescription)")
                                        self.idCard?.session?.invalidate()
                                        return
                                    }
                                    if sw1 != UInt8(0x90) || sw2 != UInt8(0x00) {
                                        ////print("[-] Got response: \(bytesConvertToHexstring(byte: [UInt8](response)))")
                                        ////print("[-] Got status: \(sw1) \(sw2)")
                                        self.idCard?.session?.invalidate()
                                        return
                                    }
                                    let output = [UInt8](response)
                                    ////print("[+] Got response: \(bytesConvertToHexstring(byte: output))")
                                    ////print("[+] Got status: \(sw1) \(sw2)")
                                    
                                    do {
                                        let fromCardPubKey = try domain.decodePoint(Array(output.suffix(from: 4)))
                                        let secret = try BInt.asMagnitudeBytes(domain.multiplyPoint(fromCardPubKey, privKey).x)()
                                        
                                        let kEnc = [UInt8] (secret) + [0x00,0x00,0x00,0x01]
                                        let kEncHash = SHA256.hash(data: kEnc)
                                        
                                        let kMac = [UInt8] (secret) + [0x00,0x00,0x00,0x02]
                                        let kMacHash = SHA256.hash(data: kMac)
                                        
                                        let apduBytes = Comms.dataForMACIncomplete + (try domain.encodePoint(fromCardPubKey))
                                        let cmacBytes = try CMAC.init(key: kMacHash.bytes).authenticate(apduBytes)
                                        let cmacBytesTrimmed = cmacBytes.prefix(upTo: 8)
                                        let commandBytes = Comms.GAMutualAuthenticationIncomplete + cmacBytesTrimmed + [0x00]
                                        ////print("[+] Sending Authenticate to conclude PACE...")
                                        self.idCard?.sendCommand(apdu: NFCISO7816APDU(data: Data(commandBytes))!, completionHandler: { response, sw1, sw2, error in
                                            guard error == nil else {
                                                ////print("[-] Error during APDU communication")
                                                ////print("[-] Error: \(error.debugDescription)")
                                                self.idCard?.session?.invalidate()
                                                return
                                            }
                                            if sw1 != UInt8(0x90) || sw2 != UInt8(0x00) {
                                                ////print("[-] Got response: \(bytesConvertToHexstring(byte: [UInt8](response)))")
                                                ////print("[-] Got status: \(sw1) \(sw2)")
                                                self.idCard?.session?.invalidate()
                                                return
                                            }
                                            let output = [UInt8](response)
                                            ////print("[+] Got response: \(bytesConvertToHexstring(byte: output))")
                                            ////print("[+] Got status: \(sw1) \(sw2)")
                                            
                                            do {
                                                let apduBytes = Comms.dataForMACIncomplete + newPubKeyBytes
                                                let cmacBytes = try CMAC.init(key: kMacHash.bytes).authenticate(apduBytes).prefix(upTo: 8)
                                                let response = output.suffix(from: 4)
                                                if cmacBytes.elementsEqual(response) {
                                                    ////print("[+] MAC established, returning keys...")
                                                    //After PACE is established, read personal data using Secure APDU
                                                    self.keyEnc = kEncHash.bytes
                                                    self.keyMac = kMacHash.bytes
                                                    
                                                    //self.readPersonalData()
                                                    
                                                    //self.idCard?.session?.invalidate()
                                                } else {
                                                    ////print("[-] MAC failed, check the code...")
                                                    self.idCard?.session?.invalidate()
                                                }
                                            }catch {
                                                ////print("[-] Error during point operations")
                                                self.idCard?.session?.invalidate()
                                            }
                                        })
                                        
                                    }catch {
                                        ////print("[-] Error during point operations")
                                        self.idCard?.session?.invalidate()
                                    }
                                })
                            }
                            catch {
                                ////print("[-] Error during point operations")
                                self.idCard?.session?.invalidate()
                            }
                        })
                    } catch {
                        ////print("[-] Could not convert public key bytes...")
                        self.idCard?.session?.invalidate()
                    }
                    //Try the other constructor for APDU: set each field by hand => cla:10 ins:86 p1:00 p2:00 Lc:45 Data:7C 43 81 41 <uncompressed EC public key> Le:00
                    //let command = NFCISO7816APDU.init(instructionClass: 10, instructionCode: 86, p1Parameter: 00, p2Parameter: 00, data: Data([0x7C, 0x43, 0x81, 0x41, 0x04]+publicKey.rawRepresentation), expectedResponseLength: -1)
                })
            })
        })
    }
}
