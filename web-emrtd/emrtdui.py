#!/usr/bin/python3

import sys, json, time, argparse, logging, base64, os, io, re
from PIL import Image

#fixing logo path issue in ubuntu (windows can deal with './' filename format)
abspath = os.path.abspath(__file__)
dname = os.path.dirname(abspath)
os.chdir(dname)

sys.path.append('../verification-lib')
import web_emrtd_verify as wemrtd_verify

from PyQt5.QtWidgets import QApplication, QDialog, QDesktopWidget, QFileDialog
from PyQt5.QtCore import QThread, pyqtSignal, QSize, QObject, pyqtSlot, QTimer
from PyQt5.QtGui import QPixmap, QImage, QIcon
from emrtddialog import Ui_WebEidDialog
import messaging
import web_emrtd_util as emrtdutil
import web_emrtd as weid
from json2html import json2html

from smartcard.CardConnection import CardConnection
from smartcard.ExclusiveTransmitCardConnection import ExclusiveTransmitCardConnection
#(Windows) produces Failed to connect with SCARD_SHARE_EXCLUSIVE The smart card cannot be accessed because of other connections outstanding.
from smartcard.ExclusiveConnectCardConnection import ExclusiveConnectCardConnection
from smartcard.CardConnectionObserver import CardConnectionObserver
from smartcard.util import toHexString
from smartcard.System import readers
from smartcard.ReaderMonitoring import ReaderMonitor, ReaderObserver
from smartcard.CardType import CardType
from smartcard.CardRequest import CardRequest
from smartcard.Exceptions import CardRequestTimeoutException
from loggerwindow import LogWindow

'''llogger = logging.getLogger(__name__)
file_handler = logging.FileHandler("emrtdui.log")
llogger.setLevel(logging.DEBUG)
file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] [%(thread)d %(threadName)s] %(message)s")
file_handler.setFormatter(formatter)
llogger.addHandler(file_handler)
llogger.debug("== Logging emrtdui.py ==")
'''

# parse arguments
parser = argparse.ArgumentParser(description='eMRTD native application')
parser.add_argument('--bac-mrz', required=False, type=str, help='Use BAC with the specified MRZ (for testing purposes only)')
parser.add_argument('--force-esteid-can', action='store_true', help='Ask CAN input even when Estonian eID over contact interface used')
parser.add_argument('--debug', action='store_true', help='Option to run native app in the standalone mode (a mock request is signed)')
parser.add_argument('--viewer', action='store_true', help='Option to run native app in the standalone mode (viewer and verifier .emrtd documents)')
args = parser.parse_args()

'''#Since disconnect is not called while app is running because of channel.lock, hiding THIS for now
class UICardConnectionObserver(CardConnectionObserver):

    def __init__(self, uisignal):
        self.uisignal = uisignal

    def update(self,cardconnection,ccevent):
        #card ATR must match to target electronic id cards
        #if 'connect'==ccevent.type:
        #    loggerWindow.logger.debug('connecting to %s',cardconnection.getReader())
        #    self.uisignal.emit({'status':'CARD_INSERTED'})

        if 'disconnect'==ccevent.type:
            loggerWindow.logger.debug("[-] card disconnected")
            llogger.debug("[+] unsupported card disconnected")
            self.uisignal.emit({'status':'CARD_REMOVED'})
'''

class SupportedReaderObserver(ReaderObserver):
    """A simple reader observer that is notified
    when readers are added/removed from the system and
    prints the list of readers
    """
    
    def __init__(self, uisignal):
        self.uisignal = uisignal
    
    def update(self, observable, actions):
        (addedreaders, removedreaders) = actions
        #When a card inserted to built-in reader, 'Windows Hello for Business 1' disappears, so we ignore this.
        openReaders = [reader.__str__() for reader in addedreaders if reader.__str__() != 'Windows Hello for Business 1']
        if len(openReaders):
            self.uisignal.emit({'status':'READER_CONNECTED'})
        else:
            self.uisignal.emit({'status':'READER_REMOVED'})

class SupportedCardType(CardType):
    def __init__(self, uisignal):
        self.uisignal = uisignal
    def matches(self, atr, reader):
        loggerWindow.logger.debug("[Worker thread] [?] verifying reader is supported: %s",reader)
        if (reader.__str__() != 'Windows Hello for Business 1'):
            if self.uisignal:
                self.uisignal.emit({'status':'READER_CONNECTED'})
            return True
        else:
            return False

#later: add other codes and messages here
ERROR_JSON = lambda code, msg: {"error": {"code": code, "message": msg}}
        

class MyWorker(QThread):
    started2 = pyqtSignal(dict,str)
    caReady = pyqtSignal(bytes)
    inserted = pyqtSignal(dict) #card inserted
    logger = pyqtSignal(str) #to logger
    stopCAtimer = pyqtSignal()
    
    def __init__(self, receivedMessage):
        super().__init__()
        self.receivedMessage = receivedMessage
        self.waitForCA = False

    def run(self):
        global CAN_INPUT, MRZ_INPUT, paceSupported
        self.logger.emit("[Worker thread] [+] worker started")
        # Your function logic goes here (find reader and card until timeout)
        if self.waitForCA:
            self.receivedMessage = messaging.getMessage()
            self.receivedMessage['arguments']['DG14'] = self.DG14
            self.receivedMessage['arguments']['SOD'] = self.SOD
        if self.receivedMessage['command'] == 'authenticate_ca' and len(self.receivedMessage['arguments']):
            self.stopCAtimer.emit()
            #authenticate CA token processing (assuming card is connected to the reader after emrtd token is sent to the web app)
            #last two parameters are same from emrtd token request
            
            #check channel is disconnected?
            channelSecure = True
            try:
                self.logger.emit("[Worker thread] [+] checking whether channel is connected...")
                self.CHANNEL.getATR()
                self.logger.emit("[Worker thread] [+] channel is connected, continue...")
            except:
                #channel not available, get new channel (what UI window should be?)
                channelSecure = False
                self.logger.emit("[Worker thread] [+] channel is disconnected, get a new channel")
                channel = CardRequest(timeout=None, cardType=SupportedCardType(None)).waitforcard().connection
                self.CHANNEL = ExclusiveTransmitCardConnection(channel)
                protocol = CardConnection.T1_protocol
                self.CHANNEL.connect(protocol) # use only protocol
                self.CHANNEL.lock()
                #calling again this deals with '6D 00' error
                weid.cardSupport(self.CHANNEL)
            self.logger.emit('[Worker thread] [+] card inserted, continue CA')
            self.logger.emit('[Worker thread] [+] running CA request')
            self.inserted.emit({'status':'CA_REQUEST'})
            try:
                self.logger.emit('[Worker thread] [+] channel is secure: %s' % channelSecure)
                emrtdCA = weid.getEMRTDCAToken(self.receivedMessage['arguments'], self.CHANNEL, MRZ_INPUT, CAN_INPUT, channelSecure=channelSecure)
                self.logger.emit('[Worker thread] [+] CA response calculated')
                self.caReady.emit(json.dumps(emrtdCA, separators=(',', ':')).encode('utf-8'))
                self.logger.emit('[Worker thread] [+] CA response sent for the extension')
            except Exception as err:
                self.CHANNEL.unlock()
                self.CHANNEL.disconnect()
                self.logger.emit("[Worker thread] [-] Fatal Error: %s" % err)
                self.inserted.emit(ERROR_JSON("ERR_WEBEID_NATIVE_FATAL",err.__str__()))
            return
        if self.receivedMessage['command'] == 'authenticate' and len(self.receivedMessage['arguments']):
            weid.setLogEmitter(self.logger)
            self.logger.emit("[Worker thread] [+] getting emrtd token with arguments: %s" % self.receivedMessage['arguments'])
            try:
                self.logger.emit("[Worker thread] [+] Discovering smart card reader and emrtd document...")
                readermonitor = ReaderMonitor()
                readerobserver = SupportedReaderObserver(self.inserted)
                readermonitor.addObserver(readerobserver)
                
                
                channel = CardRequest(timeout=None, cardType=SupportedCardType(self.inserted)).waitforcard().connection           
                self.CHANNEL = ExclusiveTransmitCardConnection(channel)
                protocol = CardConnection.T1_protocol
                self.CHANNEL.connect(protocol) # use only protocol
                self.CHANNEL.lock()
                self.logger.emit("[Worker thread] [+] locked card connection, should not be interrupted by other processes")
                
                #assuming reader is not removed during operation
                readermonitor.deleteObserver(readerobserver)
                
                #self.inserted.emit({'status':'CARD_INSERTED'})
                #channel.connect(protocol, disposition=scard.SCARD_UNPOWER_CARD) # (Power down on close.)
                #channel.disconnect()
                #channel.connect(protocol, disposition=scard.SCARD_RESET_CARD) # (Reset on close.)

                esteid_contact = False
                atr = self.CHANNEL.getATR()
                if atr == [0x3B,0xDB,0x96,0x00,0x80,0xB1,0xFE,0x45,0x1F,0x83,0x00,0x12,0x23,0x3F,0x53,0x65,0x49,0x44,0x0F,0x90,0x00,0xF1]:
                    self.logger.emit("[Worker thread] [+] Estonian ID card (2018)")
                    if not args.force_esteid_can:
                        esteid_contact = True # we don't need CAN entry in this case as we can use MRZ for PACE
                elif atr == [0x3B,0x8B,0x80,0x01,0x00,0x12,0x23,0x3F,0x53,0x65,0x49,0x44,0x0F,0x90,0x00,0xA0]:
                    self.logger.emit("[Worker thread] [+] Estonian ID card (2018) NFC")

                if args.bac_mrz:
                    self.inserted.emit({'status':'CARD_INSERTED'})
                    emrtd = weid.getEMRTDToken(self.receivedMessage['arguments'], self.CHANNEL, args.bac_mrz, None, False)
                    self.logger.emit("[Worker thread] [+] emitting eMRTD token")
                    self.started2.emit(emrtd,self.receivedMessage['arguments']['origin'])
                    self.logger.emit("[Worker thread] [+] emitted token")
                else: # PACE
                    # check if card supports PACE
                    self.logger.emit("[Worker thread] [+] checking PACE support for the card")
                    cardStatus = weid.cardSupport(self.CHANNEL)
                    
                    # do not ask for CAN input if esteid_contact==True
                    if esteid_contact and cardStatus == {'status':'ENTER_CAN'}:
                        self.inserted.emit({'status':'CARD_INSERTED'})
                    elif cardStatus == {'status':'UNSUPPORTED_CARD'}:
                        self.inserted.emit(cardStatus)
                        return
                    else:
                        self.inserted.emit(cardStatus)
                    
                    while True:
                        if (CAN_INPUT == '') and (MRZ_INPUT == '') and not esteid_contact:
                            continue
                        
                        cardConnected = False
                        try:
                            self.CHANNEL.getATR()
                            self.inserted.emit({'status':'CARD_INSERTED'})
                            cardConnected = True
                            self.logger.emit("[Worker thread] [+] obtaining eMRTD token")
                            emrtd = weid.getEMRTDToken(self.receivedMessage['arguments'], self.CHANNEL, MRZ_INPUT, CAN_INPUT, esteid_contact, force_pace=paceSupported)
                            self.DG14 = emrtd['EF_DG14']
                            self.SOD = emrtd['EF_SOD']
                            self.logger.emit("[Worker thread] [+] emitting eMRTD token")
                            self.started2.emit(emrtd,self.receivedMessage['arguments']['origin'])
                            self.logger.emit("[Worker thread] [+] emitted token")
                            return
                        except Exception as err:
                            self.logger.emit("[Worker thread] [-] error: %s" % err.__str__())
                            #later: similar condition should exist for MRZ_INPUT BAC/PACE
                            if "Incorrect CAN" == err.__str__():
                                CAN_INPUT = ''
                                self.inserted.emit({'status':'INCORRECT_CAN'})
                            else:
                                #self.CHANNEL.unlock()
                                self.logger.emit("[Worker thread] [-] other error than incorrect CAN")
                                raise err

                    self.inserted.emit(ERROR_JSON("ERR_WEBEID_NATIVE_INVALID_ARGUMENT",'Invalid method: use PACE or BAC'))
            except Exception as err:
                self.logger.emit("[Worker thread] [-] Fatal Error: %s" % err)
                self.inserted.emit(ERROR_JSON("ERR_WEBEID_NATIVE_FATAL",err.__str__()))
        else:
            self.started2.emit(ERROR_JSON("ERR_WEBEID_NATIVE_INVALID_ARGUMENT","Invalid parameters: check command and arguments"))


def confirmed(str):
    global WebEidDialog
    messaging.return_message(str)
    loggerWindow.logger.debug("[Main thread] [+] sent response to the extension")
    #WebEidDialog.close()

def deliverCAresponse(str):
    global WebEidDialog
    messaging.return_message(str)
    loggerWindow.logger.debug("[Main thread] [+] sent response to the extension")
    WebEidDialog.close()

def deliverEMRTDtoken(tokenJSON):
    global WebEidDialog
    messaging.return_message(tokenJSON)
    loggerWindow.logger.debug('[+] sent response to the extension')
    loggerWindow.logger.debug("[Main thread] [+] sent response to the extension")
    ui.okButton.hide()
    ui.cancelButton.hide()

waittimer = QTimer()
waittimer.setSingleShot(True)
def handleTimeout():
    worker.exit()
    WebEidDialog.close()
waittimer.timeout.connect(lambda: handleTimeout())
def waitForCArequest():
    #get CA request (wait 5 seconds in worker thread, if no request by then, close the app)
    loggerWindow.logger.debug('[Main thread] [+] waiting for CA request')
    '''receivedMessageCA = {"command":"authenticate_ca","arguments":{
        "eph_pubkey":"BHMEx2Zc4tnUf11K6d9SzzYo3GjtpT1QeYOH/OlY1uzkJzLC6pFlKxdA8X7zQanZjGmKC0tSxzuf5ZXFsNy7sOw=",
        "capdu":"DLB//w2XAQGOCNrSW7wEBS4lAA==","origin":"https://web-emrtd.eu",
        "signature":"Y2igbVraJitEHFFRn6oGOkUvUTv26avOuFDSeMFF7ncIuZ5hzv7K30lB39Yo5M61zuUZDelGFo0IT11+bAOZtQ==","userInteractionTimeout":120000}}'''
    #worker.receivedMessage = receivedMessageCA
    #worker.receivedMessage['arguments']['DG14'] = worker.DG14
    #worker.receivedMessage['arguments']['SOD'] = worker.SOD
    worker.caReady.connect(deliverCAresponse)
    worker.stopCAtimer.connect(lambda: waittimer.stop())
    worker.waitForCA = True
    worker.start()
    waittimer.start(5000)
    loggerWindow.logger.debug('[Main thread] [+] started worker for CA')

removetimer = QTimer()
removetimer.timeout.connect(lambda: sendEmptyCommand())
def sendEmptyCommand():
    apdu = [0x00, 0x00, 0x00, 0x00]
    try:
        worker.CHANNEL.transmit(apdu)
    except Exception as err:
        loggerWindow.logger.debug("[Main thread] [-] exception: %s" % err.__str__())
        loggerWindow.logger.debug("[Main thread] [+] worker is running: %s, is finished: %s" %(worker.isRunning(), worker.isFinished()))
        worker.CHANNEL.disconnect()
        removetimer.stop()
        worker.start()

CAN_INPUT = ''
def verifyCAN(can_input):
    global CAN_INPUT
    updateUI({'status':'READER_CONNECTED'})
    CAN_INPUT = can_input

requesttimer = QTimer()
requesttimer.setSingleShot(True)
def waitChannelThenVerifyCAN(can_input):
    updateUI({'status':'READER_CONNECTED'})
    def requestChannel():
        global CAN_INPUT
        channel = CardRequest(timeout=None, cardType=SupportedCardType(None)).waitforcard().connection           
        worker.CHANNEL = ExclusiveTransmitCardConnection(channel)
        protocol = CardConnection.T1_protocol
        worker.CHANNEL.connect(protocol) # use only protocol
        loggerWindow.logger.debug("[Main thread] [+] connected channel again...")
        worker.CHANNEL.lock()
        loggerWindow.logger.debug("[Main thread] [+] locked channel again...")
        weid.cardSupport(worker.CHANNEL)
        CAN_INPUT = can_input
        loggerWindow.logger.debug("[Main thread] [+] Set CAN value, continue PACE...")
    requesttimer.timeout.connect(lambda: requestChannel())
    requesttimer.start(100)

MRZ_INPUT,paceSupported = '',False
def obtainMRZ(doc,birth,exp):
    global MRZ_INPUT
    updateUI({'status':'CARD_INSERTED'})
    date_of_birth = getMRZpart(birth)
    date_of_expiry = getMRZpart(exp)
    mrz_information = (
        doc
        + weid.calculate_check_digit(doc)
        + date_of_birth
        + weid.calculate_check_digit(date_of_birth)
        + date_of_expiry
        + weid.calculate_check_digit(date_of_expiry)
    )
    MRZ_INPUT = mrz_information
    
def waitChannelThenObtainMRZ(doc,birth,exp):
    updateUI({'status':'READER_CONNECTED'})
    date_of_birth = getMRZpart(birth)
    date_of_expiry = getMRZpart(exp)
    mrz_information = (
        doc
        + weid.calculate_check_digit(doc)
        + date_of_birth
        + weid.calculate_check_digit(date_of_birth)
        + date_of_expiry
        + weid.calculate_check_digit(date_of_expiry)
    )
    def requestChannel():
        global MRZ_INPUT
        channel = CardRequest(timeout=None, cardType=SupportedCardType(None)).waitforcard().connection           
        worker.CHANNEL = ExclusiveTransmitCardConnection(channel)
        protocol = CardConnection.T1_protocol
        worker.CHANNEL.connect(protocol) # use only protocol
        loggerWindow.logger.debug("[Main thread] [+] connected channel again...")
        worker.CHANNEL.lock()
        loggerWindow.logger.debug("[Main thread] [+] locked channel again...")
        weid.cardSupport(worker.CHANNEL)
        MRZ_INPUT = mrz_information
        loggerWindow.logger.debug("[Main thread] [+] Set MRZ value, continue PACE...")
    requesttimer.timeout.connect(lambda: requestChannel())
    requesttimer.start(100)

def verifyMRZ(mrz_input):
    global MRZ_INPUT
    updateUI({'status':'CARD_INSERTED'})
    MRZ_INPUT = mrz_input

def getMRZpart(qdate):
    dateStr = qdate.toString("dd.MM.yyyy")
    year = dateStr[-2:]
    month = dateStr[3:5]
    day = dateStr[:2]
    return year+month+day

def cancelled():
    loggerWindow.logger.debug("[Main thread] [-] operation cancelled by user")
    res = {"error": {"code": "ERR_WEBEID_USER_CANCELLED", "message": "User cancelled"}}
    confirmed(json.dumps(res, separators=(',', ':')).encode('utf-8'))
    WebEidDialog.close()

def timeoutReached():
    loggerWindow.logger.debug("[Main thread] [-] timeout reached, closing native app...")
    res = {"error": {"code": "ERR_WEBEID_USER_TIMEOUT", "message": "User interaction timeout reached"}}
    confirmed(json.dumps(res, separators=(',', ':')).encode('utf-8'))
    WebEidDialog.close()

def updateUI(status):
    global WebEidDialog, paceSupported
    if "error" in status:
        loggerWindow.logger.debug("[Main thread] [-] display operation failed")
        #ui.resizeHeight(WebEidDialog)
        ui.helpButton.pressed.connect(loggerWindow.show)
        ui.operationFailed(WebEidDialog)
        confirmed(json.dumps(status, separators=(',', ':')).encode('utf-8'))
    elif status['status'] == 'READER_CONNECTED':
        loggerWindow.logger.debug("[Main thread] [+] reader connected, update UI")
        ui.cardReaderFound(WebEidDialog)
    elif status['status'] == 'READER_REMOVED':
        loggerWindow.logger.debug("[Main thread] [+] reader removed, update UI")
        ui.cardReaderRemoved(WebEidDialog)
    elif status['status'] == 'CARD_REMOVED':
        loggerWindow.logger.debug("[Main thread] [+] card removed, update UI")
        ui.cardReaderFound(WebEidDialog)
    elif status['status'] == 'CA_REQUEST':
        loggerWindow.logger.debug("[Main thread] [+] CA request, update UI")
        ui.processingCA(WebEidDialog)
    elif status['status'] == 'CARD_INSERTED':
        loggerWindow.logger.debug("[Main thread] [+] card inserted, update UI")
        ui.cardInserted(WebEidDialog)
    elif status['status'] == 'UNSUPPORTED_CARD':
        loggerWindow.logger.debug("[Main thread] [+] unsupported card, update UI")
        ui.unsupportedCardError('The smart card in the reader is not supported. Make sure that the entered ePassport is supported by the Web eMRTD application.', WebEidDialog)
        
        #send 00 00 00 00 every 500 ms to check card is removed from reader
        removetimer.start(500)
    elif status['status'] == 'PACE_NOT_SUPPORTED':
        loggerWindow.logger.debug("[Main thread] [+] unsupported card, update UI")
        ui.unsupportedCardError('The ePassport in the reader is not supported (does not support PACE)', WebEidDialog)
    elif status['status'] == 'ENTER_CAN':
        loggerWindow.logger.debug("[Main thread] [+] enter CAN, update UI")
        if 'cached' in status and status['cached']:
            verifyCAN(status['cached'])
            return
        #similarly ui.birthPicker.date() and ui.expiryPicker.date() for BAC
        #CAN validator
        def validateCAN():
            pattern = r"^\d{6}$"  # Matches exactly 6 digits
            if bool(re.match(pattern, ui.pinInput.text())):
                ui.okButton.setEnabled(True)
            else:
                ui.okButton.setEnabled(False)
                
        ui.pinInput.textChanged.connect(validateCAN)
        def setupForBAC():
            ui.pinInput.textChanged.disconnect(validateCAN)
            ui.okButton.setEnabled(True)
            paceSupported = True
            ui.okButton.clicked.connect(lambda: waitChannelThenObtainMRZ(ui.pinInput.text(),ui.birthPicker.date(),ui.expiryPicker.date()))
            ui.enterBAC(WebEidDialog)
        ui.alternativeLabel.linkActivated.connect(setupForBAC)
        ui.okButton.clicked.connect(lambda: waitChannelThenVerifyCAN(ui.pinInput.text()))
        ui.enterCAN(WebEidDialog)
        #disconnect channel at input phase
        worker.CHANNEL.disconnect()
        ui.pinInput.setFocus()
    elif status['status'] == 'ENTER_MRZ':
        loggerWindow.logger.debug("[Main thread] [+] enter MRZ, update UI")
        if 'cached' in status and status['cached']:
            verifyMRZ(status['cached'])
            return
        #similarly ui.birthPicker.date() and ui.expiryPicker.date() for BAC
        ui.okButton.clicked.connect(lambda: waitChannelThenObtainMRZ(ui.pinInput.text(),ui.birthPicker.date(),ui.expiryPicker.date()))
        ui.enterBAC(WebEidDialog)
        worker.CHANNEL.disconnect()
        ui.pinInput.setFocus()
    elif status['status'] == 'INCORRECT_CAN':
        loggerWindow.logger.debug("[Main thread] [+] enter CAN, update UI")
        ui.okButton.clicked.connect(lambda: waitChannelThenVerifyCAN(ui.pinInput.text()))
        worker.CHANNEL.disconnect()
        ui.incorrectCAN(WebEidDialog)

def parse_DG2(ef_dg2):
    """
    Get the JPEG image from EF.DG2
    """
    # ICAO9303-10 and ISO/IEC 19794-5
    #raise Exception('cannot parse EF.DG2')
    im_start = ef_dg2.find(b"\xFF\xD8\xFF\xE0")
    if im_start == -1:
        im_start = ef_dg2.find(b"\x00\x00\x00\x0C\x6A\x50")
    image = ef_dg2[im_start:]

    # convert from JPEG2000 to JPEG
    if image.startswith(b"\x00\x00\x00\x0c\x6a\x50\x20\x20"):
        jp2 = Image.open(io.BytesIO(image))
        jpg = io.BytesIO()
        jp2.save(jpg, format='jpeg')
        image = jpg.getvalue()

    return image

def handleEMRTD(emrtd, origin):
    global ui, WebEidDialog
    loggerWindow.logger.debug("[Main thread] [+] received eMRTD token")
    loggerWindow.logger.debug("[Main thread] [+] handleEMRTD() processing...")
    if not 'EF_DG1' in emrtd:
        try:
            confirmed(json.dumps(emrtd, separators=(',', ':')).encode('utf-8'))
        except Exception as err:
            loggerWindow.logger.debug("[Main thread] [-] Fatal Error: %s" % err)
            updateUI(ERROR_JSON("ERR_WEBEID_NATIVE_FATAL",err.__str__()))
        return
    
    try:
        parsedMRZ = emrtdutil.parse_DG1(emrtd['EF_DG1'])
        for key in parsedMRZ:
            loggerWindow.logger.debug("[Main thread] [+] handleEMRTD(): MRZ: %s: %s" % (key, parsedMRZ[key]))
    
        confirmText = 'By confirming, I agree to the transfer of my personal data listed above to the service provider.'
        photoBytes = b''
        if emrtd['EF_DG2']:
            try:
                photoBytes = parse_DG2(emrtdutil.getBytes(emrtd['EF_DG2']))
                confirmText = "By confirming, I agree to the transfer of my personal data listed above (<b>including facial photo</b>) to the service provider."
            except Exception as err:
                loggerWindow.logger.debug("[Main thread] [-] Fatal Error: %s" % err)
                updateUI(ERROR_JSON("ERR_WEBEID_NATIVE_FATAL","Cannot parse EF.DG2"))
                return
    
        ui.originLabel.setText(origin)
        ui.aboutHelp.setWordWrap(True)
        ui.aboutHelp.setText(confirmText)
        ui.userDataWindow(WebEidDialog, parsedMRZ['doctype'], photoBytes, parsedMRZ['issuing_state'], parsedMRZ)
        ui.resizeHeight(WebEidDialog)
        ui.okButton.show()
        if args.viewer:
            #save button logic
            def saveEMRTDfile():
                options = QFileDialog.Options()
                #options |= QFileDialog.DontUseNativeDialog
                docNum = parsedMRZ['document_number']
                fileName, _ = QFileDialog.getSaveFileName(WebEidDialog, "Save File", f"{docNum}_.emrtd", "All Files (*)", options=options)
                if fileName:
                    with open(fileName, 'w') as file:
                        file.write(json.dumps(emrtd, separators=(',', ':'), indent=4))
                    loggerWindow.logger.debug(f"[+] EMRTD file saved: {fileName}")
            ui.okButton.clicked.connect(saveEMRTDfile)
        else:
            ui.okButton.clicked.connect(lambda: deliverEMRTDtoken(json.dumps(emrtd, separators=(',', ':')).encode('utf-8')))
            ui.okButton.clicked.connect(lambda: waitForCArequest())
        #ui.okButton.clicked.connect(lambda: removetimer.start(500)) #after confirmed, check whether card is connected...
    except Exception as err:
        loggerWindow.logger.debug("[Main thread] [-] Fatal Error: %s" % err)
        updateUI(ERROR_JSON("ERR_WEBEID_NATIVE_FATAL","Cannot parse EF.DG1"))

app = QApplication(sys.argv)
loggerWindow = LogWindow()
WebEidDialog = QDialog()
qr = WebEidDialog.frameGeometry()  # Get the geometry of the main window
cp = QDesktopWidget().availableGeometry().center()  # Get the center of the screen
qr.moveCenter(cp)  # Move the dialog's top-left corner to the center

ui = Ui_WebEidDialog()
ui.setupUi(WebEidDialog)
ui.cancelButton.clicked.connect(cancelled)

loggerWindow.logger.debug("[Main thread] [+] show dialog")
#send version to extension
version = {'version':'1.0.0'}
#later: obtain user interaction timeout and call exit if reached.
if args.debug:
    loggerWindow.logger.debug("[Main thread] [+] debug mode")
    challengeNonce = base64.b64encode(os.urandom(32)).decode()
    origin = 'https://web-emrtd.eu'
    receivedMessage = {'command':'authenticate', 'arguments':{'challengeNonce': challengeNonce, 'origin': origin, 'photo': False, 'userInteractionTimeout': 60000}}
elif args.viewer:
    #viewer verifier mode
    loggerWindow.logger.debug("[Main thread] [+] debug mode")
    challengeNonce = b''
    origin = ''
    receivedMessage = {'command':'authenticate', 'arguments':{'challengeNonce': challengeNonce, 'origin': origin, 'photo': True}}
    ui.viewerVerifierMode(WebEidDialog)
    ui.cancelButton.clicked.disconnect(cancelled)
    def openEMRTDfile():
        #open button logic
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        fileName, _ = QFileDialog.getOpenFileName(WebEidDialog, "Open Document", "", "eMRTD files (*.emrtd)", options=options)
        if fileName:
            loggerWindow.logger.debug(f"[+] Selected emrtd file: {fileName}")
            emrtd = json.loads(open(fileName,'r').read())
            handleEMRTD(emrtd,'')
            # perform Passive Authentication (PA)
            ret = [] # will store digest_name set by passive_authentication()
            try:
                MRZ = emrtdutil.parse_DG1(emrtd['EF_DG1'])
                issuing_state = MRZ['issuing_state']
                date_of_expiry = MRZ['date_of_expiry']
                wemrtd_verify.passive_authentication(emrtd, issuing_state, date_of_expiry, ret)
            except Exception as err:
                print('[+] passive authenticate fails: ' + err.__str__())
                loggerWindow.logger.debug('[-] parse_DG1(): ' + err.__str__())
                loggerWindow.logger.debug('[-] passive_authentication(): ' + err.__str__())
                ui.originLabel.show()
                ui.originLabel.setText("Passive Authentication failed")
                ui.helpButton.setText("Verification log")
                ui.helpButton.pressed.connect(loggerWindow.show)
                ui.helpButton.setIcon(QIcon())
                ui.helpButton.show()
            else:
                ui.originLabel.show()
                ui.originLabel.setText("Passive Authentication successful")
                print('[+] passive authenticate success')
            
    ui.cancelButton.clicked.connect(openEMRTDfile)
else:
    loggerWindow.logger.debug("[Main thread] [+] extension mode")
    messaging.return_message(json.dumps(version, separators=(',', ':')).encode('utf-8'))
    receivedMessage = messaging.getMessage()

#show dialog window after message is received
WebEidDialog.show()
#start worker after extension request is reached
worker = MyWorker(receivedMessage)
worker.started2.connect(handleEMRTD)
worker.inserted.connect(updateUI)
worker.logger.connect(loggerWindow.logger.debug)
worker.start()

#call timeoutReached() after userInteractionTimeout is reached except for viewer mode
if not args.viewer:
    QTimer.singleShot(receivedMessage['arguments']['userInteractionTimeout'], timeoutReached)

    loggerWindow.logger.debug("[Main thread] [+] started worker")

app.exec_()
loggerWindow.writeLogFile()
sys.exit()