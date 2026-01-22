## Smart-ID Reverse Engineering
Reverse-engineered the [Smart-ID](https://www.smart-id.com) APK, replicated its functionality and developed some web services to simulate the Smart-ID authentication using Python

* Found some Smart-ID APKs in APKPure, decompiled them using `apktool`, analyzed the smali files using VSCode and visualized the jar files using JD-GUI.
* Replicated the logic using Python, see `smart-id` folder for the Python files.
* Developed some web services using `Flask` package of Python to simulate the Smart-ID authentication.

## Extending DigiDoc public forks
Extended NFC functionality and inter-app communication of RIA DigiDoc [iOS](https://github.com/open-eid/MOPP-iOS) and [Android](https://github.com/open-eid/RIA-DigiDoc-Android) public forks using Java and Swift

* Developed NFC support for each functionality of RIA DigiDoc iOS and Android application.
* In the Android fork, used `Java` to edit the codebase and introduce NFC support; In the iOS fork, used `Swift` for this purpose.
* See `digidoc-nfc` folder for the main files.
* Leveraged custom URL scheme and Universal Links to provide inter-app communication.

## Developing web extension and desktop app
Based on [thesis](https://thesis.cs.ut.ee/70a3293d-1f8a-4693-b7b3-67208426ba91), developed a browser extension and a desktop app to authenticate with ePassport using Python

* Implemented a Python script to communicate with a web extension using native app messaging.
* Refactored the existing Web eID extension public fork to provide the necessary paramters for ePassport.
* Read an ePassport, visualized its information in a desktop app written in Python and sent the information to the extension.
* See `web-emrtd` for the main files.

## Improving a Kotlin project
Based on [thesis](https://thesis.cs.ut.ee/28c9bc5d-52f1-478c-83bc-24fd3ec0a957), improved an Android app’s UI and functionality using Kotlin

* Reverse-engineered Eesti app to investigate used APIs, configuration files and JWT handling.
* Improved JWT operation of the existing app to remove the need of reauthentication after 12 hours.
* Improved UI using Kotlin.
* See `andmejalgija` for the main files.

