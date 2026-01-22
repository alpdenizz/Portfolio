## Smart-ID Reverse Engineering
Reverse-engineered the Smart-ID APK, replicated its functionality and developed some web services to simulate the Smart-ID authentication using Python

* Found some Smart-ID APKs online, decompiled them using `apktool`, edited the smali files using VSCode and visualized the jar files using some GUI.
* Replicated the logic using Python, see `smart-id` folder for the Python files.
* Developed some web services using `Flask` package of Python to simulate the Smart-ID authentication.

## Extending DigiDoc public forks
Extended NFC functionality and inter-app communication of RIA DigiDoc iOS and Android public forks using Java and Swift

* Developed NFC support for each functionality of RIA DigiDoc iOS and Android application.
* In the Android fork, used `Java` to edit the codebase and introduce NFC support; In the iOS fork, used `Swift` for this purpose.
* See `digidoc-nfc` folder for the main files.
* Leveraged custom URL scheme and Universal Links to provide inter-app communication.

## Developing web extension and desktop app
Developed a browser extension and a desktop app to authenticate with ePassport using Python

* Implemented a Python script to communicate with a web extension using native app messaging.
* Refactored the existing Web eID extension public fork to provide the necessary paramters for ePassport.
* Read an ePassport, visualized its information in a desktop app written in Python and sent the information to the extension.
* See `web-emrtd` for the main files.

## Improving a Kotlin project
Improved an Android app’s UI and functionality using Kotlin

* Reverse-engineered Eesti app to investigate used APIs, configuration files and JWT handling.
* Improved JWT operation of the existing app to remove the need of reauthentication after 12 hours.
* Improved UI using Kotlin.
* See `andmejalgija` for the main files.

