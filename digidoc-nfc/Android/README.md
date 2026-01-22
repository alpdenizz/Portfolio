# How to patch RIA DigiDoc to DigiDoc NFC Beta:

1- Clone MOPP-Android repository (RIA DigiDoc source code):
`git clone https://github.com/open-eid/MOPP-Android.git`

2- Checkout to this commit. This was the commit where we started developing DigiDoc NFC Beta:
`git checkout 9e1f6f8da4e4afd76553cd5b18ce7544e4df9c94`

3- Apply the patch file:
`git apply MOPP_Android_Patch.patch`

4- Put google-services.json in `app` folder