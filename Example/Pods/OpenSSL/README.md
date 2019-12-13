# openssl-ios

OpenSSL static libraries used in Vivy iOS app

In order to run library with the newest version please follow next steps:
- clone repo
- open https://www.openssl.org/
- find the newest version and correspondent signature
- open build.sh and edit version and signature
- run the script
- open example project and run it to check if everything works as it should

## Notice: auto editing
This build script is actively editing two of the files produced:

- asn1_mac.h
    - This file is produced by a bug, and it's contents can be removed without any issues (as far as we know)
- e_os2.h
- This normally contains the import of <inttypes.h>, which, being depricated in the Apple version of C, causes compilation errors.

If you see a ⚠️ , please check to make sure everything is building correctly.

