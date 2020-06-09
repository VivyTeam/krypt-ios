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

## Apple's stance on OpenSSL
>macOS includes a low-level command-line interface to the OpenSSL open-source cryptography toolkit; this interface is not available in iOS.
>
>Although OpenSSL is commonly used in the open source community, it doesn’t provide a stable API from version to version. For this reason, the programmatic interface to OpenSSL is deprecated in macOS and is not provided in iOS. Use of the Apple-provided OpenSSL libraries by apps is strongly discouraged.
>
>**To ensure compatibility, if your app depends on OpenSSL, you should compile it yourself and statically link a known version of OpenSSL into your app. Such use works on both iOS and macOS.**
>
>In general, however, you should use the CFNetwork API for secure networking and the Certificate, Key, and Trust Services API for cryptographic services. Alternatively, in macOS, you can use the Secure Transport API.
>
>[Transmitting Data Securely - Documentation Archives](https://developer.apple.com/library/archive/documentation/Security/Conceptual/cryptoservices/SecureNetworkCommunicationAPIs/SecureNetworkCommunicationAPIs.html#//apple_ref/doc/uid/TP40011172-CH13-SW1)
