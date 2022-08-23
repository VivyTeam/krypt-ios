# openssl-ios

OpenSSL libraries used in Vivy iOS app.

To update OpenSSL, please follow the steps below:
- clone repo
- open https://www.openssl.org/
- find the newest version
- open script/build.sh and edit `OPENSSL_VERSION`
- run the script: `./script/build.sh`
- open example project and run it to check if everything works as it should

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
