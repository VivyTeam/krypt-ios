# Krypt

Crypto library used in Vivy iOS app

## Installation

#### CocoaPods
Add to `Podfile`: 

```ruby 
pod 'Krypt' 
```
run `pod install`

## Usage
#### (EHR) Electronic Health Record Encryption

```swift
// Encrypt
let dataToEncrypt: Data = ...
let publicKey: Key = ...
let encrypted = try EHREncryption.encrypt(data: dataToEncrypt, with: publicKey)

encrypted.data // Data
encrypted.cipherKey // base64 String with AES key and IV
encrypted.version // Version

// Decrypt
let privateKey: Key = ...

let decrypted = try EHREncryption.decrypt(encryptedData: encrypted, with: privateKey) // Data
```

## Dev setup
- run `./bootstrap.sh` from root of cloned repo to setup SwiftFormat

## License

Krypt is available under the MIT license. See the LICENSE file for more info.
