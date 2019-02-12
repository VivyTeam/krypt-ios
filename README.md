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
#### (EHR) Electronic Health Record Encryption and LocalEncryption

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

#### Medical ID Sticker Encryption

```swift
// Encrypt
let dataToEncrypt: Data = ...
let pin: Data = ...
let code: Data = ...
let encrypted = try MedStickerEncryption.encrypt(data: dataToEncrypt, pin: pin, code: code)

encrypted.data // Data
encrypted.attr.key // AES key
encrypted.attr.iv // AES IV
encrypted.attr.version // britney

// Decrypt
let decrypted = try MedStickerEncryption.decrypt(data: encrypted.data, with attr: encrypted.attr) // Data

// Signature
let salt: Data = ...

let signature = MedStickerEncryption.accessSignature(attr: encrypted.attr, salt: salt) // base64 string
```



## Dev setup
1. clone the repo
2. run `./bootstrap.sh` from root of cloned repo to setup SwiftFormat

## License

Krypt is available under the MIT license. See the LICENSE file for more info.

## Acknowledgements

#### CryptoSwift
This product includes software developed by the "Marcin Krzyzanowski" (http://krzyzanowskim.com/).

#### Scrypt
neo-swift: [Source](https://github.com/CityOfZion/neo-swift) [LICENSE](https://github.com/CityOfZion/neo-swift/blob/master/LICENSE)
