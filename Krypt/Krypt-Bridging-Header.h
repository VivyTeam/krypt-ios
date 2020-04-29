//
//  Krypt-Bridging-Header.h
//  Krypt
//
//  Created by Caio Mello on 28.04.20.
//  Copyright © 2020 Vivy GmbH. All rights reserved.
//

#ifndef Krypt_Bridging_Header_h
#define Krypt_Bridging_Header_h

char *createCSR(const char *key, const char *country, const char *state, const char *location, const char *organization, const char *organizationUnit, const char *emailAddress, const char *uniqueIdentifier, const char *givenName, const char *surname);

char *convert_pkcs1_to_pkcs8(const char *pem);
char *pkcs8_encrypt(const char *pkcs1, const char *password);
char *pkcs8_decrypt(const char *pem, const char *password);

enum Smime_error {
  Smime_error_certificate_verify_error = 554127477,
  Smime_error_digest_fail = 554111077,
  Smime_error_invalid_mime_type = 218972365,
  Smime_error_signature_doesnt_belong_to_sender
};
char *smime_decrypt(const char *encrypted, const char *privateKey);
int smime_verify(const char *decrypted, const char *sender_email, const char **certs, int certCount, char **content, enum Smime_error *err);

char *x509_wrap_pubkey(const char *prikeypem, const char *pubkeypem);

#endif /* Krypt_Bridging_Header_h */
