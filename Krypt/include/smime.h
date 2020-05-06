//
//  smime.h
//  Krypt
//
//  Created by marko on 11.04.19.
//

#ifndef smime_h
#define smime_h

#include <stdio.h>

enum Smime_error {
  // PKCS7_verify errors
  Smime_error_certificate_verify_error = 554127477,
  Smime_error_digest_fail = 554111077,
  Smime_error_invalid_mime_type = 218972365,

  // Other errors
  Smime_error_signature_doesnt_belong_to_sender
};

/**
 Decrypts SMIME content
 
 @param encrypted Encrypted SMIME content
 @param privateKey Required private key to decrypt the content
 @return Decrypted SMIME content
 */
char *smime_decrypt(const char *encrypted, const char *privateKey);

/**
 Verifies the signature of decrypted SMIME content against the trusted certificates
 
 @param decrypted Decrypted SMIME content
 @param sender_email Email address of the sender of SMIME message
 @param certs Collection of certificate strings in form of a pointer to array of strings (char *certs[])
 @param certCount Number of provided certificate strings
 @param content Returns content of verified MIME content (without signature)
 @return Verification status: 1 = success, 0 = failure
 */
int smime_verify(const char *decrypted, const char *sender_email, const char **certs, int certCount, char **content, enum Smime_error *err);

#endif /* smime_h */
