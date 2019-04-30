//
//  smime.h
//  Krypt
//
//  Created by marko on 11.04.19.
//

#ifndef smime_h
#define smime_h

#include <stdio.h>

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
 @param certs Collection of certificate strings in form of a pointer to array of strings (char *certs[])
 @param certCount Number of provided certificate strings
 @param content Returns content of verified MIME content (without signature)
 @return Verification status: 1 = success, 0 = failure
 */
int smime_verify(const char *decrypted, const char **certs, int certCount, char **content);

#endif /* smime_h */
