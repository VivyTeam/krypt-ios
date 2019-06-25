//
//  pkcs8.c
//  Krypt
//
//  Created by Max on 24.06.19.
//

#include "pkcs8.h"
#include <openssl/bio.h>
#include <openssl/pem.h>
#include "helper.h"

char *pkcs8_convert_from_pkcs1_pem(const char *pem) {
    // Load PEM into BIO
    BIO *key = BIO_from_str(pem);
  
    // Create RSA from PEM
    RSA *rsa = PEM_read_bio_RSAPublicKey(key, NULL, 0, NULL);
  
    BIO *out = BIO_new(BIO_s_mem());
    
    // Write out PEM to bio
    if(!PEM_write_bio_RSA_PUBKEY(out, rsa)) {
      // Cannot write out public key, clean up and return
      BIO_free(key);
      RSA_free(rsa);
      return NULL;
    }
  
    BIO_free(key);
    RSA_free(rsa);
    
    return str_from_BIO(out);
}
