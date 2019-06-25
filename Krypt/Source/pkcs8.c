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


char *pkcs8_get_public_key_pem(const char *der) {
    // Load DER in BIO
    BIO *key = BIO_from_str(der);
    
    // Load bio to to RSA
    RSA *rsa;
    rsa = d2i_RSAPublicKey_bio(key, NULL);
    
    BIO *out = NULL;
    
    // Write out PEM to bio
    PEM_write_bio_RSA_PUBKEY(out, rsa);
    
    return str_from_BIO(out);
}
