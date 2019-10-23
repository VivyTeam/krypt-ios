//
//  pkcs8.c
//  Krypt
//
//  Created by Max on 24.06.19.
//

#include "pkcs8.h"
#include <string.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include "helper.h"

void pkcs8_encrypt_free_all(BIO *out, EVP_PKEY *key, PKCS8_PRIV_KEY_INFO *p8inf, X509_ALGOR *pbe, X509_SIG *p8);

char *convert_pkcs1_to_pkcs8(const char *pem) {
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

char *pkcs8_encrypt(const char *pkcs1, const char *password) {
  BIO *out = NULL;
  EVP_PKEY *pkey = NULL;
  PKCS8_PRIV_KEY_INFO *p8inf = NULL;
  X509_ALGOR *pbe = NULL;
  X509_SIG *p8 = NULL;

  const EVP_CIPHER *cipher = EVP_aes_256_cbc();
  int iter = 100000;
  int pbe_nid = NID_hmacWithSHA256;

  unsigned long int passlenuint = strlen(password);
  if (passlenuint > INT_MAX) {
    return NULL;
  }
  int passlen = passlenuint & INT_MAX;

  pkey = get_key(pkcs1);
  if (pkey == NULL) {
    pkcs8_encrypt_free_all(out, pkey, p8inf, pbe, p8);
    return NULL;
  }

  p8inf = EVP_PKEY2PKCS8(pkey);
  if (p8inf == NULL) {
    pkcs8_encrypt_free_all(out, pkey, p8inf, pbe, p8);
    return NULL;
  }

  p8 = PKCS8_encrypt(pbe_nid, cipher, password, passlen, NULL, 0, iter, p8inf);
  if (p8 == NULL) {
    pkcs8_encrypt_free_all(out, pkey, p8inf, pbe, p8);
    return NULL;
  }

  out = BIO_new(BIO_s_mem());
  BIO_set_mem_eof_return(out, 0);
  PEM_write_bio_PKCS8(out, p8);
  if (out == NULL) {
    pkcs8_encrypt_free_all(out, pkey, p8inf, pbe, p8);
    return NULL;
  }

  char *str = str_from_BIO(out);

  pkcs8_encrypt_free_all(out, pkey, p8inf, pbe, p8);
  return str;
}

void pkcs8_encrypt_free_all(BIO *out, EVP_PKEY *key, PKCS8_PRIV_KEY_INFO *p8inf, X509_ALGOR *pbe, X509_SIG *p8) {
  BIO_free_all(out);
  EVP_PKEY_free(key);
  PKCS8_PRIV_KEY_INFO_free(p8inf);
  X509_ALGOR_free(pbe);
  X509_SIG_free(p8);
}
