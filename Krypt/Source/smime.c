  //
  //  smime.c
  //  Krypt
  //
  //  Created by marko on 11.04.19.
  //

#include "smime.h"
#include <string.h>
#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

BIO *BIO_from_str(const char *str) {
  BIO *membuf = BIO_new(BIO_s_mem());
  if (BIO_puts(membuf, str) < 1) {
    return NULL;
  }
  return membuf;
}

/*
 converts PEM encoded certificate to X509
 */
X509 *get_cert(const char *certificate) {
  BIO *cert_membuf = BIO_from_str(certificate);
  if (!cert_membuf) {
    BIO_free(cert_membuf);
    return NULL;
  }
  X509 *x509 = PEM_read_bio_X509(cert_membuf, NULL, NULL, NULL);
  BIO_free(cert_membuf);
  return x509;
}

/*
 Converts private key string to EVP_PKEY
 */
EVP_PKEY *get_key(const char *privateKey) {
  BIO *key_membuf = BIO_from_str(privateKey);
  EVP_PKEY *key = PEM_read_bio_PrivateKey(key_membuf, NULL, 0, NULL);
  BIO_free(key_membuf);
  return key;
}

/**
 Converts SMIME string to PKCS7 object

 @param smime_string String that contains SMIME with encrypted content
 @param bcont Output of SMIME decrypted content in case the signature was in plain text
 @return PKCS7 object as decrypted SMIME content
 */
PKCS7 *get_pkcs7(const char *smime_string, BIO **bcont) {
  BIO* smime_membuf = BIO_new(BIO_s_mem());
    //see error here - http://openssl.6102.n7.nabble.com/SMIME-read-PKCS7-fails-with-memory-BIO-but-works-with-file-BIO-td7673.html
    //if we dont set this, then we get error: 218542222
    //This error, converted to hexadecimal, is 0xd06b08e which when used in
    //$ `openssl errstr d06b08e` gives
    //error:0D06B08E:asn1 encoding routines:ASN1_d2i_bio:not enough data
  BIO_set_mem_eof_return(smime_membuf, 0);
  BIO_puts(smime_membuf, smime_string);
  PKCS7* pkcs7 = SMIME_read_PKCS7(smime_membuf, bcont);
  return pkcs7;
}

/*
 decrypts the SMIME container
 */
char *decrypt_pkcs7(PKCS7 *pkcs7, EVP_PKEY *pkey) {
  BIO *out = BIO_new(BIO_s_mem());
  
  if (PKCS7_decrypt(pkcs7, pkey, NULL, out, 0) != 1) {
    EVP_PKEY_free(pkey);
    PKCS7_free(pkcs7);
    return NULL;
  }
  
  BUF_MEM* mem;
  BIO_get_mem_ptr(out, &mem);
  char *data = malloc(mem->length);
  memcpy(data, mem->data, mem->length);
  BIO_flush(out);
  BIO_free(out);
  return data;
}

/**
 Decrypts SMIME content

 @param encrypted Encrypted SMIME content
 @param privateKey Required private key to decrypt the content
 @return Decrypted SMIME content
 */
char *smime_decrypt(const char *encrypted, const char *privateKey) {

  EVP_PKEY *pkey = get_key(privateKey);
  if (!pkey) {
    return NULL;
  }

  PKCS7 *pkcs7 = get_pkcs7(encrypted, NULL);
  if (!pkcs7) {
    EVP_PKEY_free(pkey);
    return NULL;
  }

  char *data = decrypt_pkcs7(pkcs7, pkey);
  if (data != NULL) {
    EVP_PKEY_free(pkey);
    PKCS7_free(pkcs7);
  }

  return data;
}

/**
 Generates an instance of X509_STORE and populates it with trusted certificates

 @param certs Collection of certificate strings in form of a pointer to array of strings (char pointers)
 @param certCount Number of provided certificate strings
 @return X509_STORE instance populated with trusted certificates
 */
X509_STORE *store_with_trusted_certs(const char** certs, int certCount) {
  if (!certs) {
    return NULL;
  }
  
  X509_STORE *store = X509_STORE_new();
  
  int success = 1;
  
  for (int i = 0; i < certCount; i++) {
    const char *cert = certs[i];
    X509 *certX509 = get_cert(cert);
    if (!certX509) {
      break;
    }
    
    success &= X509_STORE_add_cert(store, certX509);
    X509_free(certX509);
  }
  
  if (success) {
    return store;
  }
  
  X509_STORE_free(store);
  return NULL;
}


/**
 Verifies the signature of decrypted SMIME content against the trusted certificates

 @param decrypted Decrypted SMIME content
 @param certs Collection of certificate strings in form of a pointer to array of strings (char *certs[])
 @param certCount Number of provided certificate strings
 @return Verification status: 1 = success, 0 = failure
 */
int smime_verify(const char *decrypted, const char** certs, int certCount) {
  BIO *bcont = NULL;
  
  PKCS7 *pkcs7 = get_pkcs7(decrypted, &bcont);
  if (!pkcs7) {
    return 0;
  }
  
  X509_STORE *store = store_with_trusted_certs(certs, certCount);
  if (!store) {
    PKCS7_free(pkcs7);
    return 0;
  }
  
  int flags = PKCS7_DETACHED;
  int ret = PKCS7_verify(pkcs7, NULL, store, bcont, NULL, flags);
  PKCS7_free(pkcs7);
  X509_STORE_free(store);

  return ret;
}
