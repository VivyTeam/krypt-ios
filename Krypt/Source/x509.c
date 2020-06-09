//
//  x509.c
//  Krypt
//
//  Created by marko on 14.11.19.
//

#include "x509.h"
#include <string.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include "helper.h"

#include <openssl/err.h>

/*
 * IETF RFC 5280 says serial number must be <= 20 bytes. Use 159 bits
 * so that the first bit will never be one, so that the DER encoding
 * rules won't force a leading octet.
 */
# define SERIAL_RAND_BITS 159

void x509_wrap_pubkey_free_all(BIO *prikeyin, BIO *pubkeyin, BIO *out, EVP_PKEY *prikey, EVP_PKEY *pubkey, X509 *x);

char *x509_wrap_pubkey(const char *prikeypem, const char *pubkeypem) {
  BIO *prikeyin = NULL;
  BIO *pubkeyin = NULL;
  BIO *out = NULL;
  EVP_PKEY *prikey = NULL;
  EVP_PKEY *pubkey = NULL;
  X509 *x = NULL;
  X509_NAME *n = NULL;

  prikeyin = BIO_from_str(prikeypem);
  prikey = PEM_read_bio_PrivateKey(prikeyin, NULL, NULL, NULL);

  pubkeyin = BIO_from_str(pubkeypem);
  pubkey = PEM_read_bio_PUBKEY(pubkeyin, NULL, NULL, NULL);

  if (prikey == NULL || pubkey == NULL) {
    x509_wrap_pubkey_free_all(prikeyin, pubkeyin, out, prikey, pubkey, x);
    return NULL;
  }

  x = X509_new();

  ASN1_INTEGER_set(X509_get_serialNumber(x), 1);

  X509_gmtime_adj(X509_get_notBefore(x), 0);
  X509_gmtime_adj(X509_get_notAfter(x), 31536000L);

  X509_set_pubkey(x, pubkey);

  n = X509_get_subject_name(x);

  X509_NAME_add_entry_by_txt(n, "C",  MBSTRING_ASC, (unsigned char *)"XX", -1, -1, 0);
  X509_NAME_add_entry_by_txt(n, "O",  MBSTRING_ASC, (unsigned char *)"XX", -1, -1, 0);
  X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (unsigned char *)"XX", -1, -1, 0);

  X509_set_issuer_name(x, n);

  X509_sign(x, prikey, EVP_sha1());

  out = BIO_new(BIO_s_mem());
  BIO_set_mem_eof_return(out, 0);
  PEM_write_bio_X509(out, x);

  if (out == NULL) {
    x509_wrap_pubkey_free_all(prikeyin, pubkeyin, out, prikey, pubkey, x);
    return NULL;
  }

  char *str = str_from_BIO(out);
  x509_wrap_pubkey_free_all(prikeyin, pubkeyin, out, prikey, pubkey, x);

  return str;
}

void x509_wrap_pubkey_free_all(BIO *prikeyin, BIO *pubkeyin, BIO *out, EVP_PKEY *prikey, EVP_PKEY *pubkey, X509 *x) {
  BIO_free_all(prikeyin);
  BIO_free_all(pubkeyin);
  BIO_free_all(out);
  EVP_PKEY_free(prikey);
  EVP_PKEY_free(pubkey);
  X509_free(x);
}
