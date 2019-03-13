//
//  csr.c
//  Krypt
//
//  Created by marko on 27.02.19.
//

#include "csr.h"
#include <string.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

EVP_PKEY *getPrivateKey(const char *key);
void freeAll(X509_REQ *req, BIO *out, EVP_PKEY *key);

char *createCSR(const char *key, const char *country, const char *state, const char *location, const char *organization, const char *organizationUnit, const char *emailAddress) {

  int             ret = 0;
  int             version = 0;

  X509_REQ        *x509_req = NULL;
  X509_NAME       *x509_name = NULL;
  EVP_PKEY        *privateKey = NULL;
  BIO             *out = NULL;

  char *data = NULL;

  // set version of x509 req
  x509_req = X509_REQ_new();
  ret = X509_REQ_set_version(x509_req, version);
  if (ret != 1) {
    freeAll(x509_req, out, privateKey);
    return NULL;
  }

  // set subject of x509 req
  x509_name = X509_NAME_new();

  ret = X509_NAME_add_entry_by_txt(x509_name, "C", MBSTRING_ASC, (const unsigned char*)country, -1, -1, 0);
  if (ret != 1) {
    freeAll(x509_req, out, privateKey);
    return NULL;
  }

  ret = X509_NAME_add_entry_by_txt(x509_name, "ST", MBSTRING_ASC, (const unsigned char*)state, -1, -1, 0);
  if (ret != 1) {
    freeAll(x509_req, out, privateKey);
    return NULL;
  }

  ret = X509_NAME_add_entry_by_txt(x509_name, "L", MBSTRING_ASC, (const unsigned char*)location, -1, -1, 0);
  if (ret != 1) {
    freeAll(x509_req, out, privateKey);
    return NULL;
  }

  ret = X509_NAME_add_entry_by_txt(x509_name, "O", MBSTRING_ASC, (const unsigned char*)organization, -1, -1, 0);
  if (ret != 1) {
    freeAll(x509_req, out, privateKey);
    return NULL;
  }

  ret = X509_NAME_add_entry_by_txt(x509_name, "OU", MBSTRING_ASC, (const unsigned char*)organizationUnit, -1, -1, 0);
  if (ret != 1) {
    freeAll(x509_req, out, privateKey);
    return NULL;
  }

  ret = X509_NAME_add_entry_by_txt(x509_name, "emailAddress", MBSTRING_ASC, (const unsigned char*)emailAddress, -1, -1, 0);
  if (ret != 1) {
    freeAll(x509_req, out, privateKey);
    return NULL;
  }

  ret = X509_REQ_set_subject_name(x509_req, x509_name);
  if (ret != 1) {
    freeAll(x509_req, out, privateKey);
    return NULL;
  }

  // set public key of x509 req
  privateKey = getPrivateKey(key);

  ret = X509_REQ_set_pubkey(x509_req, privateKey);
  if (ret != 1) {
    freeAll(x509_req, out, privateKey);
    return NULL;
  }

  // set sign key of x509 req
  ret = X509_REQ_sign(x509_req, privateKey, EVP_sha256());    // return x509_req->signature->length
  if (ret <= 0) {
    freeAll(x509_req, out, privateKey);
    return NULL;
  }

  // Convert to PEM
  out = BIO_new(BIO_s_mem());
  ret = PEM_write_bio_X509_REQ(out, x509_req);
  if (ret <= 0) {
    freeAll(x509_req, out, privateKey);
    return NULL;
  }

  BUF_MEM* mem;
  BIO_get_mem_ptr(out, &mem);
  data = malloc(mem->length + 1);
  memcpy(data, mem->data, mem->length + 1);
  BIO_flush(out);

  return data;
}

void freeAll(X509_REQ *req, BIO *out, EVP_PKEY *key) {
  X509_REQ_free(req);
  BIO_free_all(out);
  EVP_PKEY_free(key);
}

EVP_PKEY *getPrivateKey(const char *key) {
  BIO *membuf = BIO_new(BIO_s_mem());
  BIO_puts(membuf, key);
  EVP_PKEY *privateKey = PEM_read_bio_PrivateKey(membuf, NULL, 0, NULL);
  return privateKey;
}
