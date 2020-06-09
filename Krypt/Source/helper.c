//
//  helper.c
//  Krypt
//
//  Created by Miso Lubarda on 25.04.19.
//

#include "helper.h"
#include <string.h>
#include <ctype.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>

/**
 Copies buffer to string, adding NULL termination to string

 @param mem Buffer to copy from
 @return String from the content of buffer
 */
char *copy_mem_buf(BUF_MEM* mem) {
  char *str = malloc(mem->length + 1);
  memcpy(str, mem->data, mem->length);
  str[mem->length] = '\0';
  
  return str;
}

/**
 Copies BIO to string

 @param bio BIO to copy
 @return String from BIO
 */
char *str_from_BIO(BIO *bio) {
  BUF_MEM* mem;
  BIO_get_mem_ptr(bio, &mem);
  
  char *str = copy_mem_buf(mem);
  
//  BUF_MEM_free(mem);
  return str;
}

/**
 Instantiates BIO with string

 @param str String to add to BIO
 @return BIO from string
 */
BIO *BIO_from_str(const char *str) {
  BIO *membuf = BIO_new(BIO_s_mem());
  if (BIO_puts(membuf, str) < 1) {
    return NULL;
  }
  return membuf;
}

int str_equal(const char *str1, const char *str2) {
  return strcasecmp(str1, str2) == 0 ? 1 : 0;
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

