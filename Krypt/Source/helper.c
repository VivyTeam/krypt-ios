//
//  helper.c
//  Krypt
//
//  Created by Miso Lubarda on 25.04.19.
//

#include "helper.h"
#include <string.h>
#include <openssl/buffer.h>

char *str_from_BIO(BIO *bio) {
  BUF_MEM* mem;
  BIO_get_mem_ptr(bio, &mem);
  char *str = malloc(mem->length);
  memcpy(str, mem->data, mem->length);
  return str;
}

BIO *BIO_from_str(const char *str) {
  BIO *membuf = BIO_new(BIO_s_mem());
  if (BIO_puts(membuf, str) < 1) {
    return NULL;
  }
  return membuf;
}
