//
//  helper.h
//  Krypt
//
//  Created by Miso Lubarda on 25.04.19.
//

#ifndef helper_h
#define helper_h

#include <stdio.h>
#include <openssl/bio.h>

char *str_from_BIO(BIO *bio);
BIO *BIO_from_str(const char *str);

#endif /* helper_h */
