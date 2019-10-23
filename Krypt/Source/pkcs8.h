//
//  pkcs8.h
//  Krypt
//
//  Created by Max on 24.06.19.
//

#ifndef pkcs8_h
#define pkcs8_h

#include <stdio.h>

char *convert_pkcs1_to_pkcs8(const char *pem);

char *pkcs8_encrypt(const char *pkcs1, const char *password);

#endif /* pkcs8_h */
