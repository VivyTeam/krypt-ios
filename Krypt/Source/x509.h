//
//  x509.h
//  Krypt
//
//  Created by marko on 14.11.19.
//

#ifndef x509_h
#define x509_h

#include <stdio.h>

char *x509_wrap_pubkey(const char *prikeypem, const char *pubkeypem);

#endif /* x509_h */
