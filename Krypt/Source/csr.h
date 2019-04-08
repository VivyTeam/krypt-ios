//
//  csr.h
//  Krypt
//
//  Created by marko on 27.02.19.
//

#ifndef csr_h
#define csr_h

#include <stdio.h>

//char *createCSR(const char *key, const char *country, const char *state, const char *location, const char *organization, const char *organizationUnit, const char *emailAddress);
char *createCSR(const char *key,
                const char *country,
                const char *state,
                const char *location,
                const char *organization,
                const char *organizationUnit,
                const char *emailAddress,
                const char *uid,
                const char *gn,
                const char *sn);

#endif /* csr_h */
