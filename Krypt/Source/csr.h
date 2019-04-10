//
//  csr.h
//  Krypt
//
//  Created by marko on 27.02.19.
//

#ifndef csr_h
#define csr_h

#include <stdio.h>

/**
 Creates Certificate signing request (CSR) from provided attributes

 @param key Private key on basis of which CSR is created
 @param country X.509 country attribute (C)
 @param state X.509 state attribute (ST)
 @param location X.509 location attribute (L)
 @param organization X.509 organization attribute (O)
 @param organizationUnit X.509 organization unit attribute (OU)
 @param emailAddress X.509 email address attribute (emailAddress)
 @param uniqueIdentifier X.509 unique identifier attribute (UID)
 @param givenName X.509 given name attribute (GN)
 @param surname X.509 surname attribute (SN)
 @return Certificate signing request (CSR)
 */
char *createCSR(const char *key,
                const char *country,
                const char *state,
                const char *location,
                const char *organization,
                const char *organizationUnit,
                const char *emailAddress,
                const char *uniqueIdentifier,
                const char *givenName,
                const char *surname);

#endif /* csr_h */
