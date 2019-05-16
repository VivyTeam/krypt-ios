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

/**
 Checks if strings are equal.

 @param str1 First string to compare
 @param str2 Second string to compare
 @return <#return value description#>
 */
int str_equal(const char *str1, const char *str2);

#endif /* helper_h */
