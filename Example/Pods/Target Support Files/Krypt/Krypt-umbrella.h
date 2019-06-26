#ifdef __OBJC__
#import <UIKit/UIKit.h>
#else
#ifndef FOUNDATION_EXPORT
#if defined(__cplusplus)
#define FOUNDATION_EXPORT extern "C"
#else
#define FOUNDATION_EXPORT extern
#endif
#endif
#endif

#import "csr.h"
#import "helper.h"
#import "pkcs8.h"
#import "smime.h"

FOUNDATION_EXPORT double KryptVersionNumber;
FOUNDATION_EXPORT const unsigned char KryptVersionString[];

