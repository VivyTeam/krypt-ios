  //
  //  smime.c
  //  Krypt
  //
  //  Created by marko on 11.04.19.
  //

#include "smime.h"
#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include "helper.h"

/*
 converts PEM encoded certificate to X509
 */
X509 *get_cert(const char *certificate) {
  BIO *cert_membuf = BIO_from_str(certificate);
  if (!cert_membuf) {
    BIO_free(cert_membuf);
    return NULL;
  }
  X509 *x509 = PEM_read_bio_X509(cert_membuf, NULL, NULL, NULL);
  BIO_free(cert_membuf);
  return x509;
}

/**
 Converts SMIME string to PKCS7 object

 @param smime_string String that contains SMIME with encrypted content
 @param bcont Output of SMIME decrypted content in case the signature was in plain text
 @return PKCS7 object as decrypted SMIME content
 */
PKCS7 *get_pkcs7(const char *smime_string, BIO **bcont) {
  BIO* smime_membuf = BIO_new(BIO_s_mem());
    //see error here - http://openssl.6102.n7.nabble.com/SMIME-read-PKCS7-fails-with-memory-BIO-but-works-with-file-BIO-td7673.html
    //if we dont set this, then we get error: 218542222
    //This error, converted to hexadecimal, is 0xd06b08e which when used in
    //$ `openssl errstr d06b08e` gives
    //error:0D06B08E:asn1 encoding routines:ASN1_d2i_bio:not enough data
  BIO_set_mem_eof_return(smime_membuf, 0);
  BIO_puts(smime_membuf, smime_string);
  PKCS7* pkcs7 = SMIME_read_PKCS7(smime_membuf, bcont);
  return pkcs7;
}

// MARK: DECRYPTION

/*
 decrypts the SMIME container
 */
char *decrypt_pkcs7(PKCS7 *pkcs7, EVP_PKEY *pkey) {
  BIO *out = BIO_new(BIO_s_mem());
  
  if (PKCS7_decrypt(pkcs7, pkey, NULL, out, 0) != 1) {
    EVP_PKEY_free(pkey);
    PKCS7_free(pkcs7);
    return NULL;
  }
  
  char *data = str_from_BIO(out);

  return data;
}

/**
 Decrypts SMIME content

 @param encrypted Encrypted SMIME content
 @param privateKey Required private key to decrypt the content
 @return Decrypted SMIME content
 */
char *smime_decrypt(const char *encrypted, const char *privateKey) {
  EVP_PKEY *pkey = get_key(privateKey);
  if (!pkey) {
    return NULL;
  }

  PKCS7 *pkcs7 = get_pkcs7(encrypted, NULL);
  if (!pkcs7) {
    EVP_PKEY_free(pkey);
    return NULL;
  }

  char *data = decrypt_pkcs7(pkcs7, pkey);
  if (data != NULL) {
    EVP_PKEY_free(pkey);
    PKCS7_free(pkcs7);
  }

  return data;
}

// MARK: VERIFICATION

/**
 Generates an instance of X509_STORE and populates it with trusted certificates

 @param certs Collection of certificate strings in form of a pointer to array of strings (char pointers)
 @param certCount Number of provided certificate strings
 @return X509_STORE instance populated with trusted certificates
 */
X509_STORE *store_with_trusted_certs(const char** certs, int certCount) {
  if (!certs) {
    return NULL;
  }
  
  X509_STORE *store = X509_STORE_new();
  
  int success = 1;
  
  for (int i = 0; i < certCount; i++) {
    const char *cert = certs[i];
    X509 *certX509 = get_cert(cert);
    if (!certX509) {
      break;
    }
    
    success &= X509_STORE_add_cert(store, certX509);
    X509_free(certX509);
  }
  
  if (success) {
    return store;
  }
  
  X509_STORE_free(store);
  return NULL;
}

/**
 Checks whether the certificate in the PKCS7 signature belongs to the signer with specific email address.

 @param pkcs7 PKCS7 message to check
 @param email Email to look for in the signature certificate
 @return Returns 1 if the email was found in the signature, otherwise 0.
 @note
 - If the signature contains more than one certificate, only the first one will be checked.
 - If the signature certificate contains more than one email address, only the first one will be checked.
 */
int pkcs7_signature_contains_email(PKCS7 *pkcs7, const char *email) {
  STACK_OF(X509) *cert_stack = PKCS7_get0_signers(pkcs7, NULL, 0);
  X509 *cert = sk_X509_num(cert_stack) ? sk_X509_value(cert_stack, 0) : NULL;
  if (!cert) {
    return 0;
  }
  STACK_OF(OPENSSL_STRING) *emails = X509_get1_email(cert);
  const char *cert_email = sk_OPENSSL_STRING_num(emails) ? sk_OPENSSL_STRING_value(emails, 0) : NULL;

  sk_X509_free(cert_stack);
  sk_OPENSSL_STRING_free(emails);

  return str_equal(email, cert_email);
}

/**
 Verifies the signature of decrypted SMIME content against the trusted certificates

 @param decrypted Decrypted SMIME content
 @param certs Collection of certificate strings in form of a pointer to array of strings (char *certs[])
 @param certCount Number of provided certificate strings
 @param content Returns content of verified MIME content (without signature)
 @return Verification status: 1 = success, 0 = failure
 */
int smime_verify(const char *decrypted, const char *sender_email, const char** certs, int certCount, char **content, enum Smime_error *err) {
  BIO *bcont = NULL;
  
  PKCS7 *pkcs7 = get_pkcs7(decrypted, &bcont);
  if (!pkcs7) {
    unsigned long error = ERR_get_error();
    *err = (enum Smime_error) error;
    return 0;
  }
  
  X509_STORE *store = store_with_trusted_certs(certs, certCount);
  if (!store) {
    PKCS7_free(pkcs7);
    return 0;
  }
  
  BIO *out = BIO_new(BIO_s_mem());

  int flags = 0;

  // get_pkcs7() parses a message in S/MIME format using SMIME_read_PKCS7(). "If *bcont is not NULL then the message is clear text signed. *bcont can then be passed to PKCS7_verify() with the PKCS7_DETACHED flag set" (https://www.openssl.org/docs/man1.1.1/man3/SMIME_read_PKCS7.html)
  if (bcont) {
    flags |= PKCS7_DETACHED;
  }

  //  Prevents usage of any certificate contained in the message as untrusted CA.
  //  "If PKCS7_NOCHAIN is set then the certificates contained in the message are not used as untrusted CAs. This means that the whole verify chain (apart from the signer's certificate) must be contained in the trusted store." (https://www.openssl.org/docs/man1.0.2/man3/PKCS7_verify.html)
  flags |= PKCS7_NOCHAIN;

  if (!pkcs7_signature_contains_email(pkcs7, sender_email)) {
    *err = Smime_error_signature_doesnt_belong_to_sender;
    return 0;
  }

  int ret = PKCS7_verify(pkcs7, NULL, store, bcont, out, flags);
  if (ret == 0) {
    unsigned long error = ERR_get_error();
    *err = (enum Smime_error) error;
  }
  PKCS7_free(pkcs7);
  X509_STORE_free(store);
  BIO_free(bcont);
  
  if (ret && content) {
    *content = str_from_BIO(out);
  }
  
  BIO_free(out);

  return ret;
}
