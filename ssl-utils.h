#ifndef _SSL_UTILS_H_
#define _SSL_UTILS_H_

void ssl_init(void);
EVP_PKEY *ssl_build_key(void);
X509 *ssl_build_cert(EVP_PKEY *key);

#endif
