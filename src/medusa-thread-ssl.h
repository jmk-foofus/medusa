/*
 * 
 * Functions to enable multi-threaded use of crypto libraries.
 *
 * OpenSSL -- http://www.openssl.org/docs/crypto/threads.html
 * Libgcrypt -- http://gnupg.org/documentation/manuals/gcrypt/Multi_002dThreading.html
 *
 */

extern void init_crypto_locks(void);
extern void kill_crypto_locks(void);
