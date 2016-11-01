/*
 * 
 * Functions to enable multi-threaded use of crypto libraries.
 *
 * OpenSSL -- http://www.openssl.org/docs/crypto/threads.html
 * Libgcrypt -- http://gnupg.org/documentation/manuals/gcrypt/Multi_002dThreading.html
 * 
 * This code is based on Curl 7.21.1
 *
 * See <medusa-thread-ssl.h> for interface declarations.
 *
 */

#include "medusa.h"

/* In OpenSSL <= 1.0.2, an application had to set locking callbacks to use
   OpenSSL in a multi-threaded environment. OpenSSL 1.1.0 now finds pthreads
   or Windows threads, so nothing special is necessary.
*/
#if defined(HAVE_LIBSSL) && (OPENSSL_VERSION_NUMBER < 0x10100005L) 
static pthread_mutex_t *lockarray;

#include <openssl/crypto.h>
static void lock_callback(int mode, int type, char *file, int line)
{
  (void)file;
  (void)line;
  if (mode & CRYPTO_LOCK) {
    pthread_mutex_lock(&(lockarray[type]));
  }
  else {
    pthread_mutex_unlock(&(lockarray[type]));
  }
}

static unsigned long thread_id(void)
{
  unsigned long ret;

  ret=(unsigned long)pthread_self();
  return(ret);
}

void init_locks_openssl(void)
{
  int i;

  lockarray=(pthread_mutex_t *)OPENSSL_malloc(CRYPTO_num_locks() *
                                            sizeof(pthread_mutex_t));
  for (i=0; i<CRYPTO_num_locks(); i++) {
    pthread_mutex_init(&(lockarray[i]),NULL);

  }

  CRYPTO_set_id_callback((unsigned long (*)())thread_id);
  CRYPTO_set_locking_callback((void (*)())lock_callback);
}

void kill_locks_openssl(void)
{
  int i;

  CRYPTO_set_locking_callback(NULL);
  for (i=0; i<CRYPTO_num_locks(); i++)
    pthread_mutex_destroy(&(lockarray[i]));

  OPENSSL_free(lockarray);
}
#endif

#ifdef HAVE_GNUTLS
#include <gnutls/gnutls.h>
#include <gcrypt.h>

GCRY_THREAD_OPTION_PTHREAD_IMPL;

void init_locks_gnutls(void)
{
  gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
  gnutls_global_init();
}
#endif

void init_crypto_locks(void)
{
#if defined(HAVE_LIBSSL) && (OPENSSL_VERSION_NUMBER < 0x10100005L) 
  init_locks_openssl();
#endif

#ifdef HAVE_GNUTLS
  init_locks_gnutls();
#endif
}

void kill_crypto_locks(void)
{
#if defined(HAVE_LIBSSL) && (OPENSSL_VERSION_NUMBER < 0x10100005L) 
  kill_locks_openssl();
#endif
}
