/*
**   ------------------------------------------------------------------------
**  Copyright (C) 2024 Joe Mondloch
**  JoMo-Kun / jmk@foofus.net
**
**  This program is free software; you can redistribute it and/or modify
**  it under the terms of the GNU General Public License version 2,
**  as published by the Free Software Foundation
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  http://www.gnu.org/licenses/gpl.txt
**
**  This program is released under the GPL with the additional exemption
**  that compiling, linking, and/or using OpenSSL is allowed.
**
**   ------------------------------------------------------------------------
**
**
** Based on: https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying
**
*/

#include <openssl/evp.h>
#include <openssl/err.h>
#include "module.h"

int hmac_md5(const unsigned char *msg, size_t mlen, unsigned char **val, size_t *vlen, unsigned char *key, size_t key_len)
{
  int result = 0;
  EVP_MD_CTX* ctx = NULL;
  size_t req = 0;
  int rc;

  EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key, key_len);

  if(!msg || !mlen || !val || !pkey)
    return 0;

  *val = NULL;
  *vlen = 0;

  ctx = EVP_MD_CTX_new();
  if (ctx == NULL) {
    writeError(ERR_ERROR, "[HMAC-MD5] EVP_MD_CTX_create failed, error 0x%lx", ERR_get_error());
    goto err;
  }

  rc = EVP_DigestSignInit(ctx, NULL, EVP_md5(), NULL, pkey);
  if (rc != 1) {
    writeError(ERR_ERROR, "[HMAC-MD5] EVP_DigestSignInit failed, error 0x%lx", ERR_get_error());
    goto err;
  }

  rc = EVP_DigestSignUpdate(ctx, msg, mlen);
  if (rc != 1) {
    writeError(ERR_ERROR, "[HMAC-MD5] EVP_DigestSignUpdate failed, error 0x%lx", ERR_get_error());
    goto err;
  }

  rc = EVP_DigestSignFinal(ctx, NULL, &req);
  if (rc != 1) {
    writeError(ERR_ERROR, "[HMAC-MD5] EVP_DigestSignFinal failed (1), error 0x%lx", ERR_get_error());
    goto err;
  }

  *val = OPENSSL_malloc(req);
  if (*val == NULL) {
    writeError(ERR_ERROR, "[HMAC-MD5] OPENSSL_malloc failed, error 0x%lx", ERR_get_error());
    goto err;
  }

  *vlen = req;
  rc = EVP_DigestSignFinal(ctx, *val, vlen);
  if (rc != 1) {
    writeError(ERR_ERROR, "[HMAC-MD5] EVP_DigestSignFinal failed (3), return code %d, error 0x%lx", ERR_get_error());
    goto err;
  }

  result = 1;

 err:
  EVP_MD_CTX_free(ctx);
  if (!result) {
    OPENSSL_free(*val);
    *val = NULL;
  }
  return result;
}
