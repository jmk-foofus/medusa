/* TAKEN from rcf2617.txt */
/*
  Modified calculation of HA1 for MD5-sess. The sample code does not convert
  the result of MD5(username:realm:password) to HEX prior to the final stage
  of the HA1 calculation. Not sure if this due to using a different md5.h/.c
  file set than the original version or if it is indeed a bug in the RFC
  sample code.
*/

/*
#pragma GCC diagnostic push
#pragma GCC diagnostic warning "-Werror"
#pragma GCC diagnostic push
#pragma GCC diagnostic warning "-Wall"
*/

#include <string.h>
#include "http-digest.h"

void CvtHex(
    IN HASH Bin,
    OUT HASHHEX Hex
    )
{
    unsigned short i;
    unsigned char j;

    for (i = 0; i < HASHLEN; i++) {
        j = (Bin[i] >> 4) & 0xf;
        if (j <= 9)
            Hex[i*2] = (j + '0');
         else
            Hex[i*2] = (j + 'a' - 10);
        j = Bin[i] & 0xf;
        if (j <= 9)
            Hex[i*2+1] = (j + '0');
         else
            Hex[i*2+1] = (j + 'a' - 10);
    };
    Hex[HASHHEXLEN] = '\0';
};

/* calculate H(A1) as per spec */
void DigestCalcHA1(
    IN char * pszAlg,
    IN char * pszUserName,
    IN char * pszRealm,
    IN char * pszPassword,
    IN char * pszNonce,
    IN char * pszCNonce,
    OUT HASHHEX SessionKey
    )
{
      EVP_MD_CTX *Md5Ctx;
      unsigned char *md5_digest;
      unsigned int md5_digest_len = HASHLEN;

      /* MD5_Init */
      Md5Ctx = EVP_MD_CTX_new();
      EVP_DigestInit_ex(Md5Ctx, EVP_md5(), NULL);

      /* MD5_Update */
      EVP_DigestUpdate(Md5Ctx, pszUserName, strlen(pszUserName));
      EVP_DigestUpdate(Md5Ctx, ":", 1);
      EVP_DigestUpdate(Md5Ctx, pszRealm, strlen(pszRealm));
      EVP_DigestUpdate(Md5Ctx, ":", 1);
      EVP_DigestUpdate(Md5Ctx, pszPassword, strlen(pszPassword));

      /* MD5_Final */
      md5_digest = (unsigned char *)OPENSSL_malloc(md5_digest_len);
      EVP_DigestFinal_ex(Md5Ctx, md5_digest, &md5_digest_len);
      EVP_MD_CTX_free(Md5Ctx);

      if (strcasecmp(pszAlg, "md5-sess") == 0) {
            CvtHex(md5_digest, SessionKey);

            /* MD5_Init */
            Md5Ctx = EVP_MD_CTX_new();
            EVP_DigestInit_ex(Md5Ctx, EVP_md5(), NULL);

            /* MD5_Update */
            EVP_DigestUpdate(Md5Ctx, SessionKey, strlen(SessionKey));
            EVP_DigestUpdate(Md5Ctx, ":", 1);
            EVP_DigestUpdate(Md5Ctx, pszNonce, strlen(pszNonce));
            EVP_DigestUpdate(Md5Ctx, ":", 1);
            EVP_DigestUpdate(Md5Ctx, pszCNonce, strlen(pszCNonce));

            /* MD5_Final */
            md5_digest = (unsigned char *)OPENSSL_malloc(md5_digest_len);
            EVP_DigestFinal_ex(Md5Ctx, md5_digest, &md5_digest_len);
            EVP_MD_CTX_free(Md5Ctx);
      };

      CvtHex(md5_digest, SessionKey);
};

/* calculate request-digest/response-digest as per HTTP Digest spec */
void DigestCalcResponse(
    IN HASHHEX HA1,           /* H(A1) */
    IN char * pszNonce,       /* nonce from server */
    IN char * pszNonceCount,  /* 8 hex digits */
    IN char * pszCNonce,      /* client nonce */
    IN char * pszQop,         /* qop-value: "", "auth", "auth-int" */
    IN char * pszMethod,      /* method from the request */
    IN char * pszDigestUri,   /* requested URL */
    IN HASHHEX HEntity,       /* H(entity body) if qop="auth-int" */
    OUT HASHHEX Response      /* request-digest or response-digest */
    )
{
      HASHHEX HA2Hex;
      EVP_MD_CTX *Md5Ctx;
      unsigned char *md5_digest;
      unsigned int md5_digest_len = HASHLEN;

      /* MD5_Init */
      Md5Ctx = EVP_MD_CTX_new();
      EVP_DigestInit_ex(Md5Ctx, EVP_md5(), NULL);

      /* MD5_Update */
      EVP_DigestUpdate(Md5Ctx, pszMethod, strlen(pszMethod));
      EVP_DigestUpdate(Md5Ctx, ":", 1);
      EVP_DigestUpdate(Md5Ctx, pszDigestUri, strlen(pszDigestUri));

      if (strcasecmp(pszQop, "auth-int") == 0) {
            EVP_DigestUpdate(Md5Ctx, ":", 1);
            EVP_DigestUpdate(Md5Ctx, HEntity, HASHHEXLEN);
      };

      /* MD5_Final */
      md5_digest = (unsigned char *)OPENSSL_malloc(md5_digest_len);
      EVP_DigestFinal_ex(Md5Ctx, md5_digest, &md5_digest_len);

      CvtHex(md5_digest, HA2Hex);

      // calculate response

      /* MD5_Init */
      Md5Ctx = EVP_MD_CTX_new();
      EVP_DigestInit_ex(Md5Ctx, EVP_md5(), NULL);

      /* MD5_Update */
      EVP_DigestUpdate(Md5Ctx, HA1, HASHHEXLEN);
      EVP_DigestUpdate(Md5Ctx, ":", 1);
      EVP_DigestUpdate(Md5Ctx, pszNonce, strlen(pszNonce));
      EVP_DigestUpdate(Md5Ctx, ":", 1);

      if (*pszQop) {
          EVP_DigestUpdate(Md5Ctx, pszNonceCount, strlen(pszNonceCount));
          EVP_DigestUpdate(Md5Ctx, ":", 1);
          EVP_DigestUpdate(Md5Ctx, pszCNonce, strlen(pszCNonce));
          EVP_DigestUpdate(Md5Ctx, ":", 1);
          EVP_DigestUpdate(Md5Ctx, pszQop, strlen(pszQop));
          EVP_DigestUpdate(Md5Ctx, ":", 1);
      };

      EVP_DigestUpdate(Md5Ctx, HA2Hex, HASHHEXLEN);

      /* MD5_Final */
      md5_digest = (unsigned char *)OPENSSL_malloc(md5_digest_len);
      EVP_DigestFinal_ex(Md5Ctx, md5_digest, &md5_digest_len);

      CvtHex(md5_digest, Response);
};

/*
#pragma GCC diagnostic pop
#pragma GCC diagnostic pop
*/
