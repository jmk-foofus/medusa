/*
 * Medusa Parallel Login Auditor
 *
 *    Copyright (C) 2006 Joe Mondloch
 *    JoMo-Kun / jmk@foofus.net
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License version 2,
 *    as published by the Free Software Foundation
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    http://www.gnu.org/licenses/gpl.txt
 *
 *    This program is released under the GPL with the additional exemption
 *    that compiling, linking, and/or using OpenSSL is allowed.
 *
*/

#include "medusa.h"
#include "medusa-trace.h"
#include "medusa-utils.h"

/* Base64 Functions used from Wget (http://wget.sunsite.dk/) */

/* Encode the string STR of length LENGTH to base64 format and place it
   to B64STORE.  The output will be \0-terminated, and must point to a
   writable buffer of at least 1+BASE64_LENGTH(length) bytes.  It
   returns the length of the resulting base64 data, not counting the
   terminating zero.

   This implementation will not emit newlines after 76 characters of
   base64 data.  */
int base64_encode(const char *str, int length, char *b64store)
{
  /* Conversion table.  */
  static char tbl[64] = {
    'A','B','C','D','E','F','G','H',
    'I','J','K','L','M','N','O','P',
    'Q','R','S','T','U','V','W','X',
    'Y','Z','a','b','c','d','e','f',
    'g','h','i','j','k','l','m','n',
    'o','p','q','r','s','t','u','v',
    'w','x','y','z','0','1','2','3',
    '4','5','6','7','8','9','+','/'
  };
  int i;
  const unsigned char *s = (const unsigned char *) str;
  char *p = b64store;

  /* Transform the 3x8 bits to 4x6 bits, as required by base64.  */
  for (i = 0; i < length; i += 3)
    {
      *p++ = tbl[s[0] >> 2];
      *p++ = tbl[((s[0] & 3) << 4) + (s[1] >> 4)];
      *p++ = tbl[((s[1] & 0xf) << 2) + (s[2] >> 6)];
      *p++ = tbl[s[2] & 0x3f];
      s += 3;
    }

  /* Pad the result if necessary...  */
  if (i == length + 1)
    *(p - 1) = '=';
  else if (i == length + 2)
    *(p - 1) = *(p - 2) = '=';

  /* ...and zero-terminate it.  */
  *p = '\0';

  return p - b64store;
}

#define IS_ASCII(c) (((c) & 0x80) == 0)
#define IS_BASE64(c) ((IS_ASCII (c) && base64_char_to_value[c] >= 0) || c == '=')

/* Get next character from the string, except that non-base64
   characters are ignored, as mandated by rfc2045.  */
#define NEXT_BASE64_CHAR(c, p) do {     \
  c = *p++;           \
} while (c != '\0' && !IS_BASE64 (c))

/* Decode data from BASE64 (assumed to be encoded as base64) into
   memory pointed to by TO.  TO should be large enough to accomodate
   the decoded data, which is guaranteed to be less than
   strlen(base64).

   Since TO is assumed to contain binary data, it is not
   NUL-terminated.  The function returns the length of the data
   written to TO.  -1 is returned in case of error caused by malformed
   base64 input.  */

int
base64_decode (const char *base64, char *to)
{
  /* Table of base64 values for first 128 characters.  Note that this
     assumes ASCII (but so does Wget in other places).  */
  static short base64_char_to_value[128] =
    {
      -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  /*   0-  9 */
      -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  /*  10- 19 */
      -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  /*  20- 29 */
      -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  /*  30- 39 */
      -1,  -1,  -1,  62,  -1,  -1,  -1,  63,  52,  53,  /*  40- 49 */
      54,  55,  56,  57,  58,  59,  60,  61,  -1,  -1,  /*  50- 59 */
      -1,  -1,  -1,  -1,  -1,  0,   1,   2,   3,   4, /*  60- 69 */
      5,   6,   7,   8,   9,   10,  11,  12,  13,  14,  /*  70- 79 */
      15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  /*  80- 89 */
      25,  -1,  -1,  -1,  -1,  -1,  -1,  26,  27,  28,  /*  90- 99 */
      29,  30,  31,  32,  33,  34,  35,  36,  37,  38,  /* 100-109 */
      39,  40,  41,  42,  43,  44,  45,  46,  47,  48,  /* 110-119 */
      49,  50,  51,  -1,  -1,  -1,  -1,  -1   /* 120-127 */
    };

  const char *p = base64;
  char *q = to;

  while (1)
  {
    unsigned char c;
    unsigned long value;

    /* Process first byte of a quadruplet.  */
    NEXT_BASE64_CHAR (c, p);
    if (!c)
      break;
    if (c == '=')
      return -1;    /* illegal '=' while decoding base64 */
    value = base64_char_to_value[c] << 18;

    /* Process scond byte of a quadruplet.  */
    NEXT_BASE64_CHAR (c, p);
    if (!c)
      return -1;    /* premature EOF while decoding base64 */
    if (c == '=')
      return -1;    /* illegal `=' while decoding base64 */
    value |= base64_char_to_value[c] << 12;
    *q++ = value >> 16;

    /* Process third byte of a quadruplet.  */
    NEXT_BASE64_CHAR (c, p);
    if (!c)
      return -1;    /* premature EOF while decoding base64 */

    if (c == '=')
    {
      NEXT_BASE64_CHAR (c, p);
      if (!c)
        return -1;    /* premature EOF while decoding base64 */
      if (c != '=')
        return -1;    /* padding `=' expected but not found */
      continue;
    }

    value |= base64_char_to_value[c] << 6;
    *q++ = 0xff & value >> 8;

    /* Process fourth byte of a quadruplet.  */
    NEXT_BASE64_CHAR (c, p);
    if (!c)
      return -1;    /* premature EOF while decoding base64 */
    if (c == '=')
      continue;

    value |= base64_char_to_value[c];
    *q++ = 0xff & value;
  }

  return q - to;
}

/* Create the authentication header contents for the `Basic' scheme.
   This is done by encoding the string "USER:PASS" to base64 and
   prepending the string "Basic " in front of it.  */
char *basic_authentication_encode(const char *user, const char *passwd)
{
  char *t1, *t2;
  int len1 = strlen (user) + 1 + strlen (passwd);

  t1 = (char *)alloca (len1 + 1);
  sprintf (t1, "%s:%s", user, passwd);

  t2 = (char *)malloc (BASE64_LENGTH (len1) + 1);
  base64_encode (t1, len1, t2);

  return (t2);
}
/* End Wget Base64 Functions */

/* Solaris doesn't have a strcasestr */
#ifndef HAVE_STRCASESTR
char *strcasestr(const char *a, const char *b) {
  size_t l;
  char f[3];

  snprintf(f, sizeof(f), "%c%c", tolower(*b), toupper(*b));
  for (l = strcspn(a, f); l != strlen(a); l += strcspn(a + l + 1, f) + 1)
    if (strncasecmp(a + l, b, strlen(b)) == 0)
      return((char *) a + l);
    return(NULL);
}
#endif

/* Solaris (10x86, at least) does not appear to have asprintf/vasprintf functions
   Function code taken from ndoutils_sunos.c
*/
#ifndef HAVE_VASPRINTF
#define CHUNKSIZE 512
int vasprintf(char **ret, const char *fmt, va_list ap)
{
  int chunks;
  size_t buflen;
  char *buf;
  int len;

  chunks = ((strlen(fmt) + 1) / CHUNKSIZE) + 1;
  buflen = chunks * CHUNKSIZE;

  for (;;) {
    if ((buf = malloc(buflen)) == NULL) {
      *ret = NULL;
      return -1;
    }
    len = vsnprintf(buf, buflen, fmt, ap);
    if (len >= 0 && len < (buflen - 1)) {
      break;
    }
    free(buf);
    buflen = (++chunks) * CHUNKSIZE;

    /*
    * len >= 0 are required for vsnprintf implementation that
    * return -1 of buffer insufficient
    */
    if (len >= 0 && len >= buflen) {
      buflen = len + 1;
    }
  }

  *ret = buf;
  return len;
  FILE *fp;
  *ret = NULL;
}
#endif

#ifndef HAVE_ASPRINTF
int asprintf(char **ret, const char *fmt, ...)
{
  int len;
  va_list ap;

  va_start(ap, fmt);
  len = vasprintf(ret, fmt, ap);
  va_end(ap);
  return len;
}
#endif
