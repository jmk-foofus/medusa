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

#ifndef _MEDUSA_UTILS_H
#define _MEDUSA_UTILS_H

/* How many bytes it will take to store LEN bytes in base64.  */
#define BASE64_LENGTH(len) (4 * (((len) + 2) / 3))

extern int base64_encode(const char *str, int length, char *b64store);
extern int base64_decode(const char *base64, char *to);
extern char *basic_authentication_encode(const char *user, const char *passwd);

/* solaris doesn't have a strcasestr */
#ifndef HAVE_STRCASESTR
char *strcasestr(const char *, const char *);
#endif

#endif
