/* 
**   ------------------------------------------------------------------------
**    Copyright (C) 2024 Joe Mondloch
**    JoMo-Kun / jmk@foofus.net
**
**    This program is free software; you can redistribute it and/or modify
**    it under the terms of the GNU General Public License version 2,
**    as published by the Free Software Foundation
**
**    This program is distributed in the hope that it will be useful,
**    but WITHOUT ANY WARRANTY; without even the implied warranty of
**    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**    GNU General Public License for more details.
**  
**    http://www.gnu.org/licenses/gpl.txt
**  
**    This program is released under the GPL with the additional exemption
**    that compiling, linking, and/or using OpenSSL is allowed.
**
**   ------------------------------------------------------------------------
*/

#ifndef _HMAC_MD5_H

int hmac_md5(const unsigned char *msg, size_t mlen, unsigned char **val, size_t *vlen, unsigned char *key, size_t key_len);

#endif /* _HMAC_MD5_H */
