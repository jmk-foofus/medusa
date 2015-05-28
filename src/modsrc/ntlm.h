/*
**   NTLM Authentication Protocol Support Functions 
**
**   ------------------------------------------------------------------------
**    Copyright (C) 2008 Joe Mondloch
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
**
**   Functions for processing Type-1, Type-2 and Type-3 messages used during
**   NTLM authentication. The following document is an excellent resource 
**   on this topic:
**
**   http://davenport.sourceforge.net/ntlm.html
**
**   The ntlm.h/.c files combine content from multiple sources into a single
**   convenient location. It is based on code contributed to the Hydra 
**   project (ilo@reversing.org) along with analysis of the Fetchmail and 
**   Samba source.
*/

#ifndef _MEDUSA_NTLM_H_
#define _MEDUSA_NTLM_H_

#include <openssl/md5.h>
#include "../medusa-trace.h"

/* 
 These structures are byte-order dependant, and should not
 be manipulated except by the use of the routines provided
*/
typedef unsigned short uint16;
typedef unsigned int   uint32;
typedef unsigned char  uint8;

typedef struct
{
  uint16  len;
  uint16  maxlen;
  uint32  offset;
} tSmbStrHeader;

typedef struct
{
  char          ident[8];
  uint32        msgType;
  uint32        flags;
  tSmbStrHeader host;
  tSmbStrHeader domain;
  uint8         buffer[1024];
  uint32        bufIndex;
} tSmbNtlmAuthRequest;

typedef struct
{
  char          ident[8];
  uint32        msgType;
  tSmbStrHeader uDomain;
  uint32        flags;
  uint8         challengeData[8];
  uint8         reserved[8];
  tSmbStrHeader emptyString;
  uint8         buffer[1024];
  uint32        bufIndex;
} tSmbNtlmAuthChallenge;

typedef struct
{
  char          ident[8];
  uint32        msgType;
  tSmbStrHeader lmResponse;
  tSmbStrHeader ntResponse;
  tSmbStrHeader uDomain;
  tSmbStrHeader uUser;
  tSmbStrHeader uWks;
  tSmbStrHeader sessionKey;
  uint32        flags;
  uint8         buffer[1024];
  uint32        bufIndex;
} tSmbNtlmAuthResponse;

/* - public - */

#define SmbLength(ptr) (((ptr)->buffer - (uint8*)(ptr)) + (ptr)->bufIndex)

/*
  A flags value of 0 selects the minimum security level.
  Host and domain values are optional and can be set to NULL.
*/
void buildAuthRequest(tSmbNtlmAuthRequest *request, long flags, char *host, char *domain);

/*
  Generates a Type-3 response for a given Type-2 request (challenge) and user credentials.
  If the user defines the optional parameters (flags, host, and domain), these values
  will superseed what the server specified. Leave the values set to 0 and NULL to use
  the server specified values.
*/
void buildAuthResponse(tSmbNtlmAuthChallenge *challenge, tSmbNtlmAuthResponse *response, long flags, char *user, char *password, char *domain, char *host);

/* Debugging Functions */
void dumpAuthRequest(tSmbNtlmAuthRequest *request);
void dumpAuthChallenge(tSmbNtlmAuthChallenge *challenge);
void dumpAuthResponse(tSmbNtlmAuthResponse *response);

#endif
