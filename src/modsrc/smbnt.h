/*
**   SMB LAN Manager Password/HASH Checking Medusa Module
**
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
*/

#include <sys/types.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <regex.h>
#include "module.h"
#include "hmacmd5.h"

#define MODULE_NAME    "smbnt.mod"
#define MODULE_AUTHOR  "JoMo-Kun <jmk@foofus.net>"
#define MODULE_SUMMARY_USAGE  "Brute force module for SMB (SMBv1-3, Signing, LM/NTLM/LMv2/NTLMv2) sessions"
#define MODULE_VERSION    "3.0"
#define MODULE_VERSION_SVN "$Id: smbnt.c 9239 2015-05-22 15:03:03Z jmk $"
#define MODULE_SUMMARY_FORMAT  "%s : version %s"
#define MODULE_SUMMARY_FORMAT_WARN  "%s : version %s (%s)"
#define OPENSSL_WARNING "No usable OPENSSL. Module disabled."

#ifdef HAVE_LIBSSL
#include <openssl/evp.h>
#endif

#ifdef HAVE_LIBSMB2
#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
//#include <smb2/libsmb2-raw.h>
//#include <smb2/libsmb2-dcerpc-srvsvc.h>
#endif

#define PORT_NBNS 137
#define PORT_SMB 139
#define PORT_SMBNT 445
#define MODE_AUTO 1
#define MODE_NETBIOS 2
#define MODE_SMB2 3
#define PASSWORD 4
#define HASH 5
#define MACHINE_NAME 6
#define LOCAL 7
#define NTDOMAIN 8
#define BOTH 9
#define OTHER 10
#define PLAINTEXT 11
#define ENCRYPTED 12
#define AUTH_LM 13
#define AUTH_NTLM 14
#define AUTH_LMv2 15
#define AUTH_NTLMv2 16
#define SMBv2 17

#ifndef CHAR_BIT
#define CHAR_BIT 8
#endif

#ifndef TIME_T_MIN
#define TIME_T_MIN ((time_t)0 < (time_t) -1 ? (time_t) 0 \
        : ~ (time_t) 0 << (sizeof (time_t) * CHAR_BIT - 1))
#endif
#ifndef TIME_T_MAX
#define TIME_T_MAX (~ (time_t) 0 - TIME_T_MIN)
#endif

#define IVAL_NC(buf,pos) (*(unsigned int *)((char *)(buf) + (pos))) /* Non const version of above. */
#define SIVAL(buf,pos,val) IVAL_NC(buf,pos)=((unsigned int)(val))

#if (SIZEOF_LONG == 8)
#define TIME_FIXUP_CONSTANT_INT 11644473600L
#elif (SIZEOF_LONG_LONG == 8)
#define TIME_FIXUP_CONSTANT_INT 11644473600LL
#endif

typedef struct __SMBNT_DATA {
#ifdef HAVE_LIBSMB2
  struct smb2_context *smb2;
#endif
  unsigned char challenge[8];
  char workgroup[16];
  char workgroup_other[16];
  unsigned char machine_name[16];
  int security_mode;
  int authLevel;
  int hashFlag;
  int accntFlag;
  int protoFlag;
  int smbVersion;
} _SMBNT_DATA;

// Tells us whether we are to continue processing or not
enum MODULE_STATE
{
  MSTATE_NEW,
  MSTATE_RUNNING,
  MSTATE_EXITING,
  MSTATE_COMPLETE
};

int tryLogin(int hSocket, sLogin** login, _SMBNT_DATA* _psSessionData, char* szLogin, char* szPassword);
int initModule(sLogin* login, _SMBNT_DATA *_psSessionData);

char* parseFullyQualifiedUsername(_SMBNT_DATA *_psSessionData, char* szLogin);
int NBSSessionRequest(int hSocket, _SMBNT_DATA* _psSessionData);
int NBSTATQuery(sLogin *_psLogin,_SMBNT_DATA* _psSessionData);
int SMBNegProt(int hSocket, _SMBNT_DATA* _psSessionData);
unsigned long SMBSessionSetup(int hSocket, sLogin** psLogin, _SMBNT_DATA *_psSessionData, char* szLogin, char* szPassword);

int SMB2NegProt(int hSocket, _SMBNT_DATA* _psSessionData);
unsigned long SMB2SessionSetup(int hSocket, sLogin** psLogin, _SMBNT_DATA *_psSessionData, char* szLogin, char* szPassword);
