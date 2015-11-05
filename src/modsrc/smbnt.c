/*
**   SMB LAN Manager Password/HASH Checking Medusa Module
**
**   ------------------------------------------------------------------------
**    Copyright (C) 2009 Joe Mondloch
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
**   Based on code from: SMB Auditing Tool
**   [Copyright (C) Patrik Karlsson 2001]
**
**   This code allows Medusa to directly test NTLM hashes against
**   a Windows host. This may be useful for an auditor who has aquired
**   a sam._ or pwdump file and would like to quickly determine
**   which are valid entries.
**
**   Several "-m 'METHOD:VALUE'" options can be used with this module. The
**   following are valid methods: GROUP, GROUP_OTHER, PASS, AUTH and NETBIOS.
**   The following values are useful for these methods:
**
**   GROUP:?
**     LOCAL  == Check local account.
**     DOMAIN == Check credentials against this hosts primary
**               domain controller via this host.
**     BOTH   == Check both. This leaves the workgroup field set
**               blank and then attempts to check the credentials
**               against the host. If the account does not exist
**               locally on the host being tested, that host then
**               queries its domain controller.
**
**   GROUP_OTHER:?
**     Configure arbitrary domain for host to authenticate against.
**
**   PASS:?
**     PASSWORD == Use a normal password.
**     HASH     == Use a NTLM hash rather than a password.
**     MACHINE  == Use the Machine's NetBIOS name as the password.
**
**   AUTH:?
**     LM      == LM authentication (case-insensitive)
**     NTLM    == NTLMv1 authentication
**     LMv2    == LMv2 authentication
**     NTLMv2  == NTLMv2 authentication
**
**   NETBIOS
**     Force NetBIOS Mode (Disable Native Win2000 Mode)
**
**   Be careful of mass domain account lockout with this. For
**   example, assume you are checking several accounts against
**   many domain workstations. If you are not using the 'LOCAL'
**   option and these accounts do not exist locally on the
**   workstations, each workstation will in turn check their
**   respective domain controller. This could cause a bunch of
**   lockouts. Of course, it'd look like the workstations, not
**   you, were doing it. ;)
**
**   **FYI, this code is unable to test accounts on default XP
**   hosts which are not part of a domain and do not have normal
**   file sharing enabled. Default XP does not allow shares and
**   returns STATUS_LOGON_FAILED for both valid and invalid
**   credentials. XP with simple sharing enabled returns SUCCESS
**   for both valid and invalid credentials. If anyone knows a
**   way to test in these configurations...
**
**   See http://www.foofus.net/jmk/passhash.html for further
**   examples.
*/

#include <sys/types.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "module.h"

#define MODULE_NAME    "smbnt.mod"
#define MODULE_AUTHOR  "JoMo-Kun <jmk@foofus.net>"
#define MODULE_SUMMARY_USAGE  "Brute force module for SMB (LM/NTLM/LMv2/NTLMv2) sessions"
#define MODULE_VERSION    "2.1"
#define MODULE_VERSION_SVN "$Id: smbnt.c 9239 2015-05-22 15:03:03Z jmk $"
#define MODULE_SUMMARY_FORMAT  "%s : version %s"
#define MODULE_SUMMARY_FORMAT_WARN  "%s : version %s (%s)"
#define OPENSSL_WARNING "No usable OPENSSL. Module disabled."

#ifdef HAVE_LIBSSL

#include <openssl/md5.h>
#include <openssl/md4.h>
#include <openssl/des.h>
#include "hmacmd5.h"

#define PORT_NBNS 137
#define PORT_SMB 139
#define PORT_SMBNT 445
#define WIN2000_NATIVEMODE 1
#define WIN_NETBIOSMODE 2
#define PASSWORD 3
#define HASH 4
#define MACHINE_NAME 5
#define LOCAL 6
#define NTDOMAIN 7
#define BOTH 8
#define OTHER 9
#define PLAINTEXT 10
#define ENCRYPTED 11
#define AUTH_LM 12
#define AUTH_NTLM 13
#define AUTH_LMv2 14
#define AUTH_NTLMv2 15

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
  unsigned char challenge[8];
  char workgroup[16];
  char workgroup_other[16];
  unsigned char machine_name[16];
  int security_mode;
  int authLevel;
  int hashFlag;
  int accntFlag;
  int protoFlag;
} _SMBNT_DATA;

// Tells us whether we are to continue processing or not
enum MODULE_STATE
{
  MSTATE_NEW,
  MSTATE_RUNNING,
  MSTATE_EXITING,
  MSTATE_COMPLETE
};

// Forward declarations
int tryLogin(int hSocket, sLogin** login, _SMBNT_DATA* _psSessionData, char* szLogin, char* szPassword);
int initModule(sLogin* login, _SMBNT_DATA *_psSessionData);
char* parseFullyQualifiedUsername(_SMBNT_DATA *_psSessionData, char* szLogin);
int NBSSessionRequest(int hSocket, _SMBNT_DATA* _psSessionData);
int NBSTATQuery(sLogin *_psLogin,_SMBNT_DATA* _psSessionData);
int SMBNegProt(int hSocket, _SMBNT_DATA* _psSessionData);

extern void hmac_md5_init_limK_to_64(const unsigned char* key, int key_len, HMACMD5Context *ctx);
extern void hmac_md5_update(const unsigned char *text, int text_len, HMACMD5Context *ctx);
extern void hmac_md5_final(unsigned char *digest, HMACMD5Context *ctx);

// Tell medusa how many parameters this module allows
int getParamNumber()
{
  return 0;    // we don't need no stinking parameters
}

// Displays information about the module and how it must be used
void summaryUsage(char **ppszSummary)
{
  // Memory for ppszSummary will be allocated here - caller is responsible for freeing it
  int  iLength = 0;

  if (*ppszSummary == NULL)
  {
    iLength = strlen(MODULE_SUMMARY_USAGE) + strlen(MODULE_VERSION) + strlen(MODULE_SUMMARY_FORMAT) + 1;
    *ppszSummary = (char*)malloc(iLength);
    memset(*ppszSummary, 0, iLength);
    snprintf(*ppszSummary, iLength, MODULE_SUMMARY_FORMAT, MODULE_SUMMARY_USAGE, MODULE_VERSION);
  } 
  else 
  {
    writeError(ERR_ERROR, "%s reports an error in summaryUsage() : ppszSummary must be NULL when called", MODULE_NAME);
  }
}

/* Display module usage information */
void showUsage()
{
  writeVerbose(VB_NONE, "%s (%s) %s :: %s\n", MODULE_NAME, MODULE_VERSION, MODULE_AUTHOR, MODULE_SUMMARY_USAGE);
  writeVerbose(VB_NONE, "Available module options:");
  writeVerbose(VB_NONE, "  GROUP:? (DOMAIN, LOCAL*, BOTH)");
  writeVerbose(VB_NONE, "    Option sets NetBIOS workgroup field.");
  writeVerbose(VB_NONE, "    DOMAIN: Check credentials against this hosts primary domain controller via this host.");
  writeVerbose(VB_NONE, "    LOCAL:  Check local account.");
  writeVerbose(VB_NONE, "    BOTH:   Check both. This leaves the workgroup field set blank and then attempts to check");
  writeVerbose(VB_NONE, "            the credentials against the host. If the account does not exist locally on the ");
  writeVerbose(VB_NONE, "            host being tested, that host then queries its domain controller.");
  writeVerbose(VB_NONE, "  GROUP_OTHER:? ");
  writeVerbose(VB_NONE, "    Option allows manual setting of domain to check against. Use instead of GROUP.");
  writeVerbose(VB_NONE, "  PASS:?  (PASSWORD*, HASH, MACHINE)");
  writeVerbose(VB_NONE, "    PASSWORD: Use normal password.");
  writeVerbose(VB_NONE, "    HASH:     Use a NTLM hash rather than a password.");
  writeVerbose(VB_NONE, "    MACHINE:  Use the machine's NetBIOS name as the password.");
  writeVerbose(VB_NONE, "  AUTH:?  (LM, NTLM, LMv2*, NTLMv2)");
  writeVerbose(VB_NONE, "    Option sets LAN Manager Authentication level.");
  writeVerbose(VB_NONE, "    LM: ");
  writeVerbose(VB_NONE, "    NTLM: ");
  writeVerbose(VB_NONE, "    LMv2: ");
  writeVerbose(VB_NONE, "    NTLMv2: ");
  writeVerbose(VB_NONE, "  NETBIOS");
  writeVerbose(VB_NONE, "    Force NetBIOS Mode (Disable Native Win2000 Mode). Win2000 mode is the default.");
  writeVerbose(VB_NONE, "    Default mode is to test TCP/445 using Native Win2000. If this fails, module will");
  writeVerbose(VB_NONE, "    fall back to TCP/139 using NetBIOS mode. To test only TCP/139, use the following:");
  writeVerbose(VB_NONE, "    medusa -M smbnt -m NETBIOS -n 139");
  writeVerbose(VB_NONE, "\n(*) Default value");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "Usage examples:");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "1: Normal boring check..."); 
  writeVerbose(VB_NONE, "    medusa -M smbnt -h somehost -u someuser -p somepassword");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "2: Testing domain credentials against a client system..."); 
  writeVerbose(VB_NONE, "    medusa -M smbnt -h somehost -U users.txt -p password -m GROUP:DOMAIN");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "3: Testing each credential from a PwDump file against the target's domain via the target..."); 
  writeVerbose(VB_NONE, "    medusa -M smbnt -h somehost -C pwdump.txt -m PASS:HASH -m GROUP:DOMAIN");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "4: Testing each hash from a PwDump file against a specific user local to the target..."); 
  writeVerbose(VB_NONE, "    medusa -M smbnt -H hosts.txt -C pwdump.txt -u someuser -m PASS:HASH");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "5: Testing an individual NTLM hash..."); 
  writeVerbose(VB_NONE, "    medusa -M smbnt -H hosts.txt -u administrator -p 92D887C8010492C2944E2DF489A880E4:7A2EDE4F51BC5A03984C6BA2C239CF63::: -m PASS:HASH");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "Access level:");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "This module performs both an SMB authentication request (Session Setup AndX) and a ");
  writeVerbose(VB_NONE, "share connection request (Tree Connect AndX). The share connection request is for the ");
  writeVerbose(VB_NONE, "default hidden administrative share ADMIN$. The goal is to identify if the credentials ");
  writeVerbose(VB_NONE, "being tested have administrative rights to the target system. The following examples ");
  writeVerbose(VB_NONE, "highlight how to interrupt the responses.");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "  Valid administrative-level credentials: [SUCCESS (ADMIN$ - Access Allowed)]");
  writeVerbose(VB_NONE, "  Valid user-level credentials: [SUCCESS (ADMIN$ - Access Denied)]");
  writeVerbose(VB_NONE, "  Valid credentials, access level unknown: [SUCCESS (ADMIN$ - Share Unavailable)]");
  writeVerbose(VB_NONE, "");
}

// The "main" of the medusa module world - this is what gets called to actually do the work
int go(sLogin* logins, int argc, char *argv[])
{
  int i;
  char *strtok_ptr = NULL, *pOpt = NULL, *pOptTmp = NULL;
  _SMBNT_DATA *psSessionData = NULL;
  psSessionData = malloc(sizeof(_SMBNT_DATA));  
  memset(psSessionData, 0, sizeof(_SMBNT_DATA));

  if ((argc < 0) || (argc > 5))
  {
    writeError(ERR_ERROR, "%s: Incorrect number of parameters passed to module (%d). Use \"-q\" option to display module usage.", MODULE_NAME, argc);
    return FAILURE;
  }
  else 
  {
    writeError(ERR_DEBUG_MODULE, "OMG teh %s module has been called!!", MODULE_NAME);
 
    psSessionData->authLevel = AUTH_LMv2;
    psSessionData->accntFlag = LOCAL;
    psSessionData->hashFlag = PASSWORD;
    psSessionData->protoFlag = WIN2000_NATIVEMODE;

    for (i=0; i<argc; i++) {
      pOptTmp = malloc( strlen(argv[i]) + 1);
      memset(pOptTmp, 0, strlen(argv[i]) + 1);
      strncpy(pOptTmp, argv[i], strlen(argv[i]));
      writeError(ERR_DEBUG_MODULE, "Processing complete option: %s", pOptTmp);
      pOpt = strtok_r(pOptTmp, ":", &strtok_ptr);
      writeError(ERR_DEBUG_MODULE, "Processing option: %s", pOpt);
      
      if (strcmp(pOpt, "GROUP") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if (pOpt == NULL)
          writeError(ERR_WARNING, "Method GROUP requires value to be set.");
        else if (strcmp(pOpt, "LOCAL") == 0)
          psSessionData->accntFlag = LOCAL;
        else if (strcmp(pOpt, "DOMAIN") == 0)
          psSessionData->accntFlag = NTDOMAIN;
        else if (strcmp(pOpt, "BOTH") == 0)
          psSessionData->accntFlag = BOTH;
        else
          writeError(ERR_WARNING, "Invalid value for method GROUP.");
      }
      else if (strcmp(pOpt, "GROUP_OTHER") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);
    
        if ( pOpt )
        {
          strncpy((char *) psSessionData->workgroup_other, pOpt, 16);
          psSessionData->accntFlag = OTHER;
        }
        else
          writeError(ERR_WARNING, "Method GROUP_OTHER requires value to be set.");
      }
      else if (strcmp(pOpt, "PASS") == 0) {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);
        
        if (pOpt == NULL)
          writeError(ERR_WARNING, "Method PASS requires value to be set.");
        else if (strcmp(pOpt, "PASSWORD") == 0)
          psSessionData->hashFlag = PASSWORD;
        else if (strcmp(pOpt, "HASH") == 0)
          psSessionData->hashFlag = HASH;
        else if (strcmp(pOpt, "MACHINE") == 0)
          psSessionData->hashFlag = MACHINE_NAME;
        else
          writeError(ERR_WARNING, "Invalid value for method PASS.");
      }
      else if (strcmp(pOpt, "AUTH") == 0) {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);
        
        if (pOpt == NULL)
          writeError(ERR_WARNING, "Method AUTH requires value to be set.");
        else if (strcmp(pOpt, "LM") == 0)
          psSessionData->authLevel = AUTH_LM;
        else if (strcmp(pOpt, "NTLM") == 0)
          psSessionData->authLevel = AUTH_NTLM;
        else if (strcmp(pOpt, "LMv2") == 0)
          psSessionData->authLevel = AUTH_LMv2;
        else if (strcmp(pOpt, "NTLMv2") == 0)
        {
          psSessionData->authLevel = AUTH_NTLMv2;
          /* NTLMv2 authentication is returning a STATUS_INVALID_PARAMETER response with 2012R2 servers. This issue pre-dates the AndX modification. */
          writeError(ERR_FATAL, "NTLMv2 support currently disabled. The default authentication mode of LMv2 should work in all cases that NTLMv2 is required.");
        }
        else
          writeError(ERR_WARNING, "Invalid value for method AUTH.");
      }
      else if (strcmp(pOpt, "NETBIOS") == 0)
      {
        psSessionData->protoFlag = WIN_NETBIOSMODE;
      }
      else 
      {
        writeError(ERR_WARNING, "Invalid method: %s.", pOpt);
      }
    
      FREE(pOptTmp);
    }
 
    initModule(logins, psSessionData);
  }  

  FREE(psSessionData);
  return SUCCESS;
}

int initModule(sLogin* psLogin, _SMBNT_DATA *_psSessionData)
{
  int hSocket = -1;
  enum MODULE_STATE nState = MSTATE_NEW;
  char *szUser = NULL;
  sConnectParams params;
  sCredentialSet *psCredSet = NULL;

  psCredSet = malloc( sizeof(sCredentialSet) );
  memset(psCredSet, 0, sizeof(sCredentialSet));
 
  if (getNextCredSet(psLogin, psCredSet) == FAILURE)
  {
    writeError(ERR_ERROR, "[%s] Error retrieving next credential set to test.", MODULE_NAME);
    nState = MSTATE_COMPLETE;
  }
  else if (psCredSet->psUser)
  {  
    writeError(ERR_DEBUG_MODULE, "[%s] module started for host: %s user: %s", MODULE_NAME, psLogin->psServer->pHostIP, psCredSet->psUser->pUser);
    szUser = parseFullyQualifiedUsername(_psSessionData, psCredSet->psUser->pUser);
  }
  else
  {
    writeError(ERR_DEBUG_MODULE, "[%s] module started for host: %s - no more available users to test.", MODULE_NAME);
    nState = MSTATE_COMPLETE;
  }

  memset(&params, 0, sizeof(sConnectParams));
  
  if (psLogin->psServer->psAudit->iPortOverride > 0)
    params.nPort = psLogin->psServer->psAudit->iPortOverride;
  else
    params.nPort = PORT_SMBNT;
  
  initConnectionParams(psLogin, &params);

  while (nState != MSTATE_COMPLETE)
  {  
    switch (nState)
    {
      case MSTATE_NEW:
        // Already have an open socket - close it
        if (hSocket > 0)
          medusaDisconnect(hSocket);
  
        if (params.nPort == PORT_SMBNT) {
          hSocket = medusaConnect(&params);
          if ( hSocket < 0 ) {
            writeError(ERR_NOTICE, "%s Failed to establish WIN2000_NATIVE mode. Attempting WIN_NETBIOS mode.)", MODULE_NAME);
            params.nPort = PORT_SMB;
            _psSessionData->protoFlag = WIN_NETBIOSMODE;
            hSocket = medusaConnect(&params);
          }
        }
        else {
          hSocket = medusaConnect(&params);
        }
        
        if (hSocket < 0) 
        {
          writeError(ERR_ERROR, "%s: failed to connect, port %d was not open on %s", MODULE_NAME, params.nPort, psLogin->psServer->pHostIP);
          psLogin->iResult = LOGIN_RESULT_UNKNOWN;
          return FAILURE;
        }

        writeError(ERR_DEBUG_MODULE, "Connected");
 
        if (NBSTATQuery(psLogin, _psSessionData) < 0) {
          writeError(ERR_ERROR, "NetBIOS Name Query Failed with host: %s (proceeding anyways).", psLogin->psServer->pHostIP);
        }
        
        if (NBSSessionRequest(hSocket, _psSessionData) < 0) {
          writeError(ERR_ERROR, "Session Setup Failed with host: %s. Is the server service running?", psLogin->psServer->pHostIP);
          psLogin->iResult = LOGIN_RESULT_UNKNOWN;
          return FAILURE;
        }
        
        if (SMBNegProt(hSocket, _psSessionData) < 0)
        {
          writeError(ERR_ERROR, "SMB Protocol Negotiation Failed with host: %s", psLogin->psServer->pHostIP);
          psLogin->iResult = LOGIN_RESULT_UNKNOWN;
          return FAILURE;
        }
        else {
          nState = MSTATE_RUNNING;
        }
        
        break;
      case MSTATE_RUNNING:
        nState = tryLogin(hSocket, &psLogin, _psSessionData, szUser, psCredSet->pPass);
        
        if (psLogin->iResult != LOGIN_RESULT_UNKNOWN)
        {
          if (getNextCredSet(psLogin, psCredSet) == FAILURE)
          {
            writeError(ERR_ERROR, "[%s] Error retrieving next credential set to test.", MODULE_NAME);
            nState = MSTATE_EXITING;
          }
          else
          {
            if (psCredSet->iStatus == CREDENTIAL_DONE)
            {
              writeError(ERR_DEBUG_MODULE, "[%s] No more available credential sets to test.", MODULE_NAME);
              nState = MSTATE_EXITING;
            }
            else if (psCredSet->iStatus == CREDENTIAL_NEW_USER)
            {
              writeError(ERR_DEBUG_MODULE, "[%s] Starting testing for new user: %s.", MODULE_NAME, psCredSet->psUser->pUser);
              FREE(szUser);
              szUser = parseFullyQualifiedUsername(_psSessionData, psCredSet->psUser->pUser);
              nState = MSTATE_NEW;
            }
            else
              writeError(ERR_DEBUG_MODULE, "[%s] Next credential set - user: %s password: %s", MODULE_NAME, psCredSet->psUser->pUser, psCredSet->pPass);
          }
        }
        break;
      case MSTATE_EXITING:
        if (hSocket > 0)
          medusaDisconnect(hSocket);
        hSocket = -1;
        nState = MSTATE_COMPLETE;
        break;
      default:
        writeError(ERR_CRITICAL, "Unknown %s module (%d) state %d host: %s", MODULE_NAME, psLogin->iId, nState, psLogin->psServer->pHostIP);
        if (hSocket > 0)
          medusaDisconnect(hSocket);
        hSocket = -1;
        psLogin->iResult = LOGIN_RESULT_UNKNOWN;
        return FAILURE;
    }  
  }

  writeError(ERR_DEBUG_MODULE, "[%s] Exiting module...", MODULE_NAME);
 
  FREE(psCredSet);
  FREE(szUser);
  return SUCCESS;
}

/* SMBNT Specific Functions */
 
/* Split DOMAIN\USER style usernames */
char* parseFullyQualifiedUsername(_SMBNT_DATA *_psSessionData, char* szLogin)
{
  char *strtok_ptr = NULL, *pOpt = NULL, *pOptTmp = NULL;
  char *szUser = NULL;
 
  if ( strstr(szLogin, "\\") || strstr(szLogin, "\\\\") )
  {
    if ((_psSessionData->accntFlag == NTDOMAIN) || (_psSessionData->accntFlag == OTHER))
    {
      writeError(ERR_NOTICE, "[%s] Using the DOMAIN\\USER format with the GROUP/GROUP_OTHER module options is redundant.", MODULE_NAME);
    }

    pOptTmp = malloc( strlen(szLogin) + 1);
    memset(pOptTmp, 0, strlen(szLogin) + 1);
    strncpy(pOptTmp, szLogin, strlen(szLogin));
    writeError(ERR_DEBUG_MODULE, "Processing domain and username: %s", pOptTmp);

    pOpt = strtok_r(pOptTmp, "\\", &strtok_ptr); 
    strncpy((char *) _psSessionData->workgroup_other, pOpt, 16);
    writeError(ERR_DEBUG_MODULE, "Processing domain: %s", _psSessionData->workgroup_other);
    
    pOpt = strtok_r(NULL, "\\", &strtok_ptr);
    szUser = malloc(strlen(pOpt) + 1);
    memset(szUser, 0, strlen(pOpt) + 1);
    strncpy(szUser, pOpt, strlen(pOpt));
    writeError(ERR_DEBUG_MODULE, "Processing username: %s", szUser);

    FREE(pOptTmp);

    _psSessionData->accntFlag = OTHER;
  }
  else
  {
    szUser = malloc(strlen(szLogin) + 1); 
    memset(szUser, 0, strlen(szLogin) + 1);
    strncpy(szUser, szLogin, strlen(szLogin));
    writeError(ERR_DEBUG_MODULE, "Processing username: %s", szUser);
  }

  return szUser;
}

static unsigned char Get7Bits(unsigned char *input, int startBit)
{
  register unsigned int word;

  word = (unsigned) input[startBit / 8] << 8;
  word |= (unsigned) input[startBit / 8 + 1];

  word >>= 15 - (startBit % 8 + 7);

  return word & 0xFE;
}

/* Make the key */
static void MakeKey(unsigned char *key, unsigned char *des_key)
{
  des_key[0] = Get7Bits(key, 0);
  des_key[1] = Get7Bits(key, 7);
  des_key[2] = Get7Bits(key, 14);
  des_key[3] = Get7Bits(key, 21);
  des_key[4] = Get7Bits(key, 28);
  des_key[5] = Get7Bits(key, 35);
  des_key[6] = Get7Bits(key, 42);
  des_key[7] = Get7Bits(key, 49);

  DES_set_odd_parity((DES_cblock *) des_key);
}

/* Do the DesEncryption */
void DesEncrypt(unsigned char *clear, unsigned char *key, unsigned char *cipher)
{
  DES_cblock des_key;
  DES_key_schedule key_schedule;

  MakeKey(key, des_key);
  DES_set_key(&des_key, &key_schedule);
  DES_ecb_encrypt((DES_cblock *) clear, (DES_cblock *) cipher, &key_schedule, 1);
}

/*
  HashLM
  Function: Create a LM hash from the challenge
  Variables:
        lmhash    = the hash created from this function
        pass      = users password
        challenge = the challenge recieved from the server
*/
int HashLM(_SMBNT_DATA *_psSessionData, unsigned char **lmhash, unsigned char *pass, unsigned char *challenge)
{
  static unsigned char magic[] = {0x4b, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25};
  unsigned char password[14 + 1];
  unsigned char lm_hash[21];
  unsigned char lm_response[24];
  int i = 0, j = 0;
  unsigned char *p = NULL;
  char HexChar;
  int HexValue;

  memset(password, 0, 14 + 1);
  memset(lm_hash, 0, 21);
  memset(lm_response, 0, 24);

  /* Use LM Hash instead of password */
  /* D42E35E1A1E4C22BD32E2170E4857C20:5E20780DD45857A68402938C7629D3B2::: */
  if (_psSessionData->hashFlag == HASH) {
    p = pass;
    while ((*p != '\0') && (i < 1)) {
      if (*p == ':')
        i++;
      p++;
    }
  }

  /* If "-e ns" was used, don't treat these values as hashes. */
  if ((_psSessionData->hashFlag == HASH) && (i >= 1)) {
    p = pass;
    if (*p == '\0') {
      writeError(ERR_ERROR, "Error reading PwDump file.");
      return FAILURE;
    }
    else if (*p == 'N') {
      writeError(ERR_DEBUG_MODULE, "Found \"NO PASSWORD\" for LM Hash.");
      
      /* Generate 16-byte LM hash */
      DesEncrypt(magic, &password[0], &lm_hash[0]);
      DesEncrypt(magic, &password[7], &lm_hash[8]);
    }
    else {
      writeError(ERR_DEBUG_MODULE, "Convert ASCII PwDump LM Hash (%s).", p);
      for (i = 0; i < 16; i++) {
        HexValue = 0x0;
        for (j = 0; j < 2; j++) {
          HexChar = (char) p[2 * i + j];

          if (HexChar > 0x39)
            HexChar = HexChar | 0x20;     /* convert upper case to lower */

          if (!(((HexChar >= 0x30) && (HexChar <= 0x39)) ||       /* 0 - 9 */
                ((HexChar >= 0x61) && (HexChar <= 0x66)))) {      /* a - f */
            
            writeError(ERR_ERROR, "Error invalid char (%c) for hash.", HexChar);
            return FAILURE;
          }
  
          HexChar -= 0x30;
          if (HexChar > 0x09)     /* HexChar is "a" - "f" */
            HexChar -= 0x27;

          HexValue = (HexValue << 4) | (char) HexChar;
        }
        lm_hash[i] = (unsigned char) HexValue;
      }
    }
  } else {
    /* Password == Machine Name */
    if (_psSessionData->hashFlag == MACHINE_NAME) {
      for (i = 0; i < 16; i++) {
        if (_psSessionData->machine_name[i] > 0x39)
          _psSessionData->machine_name[i] = _psSessionData->machine_name[i] | 0x20;     /* convert upper case to lower */
        pass = _psSessionData->machine_name;
      }
    }
    
    /* convert lower case characters to upper case */
    strncpy((char *)password, (char *)pass, 14);
    for (i = 0; i < 14; i++) {
      if ((password[i] >= 0x61) && (password[i] <= 0x7a))      /* a - z */
        password[i] -= 0x20;
    }

    /* Generate 16-byte LM hash */
    DesEncrypt(magic, &password[0], &lm_hash[0]);
    DesEncrypt(magic, &password[7], &lm_hash[8]);
  }

  /* 
    NULL-pad 16-byte LM hash to 21-bytes
    Split resultant value into three 7-byte thirds
    DES-encrypt challenge using each third as a key
    Concatenate three 8-byte resulting values to form 24-byte LM response
  */
  DesEncrypt(challenge, &lm_hash[0], &lm_response[0]);
  DesEncrypt(challenge, &lm_hash[7], &lm_response[8]);
  DesEncrypt(challenge, &lm_hash[14], &lm_response[16]);

  memcpy(*lmhash, lm_response, 24);

  return SUCCESS;
}

/*
  MakeNTLM
  Function: Create a NTLM hash from the password 
*/
int MakeNTLM(_SMBNT_DATA *_psSessionData, unsigned char *ntlmhash, unsigned char *pass)
{
  MD4_CTX md4Context;
  unsigned char hash[16];                       /* MD4_SIGNATURE_SIZE = 16 */
  unsigned char unicodePassword[256 * 2];       /* MAX_NT_PASSWORD = 256 */
  unsigned int i = 0, j = 0;
  int mdlen;
  unsigned char *p = NULL;
  char HexChar;
  int HexValue;
  unsigned char NO_PASSWORD[1] = "";

  /* Use NTLM Hash instead of password */
  if (_psSessionData->hashFlag == HASH) {
    /* [OLD] 1000:D42E35E1A1E4C22BD32E2170E4857C20:5E20780DD45857A68402938C7629D3B2::: */
    /* [NEW] D42E35E1A1E4C22BD32E2170E4857C20:5E20780DD45857A68402938C7629D3B2::: */
    p = pass;
    while ((*p != '\0') && (i < 1)) {
      if (*p == ':')
        i++;
      p++;
    }
  }

  /* If "-e ns" was used, don't treat these values as hashes. */
  if ((_psSessionData->hashFlag == HASH) && (i >= 1)) {
    if (*p == '\0') {
      writeError(ERR_ERROR, "Error reading PwDump file.");
      return FAILURE;
    }
    else if (*p == 'N') {
      writeError(ERR_DEBUG_MODULE, "Found \"NO PASSWORD\" for NTLM Hash.");
      pass = NO_PASSWORD;
 
      /* Initialize the Unicode version of the secret (== password). */
      /* This implicitly supports 8-bit ISO8859/1 characters. */
      bzero(unicodePassword, sizeof(unicodePassword));
      for (i = 0; i < strlen((char *) pass); i++)
        unicodePassword[i * 2] = (unsigned char) pass[i];

      mdlen = strlen((char *) pass) * 2;    /* length in bytes */
      MD4_Init(&md4Context);
      MD4_Update(&md4Context, unicodePassword, mdlen);
      MD4_Final(hash, &md4Context);        /* Tell MD4 we're done */
    }
    else {
      writeError(ERR_DEBUG_MODULE, "Convert ASCII PwDump NTLM Hash (%s).", p);
      for (i = 0; i < 16; i++) {
        HexValue = 0x0;
        for (j = 0; j < 2; j++) {
          HexChar = (char) p[2 * i + j];

          if (HexChar > 0x39)
            HexChar = HexChar | 0x20;     /* convert upper case to lower */

          if (!(((HexChar >= 0x30) && (HexChar <= 0x39)) ||       /* 0 - 9 */
                ((HexChar >= 0x61) && (HexChar <= 0x66)))) {      /* a - f */
            
            writeError(ERR_ERROR, "Error invalid char (%c) for hash.", HexChar);
            return FAILURE;
          }
  
          HexChar -= 0x30;
          if (HexChar > 0x09)     /* HexChar is "a" - "f" */
            HexChar -= 0x27;

          HexValue = (HexValue << 4) | (char) HexChar;
        }
        hash[i] = (unsigned char) HexValue;
      }
    }
  } else {
    /* Password == Machine Name */
    if (_psSessionData->hashFlag == MACHINE_NAME) {
      for (i = 0; i < 16; i++) {
        if (_psSessionData->machine_name[i] > 0x39)
          _psSessionData->machine_name[i] = _psSessionData->machine_name[i] | 0x20;     /* convert upper case to lower */
        pass = _psSessionData->machine_name;
      }
    }
   
    /* Initialize the Unicode version of the secret (== password). */
    /* This implicitly supports 8-bit ISO8859/1 characters. */
    bzero(unicodePassword, sizeof(unicodePassword));
    for (i = 0; i < strlen((char *) pass); i++)
      unicodePassword[i * 2] = (unsigned char) pass[i];

    mdlen = strlen((char *) pass) * 2;    /* length in bytes */
    MD4_Init(&md4Context);
    MD4_Update(&md4Context, unicodePassword, mdlen);
    MD4_Final(hash, &md4Context);        /* Tell MD4 we're done */
  }

  memcpy(ntlmhash, hash, 16);

  return SUCCESS;
}

/*
  HashNTLM
  Function: Create a NTLM hash from the challenge
  Variables:
        ntlmhash  = the hash created from this function
        pass      = users password
        challenge = the challenge recieved from the server
*/
int HashNTLM(_SMBNT_DATA *_psSessionData, unsigned char **ntlmhash, unsigned char *pass, unsigned char *challenge)
{
  int ret;
  unsigned char hash[16];                       /* MD4_SIGNATURE_SIZE = 16 */
  unsigned char p21[21];
  unsigned char ntlm_response[24];

  ret = MakeNTLM(_psSessionData, (unsigned char *)&hash, (unsigned char *)pass);
  if (ret == FAILURE)
    return FAILURE;

  memset(p21, '\0', 21);
  memcpy(p21, hash, 16);

  DesEncrypt(challenge, p21 + 0, ntlm_response + 0);
  DesEncrypt(challenge, p21 + 7, ntlm_response + 8);
  DesEncrypt(challenge, p21 + 14, ntlm_response + 16);

  memcpy(*ntlmhash, ntlm_response, 24);

  return SUCCESS;
}


/*
  HashLMv2

  This function implements the LMv2 response algorithm. The LMv2 response is used to 
  provide pass-through authentication compatibility with older servers. The response
  is based on the NTLM password hash and is exactly 24 bytes.

  The below code is based heavily on the following resources:

    http://davenport.sourceforge.net/ntlm.html#theLmv2Response
    samba-3.0.28a - libsmb/smbencrypt.c
    jcifs - packet capture of LMv2-only connection
*/
int HashLMv2(_SMBNT_DATA *_psSessionData, unsigned char **LMv2hash, unsigned char *szLogin, unsigned char *szPassword)
{
  unsigned char ntlm_hash[16];
  unsigned char lmv2_response[24];
  unsigned char unicodeUsername[20 * 2];
  unsigned char unicodeTarget[256 * 2];
  HMACMD5Context ctx;
  unsigned char kr_buf[16];
  int ret;
  unsigned int i;
  unsigned char client_challenge[8] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };

  memset(ntlm_hash, 0, 16);
  memset(lmv2_response, 0, 24);
  memset(kr_buf, 0, 16);

  /* --- HMAC #1 Caculations --- */

  /* Calculate and set NTLM password hash */
  ret = MakeNTLM(_psSessionData, (unsigned char *)&ntlm_hash, (unsigned char *) szPassword);
  if (ret == FAILURE)
    return FAILURE;

  /*
    The Unicode uppercase username is concatenated with the Unicode authentication target
    (the domain or server name specified in the Target Name field of the Type 3 message).
    Note that this calculation always uses the Unicode representation, even if OEM encoding
    has been negotiated; also note that the username is converted to uppercase, while the
    authentication target is case-sensitive and must match the case presented in the Target
    Name field.

    The HMAC-MD5 message authentication code algorithm (described in RFC 2104) is applied to
    this value using the 16-byte NTLM hash as the key. This results in a 16-byte value - the
    NTLMv2 hash.
  */

  /* Initialize the Unicode version of the username and target. */
  /* This implicitly supports 8-bit ISO8859/1 characters. */
  /* convert lower case characters to upper case */
  bzero(unicodeUsername, sizeof(unicodeUsername));
  for (i = 0; i < strlen((char *)szLogin); i++)
  {
    if ((szLogin[i] >= 0x61) && (szLogin[i] <= 0x7a))      /* a - z */
      unicodeUsername[i * 2] = (unsigned char) szLogin[i] - 0x20;
    else
      unicodeUsername[i * 2] = (unsigned char) szLogin[i];
  } 

  bzero(unicodeTarget, sizeof(unicodeTarget));
  for (i = 0; i < strlen((char *)_psSessionData->workgroup); i++)
    unicodeTarget[i * 2] = (unsigned char)_psSessionData->workgroup[i];
  
  hmac_md5_init_limK_to_64(ntlm_hash, 16, &ctx);
  hmac_md5_update((const unsigned char *)unicodeUsername, 2 * strlen((char *)szLogin), &ctx);
  hmac_md5_update((const unsigned char *)unicodeTarget, 2 * strlen((char *)_psSessionData->workgroup), &ctx);
  hmac_md5_final(kr_buf, &ctx);
 
  /* --- HMAC #2 Calculations --- */
  /*
    The challenge from the Type 2 message is concatenated with our fixed client nonce. The HMAC-MD5 
    message authentication code algorithm is applied to this value using the 16-byte NTLMv2 hash 
    (calculated above) as the key. This results in a 16-byte output value.
  */
  hmac_md5_init_limK_to_64(kr_buf, 16, &ctx);
  hmac_md5_update(_psSessionData->challenge, 8, &ctx);
  hmac_md5_update(client_challenge, 8, &ctx);
  hmac_md5_final(lmv2_response, &ctx);

  /* --- 24-byte LMv2 Response Complete --- */
  *LMv2hash = malloc(24);
  memset(*LMv2hash, 0, 24); 
  memcpy(*LMv2hash, lmv2_response, 16);
  memcpy(*LMv2hash + 16, client_challenge, 8);

  return SUCCESS;
}


/*
  HashNTLMv2

  This function implements the NTLMv2 response algorithm. Support for this algorithm
  was added with Microsoft Windows with NT 4.0 SP4. It should be noted that code doesn't
  currently work with Microsoft Vista. While NTLMv2 authentication with Samba and Windows
  2003 functions as expected, Vista systems respond with the oh-so-helpful 
  "INVALID_PARAMETER" error code. LMv2-only authentication appears to work against Vista 
  in cases where LM and NTLM are refused. 

  The below code is based heavily on the following two resources:

    http://davenport.sourceforge.net/ntlm.html#theNtlmv2Response
    samba-3.0.28 - libsmb/smbencrypt.c

  NTLMv2 network authentication is required when attempting to authenticated to
  a system which has the following policy enforced:
  
  GPO:     "Network Security: LAN Manager authentication level"
  Setting: "Send NTLMv2 response only\refuse LM & NTLM"
*/
int HashNTLMv2(_SMBNT_DATA *_psSessionData, unsigned char **NTLMv2hash, int *iByteCount, unsigned char *szLogin, unsigned char *szPassword)
{
  unsigned char ntlm_hash[16];
  unsigned char ntlmv2_response[56 + 20 * 2 + 256 * 2];
  unsigned char unicodeUsername[20 * 2];
  unsigned char unicodeTarget[256 * 2];
  HMACMD5Context ctx;
  unsigned char kr_buf[16];
  unsigned int i;
  int ret, iTargetLen;
  unsigned char client_challenge[8] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };

  /*
    -- Example NTLMv2 Response Data --

    [0]       HMAC: (16 bytes) 

    [16]      Header: Blob Signature [01 01 00 00] (4 bytes)
    [20]      Reserved: [00 00 00 00] (4 bytes)
    [24]      Time: Little-endian, 64-bit signed value representing the number of
                    tenths of a microsecond since January 1, 1601. (8 bytes)
    [32]      Client Nonce: (8 bytes)
    [40]      Unknown: 00 00 00 00 (4 bytes)
    [44]      Target Information (from the Type 2 message)    
              NetBIOS domain/workgroup:
                Type: domain 02 00 (2 bytes)
                Length: 12 00 (2 bytes)
                Name: WORKGROUP [NULL spacing -> 57 00 4f 00 ...] (18 bytes)  
                End-of-list: 00 00 00 00 (4 bytes)
              Termination: 00 00 00 00 (4 bytes)
  */

  iTargetLen = 2 * strlen((char *)_psSessionData->workgroup);

  memset(ntlm_hash, 0, 16);
  memset(ntlmv2_response, 0, 56 + 20 * 2 + 256 * 2);
  memset(kr_buf, 0, 16);

  /* --- HMAC #1 Caculations --- */

  /* Calculate and set NTLM password hash */
  ret = MakeNTLM(_psSessionData, (unsigned char *)&ntlm_hash, (unsigned char *) szPassword);
  if (ret == FAILURE)
    return FAILURE;

  /*
    The Unicode uppercase username is concatenated with the Unicode authentication target
    (the domain or server name specified in the Target Name field of the Type 3 message).
    Note that this calculation always uses the Unicode representation, even if OEM encoding
    has been negotiated; also note that the username is converted to uppercase, while the
    authentication target is case-sensitive and must match the case presented in the Target
    Name field.

    The HMAC-MD5 message authentication code algorithm (described in RFC 2104) is applied to
    this value using the 16-byte NTLM hash as the key. This results in a 16-byte value - the
    NTLMv2 hash.
  */

  /* Initialize the Unicode version of the username and target. */
  /* This implicitly supports 8-bit ISO8859/1 characters. */
  /* convert lower case characters to upper case */
  bzero(unicodeUsername, sizeof(unicodeUsername));
  for (i = 0; i < strlen((char *)szLogin); i++)
  {
    if ((szLogin[i] >= 0x61) && (szLogin[i] <= 0x7a))      /* a - z */
      unicodeUsername[i * 2] = (unsigned char) szLogin[i] - 0x20;
    else
      unicodeUsername[i * 2] = (unsigned char) szLogin[i];
  } 

  bzero(unicodeTarget, sizeof(unicodeTarget));
  for (i = 0; i < strlen((char *)_psSessionData->workgroup); i++)
    unicodeTarget[i * 2] = (unsigned char)_psSessionData->workgroup[i];
  
  hmac_md5_init_limK_to_64(ntlm_hash, 16, &ctx);
  hmac_md5_update((const unsigned char *)unicodeUsername, 2 * strlen((char *)szLogin), &ctx);
  hmac_md5_update((const unsigned char *)unicodeTarget, 2 * strlen((char *)_psSessionData->workgroup), &ctx);
  hmac_md5_final(kr_buf, &ctx);

  /* --- Blob Construction --- */
 
  memset(ntlmv2_response + 16, 1, 2); /* Blob Signature 0x01010000 */
  memset(ntlmv2_response + 18, 0, 2);
  memset(ntlmv2_response + 20, 0, 4); /* Reserved */
  
  /* Time -- Take a Unix time and convert to an NT TIME structure:
     Little-endian, 64-bit signed value representing the number of tenths of a 
     microsecond since January 1, 1601.
  */
  struct timespec ts;
  unsigned long long nt;

  ts.tv_sec = (time_t)time(NULL);
  ts.tv_nsec = 0;

  if (ts.tv_sec ==0)
    nt = 0;
  else if (ts.tv_sec == TIME_T_MAX)
    nt = 0x7fffffffffffffffLL;
  else if (ts.tv_sec == (time_t)-1)
    nt = (unsigned long)-1;
  else
  { 
    nt = ts.tv_sec;
    nt += TIME_FIXUP_CONSTANT_INT;
    nt *= 1000*1000*10; /* nt is now in the 100ns units */
  }

  SIVAL(ntlmv2_response + 24, 0, nt & 0xFFFFFFFF);
  SIVAL(ntlmv2_response + 24, 4, nt >> 32);
  /* End time calculation */

  /* Set client challenge - using a non-random value in this case. */
  memcpy(ntlmv2_response + 32, client_challenge, 8); /* Client Nonce */
  memset(ntlmv2_response + 40, 0, 4); /* Unknown */

  /* Target Information Block */
  /*
    0x0100 Server name
    0x0200 Domain name
    0x0300 Fully-qualified DNS host name
    0x0400 DNS domain name
  
    TODO: Need to rework negotiation code to correctly extract target information
  */

  memset(ntlmv2_response + 44, 0x02, 1); /* Type: Domain */
  memset(ntlmv2_response + 45, 0x00, 1);
  memset(ntlmv2_response + 46, iTargetLen, 1); /* Length */
  memset(ntlmv2_response + 47, 0x00, 1);
 
  /* Name of domain or workgroup */ 
  for (i = 0; i < strlen((char *)_psSessionData->workgroup); i++)
    ntlmv2_response[48 + i * 2] = (unsigned char)_psSessionData->workgroup[i];

  memset(ntlmv2_response + 48 + iTargetLen, 0, 4); /* End-of-list */

  /* --- HMAC #2 Caculations --- */

  /*
    The challenge from the Type 2 message is concatenated with the blob. The HMAC-MD5 message 
    authentication code algorithm is applied to this value using the 16-byte NTLMv2 hash 
    (calculated above) as the key. This results in a 16-byte output value.
  */

  hmac_md5_init_limK_to_64(kr_buf, 16, &ctx);
  hmac_md5_update(_psSessionData->challenge, 8, &ctx);
  hmac_md5_update(ntlmv2_response + 16, 48 - 16 + iTargetLen + 4, &ctx);
  hmac_md5_final(ntlmv2_response, &ctx);

  *iByteCount = 48 + iTargetLen + 4;
  *NTLMv2hash = malloc(*iByteCount);
  memset(*NTLMv2hash, 0, *iByteCount); 
  memcpy(*NTLMv2hash, ntlmv2_response, *iByteCount);

  return SUCCESS;
}


/*
   NBS Session Request
   Function: Request a new session from the server
   Returns: TRUE on success else FALSE.
*/
int NBSSessionRequest(int hSocket, _SMBNT_DATA* _psSessionData)
{
  char nb_name[32];             /* netbiosname */
  char nb_local[32];            /* netbios localredirector */
  unsigned char rqbuf[7] = { 0x81, 0x00, 0x00, 0x48, 0x20, 0x00, 0x20 };
  unsigned char *buf = NULL;
  unsigned char *bufReceive = NULL;
  int nReceiveBufferSize = 0;
  int i = 0;  

  /* if we are running in native mode (aka port 445) don't do netbios */
  if (_psSessionData->protoFlag == WIN2000_NATIVEMODE)
    return 0;

  /* convert computer name to netbios name -- https://support.microsoft.com/kb/194203 */
  memset(nb_name, 0, 32);
  memset(nb_local, 0, 32);

  if (_psSessionData->machine_name[0] == 0x00) {
    writeVerbose(VB_GENERAL, "%s: NetBIOS calling name: *SMBSERVER", MODULE_NAME);
    memcpy(nb_name, "CKFDENECFDEFFCFGEFFCCACACACACACA", 32);      /* *SMBSERVER */
  }
  else
  {
    writeVerbose(VB_GENERAL, "%s: NetBIOS calling name: %s", MODULE_NAME, _psSessionData->machine_name);
    for (i = 0; i< 16; i++)
    {
      memset(nb_name + i * 2, ((_psSessionData->machine_name[i]) >> 4) + 0x41, 1);
      memset(nb_name + i * 2 + 1, ((_psSessionData->machine_name[i]) & 0x0F) + 0x41, 1);
    }
  }
  writeVerbose(VB_GENERAL, "%s: NetBIOS calling name: %s (encoded)", MODULE_NAME, nb_name);

  memcpy(nb_local, "ENEFEEFFFDEBCACACACACACACACACACA", 32);     /* MEDUSA */
  
  buf = malloc(100);
  memset(buf, 0, 100);
  memcpy(buf, (char *) rqbuf, 5);
  memcpy(buf + 5, nb_name, 32);
  memcpy(buf + 37, (char *) rqbuf + 5, 2);
  memcpy(buf + 39, nb_local, 32);
  memcpy(buf + 71, (char *) rqbuf + 5, 1);

  if (medusaSend(hSocket, buf, 76, 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
  }

  FREE(buf);

  nReceiveBufferSize = 0;
  bufReceive = medusaReceiveRaw(hSocket, &nReceiveBufferSize);
  if (bufReceive == NULL)
    return FAILURE;

  if ((unsigned char)bufReceive[0] == 0x82)
    return SUCCESS;                   /* success */
  else
    return FAILURE;                  /* failed */
}

/* NetBIOS Name Service Query */
int NBSTATQuery(sLogin *_psLogin,_SMBNT_DATA* _psSessionData)
{
  sConnectParams params;
  int hSocket;
  int i = 0, j = 0;
  int iResponseOffset = 56;
  int iNameCount = 0;
  int iNameType = 0;
  char nb_name[16];

  unsigned char nbstat[50] = {
    0x81, 0xec, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
    0x00, 0x01
  };
  
  unsigned char *bufReceive = NULL;
  int nReceiveBufferSize = 0;
  
  /* if we are running in native mode (aka port 445) don't do netbios */
  if (_psSessionData->protoFlag == WIN2000_NATIVEMODE)
    return 0;

  memset(&params, 0, sizeof(sConnectParams));
  initConnectionParams(_psLogin, &params);
  params.nPort = PORT_NBNS;

  hSocket = medusaConnectUDP(&params);
  if (hSocket < 0)
  {
    writeError(ERR_ERROR, "[%s] Failed to connect to NBNS UDP port (%d). Auto-identification of NetBIOS name unsuccessful on host: %s.", MODULE_NAME, PORT_NBNS, _psLogin->psServer->pHostIP);
    _psLogin->iResult = LOGIN_RESULT_UNKNOWN;
    return FAILURE;
  }

  if (medusaSend(hSocket, nbstat, 50, 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
    return FAILURE;
  }

  nReceiveBufferSize = 0;
  bufReceive = medusaReceiveRaw(hSocket, &nReceiveBufferSize);
  if ((bufReceive == NULL) || (nReceiveBufferSize < iResponseOffset + 1))
    return FAILURE;
 
  /* Find the primary domain/workgroup name */
  /* name (15 bytes) + type (1 byte) + flages (2 bytes) */
  iNameCount = bufReceive[iResponseOffset];
  writeVerbose(VB_GENERAL, "%s: NBSTAT - Number of names: %d", MODULE_NAME, iNameCount);
  if ((iResponseOffset + iNameCount * 16) > nReceiveBufferSize)
  {
    writeError(ERR_ERROR, "%s failed: unexpected response size to nbstat query.", MODULE_NAME);
    return FAILURE;
  }

  iResponseOffset++;
  for (i = 0; i < iNameCount; i++)
  {
    iNameType = bufReceive[iResponseOffset + 15];
    memset(nb_name, 0, 16);
    memcpy(nb_name, bufReceive + iResponseOffset, 16);

    switch(iNameType)
    {
      case 0x00:
        writeVerbose(VB_GENERAL, "%s: NetBIOS Name (workstation service name): %s", MODULE_NAME, nb_name);
        break;
      case 0x03:
        writeVerbose(VB_GENERAL, "%s: NetBIOS Name (messenger service name): %s", MODULE_NAME, nb_name);
        break;
      case 0x1B:
        writeVerbose(VB_GENERAL, "%s: NetBIOS Name (domain master browser name): %s", MODULE_NAME, nb_name);
        break;
      case 0x1C:
        writeVerbose(VB_GENERAL, "%s: NetBIOS Name (domain group name): %s", MODULE_NAME, nb_name);
        for (j = 0; j < 16; j++)
          _psSessionData->workgroup[j] = nb_name[j];
        break;
      case 0x20:
        writeVerbose(VB_GENERAL, "%s: NetBIOS Name (server service name): %s", MODULE_NAME, nb_name);
        for (j = 0; j < 16; j++)
          _psSessionData->machine_name[j] = nb_name[j];
        break;
      default:
        writeVerbose(VB_GENERAL, "%s: NetBIOS Name (other type - %d): %s", MODULE_NAME,iNameType, nb_name);
        break;
    }

    iResponseOffset += 18;
  }

  writeVerbose(VB_GENERAL, "%s: Server machine name: %s", MODULE_NAME, _psSessionData->machine_name);
  writeVerbose(VB_GENERAL, "%s: Server primary domain: %s", MODULE_NAME, _psSessionData->workgroup);

  FREE(bufReceive);

  return SUCCESS;
}


/*
   SMBNegProt
   Function: Negotiate protocol with server ...
       Actually a pseudo negotiation since the whole
       program counts on NTLM support :)

    The challenge is retrieved from the answer
    No error checking is performed i.e cross your fingers....
*/
int SMBNegProt(int hSocket, _SMBNT_DATA* _psSessionData)
{
  unsigned char buf[168] = {
    0x00, 0x00, 0x00, 0xa4, 0xff, 0x53, 0x4d, 0x42,
    0x72, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0x40,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x7d,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x81, 0x00, 0x02,
    0x50, 0x43, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f,
    0x52, 0x4b, 0x20, 0x50, 0x52, 0x4f, 0x47, 0x52,
    0x41, 0x4d, 0x20, 0x31, 0x2e, 0x30, 0x00, 0x02,
    0x4d, 0x49, 0x43, 0x52, 0x4f, 0x53, 0x4f, 0x46,
    0x54, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f, 0x52,
    0x4b, 0x53, 0x20, 0x31, 0x2e, 0x30, 0x33, 0x00,
    0x02, 0x4d, 0x49, 0x43, 0x52, 0x4f, 0x53, 0x4f,
    0x46, 0x54, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f,
    0x52, 0x4b, 0x53, 0x20, 0x33, 0x2e, 0x30, 0x00,
    0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31,
    0x2e, 0x30, 0x00, 0x02, 0x4c, 0x4d, 0x31, 0x2e,
    0x32, 0x58, 0x30, 0x30, 0x32, 0x00, 0x02, 0x53,
    0x61, 0x6d, 0x62, 0x61, 0x00, 0x02, 0x4e, 0x54,
    0x20, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x20,
    0x31, 0x2e, 0x30, 0x00, 0x02, 0x4e, 0x54, 0x20,
    0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00
  };

  unsigned char* bufReceive;
  int nReceiveBufferSize = 0;
  int i = 0, j = 0;
  int iLength = 168;
  int iResponseOffset = 73;

  if (_psSessionData->authLevel == AUTH_LM)
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Setting Negotiate Protocol Response for LM.", MODULE_NAME);
    buf[3] = 0x89;    /* Set message length */
    buf[37] = 0x66;   /* Set byte count for dialects */
    iLength = 141;
    iResponseOffset = 65;
  }

  if (medusaSend(hSocket, buf, iLength, 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
  }

  nReceiveBufferSize = 0;
  bufReceive = medusaReceiveRaw(hSocket, &nReceiveBufferSize);
  if (bufReceive == NULL)
    return FAILURE;

  /* retrieve the security mode */
  /*
    [0] Mode:       (0) ?                                 (1) USER security mode 
    [1] Password:   (0) PLAINTEXT password                (1) ENCRYPTED password. Use challenge/response
    [2] Signatures: (0) Security signatures NOT enabled   (1) ENABLED
    [3] Sig Req:    (0) Security signatures NOT required  (1) REQUIRED
  
    SAMBA: 0x01 (default)
    WinXP: 0x0F (default)
    WinXP: 0x07 (Windows 2003 / DC)
  */
  switch (bufReceive[39])
  {
    case 0x01:
      writeVerbose(VB_GENERAL, "%s: Server requested PLAINTEXT password.", MODULE_NAME);
      _psSessionData->security_mode = PLAINTEXT;
      
      if (_psSessionData->hashFlag == HASH)
      {
        writeError(ERR_ERROR, "%s: Server requested PLAINTEXT password. HASH password mode not supported for this configuration.", MODULE_NAME);
        return FAILURE;
      }
      if (_psSessionData->hashFlag == MACHINE_NAME)
      {
        writeError(ERR_ERROR, "%s: Server requested PLAINTEXT password. MACHINE password mode not supported for this configuration.", MODULE_NAME);
        return FAILURE;
      }
      
      break;
    case 0x03:
      writeVerbose(VB_GENERAL, "%s: Server requested ENCRYPTED password without security signatures.", MODULE_NAME);
      _psSessionData->security_mode = ENCRYPTED;
      break;
    case 0x07:
    case 0x0F:
      writeVerbose(VB_GENERAL, "%s: Server requested ENCRYPTED password.", MODULE_NAME);
      _psSessionData->security_mode = ENCRYPTED;
      break;
    default:
      writeError(ERR_ERROR, "%s: Unknown security mode request: %2.2X. Proceeding using ENCRYPTED password mode.", MODULE_NAME, bufReceive[39]);
      _psSessionData->security_mode = ENCRYPTED;
      break;
  }

  /* Retrieve the challenge */
  memcpy(_psSessionData->challenge, (char *) bufReceive + iResponseOffset, sizeof(_psSessionData->challenge));

  /* Find the primary domain/workgroup name */
  while ((bufReceive[iResponseOffset + 8 + i * 2] != 0) && (i < 16)) {
    _psSessionData->workgroup[i] = bufReceive[iResponseOffset + 8 + i * 2];
    i++;
  }
  
  while ((bufReceive[iResponseOffset + 8 + (i + j + 1) * 2] != 0) && (j < 16)) {
    _psSessionData->machine_name[j] = bufReceive[iResponseOffset + 8 + (i + j + 1) * 2];
    j++;
  }
      
  writeVerbose(VB_GENERAL, "%s: Server machine name: %s", MODULE_NAME, _psSessionData->machine_name);
  writeVerbose(VB_GENERAL, "%s: Server primary domain: %s", MODULE_NAME, _psSessionData->workgroup);

  FREE(bufReceive);

  return SUCCESS;
}


/*
  SMBSessionSetup
  Function: Send username + response to the challenge from
            the server.
  Returns: TRUE on success else FALSE.
*/
unsigned long SMBSessionSetup(int hSocket, sLogin** psLogin, _SMBNT_DATA *_psSessionData, char* szLogin, char* szPassword)
{
  unsigned char buf[512];
  unsigned char *LMv2hash = NULL;
  unsigned char *NTLMv2hash = NULL;
  unsigned char *NTLMhash = NULL;
  unsigned char *LMhash = NULL;
  unsigned char *bufReceive = NULL;
  int nReceiveBufferSize = 0;
  int ret;
  int iByteCount;
  int iOffset = 0;
  unsigned char szPath[256];
  unsigned long SMBSessionRet;
  
  if (_psSessionData->accntFlag == LOCAL) {
    strcpy((char *) _psSessionData->workgroup, "localhost");
  } else if (_psSessionData->accntFlag == BOTH) {
    memset(_psSessionData->workgroup, 0, 16);
  } else if (_psSessionData->accntFlag == OTHER) {
    strncpy(_psSessionData->workgroup, _psSessionData->workgroup_other, 16);
  }

  /* NetBIOS Session Service */
  unsigned char szNBSS[4] = {
    0x00,                                             /* Message Type: Session Message */
    0x00, 0x00, 0x85                                  /* Length -- MUST SET */
  };

  /* SMB Header */
  unsigned char szSMB[32] = {
    0xff, 0x53, 0x4d, 0x42,                           /* Server Component */
    0x73,                                             /* SMB Command: Session Setup AndX */
    0x00, 0x00, 0x00, 0x00,                           /* NT Status: STATUS_SUCCESS */
    0x08,                                             /* Flags */
    0x01, 0x40,                                       /* Flags2 */
    0x00, 0x00,                                       /* Process ID High */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   /* Signature */
    0x00, 0x00,                                       /* Reserved */
    0xFF, 0xFF,                                       /* Tree ID */
    0x13, 0x37,                                       /* Process ID */
    0x00, 0x00,                                       /* User ID */
    0x01, 0x00                                        /* Multiplex ID */
  };

  memset(buf, 0, 512);
  memcpy(buf, szNBSS, 4);
  memcpy(buf +4, szSMB, 32);

  if (_psSessionData->security_mode == ENCRYPTED)
  {
    /* Session Setup AndX Request */
    if (_psSessionData->authLevel == AUTH_LM)
    {
      writeError(ERR_DEBUG_MODULE, "[%s] Attempting LM password authentication.", MODULE_NAME);

      unsigned char szSessionRequest[23] = {
        0x0a,                             /* Word Count */
        0x75,                             /* AndXCommand: Tree Connect */
        0x00,                             /* Reserved */
        0x00, 0x00,                       /* AndXOffset */
        0xff, 0xff,                       /* Max Buffer */
        0x02, 0x00,                       /* Max Mpx Count */
        0x3c, 0x7d,                       /* VC Number */
        0x00, 0x00, 0x00, 0x00,           /* Session Key */
        0x18, 0x00,                       /* LAN Manager Password Hash Length */
        0x00, 0x00, 0x00, 0x00,           /* Reserved */
        0x49, 0x00                        /* Byte Count -- MUST SET */
      };

      iOffset = 59; /* szNBSS + szSMB + szSessionRequest */
      iByteCount = 24; /* Start with length of LM hash */

      /* Set Session Setup AndX Request header information */
      memcpy(buf + 36, szSessionRequest, 23);

      /* Calculate and set LAN Manager password hash */
      LMhash = (unsigned char *) malloc(24);
      memset(LMhash, 0, 24);

      ret = HashLM(_psSessionData, &LMhash, (unsigned char *) szPassword, (unsigned char *) _psSessionData->challenge);
      if (ret == FAILURE)
        return FAILURE;

      memcpy(buf + iOffset, LMhash, 24);
      FREE(LMhash); 
   
    }
    else if (_psSessionData->authLevel == AUTH_NTLM)
    {
      writeError(ERR_DEBUG_MODULE, "[%s] Attempting NTLM password authentication.", MODULE_NAME);
    
      unsigned char szSessionRequest[29] = {
        0x0d,                             /* Word Count */
        0x75,                             /* AndXCommand: Tree Connect */
        0x00,                             /* Reserved */
        0x00, 0x00,                       /* AndXOffset */
        0xff, 0xff,                       /* Max Buffer */
        0x02, 0x00,                       /* Max Mpx Count */
        0x3c, 0x7d,                       /* VC Number */
        0x00, 0x00, 0x00, 0x00,           /* Session Key */
        0x18, 0x00,                       /* LAN Manager Password Hash Length */
        0x18, 0x00,                       /* NT LAN Manager Password Hash Length */
        0x00, 0x00, 0x00, 0x00,           /* Reserved */
        0x50, 0x00, 0x00, 0x00,           /* Capabilities */
        0x49, 0x00                        /* Byte Count -- MUST SET */
      };

      iOffset = 65; /* szNBSS + szSMB + szSessionRequest */
      iByteCount = 48; /* Start with length of NTLM and LM hashes */

      /* Set Session Setup AndX Request header information */
      memcpy(buf + 36, szSessionRequest, 29);

      /* Calculate and set NTLM password hash */
      NTLMhash = (unsigned char *) malloc(24);
      memset(NTLMhash, 0, 24);

      /* We don't need to actually calculated a LM hash for this mode, only NTLM */
      ret = HashNTLM(_psSessionData, &NTLMhash, (unsigned char *) szPassword, (unsigned char *) _psSessionData->challenge);
      if (ret == FAILURE)
        return FAILURE;

      memcpy(buf + iOffset + 24, NTLMhash, 24); /* Skip space for LM hash */
      FREE(NTLMhash);
    }
    else if (_psSessionData->authLevel == AUTH_LMv2)
    {
      writeError(ERR_DEBUG_MODULE, "[%s] Attempting LMv2 password authentication.", MODULE_NAME);
    
      unsigned char szSessionRequest[29] = {
        0x0d,                             /* Word Count */
        0x75,                             /* AndXCommand: Tree Connect */
        0x00,                             /* Reserved */
        0x00, 0x00,                       /* AndXOffset */
        0xff, 0xff,                       /* Max Buffer */
        0x02, 0x00,                       /* Max Mpx Count */
        0x3c, 0x7d,                       /* VC Number */
        0x00, 0x00, 0x00, 0x00,           /* Session Key */
        0x18, 0x00,                       /* LAN Manager Password Hash Length */
        0x00, 0x00,                       /* NT LAN Manager Password Hash Length */
        0x00, 0x00, 0x00, 0x00,           /* Reserved */
        0x50, 0x00, 0x00, 0x00,           /* Capabilities */
        0x49, 0x00                        /* Byte Count -- MUST SET */
      };

      iOffset = 65; /* szNBSS + szSMB + szSessionRequest */
      iByteCount = 24; /* Start with length of LMv2 response */

      /* Set Session Setup AndX Request header information */
      memcpy(buf + 36, szSessionRequest, 29);

      /* Calculate and set LMv2 response hash */
      ret = HashLMv2(_psSessionData, &LMv2hash, (unsigned char *) szLogin, (unsigned char *) szPassword);
      if (ret == FAILURE)
        return FAILURE;

      memcpy(buf + iOffset, LMv2hash, 24);
      FREE(LMv2hash);
    }
    else if (_psSessionData->authLevel == AUTH_NTLMv2)
    {
      writeError(ERR_DEBUG_MODULE, "[%s] Attempting LMv2/NTLMv2 password authentication.", MODULE_NAME);
    
      unsigned char szSessionRequest[29] = {
        0x0d,                             /* Word Count */
        0x75,                             /* AndXCommand: Tree Connect */
        0x00,                             /* Reserved */
        0x00, 0x00,                       /* AndXOffset */
        0xff, 0xff,                       /* Max Buffer */
        0x02, 0x00,                       /* Max Mpx Count */
        0x3c, 0x7d,                       /* VC Number */
        0x00, 0x00, 0x00, 0x00,           /* Session Key */
        0x18, 0x00,                       /* LMv2 Response Hash Length */
        0x4b, 0x00,                       /* NTLMv2 Response Hash Length -- MUST SET */
        0x00, 0x00, 0x00, 0x00,           /* Reserved */
        0x50, 0x00, 0x00, 0x00,           /* Capabilities */
        0x49, 0x00                        /* Byte Count -- MUST SET */
      };

      iOffset = 65; /* szNBSS + szSMB + szSessionRequest */

      /* Set Session Setup AndX Request header information */
      memcpy(buf + 36, szSessionRequest, 29);

      /* Calculate and set LMv2 response hash */
      ret = HashLMv2(_psSessionData, &LMv2hash, (unsigned char *) szLogin, (unsigned char *) szPassword);
      if (ret == FAILURE)
        return FAILURE;
      
      memcpy(buf + iOffset, LMv2hash, 24);
      FREE(LMv2hash);

      /* Calculate and set NTLMv2 response hash */
      ret = HashNTLMv2(_psSessionData, &NTLMv2hash, &iByteCount, (unsigned char *) szLogin, (unsigned char *) szPassword);
      if (ret == FAILURE)
        return FAILURE;

      /* Set NTLMv2 Response Length */
      memset(buf + iOffset - 12, iByteCount, 1);
      writeError(ERR_DEBUG_MODULE, "HashNTLMv2 response length: %d", iByteCount);

      memcpy(buf + iOffset + 24, NTLMv2hash, iByteCount);
      FREE(NTLMv2hash);

      iByteCount += 24; /* Reflects length of both LMv2 and NTLMv2 responses */
    }
  }
  else if (_psSessionData->security_mode == PLAINTEXT)
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Attempting PLAINTEXT password authentication.", MODULE_NAME);

    unsigned char szSessionRequest[23] = {
      0x0a,                             /* Word Count */
      0x75,                             /* AndXCommand: Tree Connect */
      0x00,                             /* Reserved */
      0x00, 0x00,                       /* AndXOffset */
      0xff, 0xff,                       /* Max Buffer */
      0x02, 0x00,                       /* Max Mpx Count */
      0x3c, 0x7d,                       /* VC Number */
      0x00, 0x00, 0x00, 0x00,           /* Session Key */
      0x00, 0x00,                       /* Password Length -- MUST SET */
      0x00, 0x00, 0x00, 0x00,           /* Reserved */
      0x49, 0x00                        /* Byte Count -- MUST SET */
    };

    iOffset = 59; /* szNBSS + szSMB + szSessionRequest */

    /* Set Session Setup AndX Request header information */
    memcpy(buf + 36, szSessionRequest, 23);

    /* Calculate and set password length */
    /* Samba appears to append NULL characters equal to the password length plus 2 */
    iByteCount = 2 * strlen(szPassword) + 2;
    buf[iOffset - 8] = (iByteCount) % 256;
    buf[iOffset - 7] = (iByteCount) / 256;
 
    /* set ANSI password */
    /*
      Depending on the SAMBA server configuration, multiple passwords may be successful
      when dealing with mixed-case values. The SAMBA parameter "password level" appears
      to determine how many characters within a password are tested by the server both  
      upper and lower case. For example, assume a SAMBA account has a password of "Fred" 
      and the server is configured with "password level = 2". Medusa sends the password
      "FRED". The SAMBA server will brute-force test this value for us with values
      like: "FRed", "FrEd", "FreD", "fREd", "fReD", "frED", ... The default setting
      is "password level = 0". This results in only two attempts to being made by the 
      remote server; the password as is and the password in all-lower case.
    */
    strncpy((char *)buf + iOffset, szPassword, 256);
  }
  else
  {
    writeError(ERR_ERROR, "%s: security_mode was not properly set. This should not happen.", MODULE_NAME);
    return FAILURE;
  }
    
  /* Set account and workgroup values */ 
  memcpy(buf + iOffset + iByteCount, szLogin, strlen(szLogin));
  iByteCount += strlen(szLogin) + 1; /* NULL pad account name */
  memcpy(buf + iOffset + iByteCount, _psSessionData->workgroup, strlen((char *) _psSessionData->workgroup));
  iByteCount += strlen((char *) _psSessionData->workgroup) + 1; /* NULL pad workgroup name */

  /* Set native OS and LAN Manager values */
  sprintf((char *)buf + iOffset + iByteCount, "Unix"); 
  iByteCount += strlen("Unix") + 1; /* NULL pad OS name */
  sprintf((char *)buf + iOffset + iByteCount, "Samba"); 
  iByteCount += strlen("Samba") + 1; /* NULL pad LAN Manager name */

  /* Set data byte count */
  buf[iOffset - 2] = iByteCount;
  writeError(ERR_DEBUG_MODULE, "[%s] Set byte count: %2.2X", MODULE_NAME, buf[57]);

  /* Set AndXOffset */
  buf[39] = (iOffset - 4 + iByteCount) % 256;
  buf[40] = (iOffset - 4 + iByteCount) / 256;

  /* Chained Tree AndX Request - Test for ADMIN$ access */
  iOffset += iByteCount;

  unsigned char szTreeConnectRequest[9] = {
    0x04,                               /* Word Count */
    0xff,                               /* AndXCommand: No further commands */
    0x00,                               /* Reserved */
    0x00, 0x00,                         /* AndXOffset */
    0x08, 0x00,                         /* Flags */
    0x01, 0x00                          /* Password Length */
  };

  memcpy(buf + iOffset, szTreeConnectRequest, 9);
  iOffset += 9;

  /* Set byte count (BCC) */
  /* Password (1) + "\\" + "host IP" + "\ADMIN$" + null termination + service (6) */
  iByteCount = 1 + 2 + strlen((char *) (*psLogin)->psServer->pHostIP) + 7 + 1 + 6;
  buf[iOffset] = (iByteCount) % 256;
  buf[iOffset + 1] = (iByteCount) / 256;
  writeError(ERR_DEBUG_MODULE, "[%s] Set byte count (BCC): 0x%2.2X%2.2X", MODULE_NAME, buf[iOffset + 1], buf[iOffset]);
  iOffset += 2;

  /* Set password field */
  memset(buf + iOffset, 0, 1);
  iOffset++;
 
  /* Set target path -- e.g., \\192.168.0.1\ADMIN$ */
  memset(szPath, 0, 256);
  snprintf((char *)szPath, sizeof(szPath), "\\\\%s\\ADMIN$", (*psLogin)->psServer->pHostIP);

  memcpy(buf + iOffset, szPath, strlen((char *)szPath));
  iOffset += strlen((char *)szPath) + 1;

  /* Set service field */
  unsigned char szService[6] = { 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x00 };
  memcpy(buf + iOffset, szService, 6);
  iOffset += 6;
  /* End Chained Tree AndX Request */
  
  /* Set the header length */
  buf[2] = (iOffset - 4) / 256;
  buf[3] = (iOffset - 4) % 256;
  writeError(ERR_DEBUG_MODULE, "[%s] Set NBSS header length: %2.2X", MODULE_NAME, buf[3]);

  if (medusaSend(hSocket, buf, iOffset, 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
  }

  nReceiveBufferSize = 0;
  bufReceive = medusaReceiveRaw(hSocket, &nReceiveBufferSize);
  if ((bufReceive == NULL) || (nReceiveBufferSize == 0))
    return FAILURE;
 
  /* 41 - Action (Guest/Non-Guest Account) */
  /*  9 - NT Status (Error code) */
  SMBSessionRet = ((bufReceive[41] & 0x01) << 24) | ((bufReceive[11] & 0xFF) << 16) | ((bufReceive[10] & 0xFF) << 8) | (bufReceive[9] & 0xFF);
  FREE(bufReceive);

  return SMBSessionRet;
}

int tryLogin(int hSocket, sLogin** psLogin, _SMBNT_DATA* _psSessionData, char* szLogin, char* szPassword)
{
  int SMBerr, SMBaction;
  unsigned long SMBSessionRet;
  char *pErrorMsg = NULL;
  char ErrorCode[10];
  int iRet;
  unsigned int i;

  /* Nessus Plugins: smb_header.inc */
  /* Note: we are currently only examining the lower 2 bytes of data */
  int smbErrorCode[] = {
    0xFFFFFFFF,         /* UNKNOWN_ERROR_CODE */
    0x00000000,         /* STATUS_SUCCESS */
    0xC000000D,         /* STATUS_INVALID_PARAMETER */
    0xC000005E,         /* STATUS_NO_LOGON_SERVERS */
    0xC000006D,         /* STATUS_LOGON_FAILURE */
    0xC000006E,         /* STATUS_ACCOUNT_RESTRICTION */
    0xC000006F,         /* STATUS_INVALID_LOGON_HOURS */
    0x00C10002,         /* STATUS_INVALID_LOGON_HOURS (LM Authentication) */
    0xC0000070,         /* STATUS_INVALID_WORKSTATION */
    0x00C00002,         /* STATUS_INVALID_WORKSTATION (LM Authentication) */
    0xC0000071,         /* STATUS_PASSWORD_EXPIRED */
    0xC0000072,         /* STATUS_ACCOUNT_DISABLED */
    0xC000015B,         /* STATUS_LOGON_TYPE_NOT_GRANTED */
    0xC000018D,         /* STATUS_TRUSTED_RELATIONSHIP_FAILURE */
    0xC0000193,         /* STATUS_ACCOUNT_EXPIRED */
    0xC0000199,         /* STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT */
    0x00BF0002,         /* STATUS_ACCOUNT_EXPIRED_OR_DISABLED (LM Authentication) */
    0xC0000224,         /* STATUS_PASSWORD_MUST_CHANGE */
    0x00C20002,         /* STATUS_PASSWORD_MUST_CHANGE (LM Authentication) */
    0xC0000234,         /* STATUS_ACCOUNT_LOCKED_OUT (No LM Authentication Code) */
    0x00050001,         /* AS400_STATUS_LOGON_FAILURE */
    0x00000064,         /* The machine you are logging onto is protected by an authentication firewall. */
    0xC0000022,         /* STATUS_ACCESS_DENIED */
    0xC00000CC          /* STATUS_BAD_NETWORK_NAME */
  };

  char *smbErrorMsg[] = {
    "UNKNOWN_ERROR_CODE",
    "STATUS_SUCCESS",
    "STATUS_INVALID_PARAMETER",
    "STATUS_NO_LOGON_SERVERS",
    "STATUS_LOGON_FAILURE",
    "STATUS_ACCOUNT_RESTRICTION",
    "STATUS_INVALID_LOGON_HOURS",
    "STATUS_INVALID_LOGON_HOURS (LM)",
    "STATUS_INVALID_WORKSTATION",
    "STATUS_INVALID_WORKSTATION (LM)",
    "STATUS_PASSWORD_EXPIRED",
    "STATUS_ACCOUNT_DISABLED",
    "STATUS_LOGON_TYPE_NOT_GRANTED",
    "STATUS_TRUSTED_RELATIONSHIP_FAILURE",
    "STATUS_ACCOUNT_EXPIRED",
    "STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT",
    "STATUS_ACCOUNT_EXPIRED_OR_DISABLED (LM)",
    "STATUS_PASSWORD_MUST_CHANGE",
    "STATUS_PASSWORD_MUST_CHANGE (LM)",
    "STATUS_ACCOUNT_LOCKED_OUT",
    "AS400_STATUS_LOGON_FAILURE",
    "AUTHENTICATION_FIREWALL_PROTECTION",
    "STATUS_ACCESS_DENIED",
    "STATUS_BAD_NETWORK_NAME"
  };

  memset(&ErrorCode, 0, 10);

  SMBSessionRet = SMBSessionSetup(hSocket, psLogin, _psSessionData, szLogin, szPassword);
  SMBerr = (unsigned long) SMBSessionRet & 0x00FFFFFF;
  SMBaction = ((unsigned long) SMBSessionRet & 0xFF000000) >> 24;

  writeError(ERR_DEBUG_MODULE, "SMBSessionRet: %8.8X SMBerr: %4.4X SMBaction: %2.2X", SMBSessionRet, SMBerr, SMBaction);
 
  /* Locate appropriate SMB code message */
  pErrorMsg = smbErrorMsg[0]; /* UNKNOWN_ERROR_CODE */
  for (i = 0; i < sizeof(smbErrorCode)/4; i++) {
    if (SMBerr == (smbErrorCode[i] & 0x00FFFFFF)) {
      pErrorMsg = smbErrorMsg[i];
      break;
    }
  }

  switch (SMBerr)
  {
    case 0x000000:
      /*
        Non-domain connected XP and 2003 hosts map non-existant accounts to
        the anonymous user and return SUCCESS during password checks. Medusa
        will check the value of the ACTION flag in the target's response to 
        determine if the account is a legitimate or anonymous success.
      */
      if (SMBaction == 0x01) {
        (*psLogin)->pErrorMsg = malloc( 40 + 1 );
        memset((*psLogin)->pErrorMsg, 0, 40 + 1 );
        sprintf((*psLogin)->pErrorMsg, "Non-existant account. Anonymous success.");
        (*psLogin)->iResult = LOGIN_RESULT_ERROR;
      }
      else
      {
        (*psLogin)->pErrorMsg = malloc( 23 + 1 );
        memset((*psLogin)->pErrorMsg, 0, 23 + 1 );
        sprintf((*psLogin)->pErrorMsg, "ADMIN$ - Access Allowed");
        (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
      }      

      iRet = MSTATE_EXITING;
      break;
    case 0x00006F:  /* STATUS_INVALID_LOGON_HOURS - Valid password */
    case 0xC10002:  /* STATUS_INVALID_LOGON_HOURS - Valid password (LM) */
    case 0x000064:  /* Valid password, "The machine you are logging onto is protected by an 
                       authentication firewall. The specificed account is not allowed to 
                       authenticate to the machine." */
    case 0x000070:  /* STATUS_INVALID_WORKSTATION - Valid password */
    case 0xC00002:  /* STATUS_INVALID_WORKSTATION - Valid password (LM) */
    // TODO: Verify whether we can determine password validity from DISABLED. Win7 doesn't seem to tell us...
    //case 0x000072:  /* STATUS_ACCOUNT_DISABLED - Valid password */
    case 0x000193:  /* STATUS_ACCOUNT_EXPIRED - Valid password */
    case 0xBF0002:  /* STATUS_ACCOUNT_DISABLED or STATUS_ACCOUNT_EXPIRED - Valid password (LM) */
    case 0x000224:  /* STATUS_PASSWORD_MUST_CHANGE - Valid password */
    case 0xC20002:  /* STATUS_PASSWORD_MUST_CHANGE - Valid password (LM) */
    // TODO: Verify whether we can determine password validity from STATUS_ACCOUNT_RESTRICTION. Win7 doesn't seem to tell us...
    //case 0x00006E:  /* Valid password, GPO Disabling Remote Connections Using NULL Passwords */
    // TODO: Verify whether we can determine password validity from STATUS_ACCOUNT_RESTRICTION. Win7 doesn't seem to tell us...
    //case 0x00015B:  /* Valid password, GPO "Deny access to this computer from the network" */
    case 0x000071:  /* Valid password, password expired and must be changed on next logon */
      (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
      sprintf(ErrorCode, "0x%6.6X:", SMBerr);
      (*psLogin)->pErrorMsg = malloc( strlen(ErrorCode) + strlen(pErrorMsg) + 1);
      memset((*psLogin)->pErrorMsg, 0, strlen(ErrorCode) + strlen(pErrorMsg) + 1);
      strncpy((*psLogin)->pErrorMsg, ErrorCode, strlen(ErrorCode));
      strncat((*psLogin)->pErrorMsg, pErrorMsg, strlen(pErrorMsg));
      iRet = MSTATE_EXITING;
      break;
    case 0x000022:  /* Valid password, no access to ADMIN$ (non-administative account) */
      (*psLogin)->pErrorMsg = malloc( 22 + 1 );
      memset((*psLogin)->pErrorMsg, 0, 22 + 1 );
      sprintf((*psLogin)->pErrorMsg, "ADMIN$ - Access Denied");
      (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
      iRet = MSTATE_EXITING;
      break;
    case 0x0000CC:  /* Valid password, but ADMIN$ not found (STATUS_BAD_NETWORK_NAME) */
      (*psLogin)->pErrorMsg = malloc( 26 + 1 );
      memset((*psLogin)->pErrorMsg, 0, 26 + 1 );
      sprintf((*psLogin)->pErrorMsg, "ADMIN$ - Share Unavailable");
      (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
      iRet = MSTATE_EXITING;
      break;
    case 0x050001:  /* AS/400 -- Incorrect password */
      writeError(ERR_DEBUG_MODULE, "[%s] AS/400 Access is Denied. Incorrect password or disabled account.", MODULE_NAME);
      (*psLogin)->iResult = LOGIN_RESULT_FAIL;
      iRet = MSTATE_RUNNING;
      break;
    case 0x00006D:  /* Incorrect password */
      (*psLogin)->iResult = LOGIN_RESULT_FAIL;
      iRet = MSTATE_RUNNING;
      break;
    default:
      sprintf(ErrorCode, "0x%6.6X:", SMBerr);
      (*psLogin)->pErrorMsg = malloc( strlen(ErrorCode) + strlen(pErrorMsg) + 1);
      memset((*psLogin)->pErrorMsg, 0, strlen(ErrorCode) + strlen(pErrorMsg) + 1);
      strncpy((*psLogin)->pErrorMsg, ErrorCode, strlen(ErrorCode));
      strncat((*psLogin)->pErrorMsg, pErrorMsg, strlen(pErrorMsg));
      (*psLogin)->iResult = LOGIN_RESULT_ERROR;
      iRet = MSTATE_EXITING;
      break;
  }

  if (_psSessionData->hashFlag == MACHINE_NAME) { 
    setPassResult((*psLogin), (char *)_psSessionData->machine_name);
    iRet = MSTATE_EXITING;
  }
  else {
    setPassResult((*psLogin), szPassword);
  }
 
  return(iRet);
}

#else

void summaryUsage(char **ppszSummary)
{
  // Memory for ppszSummary will be allocated here - caller is responsible for freeing it
  int  iLength = 0;


  if (*ppszSummary == NULL)
  {
    iLength = strlen(MODULE_SUMMARY_USAGE) + strlen(MODULE_VERSION) + strlen(MODULE_SUMMARY_FORMAT) + strlen(OPENSSL_WARNING) + 1;
    *ppszSummary = (char*)malloc(iLength);
    memset(*ppszSummary, 0, iLength);
    snprintf(*ppszSummary, iLength, MODULE_SUMMARY_FORMAT_WARN, MODULE_SUMMARY_USAGE, MODULE_VERSION, OPENSSL_WARNING);
  }
  else
  {
    writeError(ERR_ERROR, "%s reports an error in summaryUsage() : ppszSummary must be NULL when called", MODULE_NAME);
  }
}

void showUsage()
{
  writeVerbose(VB_NONE, "%s (%s) %s :: %s\n", MODULE_NAME, MODULE_VERSION, MODULE_AUTHOR, MODULE_SUMMARY_USAGE);
  writeVerbose(VB_NONE, "** Module was not properly built. Is OPENSSL installed correctly? **");
  writeVerbose(VB_NONE, "");
}

int go(sLogin* logins, int argc, char *argv[])
{
  writeVerbose(VB_NONE, "%s (%s) %s :: %s\n", MODULE_NAME, MODULE_VERSION, MODULE_AUTHOR, MODULE_SUMMARY_USAGE);
  writeVerbose(VB_NONE, "** Module was not properly built. Is OPENSSL installed correctly? **");
  writeVerbose(VB_NONE, "");
  return FAILURE;
}

#endif

