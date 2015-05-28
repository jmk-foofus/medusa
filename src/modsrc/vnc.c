/*
**   VNC Password Checking Medusa Module
**
**   ------------------------------------------------------------------------
**    Copyright (C) 2011 Joe Mondloch
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
**   Based on code from: 
**      VNCrack [FX/Phenolite]
**      RealVNC (VNC Server 4 -- FREE)
**      UltraVNC 1.0.9.6.1
**
**   Supports: password-less VNC, password-only VNC and UltraVNC MS-Logon
*/

#include <sys/types.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "module.h"
#include "d3des.h"

#define MODULE_NAME    "vnc.mod"
#define MODULE_AUTHOR  "JoMo-Kun <jmk@foofus.net>"
#define MODULE_SUMMARY_USAGE  "Brute force module for VNC sessions"
#define MODULE_VERSION    "2.1"
#define MODULE_VERSION_SVN "$Id: vnc.c 9217 2015-05-07 18:07:03Z jmk $"
#define MODULE_SUMMARY_FORMAT  "%s : version %s"
#define MODULE_SUMMARY_FORMAT_WARN  "%s : version %s (%s)"
#define OPENSSL_WARNING "No usable OPENSSL. Module disabled."

#ifdef HAVE_LIBSSL

#include <openssl/dh.h>

#define PORT_VNC 5900
#define CHALLENGE_SIZE 16

#define SESSION_SUCCESS 1
#define SESSION_FAILURE 2
#define SESSION_SUCCESS_NO_AUTH 3
#define SESSION_MAX_AUTH_REALVNC 4
#define SESSION_MAX_AUTH_ULTRAVNC 5

#define AUTH_VNC 1
#define AUTH_UVNC_MSLOGIN 2

typedef struct __VNC_DATA {
  int nMaxAuthSleep;
  int nAuthType;
  unsigned char* szChallenge;
  char* szDomain;
} _VNC_DATA;

// Tells us whether we are to continue processing or not
enum MODULE_STATE
{
  MSTATE_NEW,
  MSTATE_RUNNING,
  MSTATE_EXITING,
  MSTATE_COMPLETE
};

// Forward declarations
int tryLogin(int hSocket, sLogin** login, _VNC_DATA* _psSessionData, char* szLogin, char* szPassword);
int initModule(sLogin* login, _VNC_DATA *_psSessionData);
int vncSessionSetup(int hSocket, _VNC_DATA *_psSessionData);

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
  writeVerbose(VB_NONE, "  MAXSLEEP:?");
  writeVerbose(VB_NONE, "    Sets the maximum allowed sleep time when the VNC RealVNC anti-brute force delay");
  writeVerbose(VB_NONE, "    is encountered. This value is in seconds and, if left unset, defaults to 60.");
  writeVerbose(VB_NONE, "  DOMAIN:?");
  writeVerbose(VB_NONE, "    Sets the domain value when authenticating against UltraVNC's MS-Logon feature.");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "Some versions of VNC have built-in anti-brute force functionality. RealVNC, for example,");
  writeVerbose(VB_NONE, "allows 5 failed attempts and then enforces a 10 second delay. For each subsequent");
  writeVerbose(VB_NONE, "attempt that delay is doubled. UltraVNC appears to allow 6 invalid attempts and then forces");
  writeVerbose(VB_NONE, "a 10 second delay between each following attempt. This module attempts to identify these");
  writeVerbose(VB_NONE, "situations and react appropriately by invoking sleep(). The user can set a sleep limit when");
  writeVerbose(VB_NONE, "brute forcing RealVNC using the MAXSLEEP parameter. Once this value has been reached, the");
  writeVerbose(VB_NONE, "module will exit.");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "It should be noted that this module currently supports password-less and password-only VNC");
  writeVerbose(VB_NONE, "servers. In addition, it supports UltraVNC's MS-Logon feature that can be used to provide");
  writeVerbose(VB_NONE, "pass-through authentication against local and domain Windows accounts. In the case of basic");
  writeVerbose(VB_NONE, "password-only VNC, provide any arbitrary username value.");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "Usage example: \"-M vnc -m MAXSLEEP:120 -m DOMAIN:FOOFUSDOM\"");
}

// The "main" of the medusa module world - this is what gets called to actually do the work
int go(sLogin* logins, int argc, char *argv[])
{
  int i;
  char *strtok_ptr, *pOpt, *pOptTmp;
  _VNC_DATA *psSessionData;
  psSessionData = malloc(sizeof(_VNC_DATA));
  memset(psSessionData, 0, sizeof(_VNC_DATA));
  psSessionData->nMaxAuthSleep = 60;

  if ((argc < 0) || (argc > 2))
  {
    writeError(ERR_ERROR, "%s: Incorrect number of parameters passed to module (%d). Use \"-q\" option to display module usage.", MODULE_NAME, argc);
    return FAILURE;
  } 
  else 
  {
    writeError(ERR_DEBUG_MODULE, "OMG teh %s module has been called!!", MODULE_NAME);
 
    for (i=0; i<argc; i++) {
      pOptTmp = malloc( strlen(argv[i]) + 1);
      memset(pOptTmp, 0, strlen(argv[i]) + 1);
      strncpy(pOptTmp, argv[i], strlen(argv[i]));
      writeError(ERR_DEBUG_MODULE, "Processing complete option: %s", pOptTmp);
      pOpt = strtok_r(pOptTmp, ":", &strtok_ptr);
      writeError(ERR_DEBUG_MODULE, "Processing option: %s", pOpt);

      if (strcmp(pOpt, "MAXSLEEP") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if ( pOpt )
          psSessionData->nMaxAuthSleep = atoi(pOpt);        
        else
          writeError(ERR_WARNING, "Method MAXSLEEP requires value to be set.");
      }
      else if (strcmp(pOpt, "DOMAIN") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if ( pOpt )
        {
          psSessionData->szDomain = malloc(strlen(pOpt) + 1);
          memset(psSessionData->szDomain, 0, strlen(pOpt) + 1);
          strncpy((char *) psSessionData->szDomain, pOpt, strlen(pOpt));
        }
        else
          writeError(ERR_WARNING, "Method DOMAIN requires value to be set.");
      }
      else
         writeError(ERR_WARNING, "Invalid method: %s.", pOpt);

      free(pOptTmp);
    }

    initModule(logins, psSessionData);
  }  

  FREE(psSessionData);
  return SUCCESS;
}

int initModule(sLogin* psLogin, _VNC_DATA *_psSessionData)
{
  int hSocket = -1;
  enum MODULE_STATE nState = MSTATE_NEW;
  int iRet;
  sConnectParams params;
  int nAngrySleep = 10;
  int bAuthAllowed = FALSE;
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
    params.nPort = PORT_VNC;
  initConnectionParams(psLogin, &params);

  while (nState != MSTATE_COMPLETE)
  {  
    switch (nState)
    {
      case MSTATE_NEW:
        while (!bAuthAllowed)
        {
          if (hSocket > 0)
            medusaDisconnect(hSocket);
  
          hSocket = medusaConnect(&params);
        
          if (hSocket < 0) 
          {
            writeError(ERR_NOTICE, "%s: failed to connect, port %d was not open on %s", MODULE_NAME, params.nPort, psLogin->psServer->pHostIP);
            psLogin->iResult = LOGIN_RESULT_UNKNOWN;
            return FAILURE;
          }

          writeError(ERR_DEBUG_MODULE, "Connected");

          iRet = vncSessionSetup(hSocket, _psSessionData);
          switch( iRet )
          {
            case SESSION_SUCCESS:
              writeError(ERR_DEBUG_MODULE, "VNC Session Initialized.");
              bAuthAllowed = TRUE;
              nState = MSTATE_RUNNING;
              break;
            case SESSION_SUCCESS_NO_AUTH:
              writeError(ERR_DEBUG_MODULE, "VNC Server Does Not Require Authentication.");
              psLogin->iResult = LOGIN_RESULT_SUCCESS;
              setPassResult(psLogin, "[NO AUTH REQUIRED]");
              bAuthAllowed = TRUE;
              nState = MSTATE_EXITING;
              break;
            case SESSION_MAX_AUTH_REALVNC:
              writeError(ERR_ALERT, "[%s] Host %s reported too many security failures. Sleeping %d seconds before next attempt.", MODULE_NAME, psLogin->psServer->pHostIP, nAngrySleep);
              if (nAngrySleep > _psSessionData->nMaxAuthSleep)
              {
                writeError(ERR_ERROR, "[%s] Host %s exceeded maximum allowed sleep. Terminating connection.", MODULE_NAME, psLogin->psServer->pHostIP);
                psLogin->iResult = LOGIN_RESULT_UNKNOWN;
                bAuthAllowed = TRUE;
                nState = MSTATE_EXITING;
              }
              else
              {
                sleep(nAngrySleep + 1);
                nAngrySleep = 2 * nAngrySleep;
              }
              break;
            case SESSION_MAX_AUTH_ULTRAVNC:
              writeError(ERR_ALERT, "[%s] Host %s has rejected the connection. Sleeping 10 seconds before next attempt.", MODULE_NAME, psLogin->psServer->pHostIP);
              if (nAngrySleep > _psSessionData->nMaxAuthSleep)
              {
                writeError(ERR_ERROR, "[%s] Host %s exceeded maximum allowed sleep. Terminating connection.", MODULE_NAME, psLogin->psServer->pHostIP);
                psLogin->iResult = LOGIN_RESULT_UNKNOWN;
                bAuthAllowed = TRUE;
                nState = MSTATE_EXITING;
              }
              else
              {
                sleep(10 + 1);
                nAngrySleep = nAngrySleep + 10;
              }
              break;
            default:
              writeError(ERR_DEBUG_MODULE, "VNC Session Setup Failed.");
              psLogin->iResult = LOGIN_RESULT_UNKNOWN;
              bAuthAllowed = TRUE;
              nState = MSTATE_EXITING;
              break;
          }
        }

        bAuthAllowed = FALSE;
        break;
      case MSTATE_RUNNING:
        nState = tryLogin(hSocket, &psLogin, _psSessionData, psCredSet->psUser->pUser, psCredSet->pPass);

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
        writeError(ERR_CRITICAL, "Unknown %s module state %d", MODULE_NAME, nState);
        if (hSocket > 0)
          medusaDisconnect(hSocket);
        hSocket = -1;
        psLogin->iResult = LOGIN_RESULT_UNKNOWN;
        return FAILURE;
    }  
  }

  FREE(psCredSet);
  return SUCCESS;
}

/* VNC Specific Functions */

/*
** Encrypt CHALLENGE_SIZE bytes in memory using a password.
** Ripped from vncauth.c
*/
void vncEncryptBytes(unsigned char *bytes, char *passwd)
{
  unsigned char key[8];
  unsigned int i;

  /* key is simply password padded with nulls */
  for (i = 0; i < 8; i++) {
    if (i < strlen(passwd)) {
      key[i] = passwd[i];
    } else {
      key[i] = 0;
    }
  }
  deskey(key, EN0);
  for (i = 0; i < CHALLENGE_SIZE; i += 8) {
    des(bytes + i, bytes + i);
  }
}

void vncEncryptPasswdMs( unsigned char *encryptedPasswd, char *passwd )
{
  unsigned char key[8];
  unsigned int i;

  /* pad password with nulls */
  for (i = 0; i < 32; i++) {
    if (i < strlen(passwd)) {
      encryptedPasswd[i] = passwd[i];
    } else {
      encryptedPasswd[i] = 0;
    }
  }

  /* Do encryption in-place - this way we overwrite our copy of the plaintext
     password */
  deskey(key, EN0);
  des(encryptedPasswd, encryptedPasswd);
}

/* [UltraVNC/rfb/dh.cpp] */
uint64_t bytesToInt64(const unsigned char* const bytes) {
  uint64_t result = 0;
  int i;

  for (i = 0; i < 8; i++) {
    result <<= 8;
    result += bytes[i];
  }
  return result;
}

int int64ToBytes(const uint64_t integer, char* const bytes) {
  int i;
  for (i = 0; i < 8; i++) {
    bytes[i] = (unsigned char) (integer >> (8 * (7 - i)));
  }
  return SUCCESS;
}

/* [UltraVNC/vncviewer/vncauth.c] */
void vncEncryptBytes2(unsigned char *where, const int length, unsigned char *key) {
  int i, j;
  deskey(key, EN0);
  for (i = 0; i< 8; i++)
    where[i] ^= key[i];
  des(where, where);
  for (i = 8; i < length; i += 8) {
    for (j = 0; j < 8; j++)
      where[i + j] ^= where[i + j - 8];
    des(where + i, where + i);
  }
}


int vncSessionSetup(int hSocket, _VNC_DATA* _psSessionData)
{
  unsigned char ProtocolVersion[13];
  int iServerProtocolVersion;
  unsigned char* bufReceive;
  int nReceiveBufferSize = 0;
  int i = 0; 
  int nSecurityTypes = 0;
  unsigned char* szSecurityTypes = NULL;
 
  memset(ProtocolVersion, 0, 13);
 
  /* --- VNC Protocol Handshake --- */
 
  /* Retrieve server VNC protocol version */
  nReceiveBufferSize = 0;
  bufReceive = medusaReceiveRaw(hSocket, &nReceiveBufferSize);
  if (bufReceive == NULL)
    return SESSION_FAILURE;

  writeError(ERR_DEBUG_MODULE, "VNC Server Protocol Version: %s", bufReceive);

  /* The following message is triggered by 5 failed authentication attempts, at which 
  ** point a 10 second lockout is applied before the next attempt is permitted.  Each
  ** subsequent failed attempt causes the timeout to be doubled. 
  **
  **   RealVNC: Too many security failures
  **   WinVNC (<=3.3.3r2): Too many authentication failures
  */
  if ((strncmp((char *)bufReceive + 20, "Too many security failures", 26) == 0) || (strncmp((char *)bufReceive + 20, "Too many authentication failures", 32) == 0))
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Host reported too many security failures.", MODULE_NAME);
    return SESSION_MAX_AUTH_REALVNC;
  }
  /* 3.3, 3.7 and 3.8 are the only published protocol versions (RFB Protocol v3.8 11/26/2010) */
  else if (strncmp((char *)bufReceive, "RFB 003.003", 11) == 0)
  {
    memcpy(ProtocolVersion, "RFB 003.003\n", 12);
    iServerProtocolVersion = 3;
  }
  else if (strncmp((char *)bufReceive, "RFB 003.007", 11) == 0)
  {
    memcpy(ProtocolVersion, "RFB 003.007\n", 12);
    iServerProtocolVersion = 7;
  }
  else if (strncmp((char *)bufReceive, "RFB 003.008", 11) == 0)
  {
    memcpy(ProtocolVersion, "RFB 003.008\n", 12);
    iServerProtocolVersion = 8;
  }
  /* RealVNC - VNC Server Enterprise Edition E4.6.3 (r66752) */
  else if (strncmp((char *)bufReceive, "RFB 004.001", 11) == 0)
  {
    memcpy(ProtocolVersion, "RFB 004.001\n", 12);
    iServerProtocolVersion = 8;
  }
  else
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Unknown session setup response: %s. Setting client response to version 3.3.", MODULE_NAME, bufReceive);
    memcpy(ProtocolVersion, "RFB 003.003\n", 12);
    iServerProtocolVersion = 3;
  }

  /* Send client VNC protocol version */
  writeError(ERR_DEBUG_MODULE, "VNC Client Protocol Version: %s", ProtocolVersion);
  if (medusaSend(hSocket, ProtocolVersion, 12, 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
  }
 
  /* Some VNC servers seem to get upset if we go too fast. Sleeping 1/2 second seems to help. */
  usleep(0.5 * 1000000);
  
  /* --- VNC Security Type Handshake --- */
  
  /* Retrieve VNC protocol authentication scheme response */
  nReceiveBufferSize = 0;
  bufReceive = medusaReceiveRaw(hSocket, &nReceiveBufferSize);

  if ((bufReceive == NULL) || (nReceiveBufferSize == 0))
  {  
    writeError(ERR_ERROR, "No security type response received from server.");
    return SESSION_FAILURE;
  }
  /* RFB Protocol 3.3 - Security Type 
  **
  ** Server: U32 [security type]
  **
  ** if the security types is 0, response is followed by:
  ** Server: U32 [reason-length]
  **         U8 array [reason for connection failure]
  */
  else if (iServerProtocolVersion == 3)
  {
    writeErrorBin(ERR_DEBUG_MODULE, "Supported Security Types (version 3.3): ", bufReceive, nReceiveBufferSize);
    switch (bufReceive[3])
    {
      case 0x00:  /* connection failure */
        writeError(ERR_DEBUG_MODULE, "VNC Session Setup - Failed.");

        if (nReceiveBufferSize > 16)
          writeError(ERR_DEBUG_MODULE, "VNC Session Setup Failure Message: %s", bufReceive + 8);

        /* Server is probably in anti-brute force mode (UltraVNC) */
        if ((nReceiveBufferSize == 42) && (strncmp((char *)bufReceive + 8, "Your connection has been rejected.", 34) == 0)) 
          return SESSION_MAX_AUTH_ULTRAVNC;
        else
          return SESSION_FAILURE;
        break;

      case 0x01:  /* no authentication required */
        writeError(ERR_DEBUG_MODULE, "VNC Session Setup - Successful - No Authentication Required.");
        return SESSION_SUCCESS_NO_AUTH;
        break;

      case 0x02:  /* authentication required -- set authentication challenge */
        writeError(ERR_DEBUG_MODULE, "VNC Session Setup - Successful.");
        if (nReceiveBufferSize == 20)
        {
          _psSessionData->szChallenge = malloc(17);
          memset(_psSessionData->szChallenge, 0, 17);
          memcpy(_psSessionData->szChallenge, bufReceive + 4, 16);
          writeError(ERR_DEBUG_MODULE, "VNC authentication challenge: %s", _psSessionData->szChallenge);
          _psSessionData->nAuthType = AUTH_VNC;
          return SESSION_SUCCESS;
        }
        else
        {
          writeError(ERR_ERROR, "[%s] Unknown session challenge. Possible unsupported authentication type.", MODULE_NAME);
          return SESSION_FAILURE;
        }
        break;
      
      case 0xFA: /* UltaVNC MS-Logon */
        writeError(ERR_DEBUG_MODULE, "VNC Session Setup - UltraVNC MS-Logon.");

        if (nReceiveBufferSize == 28)
        {
          _psSessionData->szChallenge = malloc(25);
          memset(_psSessionData->szChallenge, 0, 25);
          memcpy(_psSessionData->szChallenge, bufReceive + 4, 24);
          writeErrorBin(ERR_DEBUG_MODULE, "VNC authentication challenge: ", bufReceive + 4, 24);
          _psSessionData->nAuthType = AUTH_UVNC_MSLOGIN;
          return SESSION_SUCCESS;
        }
        else
        {
          writeError(ERR_ERROR, "[%s] Unknown session challenge. Possible unsupported authentication type.", MODULE_NAME);
          return SESSION_FAILURE;
        }

        break;
        
      default: /* unknown response */
        writeError(ERR_ERROR, "[%s] VNC Session Setup - Unknown Response (3.3): %d", MODULE_NAME, bufReceive[3]);
        return SESSION_FAILURE;
        break;
    }
  }
  /* RFB Protocol 3.7, 3.8 - Security Type 
  **
  ** Server: U8 [number of security types]
  **         U8 array [security type]
  **
  ** If the number of security types is 0, response is followed by:
  ** Server: U32 [reason-length]
  **         U8 array [reason for connection failure]
  */
  else if ((iServerProtocolVersion == 7) || (iServerProtocolVersion == 8))
  {
    writeErrorBin(ERR_DEBUG_MODULE, "Supported Security Types (> version 3.7): ", bufReceive, nReceiveBufferSize);

    /* connection failure */
    if (bufReceive[0] == 0)
    {
      writeError(ERR_DEBUG_MODULE, "VNC Session Setup - Failed.");

      //memcpy(nReasonLength + sizeof(int), bufReceive + 1, 4);

      if (nReceiveBufferSize > 8)
        writeError(ERR_DEBUG_MODULE, "VNC Session Setup Failure Message: %s", bufReceive + 5);

      /* Server is probably in anti-brute force mode (UltraVNC) */
      if (strncmp((char *)bufReceive + 5, "Your connection has been rejected.", 34) == 0)
        return SESSION_MAX_AUTH_ULTRAVNC;
      else
        return SESSION_FAILURE;
    }
    /* verify response length */
    else if (nReceiveBufferSize == 1 + (int)bufReceive[0])
    {
      nSecurityTypes = (int)bufReceive[0];
      szSecurityTypes = malloc(nSecurityTypes + 1);
      memset(szSecurityTypes, 0, nSecurityTypes + 1);
      memcpy(szSecurityTypes, bufReceive + 1, nSecurityTypes);

      for (i = 0; i <= nSecurityTypes; i++)
      {
        writeError(ERR_DEBUG_MODULE, "Processing server security type: %d (%d/%d). We will select the first supported type encountered.", szSecurityTypes[i], i + 1, nSecurityTypes);
        switch (szSecurityTypes[i])
        {
          case 0x01:  /* no authentication required */
            writeError(ERR_DEBUG_MODULE, "VNC Session Setup - Password-only VNC - No Authentication Required");
              
            if (medusaSend(hSocket, &szSecurityTypes[i], 1, 0) < 0)
            {
              writeError(ERR_ERROR, "[%s] failed: medusaSend was not successful", MODULE_NAME);
              return FAILURE;
            }

            nReceiveBufferSize = 0;
            bufReceive = medusaReceiveRaw(hSocket, &nReceiveBufferSize);
            if (bufReceive == NULL)
              return FAILURE;
            else if (bufReceive[3] == 0)
              return SESSION_SUCCESS_NO_AUTH;
            else
              return FAILURE;

            break;
          case 0x02:  /* authentication required -- set authentication challenge */
            writeError(ERR_DEBUG_MODULE, "VNC Session Setup - Password-only VNC");

            if (medusaSend(hSocket, &szSecurityTypes[i], 1, 0) < 0)
            {
              writeError(ERR_ERROR, "[%s] failed: medusaSend was not successful", MODULE_NAME);
              return FAILURE;
            }

            nReceiveBufferSize = 0;
            bufReceive = medusaReceiveRaw(hSocket, &nReceiveBufferSize);
           
            if (nReceiveBufferSize == 16)
            {
              _psSessionData->szChallenge = malloc(17);
              memset(_psSessionData->szChallenge, 0, 17);
              memcpy(_psSessionData->szChallenge, bufReceive, 16);
              writeError(ERR_DEBUG_MODULE, "VNC authentication challenge: %s", _psSessionData->szChallenge);
              _psSessionData->nAuthType = AUTH_VNC;
              return SESSION_SUCCESS;
            }
            else
            {
              writeError(ERR_ERROR, "[%s] Unknown session challenge. Possible unsupported authentication type.", MODULE_NAME);
              return SESSION_FAILURE;
            }
            break;

          case 0x05:  /* 5: RealVNC RA2 */
          case 0x06:  /* 6: RealVNC RA2ne */
          case 0x81:  /* 129: UNIX Logon Authentication */
          case 0x82:  /* 130: External Authentication */
            writeError(ERR_ERROR, "[%s] VNC Session Setup - RealVNC (Type %d). RealVNC native authentication mode is NOT currently supported.", MODULE_NAME, szSecurityTypes[i]);
            break;

          case 0x11:  /* 17: UltraVNC */
            /* http://www.uvnc.com/features/authentication.html */
            /*
              [rfb/rfbproto.h]
              rfbUltraVNC 0x17 - after rfbUltraVNC, auth repeats via rfbVncAuthContinue

              rfbUltraVNC_SCPrompt 0x68
              rfbUltraVNC_SessionSelect 0x69
              rfbUltraVNC_MsLogonIAuth 0x70
              rfbUltraVNC_MsLogonIIAuth 0x71
              rfbUltraVNC_SecureVNCPluginAuth 0x72
            */
            
            writeError(ERR_DEBUG_MODULE, "VNC Session Setup - UltraVNC");

            /*
              0x11 UltraVNC contains multiple sub-types. If we respond with 0x11, the server
              should send us a list. For example, 0xffffffff 0x0171 (UltraVNC MS-Logon II).
              This appears to be sent sometimes as a single packet, sometimes as two. It seems
              that any sub-types we would enumerate here, however, were also listed in the initial
              supported security type response. As such, let's just skip this type and move on
              to the next in the list. If this assumption turns out to be incorrect, we should
              continue the security type negotiation here.
            */

            break;

          case 0x70:  /* 17: UltraVNC MS-Logon I */
          case 0x71:  /* 17: UltraVNC MS-Logon II */
            writeError(ERR_DEBUG_MODULE, "VNC Session Setup - UltraVNC (Type %d)", szSecurityTypes[i]);

            if (medusaSend(hSocket, &szSecurityTypes[i], 1, 0) < 0)
            {
              writeError(ERR_ERROR, "[%s] failed: medusaSend was not successful", MODULE_NAME);
              return FAILURE;
            }

            nReceiveBufferSize = 0;
            bufReceive = medusaReceiveRaw(hSocket, &nReceiveBufferSize);

            if (nReceiveBufferSize == 24)
            {
              writeError(ERR_DEBUG_MODULE, "VNC Session Setup - UltraVNC MS-Logon II - Process authentication challenge");
              _psSessionData->szChallenge = malloc(25);
              memset(_psSessionData->szChallenge, 0, 25);
              memcpy(_psSessionData->szChallenge, bufReceive, 24);
              writeErrorBin(ERR_DEBUG_MODULE, "VNC authentication challenge: ", _psSessionData->szChallenge, 24);
              _psSessionData->nAuthType = AUTH_UVNC_MSLOGIN;
              return SESSION_SUCCESS;
            }
            
            break;
 
          default: /* unknown response - skip and see if we find a supported type */
            writeError(ERR_ERROR, "[%s] VNC Session Setup - Unknown Response (3.7/3.8): %d", MODULE_NAME, szSecurityTypes[i]);
            break;
        }
      }
    }
    else
    {
      writeError(ERR_ERROR, "[%s] VNC Session Setup - Unknown Response", MODULE_NAME);
      return SESSION_FAILURE;
    }
  }

  FREE(szSecurityTypes);
  return SESSION_FAILURE;
}

int sendAuthVNC(int hSocket, _VNC_DATA* _psSessionData, char* szPassword)
{
  writeError(ERR_DEBUG_MODULE, "[%s] VNC authentication challenge: %s", MODULE_NAME, _psSessionData->szChallenge);
  vncEncryptBytes(_psSessionData->szChallenge, szPassword);
  writeError(ERR_DEBUG_MODULE, "[%s] VNC authentication response: %s", MODULE_NAME, _psSessionData->szChallenge);

  if (medusaSend(hSocket, _psSessionData->szChallenge, 16, 0) < 0)
  {
    writeError(ERR_ERROR, "[%s] failed: medusaSend was not successful", MODULE_NAME);
    return FAILURE;
  }

  return SUCCESS;
}

/*
    Based on ClientConnection::AuthMsLogonII() [UltraVNC/vncviewer/ClientConnection.cpp]
  
    MS Logon authentication supports "domain\user", "user" and "user@domain" logins
*/
int sendAuthMSLogin(int hSocket, _VNC_DATA* _psSessionData, char* szLogin, char* szPassword)
{
  unsigned char ms_user[256], ms_passwd[64];
  unsigned char key[8];
  int i = 0;
  
  int client_priv = 31337; /* arbitrary value -- client would typically randomly generate */ 
  uint64_t g, p, resp;
  char client_pub[8];
  BIGNUM* server_pub;

  DH *dh_struct;
  int dh_error;
  unsigned char *dh_secret;

  unsigned char *bufSend = NULL;

  writeError(ERR_DEBUG_MODULE, "[%s] VNC Authentication - UltraVNC Microsoft Logon", MODULE_NAME);
  
  /* parse server challenge -- g, p (mod) and server public key */
  g = bytesToInt64(_psSessionData->szChallenge);
  p = bytesToInt64(_psSessionData->szChallenge + 8);
  resp = bytesToInt64(_psSessionData->szChallenge + 16);

  writeError(ERR_DEBUG_MODULE, "[%s] Server DH values: g: %d p/mod: %d public key: %d", MODULE_NAME, g, p, resp);

  /* create and populate DH structure */ 
  dh_struct = DH_new();
 
  dh_struct->g = BN_new();
  BN_set_word(dh_struct->g, g);
  
  dh_struct->p = BN_new();
  BN_set_word(dh_struct->p, p);
  
  dh_struct->priv_key = BN_new();
  BN_set_word(dh_struct->priv_key, client_priv);

  if (DH_generate_key(dh_struct) == 0)
    writeError(ERR_ERROR, "[%s] Failed to generate key", MODULE_NAME);
  
  writeError(ERR_DEBUG_MODULE, "[%s] Client DH private key: %s public key: %s", MODULE_NAME, BN_bn2hex(dh_struct->priv_key), BN_bn2hex(dh_struct->pub_key));
  
  DH_check(dh_struct, &dh_error);
  if (dh_error & DH_CHECK_P_NOT_SAFE_PRIME)
    writeError(ERR_DEBUG_MODULE, "[%s] Failed to create DH structure: DH_CHECK_P_NOT_SAFE_PRIME", MODULE_NAME);
  if (dh_error & DH_NOT_SUITABLE_GENERATOR)
    writeError(ERR_DEBUG_MODULE, "[%s] Failed to create DH structure: DH_NOT_SUITABLE_GENERATOR", MODULE_NAME);
  if (dh_error & DH_UNABLE_TO_CHECK_GENERATOR)
    writeError(ERR_DEBUG_MODULE, "[%s] Failed to create DH structure: DH_UNABLE_TO_CHECK_GENERATOR", MODULE_NAME);

  /* convert client public key into proper format for sending */
  int64ToBytes(BN_get_word(dh_struct->pub_key), client_pub);

  /* generate shared secret using private DH key and server's public key */
  server_pub = BN_new();
  BN_set_word(server_pub, resp);
  
  dh_secret = malloc( DH_size(dh_struct) );
  DH_compute_key(dh_secret, server_pub, dh_struct);
  
  /* OpenSSLs DH implementation is compliant with the SSL/TLS requirements that skip
     leading zeroes on the output. We need our key to be exactly 8 bytes long, so
     let's prepend it with the necessary number of zeros. */
  memset(key, 0, 8);
  if (DH_size(dh_struct) < 8)
    for (i=0; i < DH_size(dh_struct); i++)
      key[8 - DH_size(dh_struct) + i] = dh_secret[i];
  
  DH_free(dh_struct);

  writeErrorBin(ERR_DEBUG_MODULE, "Shared secret key: ", key, 8);

  memset(ms_user, 0, 256);
  memset(ms_passwd, 0, 64);

  if ((_psSessionData->szDomain) && (strlen(_psSessionData->szDomain) + 1 + strlen(szLogin) < 256))
  { 
    strncpy((char *)ms_user, _psSessionData->szDomain, strlen(_psSessionData->szDomain));
    strncat((char *)ms_user, "\\", 1);
    strncat((char *)ms_user, szLogin, strlen(szLogin));
  }
  else
    strncpy((char *)ms_user, szLogin, 256);

  strncpy((char *)ms_passwd, szPassword, 64);

  writeError(ERR_DEBUG_MODULE, "Username: %s Password: %s", ms_user, ms_passwd);
  writeErrorBin(ERR_DEBUG_MODULE, "Username: ", ms_user, 256);
  writeErrorBin(ERR_DEBUG_MODULE, "Password: ", ms_passwd, 64);

  vncEncryptBytes2((unsigned char*) &ms_user, sizeof(ms_user), key);
  vncEncryptBytes2((unsigned char*) &ms_passwd, sizeof(ms_passwd), key);

  writeErrorBin(ERR_DEBUG_MODULE, "Encrypted username: ", ms_user, 256);
  writeErrorBin(ERR_DEBUG_MODULE, "Encrypted password: ", ms_passwd, 64);

  /* send client public key, encrypted username, and encrypted password */
  bufSend = malloc(8 + sizeof(ms_user) + sizeof(ms_passwd) + 1);
  memset(bufSend, 0, 8 + sizeof(ms_user) + sizeof(ms_passwd) + 1);

  /*
    For extra fun, set client_pub to a value of 0x80000000 or greater. No more server...
    memset(client_pub, 0x0000000080, 5);
  */
  memcpy(bufSend, client_pub, 8);
  memcpy(bufSend + 8, ms_user, sizeof(ms_user));
  memcpy(bufSend + 8 + sizeof(ms_user), ms_passwd, sizeof(ms_passwd));

  if (medusaSend(hSocket, bufSend, 8 + sizeof(ms_user) + sizeof(ms_passwd), 0) < 0)
  {
    writeError(ERR_ERROR, "[%s] failed: medusaSend was not successful", MODULE_NAME);
    return FAILURE;
  }

  return SUCCESS;
}

int sendExit(int hSocket)
{
  unsigned char szExit[] = { 0x00, 0x00, 0x00, 0x00, 0x05, 0x1D, 0x03, 0x20 }; 
  
  writeError(ERR_DEBUG_MODULE, "[%s] Send VNC connection termination command.", MODULE_NAME);

  if (medusaSend(hSocket, szExit, 8, 0) < 0)
  {
    writeError(ERR_ERROR, "[%s] failed: medusaSend was not successful", MODULE_NAME);
    return FAILURE;
  }

  return SUCCESS;
}

int tryLogin(int hSocket, sLogin** psLogin, _VNC_DATA* _psSessionData, char* szLogin, char* szPassword)
{
  unsigned char* bufReceive;
  int nReceiveBufferSize = 0;
  int iRet;

  /* perform authentication */
  switch(_psSessionData->nAuthType)
  {
    case AUTH_VNC:
      sendAuthVNC(hSocket, _psSessionData, szPassword);
      break;
    case AUTH_UVNC_MSLOGIN:
      sendAuthMSLogin(hSocket, _psSessionData, szLogin, szPassword);
      break;
    default:
      writeError(ERR_DEBUG_MODULE, "[%s] VNC Authentication - blah", MODULE_NAME);
      break;
  }

  writeError(ERR_DEBUG_MODULE, "[%s] VNC Authentication - Waiting for authentication result", MODULE_NAME);
  nReceiveBufferSize = 0;
  bufReceive = medusaReceiveRaw(hSocket, &nReceiveBufferSize);
  if (bufReceive == NULL)
    return FAILURE;
  else if (nReceiveBufferSize == 0)
  {
    /* Some VNC servers (e.g. TightVNC 2.0 Beta) simply drop the connection on a bad password */
    writeError(ERR_DEBUG_MODULE, "[%s] VNC Authentication - Failed (no response from server)", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_FAIL;
    iRet = MSTATE_NEW;
  }
  else if (nReceiveBufferSize >= 4)
  {
    switch (bufReceive[3])
    {
      case 0x00:
        writeError(ERR_DEBUG_MODULE, "[%s] VNC Authentication - Success", MODULE_NAME);
        (*psLogin)->iResult = LOGIN_RESULT_SUCCESS; 
        iRet = MSTATE_EXITING;

        // TODO: Is this only for UltraVNC?
        sendExit(hSocket);
        break;
      case 0x01:
        if ((nReceiveBufferSize > 8) && (strstr((char *)bufReceive + 8, "Connection rejected by user") != NULL))
        {
          writeError(ERR_DEBUG_MODULE, "[%s] VNC Authentication - Success (User rejected connection)", MODULE_NAME);
          (*psLogin)->pErrorMsg = malloc( 40 + 1 );
          memset((*psLogin)->pErrorMsg, 0, 40 + 1 );
          sprintf((*psLogin)->pErrorMsg, "User rejected connection request.");
          (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
          iRet = MSTATE_EXITING;
        }
        else
        {
          writeError(ERR_DEBUG_MODULE, "[%s] VNC Authentication - Failed", MODULE_NAME);
          (*psLogin)->iResult = LOGIN_RESULT_FAIL;
          iRet = MSTATE_NEW;
        }
        break;
      default:
        writeError(ERR_ERROR, "[%s] VNC Authentication - Unknown Response: %d", MODULE_NAME, bufReceive[3]);
        (*psLogin)->iResult = LOGIN_RESULT_ERROR;
        iRet = MSTATE_EXITING;
        break;
    }
  }
  else
  {
    writeError(ERR_ERROR, "[%s] VNC Authentication - Unknown Response", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_ERROR;
    iRet = MSTATE_EXITING;
  }

  setPassResult((*psLogin), szPassword);

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
