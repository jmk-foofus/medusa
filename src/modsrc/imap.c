/*
**   IMAP Password Checking Medusa Module
**
**   ------------------------------------------------------------------------
**    Copyright (C) 2006 pMonkey
**    pMonkey <pmonkey@foofus.net>
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
**   Helpful item besides reading lots of RFC's
**   http://www.kolab.org/pipermail/kolab-commits/2005q1/001959.html
**
**   Modifications: (JoMo-Kun)
**    Support for LOGIN command
**    Optional module parameters
**
*/

#include <sys/types.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "module.h"
#include "ntlm.h"

#define MODULE_NAME    "imap.mod"
#define MODULE_AUTHOR  "pMonkey <pmonkey@foofus.net>"
#define MODULE_SUMMARY_USAGE  "Brute force module for IMAP sessions"
#define MODULE_VERSION    "2.0"
#define MODULE_VERSION_SVN "$Id: imap.c 1878 2014-03-04 00:13:42Z jmk $"
#define MODULE_SUMMARY_FORMAT  "%s : version %s"

#define BUF_SIZE 300

#define PORT_IMAP  143
#define PORT_IMAPS 993

#define RECEIVE_DELAY_1 20 * 1000000
#define RECEIVE_DELAY_2 0.5 * 1000000

#define AUTH_UNKNOWN 0
#define AUTH_LOGIN 1
#define AUTH_PLAIN 2
#define AUTH_NTLM 3

typedef struct __MODULE_DATA {
  char *szTag;
  int nAuthType;
  char* szDomain;
} _MODULE_DATA;

// Tells us whether we are to continue processing or not
enum MODULE_STATE
{
  MSTATE_NEW,
  MSTATE_RUNNING,
  MSTATE_EXITING,
  MSTATE_COMPLETE
};

// Forward declarations
int initConnection(_MODULE_DATA *_psSessionData, int hSocket, sConnectParams *params);
int tryLogin(int hSocket,  _MODULE_DATA* _psSessionData, sLogin** login, char* szLogin, char* szPassword);
int initModule(_MODULE_DATA* _psSessionData, sLogin* login);

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
  writeVerbose(VB_NONE, "  TAG:? (Default: gerg)");
  writeVerbose(VB_NONE, "  AUTH:? (Authentication Type (LOGIN/PLAIN/NTLM). Default: automatic)");
  writeVerbose(VB_NONE, "  DOMAIN:? [optional]");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "Usage example: \"-M imap -m TAG:A0001 -m AUTH:PLAIN");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "The DOMAIN option should supply the specified domain appropriately,");
  writeVerbose(VB_NONE, "regardless of authentication type. The domain can also be supplied ");
  writeVerbose(VB_NONE, "via the username field, but the format appears to differ by auth type.");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "Example 1: NTLM authentication with DOMAIN option");
  writeVerbose(VB_NONE, "   \"medusa -M imap -m AUTH:NTLM -m DOMAIN:FOODOM -h host -u foo -p bar\"");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "Example 2: NTLM authentication with domain via username");
  writeVerbose(VB_NONE, "   \"medusa -M imap -m AUTH:NTLM -h host -u foo@domain -p bar\"");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "* If no domain is specified when using NTLM authentication, the server");
  writeVerbose(VB_NONE, "supplied value will be used.");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "Example 3: LOGIN authentication with domain via username");
  writeVerbose(VB_NONE, "   \"medusa -M imap -m AUTH:LOGIN -h host -u 'domain\\\\foo' -p bar\"");
}

// The "main" of the medusa module world - this is what gets called to actually do the work
int go(sLogin* logins, int argc, char *argv[])
{
  int i;
  char *strtok_ptr, *pOpt, *pOptTmp;
  _MODULE_DATA *psSessionData;
  psSessionData = malloc(sizeof(_MODULE_DATA));
  memset(psSessionData, 0, sizeof(_MODULE_DATA));

  if ((argc < 0) || (argc > 3))
  {
    writeError(ERR_ERROR, "%s: Incorrect number of parameters passed to module (%d). Use \"-q\" option to display module usage.", MODULE_NAME, argc);
    return FAILURE;
  }
  else 
  {
    // Parameters are good - make module go now
    writeError(ERR_DEBUG_MODULE, "OMG teh %s module has been called!!", MODULE_NAME);

    for (i=0; i<argc; i++) {
      pOptTmp = malloc( strlen(argv[i]) + 1);
      memset(pOptTmp, 0, strlen(argv[i]) + 1);
      strncpy(pOptTmp, argv[i], strlen(argv[i]));
      writeError(ERR_DEBUG_MODULE, "Processing complete option: %s", pOptTmp);
      pOpt = strtok_r(pOptTmp, ":", &strtok_ptr);
      writeError(ERR_DEBUG_MODULE, "Processing option: %s", pOpt);

      if (strcmp(pOpt, "TAG") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if ( pOpt )
        {
          psSessionData->szTag = malloc(strlen(pOpt) + 1);
          memset(psSessionData->szTag, 0, strlen(pOpt) + 1);
          strncpy(psSessionData->szTag, pOpt, strlen(pOpt) + 1);
        }
        else
          writeError(ERR_WARNING, "Method TAG requires value to be set.");
      }
      else if (strcmp(pOpt, "AUTH") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if (pOpt == NULL)
          writeError(ERR_WARNING, "Method AUTH requires value to be set.");
        else if (strcmp(pOpt, "LOGIN") == 0)
          psSessionData->nAuthType = AUTH_LOGIN;
        else if (strcmp(pOpt, "PLAIN") == 0)
          psSessionData->nAuthType = AUTH_PLAIN;
        else if (strcmp(pOpt, "NTLM") == 0)
          psSessionData->nAuthType = AUTH_NTLM;
        else
          writeError(ERR_WARNING, "Invalid value for method AUTH.");
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
      {
        writeError(ERR_WARNING, "Invalid method: %s.", pOpt);
      }

      free(pOptTmp);
    }

    initModule(psSessionData, logins);
  }  

  FREE(psSessionData);
  return SUCCESS;
}

int initModule(_MODULE_DATA *_psSessionData, sLogin* psLogin)
{
  int hSocket = -1;
  enum MODULE_STATE nState = MSTATE_NEW;
  sCredentialSet *psCredSet = NULL;
  sConnectParams params;

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
  else if (psLogin->psServer->psHost->iUseSSL > 0)
    params.nPort = PORT_IMAPS;
  else
    params.nPort = PORT_IMAP;
  initConnectionParams(psLogin, &params);

  /* set TAG, if not specified by user */
  if (_psSessionData->szTag == NULL)
  {
    _psSessionData->szTag = malloc(5);
    memset(_psSessionData->szTag, 0, 5);
    sprintf(_psSessionData->szTag, "gerg");
  }

  while (nState != MSTATE_COMPLETE)
  {  
    switch (nState)
    {
      case MSTATE_NEW:
        // Already have an open socket - close it
        if (hSocket > 0)
          medusaDisconnect(hSocket);

        /* Reset SSL flag if set (e.g., SSL connection had been reset by anti-bruteforce mechanism) */
        params.nUseSSL = 0;
        if (psLogin->psServer->psHost->iUseSSL > 0)
          hSocket = medusaConnectSSL(&params);
        else
          hSocket = medusaConnect(&params);
        
        if (hSocket < 0) 
        {
          writeError(ERR_NOTICE, "%s: failed to connect, port %d was not open on %s", MODULE_NAME, params.nPort, psLogin->psServer->pHostIP);
          psLogin->iResult = LOGIN_RESULT_UNKNOWN;
          return FAILURE;
        }

        if (initConnection(_psSessionData, hSocket, &params) == FAILURE)
        {
          psLogin->iResult = LOGIN_RESULT_UNKNOWN;
          return FAILURE;
        }

        writeError(ERR_DEBUG_MODULE, "Connected");

        nState = MSTATE_RUNNING;
        break;
      case MSTATE_RUNNING:
        /* The IMAP service may be configured to drop connections after an arbitrary number of failed
           logon attempts. We will reuse the established connection to send authentication attempts 
           until that disconnect happens. At that point the connection should be reestablished. */
        if ( medusaCheckSocket(hSocket, psLogin->psServer->psAudit->iSocketWait) )
        {
          nState = tryLogin(hSocket, _psSessionData, &psLogin, psCredSet->psUser->pUser, psCredSet->pPass);

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
        }
        else
        {
          writeError(ERR_NOTICE, "[%s] Socket is no longer valid. Server likely dropped connection. Establishing new session.", MODULE_NAME);
          nState = MSTATE_NEW;

          if (hSocket > 0)
            medusaDisconnect(hSocket);
          hSocket = -1;
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

/* Module Specific Functions */
int initConnection(_MODULE_DATA *_psSessionData, int hSocket, sConnectParams *params)
{
  unsigned char *bufSend = NULL;
  unsigned char *bufReceive = NULL;
  int nReceiveBufferSize = 0;
  int nSendBufferSize = 0;

  /* Retrieve IMAP server banner */
  if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "^\\* OK .*\r\n") == FAILURE) || (bufReceive == NULL))
  {
    writeError(ERR_ERROR, "[%s] Failed to retrieve IMAP server banner. Exiting...", MODULE_NAME);
    return FAILURE; 
  }
  else if ((strstr((char*)bufReceive,"* OK ") != NULL))
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Received IMAP server banner: %s", MODULE_NAME, bufReceive);
    FREE(bufReceive);
  }
  else if ((strstr((char*)bufReceive,"* BYE Connection refused") != NULL))
  {
    writeError(ERR_ERROR, "[%s] IMAP server refused connection. Is SSL required?", MODULE_NAME);
    FREE(bufReceive);
    return FAILURE;
  }
  else
  {
    writeError(ERR_ERROR, "[%s] Failed to retrieve IMAP server banner.", MODULE_NAME);
    FREE(bufReceive);
    return FAILURE;
  }

  /* Request IMAP server capabilities */
  writeError(ERR_DEBUG_MODULE, "[%s] Sending IMAP CAPABILITIES request.", MODULE_NAME);
  nSendBufferSize = strlen(_psSessionData->szTag) + 13;
  bufSend = malloc(nSendBufferSize + 1);
  memset(bufSend, 0, nSendBufferSize + 1);
  sprintf((char*)bufSend, "%s CAPABILITY\r\n", _psSessionData->szTag);

  if (medusaSend(hSocket, bufSend, strlen((char*)bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "[%s] Failed: medusaSend was not successful", MODULE_NAME);
    FREE(bufSend);
    return FAILURE;
  }
  FREE(bufSend);

  nReceiveBufferSize = 0;
  if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "OK .*\r\n") == FAILURE) || (bufReceive == NULL))
  {
    writeError(ERR_ERROR, "[%s] Failed: No OK message received for CAPABILITY request.", MODULE_NAME);
    return FAILURE;
  }

  /* If server supports STARTTLS and we are not already within a SSL connection, let's use it. */
  if ((params->nUseSSL == 0) && (strstr((char*)bufReceive, "STARTTLS") != NULL))
  {
    FREE(bufReceive);

    writeError(ERR_DEBUG_MODULE, "[%s] Initiating STARTTLS session.", MODULE_NAME);

    bufSend = malloc(strlen(_psSessionData->szTag) + 11 + 1);
    memset(bufSend, 0, strlen(_psSessionData->szTag) + 11 + 1);
    sprintf((char*)bufSend, "%s STARTTLS\r\n", _psSessionData->szTag);
    if (medusaSend(hSocket, bufSend, strlen((char*)bufSend), 0) < 0)
    {
      writeError(ERR_ERROR, "[%s] failed: medusaSend was not successful", MODULE_NAME);
      FREE(bufSend);
      return FAILURE;
    }
    FREE(bufSend);
  
    nReceiveBufferSize = 0;
    if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "OK .*\r\n") == FAILURE) || (bufReceive == NULL))
    {
      writeError(ERR_ERROR, "[%s] Failed: No OK message received for STARTTLS request.", MODULE_NAME);
      return FAILURE;
    }
    /* OK Begin TLS negotiation now. */
    else
    {
      FREE(bufReceive);

      params->nSSLVersion = 3.1; /* Force the use of TLSv1 */
      if (medusaConnectSocketSSL(params, hSocket) < 0)
      {
        writeError(ERR_ERROR, "[%s] Failed to establish TLSv1 connection.", MODULE_NAME);
        return FAILURE;
      }

      /* Resend CAPABILITY request as the AUTH types may have changed. */
      writeError(ERR_DEBUG_MODULE, "[%s] Sending IMAP CAPABILITIES request.", MODULE_NAME);
      nSendBufferSize = strlen(_psSessionData->szTag) + 13;
      bufSend = malloc(nSendBufferSize + 1);
      memset(bufSend, 0, nSendBufferSize + 1);
      sprintf((char*)bufSend, "%s CAPABILITY\r\n", _psSessionData->szTag);

      if (medusaSend(hSocket, bufSend, strlen((char*)bufSend), 0) < 0)
      {
        writeError(ERR_ERROR, "[%s] Failed: medusaSend was not successful", MODULE_NAME);
        FREE(bufSend);
        return FAILURE;
      }
      FREE(bufSend);

      nReceiveBufferSize = 0;
      if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "OK .*\r\n") == FAILURE) || (bufReceive == NULL))
      {
        writeError(ERR_ERROR, "[%s] Failed: No OK message received for CAPABILITY request.", MODULE_NAME);
        return FAILURE;
      }
    }
  }

  /* Process IMAP supported authentication types */
  if (_psSessionData->nAuthType != AUTH_UNKNOWN)
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Ignoring server requested AUTH type and using user-specified value.", MODULE_NAME);
  }
  else if ((strstr((char*)bufReceive,"AUTH=LOGIN") != NULL))
  {
    writeError(ERR_DEBUG_MODULE, "Server requested authentication type: LOGIN");
    _psSessionData->nAuthType = AUTH_LOGIN;
  }
  else if ((strstr((char*)bufReceive,"AUTH=PLAIN") != NULL))
  {
    writeError(ERR_DEBUG_MODULE, "Server requested authentication type: PLAIN");
    _psSessionData->nAuthType = AUTH_PLAIN;
  }
  else if ((strstr((char*)bufReceive,"AUTH=NTLM") != NULL))
  {
    writeError(ERR_DEBUG_MODULE, "Server requested authentication type: NTLM");
    _psSessionData->nAuthType = AUTH_NTLM;
  }
  else
  {
    writeError(ERR_ERROR, "[%s] Failed: Server did not respond that it supported any of the authentication types we handle (PLAIN, LOGIN, NTLM). Use the AUTH module option to force the use of an authentication type.", MODULE_NAME);
    return FAILURE; 
  }

  FREE(bufReceive);
  return SUCCESS;
}

/* A0001 LOGIN username password */
int sendAuthLogin(int hSocket, _MODULE_DATA* _psSessionData, char* szLogin, char* szPassword)
{
  unsigned char* bufSend = NULL;
  int nSendBufferSize = 0;
  int nRet = SUCCESS;

  nSendBufferSize = strlen(_psSessionData->szTag) + 7 + strlen(szLogin) + 1 + strlen(szPassword) + 4 + 2; 
  bufSend = malloc(nSendBufferSize + 1);
  memset(bufSend, 0, nSendBufferSize + 1);

  if (_psSessionData->szDomain) 
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Sending authenticate login value: %s\\\\%s %s", MODULE_NAME, _psSessionData->szDomain, szLogin, szPassword); 
    sprintf((char*)bufSend, "%s LOGIN \"%s\\\\%s\" \"%s\"\r\n", _psSessionData->szTag, _psSessionData->szDomain, szLogin, szPassword);
  }
  else
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Sending authenticate login value: %s %s", MODULE_NAME, szLogin, szPassword); 
    sprintf((char*)bufSend, "%s LOGIN \"%s\" \"%s\"\r\n", _psSessionData->szTag, szLogin, szPassword);
  }

  if (medusaSend(hSocket, bufSend, strlen((char*)bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
    nRet = FAILURE;
  }

  FREE(bufSend); 
  return(nRet);
}

/* A0001 AUTHENTICATE PLAIN credentials(base64) */
int sendAuthPlain(int hSocket, _MODULE_DATA* _psSessionData, char* szLogin, char* szPassword)
{
  unsigned char* bufSend = NULL;
  unsigned char* bufReceive = NULL;
  char* szTmp = NULL;
  char* szEncodedAuth = NULL;
  int nSendBufferSize = 0;
  int nReceiveBufferSize = 0;

  /* Send initial AUTHENTICATE PLAIN command */
  nSendBufferSize = strlen(_psSessionData->szTag) + 21;
  bufSend = malloc(nSendBufferSize + 1);
  memset(bufSend, 0, nSendBufferSize + 1);
  sprintf((char*)bufSend, "%s AUTHENTICATE PLAIN\r\n", _psSessionData->szTag);
  
  if (medusaSend(hSocket, bufSend, strlen((char*)bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
  }
  FREE(bufSend); 

  nReceiveBufferSize = 0;
  if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "\\+.*\r\n") == FAILURE) || (bufReceive == NULL))
  {
    writeError(ERR_ERROR, "[%s] IMAP server did not respond with \"+\" to AUTHENTICATE PLAIN request.", MODULE_NAME);
    writeError(ERR_ERROR, "[%s] IMAP server sent the following response: %s", MODULE_NAME, bufReceive);
    return FAILURE;
  }

  /* Build a null separated string of szLogin \0 szLogin \0 szPassword */
  nSendBufferSize = strlen(szLogin) + 1 + strlen(szLogin) + 1 + strlen(szPassword); 
  
  szTmp = malloc(nSendBufferSize + 1);
  memset(szTmp, 0, nSendBufferSize + 1);
  
  /* username\0username\0password */
  memcpy(szTmp, szLogin, strlen(szLogin));
  memcpy(szTmp + strlen(szLogin) + 1, szLogin, strlen(szLogin));
  memcpy(szTmp + strlen(szLogin) + 1 + strlen(szLogin) + 1, szPassword, strlen(szPassword)); 
  
  szEncodedAuth = malloc(2 * nSendBufferSize + 1);
  memset(szEncodedAuth, 0, 2 * nSendBufferSize + 1);
  base64_encode(szTmp, nSendBufferSize, szEncodedAuth);
  FREE(szTmp);
 
  writeError(ERR_DEBUG_MODULE, "[%s] Sending authenticate plain value: %s", MODULE_NAME, szEncodedAuth); 
  nSendBufferSize = strlen(szEncodedAuth) + 2;
  bufSend = malloc(nSendBufferSize + 1);
  memset(bufSend, 0, nSendBufferSize + 1);
  sprintf((char*)bufSend, "%s\r\n", szEncodedAuth);
  FREE(szEncodedAuth);
  
  if (medusaSend(hSocket, bufSend, strlen((char*)bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
    return FAILURE;
  }

  FREE(bufSend); 
  return SUCCESS;
}

/*
  A0001 AUTHENTICATE NTLM
  
  NTLM IMAP Authentication
  Based on:
    http://curl.haxx.se/rfc/ntlm.html#ntlmImapAuthentication
    http://src.opensolaris.org/source/xref/sfw/usr/src/cmd/fetchmail/fetchmail-6.3.8/README.NTLM
*/
int sendAuthNTLM(int hSocket, _MODULE_DATA* _psSessionData, char* szLogin, char* szPassword)
{
  unsigned char* bufSend = NULL;
  unsigned char* bufReceive = NULL;
  int nSendBufferSize = 0;
  int nReceiveBufferSize = 0;
  tSmbNtlmAuthRequest   sTmpReq;
  tSmbNtlmAuthChallenge sTmpChall;
  tSmbNtlmAuthResponse  sTmpResp;
  char* szTmpBuf = NULL;
  char* szTmpBuf64 = NULL;

  /* --- Send initial AUTHENTICATE NTLM command --- */
  nSendBufferSize = strlen(_psSessionData->szTag) + 21;
  bufSend = malloc(nSendBufferSize + 1);
  memset(bufSend, 0, nSendBufferSize + 1);
  sprintf((char*)bufSend, "%s AUTHENTICATE NTLM\r\n", _psSessionData->szTag);
  
  if (medusaSend(hSocket, bufSend, strlen((char*)bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
  }
  FREE(bufSend); 

  /* Server should respond with an empty challenge, consisting simply of a "+" */
  nReceiveBufferSize = 0;
  if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "\\+\r\n") == FAILURE) || (bufReceive == NULL))
  {
    writeError(ERR_ERROR, "[%s] IMAP server did not respond with \"+\" to AUTHENTICATE NTLM request.", MODULE_NAME);
    writeError(ERR_ERROR, "[%s] IMAP server sent the following response: %s", MODULE_NAME, bufReceive);
    return FAILURE;
  }
  FREE(bufReceive);

  /* --- Send Base-64 encoded Type-1 message --- */
  buildAuthRequest(&sTmpReq, 0, NULL, NULL);
  
  szTmpBuf64 = malloc(2 * SmbLength(&sTmpReq) + 2);
  memset(szTmpBuf64, 0, 2 * SmbLength(&sTmpReq) + 2);

  base64_encode((char *)&sTmpReq, SmbLength(&sTmpReq), szTmpBuf64);
  writeError(ERR_DEBUG_MODULE, "[%s] Sending initial challenge (B64 Encoded): %s", MODULE_NAME, szTmpBuf64);

  nSendBufferSize = strlen(szTmpBuf64) + 2;
  bufSend = malloc(nSendBufferSize + 1);
  memset(bufSend, 0, nSendBufferSize + 1);
  sprintf((char*)bufSend, "%s\r\n", szTmpBuf64);

  FREE(szTmpBuf64);

  if (medusaSend(hSocket, bufSend, strlen((char*)bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "[%s] failed: medusaSend was not successful", MODULE_NAME);
    return FAILURE;
  }
  FREE(bufSend); 
  
  /* Server should respond with a Base-64 encoded Type-2 challenge message. The challenge response format is 
     specified by RFC 1730 ("+", followed by a space, followed by the challenge message). */
  nReceiveBufferSize = 0;
  if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "\\+ .*\r\n") == FAILURE) || (bufReceive == NULL))
  {
    writeError(ERR_ERROR, "[%s] Server did not send valid Type-2 challenge response.", MODULE_NAME);
    return FAILURE;
  }

  szTmpBuf = index((char*)bufReceive, '\r');
  szTmpBuf[0] = '\0';

  writeError(ERR_DEBUG_MODULE, "[%s] NTLM Challenge (B64 Encoded): %s", MODULE_NAME, bufReceive + 2);
  base64_decode((char*)bufReceive + 2, (char*)&sTmpChall);

  FREE(bufReceive);
  
  /* --- Calculate and send Base-64 encoded Type 3 response --- */
 
  buildAuthResponse(&sTmpChall, &sTmpResp, 0, szLogin, szPassword, _psSessionData->szDomain, NULL); 

  szTmpBuf64 = malloc(2 * SmbLength(&sTmpResp) + 2);
  memset(szTmpBuf64, 0, 2 * SmbLength(&sTmpResp) + 2);

  base64_encode((char *)&sTmpResp, SmbLength(&sTmpResp), szTmpBuf64);
  writeError(ERR_DEBUG_MODULE, "[%s] NTLM Response (B64 Encoded): %s", MODULE_NAME, szTmpBuf64);

  nSendBufferSize = strlen(szTmpBuf64) + 2;
  bufSend = malloc(nSendBufferSize + 1);
  memset(bufSend, 0, nSendBufferSize + 1);
  sprintf((char*)bufSend, "%s\r\n", szTmpBuf64);

  if (medusaSend(hSocket, bufSend, nSendBufferSize, 0) < 0)
  {
    writeError(ERR_ERROR, "[%s] failed: medusaSend was not successful", MODULE_NAME);
    return FAILURE;
  }

  FREE(szTmpBuf64);
  FREE(bufSend);

  /* Server should validate the response and indicate the result of authentication.
     e.g.  0001 OK AUTHENTICATE NTLM completed. */

  return SUCCESS;
}

int tryLogin(int hSocket, _MODULE_DATA* _psSessionData, sLogin** psLogin, char* szLogin, char* szPassword)
{
  int nRet = FAILURE;
  unsigned char* bufReceive = NULL;
  int nReceiveBufferSize = 0;

  switch(_psSessionData->nAuthType)
  {
    case AUTH_LOGIN:
      writeError(ERR_DEBUG_MODULE, "[%s] Sending LOGIN Authentication.", MODULE_NAME);
      nRet = sendAuthLogin(hSocket, _psSessionData, szLogin, szPassword);
      break;
    case AUTH_PLAIN:
      writeError(ERR_DEBUG_MODULE, "[%s] Sending PLAIN Authentication.", MODULE_NAME);
      nRet = sendAuthPlain(hSocket, _psSessionData, szLogin, szPassword);
      break;
    case AUTH_NTLM:
      writeError(ERR_DEBUG_MODULE, "[%s] Sending NTLM Authentication.", MODULE_NAME);
      nRet = sendAuthNTLM(hSocket, _psSessionData, szLogin, szPassword);
      break;
    default:
      break;
  }

  if (nRet == FAILURE)
  {
    writeError(ERR_ERROR, "[%s] Failed during sending of authentication data.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_UNKNOWN;
    setPassResult(*psLogin, szPassword);
    return MSTATE_EXITING;
  }

  /*
    Exchange 2003 Server Response Messages

    NO Logon failure: unknown user name or bad password.
    NO The specified authentication package is not supported.
    NO Clear text passwords have been disabled for this protocol.
    NO Cleartext login on this server requires the use of transport level security (SSL/TLS)
  */
 
  writeError(ERR_DEBUG_MODULE, "[%s] Retrieving server response.", MODULE_NAME);
  nReceiveBufferSize = 0;
  if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, ".*\r\n") == FAILURE) || (bufReceive == NULL))
  {
    /* The IMAP service may be configured to drop connections after an arbitrary number of failed
       logon attempts. We will reuse the established connection to send authentication attempts 
       until that disconnect happens.
 
       A default install of Debian (6.0.3 Squeeze) and the Courier Mail Server (0.65) was found 
       to drop connections immediately after the 8th failed attempt.
    */
    if ( medusaCheckSocket(hSocket, (*psLogin)->psServer->psAudit->iSocketWait) )
    {
      writeError(ERR_ERROR, "[%s] Failed: Unexpected or no data received.", MODULE_NAME);
      (*psLogin)->iResult = LOGIN_RESULT_ERROR;
      nRet = MSTATE_EXITING;
      return FAILURE;
    }
    else
    {
      writeError(ERR_NOTICE, "[%s] Socket is no longer valid. Server likely dropped connection. Establishing new session.", MODULE_NAME);
      (*psLogin)->iResult = LOGIN_RESULT_FAIL;
      nRet = MSTATE_NEW;
    }
  }
  else if (strstr((char*)bufReceive, "OK") != NULL) 
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Login attempt successful.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
    nRet = MSTATE_EXITING;
  }
  else if (strstr((char*)bufReceive, "NO Clear text passwords have been disabled for this protocol.") != NULL) 
  {
    writeError(ERR_ERROR, "[%s] Server reports that clear-text passwords have been disabled.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_ERROR;
    nRet = MSTATE_EXITING;
  }
  else if (strstr((char*)bufReceive, "NO Cleartext login on this server requires the use of transport level security (SSL/TLS)") != NULL) 
  {
    writeError(ERR_ERROR, "[%s] Server reports that clear-text passwords are only allowed over SSL/TLS.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_ERROR;
    nRet = MSTATE_EXITING;
  }
  else if (strstr((char*)bufReceive, "NO The specified authentication package is not supported.") != NULL) 
  {
    writeError(ERR_ERROR, "[%s] Server reports that the specified authentication package is not supported.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_ERROR;
    nRet = MSTATE_EXITING;
  }
  else if (strstr((char*)bufReceive, "NO") != NULL) 
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Login attempt failed.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_FAIL;
    nRet = MSTATE_RUNNING;
    
    /* Exchange 2010 can include disconnect in message -- NO AUTHENTICATE failed.[0D][0A]* BYE Connection is closed. */
    if (strstr((char*)bufReceive, "* BYE ") != NULL)
    {
      writeError(ERR_NOTICE, "[%s] Socket is no longer valid. Server likely dropped connection. Establishing new session.", MODULE_NAME);
      nRet = MSTATE_NEW;
    }
  }
  else if (strstr((char*)bufReceive, "BAD") != NULL) 
  {
    writeError(ERR_ERROR, "[%s] IMAP server responded that the command was unknown or the arguments were invalid.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_ERROR;
    nRet = MSTATE_EXITING;
  }
  else 
  {
    writeError(ERR_ERROR, "[%s] Unknown IMAP server response: %s", MODULE_NAME, bufReceive);
    (*psLogin)->iResult = LOGIN_RESULT_ERROR;
    nRet = MSTATE_EXITING;
  }

  FREE(bufReceive);
  setPassResult((*psLogin), szPassword);

  return(nRet);
}
