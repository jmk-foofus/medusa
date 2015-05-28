/*
**   SMTP Authentication Daemon Password Checking Medusa Module
**
**   ------------------------------------------------------------------------
**    Copyright (C) 2009 pMonkey
**    pMonkey <pmonkey@foofus.net>
**
**    Copyright (C) 2008 JoMo-Kun
**    JoMo-Kun <jmk@foofus.net>
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
**
*/

#include <sys/types.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "module.h"
#include "ntlm.h"

#define MODULE_NAME    "smtp.mod"
#define MODULE_AUTHOR  "pmonkey@foofus.net"
#define MODULE_SUMMARY_USAGE  "Brute force module for SMTP Authentication with TLS"
#define MODULE_VERSION    "2.0"
#define MODULE_VERSION_SVN "$Id: smtp.c 9217 2015-05-07 18:07:03Z jmk $"
#define MODULE_SUMMARY_FORMAT  "%s : version %s"
#define MODULE_SUMMARY_FORMAT_WARN  "%s : version %s (%s)"

#define PORT_SMTP 25
#define PORT_SMTPS 465

#define RECEIVE_DELAY_1 20 * 1000000
#define RECEIVE_DELAY_2 0.5 * 1000000

#define AUTH_UNKNOWN 0
#define AUTH_PLAIN 1
#define AUTH_LOGIN 2
#define AUTH_NTLM 3

typedef struct __MODULE_DATA {
  char *szEHLO;
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
int tryLogin(int hSocket, sLogin** login, _MODULE_DATA* _psSessionData, char* szLogin, char* szPassword);
int initModule(sLogin* login, _MODULE_DATA *_psSessionData);

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
  writeVerbose(VB_NONE, " EHLO:? [optional] ");
  writeVerbose(VB_NONE, "    Specify the EHLO greeting.");
  writeVerbose(VB_NONE, " AUTH:? (Authentication Type (PLAIN/LOGIN/NTLM). Default: automatic)");
  writeVerbose(VB_NONE, "    Module will query service for accepted methods via an \"AUTH\" request.");
  writeVerbose(VB_NONE, "    PLAIN, LOGIN, and NTLM authentication methods are supported.");
  writeVerbose(VB_NONE, "  DOMAIN:? [optional]");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "The DOMAIN option should supply the specified domain appropriately,");
  writeVerbose(VB_NONE, "regardless of authentication type. The domain can also be supplied ");
  writeVerbose(VB_NONE, "via the username field, but the format appears to differ by auth type.");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "  Usage example: ");
  writeVerbose(VB_NONE, "    \"medusa -M smtp -m AUTH:NTLM -U accounts.txt -p password\"");
  writeVerbose(VB_NONE, "    \"medusa -M smtp -m EHLO:world -U accounts.txt -p password\"");
  writeVerbose(VB_NONE, "");
}

// The "main" of the medusa module world - this is what gets called to actually do the work
int go(sLogin* logins, int argc, char *argv[])
{
  int i;
  char *strtok_ptr = NULL, *pOpt = NULL, *pOptTmp = NULL;
  _MODULE_DATA *psSessionData = NULL;

  psSessionData = malloc(sizeof(_MODULE_DATA));
  memset(psSessionData, 0, sizeof(_MODULE_DATA));

  if ((argc < 0) || (argc > 3))
  {
    writeError(ERR_ERROR, "%s: Incorrect number of parameters passed to module (%d).", MODULE_NAME, argc);
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

      if (strcmp(pOpt, "AUTH") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if (pOpt == NULL)
          writeError(ERR_WARNING, "Method AUTH requires value to be set.");
        else if (strcmp(pOpt, "PLAIN") == 0)
          psSessionData->nAuthType = AUTH_PLAIN;
        else if (strcmp(pOpt, "LOGIN") == 0)
          psSessionData->nAuthType = AUTH_LOGIN;
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
      else if (strcmp(pOpt, "EHLO") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if ( pOpt )
        {
          psSessionData->szEHLO = malloc(strlen(pOpt));
          strncpy((char *) psSessionData->szEHLO, pOpt, strlen(pOpt));
        }
        else
          writeError(ERR_WARNING, "Method EHLO requires value to be set.");
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

int initModule(sLogin* psLogin, _MODULE_DATA *_psSessionData)
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
    params.nPort = PORT_SMTPS;
  else
    params.nPort = PORT_SMTP;
  initConnectionParams(psLogin, &params);

  /* set EHLO, if not specified by user */
  if (_psSessionData->szEHLO == NULL)
  {
    _psSessionData->szEHLO = malloc(5);
    memset(_psSessionData->szEHLO, 0, 5);
    sprintf(_psSessionData->szEHLO, "gerg");
  }

  while (nState != MSTATE_COMPLETE)
  {  
    switch(nState)
    {
      case MSTATE_NEW:
        if (hSocket > 0)
          medusaDisconnect(hSocket);
  
        if (psLogin->psServer->psHost->iUseSSL > 0)
          hSocket = medusaConnectSSL(&params);
        else
          hSocket = medusaConnect(&params);

        if (hSocket < 0) 
        {
          writeError(ERR_NOTICE, "[%s] failed to connect, port %d was not open on %s", MODULE_NAME, params.nPort, psLogin->psServer->pHostIP);
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
        if ( medusaCheckSocket(hSocket, psLogin->psServer->psAudit->iSocketWait) )
        {
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

  /* Retrieve SMTP banner */
  writeError(ERR_DEBUG_MODULE, "[%s] Retrieving SMTP banner.", MODULE_NAME);  
  nReceiveBufferSize = 0;
  if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "^220 .*\r\n") == FAILURE) || (bufReceive == NULL))
  {
    writeError(ERR_DEBUG_MODULE, "[%s] failed: Server did not respond with '220'. Exiting...", MODULE_NAME);
    FREE(bufReceive);  
    return FAILURE;
  }
 
  /* Send greeting to SMTP server */
  writeError(ERR_DEBUG_MODULE, "[%s] Sending SMTP EHLO greeting.", MODULE_NAME);  
  nSendBufferSize = 5 + strlen(_psSessionData->szEHLO) + 2;
  bufSend = malloc(nSendBufferSize + 1);
  memset(bufSend, 0, nSendBufferSize + 1);
  sprintf((char *)bufSend, "EHLO %s\r\n", _psSessionData->szEHLO);
  
  if (medusaSend(hSocket, bufSend, strlen((char *)bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "[%s] Failed: medusaSend was not successful", MODULE_NAME);
    FREE(bufSend); 
    return FAILURE;
  }
  FREE(bufSend); 
 
  nReceiveBufferSize = 0;
  if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "250 .*\r\n") == FAILURE) || (bufReceive == NULL))
  {
    writeError(ERR_ERROR, "[%s] failed: Server did not respond with '250'. Exiting...", MODULE_NAME);
    FREE(bufReceive);
    return FAILURE;
  }

  /* If server supports STARTTLS and we are not already within a SSL connection, let's use it. */
  if ((params->nUseSSL == 0) && (strstr((char *)bufReceive, "STARTTLS") != NULL))
  {
    FREE(bufReceive);
  
    writeError(ERR_DEBUG_MODULE, "[%s] Initiating STARTTLS session.", MODULE_NAME);  
  
    bufSend = malloc(10 + 1);
    memset(bufSend, 0, 10 + 1);
    sprintf((char *)bufSend, "STARTTLS\r\n");
    if (medusaSend(hSocket, bufSend, strlen((char *)bufSend), 0) < 0)
    {
      writeError(ERR_ERROR, "[%s] failed: medusaSend was not successful", MODULE_NAME);
      FREE(bufSend);
      return FAILURE;
    }
    FREE(bufSend);
  
    nReceiveBufferSize = 0;
    if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "^220 .*\r\n") == FAILURE) || (bufReceive == NULL))
    {
      writeError(ERR_ERROR, "[%s] failed: Server did not respond with '220'. Exiting...", MODULE_NAME);
      FREE(bufReceive);
      return FAILURE;
    }
    else
    {
      FREE(bufReceive);
     
      params->nSSLVersion = 3.1; /* Force the use of TLSv1 */ 
      if (medusaConnectSocketSSL(params, hSocket) < 0)
      {
        writeError(ERR_ERROR, "[%s] Failed to establish SSLv3 connection.", MODULE_NAME);
        return FAILURE;
      }
  
      /* Resend EHLO greeting as the AUTH types may have changed. */
      writeError(ERR_DEBUG_MODULE, "[%s] Sending SMTP EHLO greeting.", MODULE_NAME);  
      nSendBufferSize = 5 + strlen(_psSessionData->szEHLO) + 2;
      bufSend = malloc(nSendBufferSize + 1);
      memset(bufSend, 0, nSendBufferSize + 1);
      sprintf((char *)bufSend, "EHLO %s\r\n", _psSessionData->szEHLO);
  
      if (medusaSend(hSocket, bufSend, strlen((char *)bufSend), 0) < 0)
      {
        writeError(ERR_ERROR, "[%s] Failed: medusaSend was not successful", MODULE_NAME);
        FREE(bufSend); 
        return FAILURE;
      }
      FREE(bufSend); 
 
      nReceiveBufferSize = 0;
      if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "250 .*\r\n") == FAILURE) || (bufReceive == NULL))
      {
        writeError(ERR_ERROR, "[%s] failed: Server did not respond with '250'. Exiting...", MODULE_NAME);
        FREE(bufReceive);
        return FAILURE;
      }
    }
  }

  /* Process SMTP supported authentication types */
  if (_psSessionData->nAuthType != AUTH_UNKNOWN)
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Ignoring server requested AUTH type and using user-specified value.", MODULE_NAME);
  }
  else if ((strstr((char *)bufReceive, "AUTH=LOGIN") != NULL))
  {
    writeError(ERR_DEBUG_MODULE, "Detected authentication type: LOGIN");
    _psSessionData->nAuthType = AUTH_LOGIN;
  }
  else if ((strstr((char *)bufReceive, "AUTH=PLAIN") != NULL))
  {
    writeError(ERR_DEBUG_MODULE, "Detected authentication type: PLAIN");
    _psSessionData->nAuthType = AUTH_PLAIN;
  }
  else if ((strstr((char *)bufReceive, "AUTH ") != NULL))
  {
    if ((strstr((char *)bufReceive, "LOGIN") != NULL))
    {
      writeError(ERR_DEBUG_MODULE, "Detected authentication type: LOGIN");
      _psSessionData->nAuthType = AUTH_LOGIN;
    }
    else if ((strstr((char *)bufReceive, "PLAIN") != NULL))
    {
      writeError(ERR_DEBUG_MODULE, "Detected authentication type: PLAIN");
      _psSessionData->nAuthType = AUTH_PLAIN;
    }
    else if ((strstr((char *)bufReceive, "NTLM") != NULL))
    {
      writeError(ERR_DEBUG_MODULE, "Detected authentication type: NTLM");
      _psSessionData->nAuthType = AUTH_NTLM;
    }
  }
  else
  {
    writeError(ERR_ERROR, "%s failed: Server did not respond that it supported LOGIN, PLAIN or NTLM as an authentication type. Use the AUTH module option to force the use of an authentication type.", MODULE_NAME);
    return FAILURE;
  }

  FREE(bufReceive);
  return SUCCESS;
}

/*
  http://www.technoids.org/saslmech.html

  C: AUTH PLAIN
  S: 334
  C: AHdlbGRvbgB3M2xkMG4=
  S: 235 2.0.0 OK Authenticated
*/
int sendAuthPLAIN(int hSocket, char* szLogin, char* szPassword)
{
  unsigned char* bufReceive = NULL;
  unsigned char* bufSend = NULL;
  unsigned char* szTmpBuf = NULL;
  unsigned char* szTmpBuf64 = NULL;
  int nSendBufferSize = 0;
  int nReceiveBufferSize = 0;

  writeError(ERR_DEBUG_MODULE, "[%s] Initiating PLAIN Authentication Attempt.", MODULE_NAME);

  /* --- Send initial AUTH PLAIN command --- */
  bufSend = malloc(12 + 1);
  memset(bufSend, 0, 12 + 1);
  sprintf((char *)bufSend, "AUTH PLAIN\r\n");

  if (medusaSend(hSocket, bufSend, strlen((char *)bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "[%s] Failed: medusaSend was not successful", MODULE_NAME);
  }
  FREE(bufSend);

  /* Server should respond with a 334 response code */
  nReceiveBufferSize = 0;
  if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "^334 .*\r\n") == FAILURE) || (bufReceive == NULL))
  {
    writeError(ERR_ERROR, "[%s] SMTP server did not respond with \"334 \" to AUTH PLAIN request.", MODULE_NAME);
    FREE(bufReceive);
    return FAILURE;
  }

  /* Send logon credentials: B64(USERNAME\0USERNAME\0PASSWORD) */
  nSendBufferSize = strlen(szLogin) + 1 + strlen(szLogin) + 1 + strlen(szPassword);
  szTmpBuf = malloc(nSendBufferSize + 1);
  memset(szTmpBuf, 0, nSendBufferSize + 1);
  strncpy((char *)szTmpBuf, szLogin, strlen((char *)szLogin));
  strncpy((char *)szTmpBuf + strlen(szLogin) + 1, szLogin, strlen(szLogin));
  strncpy((char *)szTmpBuf + strlen(szLogin) + 1 + strlen(szLogin) + 1, szPassword, strlen(szPassword));

  szTmpBuf64 = malloc((2 * nSendBufferSize + 2) + 1);
  memset(szTmpBuf64, 0, (2 * nSendBufferSize + 2) + 1);
  base64_encode((char *)szTmpBuf, nSendBufferSize, (char *)szTmpBuf64);
  FREE(szTmpBuf);

  bufSend = malloc(strlen((char *)szTmpBuf64) + 2 + 1);
  memset(bufSend, 0, strlen((char *)szTmpBuf64) + 2 + 1);

  sprintf((char *)bufSend, "%s\r\n", szTmpBuf64);
  FREE(szTmpBuf64);

  if (medusaSend(hSocket, bufSend, strlen((char *)bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "[%s] Failed: medusaSend was not successful", MODULE_NAME);
  }
  FREE(bufSend);

  return SUCCESS;
}

/*
  http://www.technoids.org/saslmech.html

  C: AUTH LOGIN
  S: 334 VXNlcm5hbWU6             (Username:)
  C: d2VsZG9u                     (weldon)
  S: 334 UGFzc3dvcmQ6             (Password:)
  C: dzNsZDBu                     (w3ld0n)
  S: 235 2.0.0 OK Authenticated
*/
int sendAuthLOGIN(int hSocket, _MODULE_DATA* _psSessionData, char* szLogin, char* szPassword)
{
  unsigned char* bufReceive = NULL;
  unsigned char* bufSend = NULL;
  unsigned char* szPrompt = NULL;
  unsigned char* szTmpBuf = NULL;
  unsigned char* szTmpBuf2 = NULL;
  unsigned char* szLoginDomain = NULL;
  int nReceiveBufferSize = 0;

  writeError(ERR_DEBUG_MODULE, "[%s] Initiating LOGIN Authentication Attempt.", MODULE_NAME);

  /* --- Send initial AUTH LOGIN command --- */
  bufSend = malloc(12 + 1);
  memset(bufSend, 0, 12 + 1);
  sprintf((char *)bufSend, "AUTH LOGIN\r\n");

  if (medusaSend(hSocket, bufSend, strlen((char *)bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "[%s] Failed: medusaSend was not successful", MODULE_NAME);
  }
  FREE(bufSend);

  /* Server should respond with a base64-encoded username prompt */
  nReceiveBufferSize = 0;
  if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "^334 .*\r\n") == FAILURE) || (bufReceive == NULL))
  {
    writeError(ERR_ERROR, "[%s] SMTP server did not respond with \"334 \" to AUTH LOGIN request.", MODULE_NAME);
    FREE(bufReceive);
    return FAILURE;
  }

  if (((szTmpBuf = (unsigned char *)strstr((char *)bufReceive, "334 ")) == NULL) || ((szTmpBuf2 = (unsigned char *)index((char *)szTmpBuf, '\r')) == NULL))
  {
    writeError(ERR_ERROR, "[%s] SMTP server sent unexpected response to AUTH LOGIN request.", MODULE_NAME);
    return FAILURE;
  }
    
  szTmpBuf2[0] = '\0';

  szTmpBuf += 4;
  szPrompt = malloc(strlen((char *)szTmpBuf) + 1);
  memset(szPrompt, 0, strlen((char *)szTmpBuf) + 1);

  base64_decode((char *)szTmpBuf, (char *)szPrompt);
  FREE(bufReceive);

  writeError(ERR_DEBUG_MODULE, "[%s] SMTP server sent the following prompt: %s", MODULE_NAME, szPrompt);
  FREE(szPrompt);
  
  /* --- Send username --- */

  /* Base64 encoded value can be up to 2x+2 original text. Leave additional space for "\r\n" and NULL */
  if (_psSessionData->szDomain)
  {
    /* DOMAIN\USERNAME */
    szLoginDomain = malloc(strlen(_psSessionData->szDomain) + 1 + strlen(szLogin) + 1);
    memset(szLoginDomain, 0, strlen(_psSessionData->szDomain) + 1 + strlen(szLogin) + 1);
    sprintf((char *)szLoginDomain, "%s\\%s", _psSessionData->szDomain, szLogin); 
  }
  else
    szLoginDomain = (unsigned char *)szLogin;

  writeError(ERR_DEBUG_MODULE, "[%s] Sending authenticate login value: %s %s", MODULE_NAME, szLoginDomain, szPassword);
  
  bufSend = malloc((2 * strlen((char *)szLoginDomain) + 2) + 2 + 1);
  memset(bufSend, 0, (2 * strlen((char *)szLoginDomain) + 2) + 2 + 1);
  base64_encode((char *)szLoginDomain, strlen((char *)szLoginDomain), (char *)bufSend);
  strncat((char *)bufSend, "\r\n", 2);
  
  if (_psSessionData->szDomain)
    FREE(szLoginDomain);

  if (medusaSend(hSocket, bufSend, strlen((char *)bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "[%s] Failed: medusaSend was not successful", MODULE_NAME);
  }

  /* Server should respond with a base64-encoded password prompt */
  nReceiveBufferSize = 0;
  if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "^334 .*\r\n") == FAILURE) || (bufReceive == NULL))
  {
    writeError(ERR_ERROR, "[%s] SMTP server did not respond with \"334 \" to AUTH LOGIN request.", MODULE_NAME);
    FREE(bufReceive);  
    return FAILURE;
  }

  if (((szTmpBuf = (unsigned char *)strstr((char *)bufReceive, "334 ")) == NULL) || ((szTmpBuf2 = (unsigned char *)index((char *)szTmpBuf, '\r')) == NULL))
  {
    writeError(ERR_ERROR, "[%s] SMTP server sent unexpected response to AUTH LOGIN request.", MODULE_NAME);
    return FAILURE;
  }
    
  szTmpBuf2[0] = '\0';

  szTmpBuf += 4;
  szPrompt = malloc(strlen((char *)szTmpBuf) + 1);
  memset(szPrompt, 0, strlen((char *)szTmpBuf) + 1);

  base64_decode((char *)szTmpBuf, (char *)szPrompt);
  FREE(bufReceive);

  writeError(ERR_DEBUG_MODULE, "[%s] SMTP server sent the following prompt: %s", MODULE_NAME, szPrompt);
  FREE(szPrompt);

  /* --- Send password --- */

  /* Base64 encoded value can be up to 2x+2 original text. Leave additional space for "\r\n" and NULL */
  bufSend = malloc((2 * strlen(szPassword) + 2) + 2 + 1);
  memset(bufSend, 0, (2 * strlen(szPassword) + 2) + 2 + 1);
  base64_encode((char *)szPassword, strlen((char *)szPassword), (char *)bufSend);
  strncat((char *)bufSend, "\r\n", 2);

  if (medusaSend(hSocket, bufSend, strlen((char *)bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "[%s] Failed: medusaSend was not successful", MODULE_NAME);
  }

  return SUCCESS;
}

/*
  http://davenport.sourceforge.net/ntlm.html#ntlmSmtpAuthentication
*/
int sendAuthNTLM(int hSocket, _MODULE_DATA* _psSessionData, char* szLogin, char* szPassword)
{
  unsigned char* bufSend = NULL;
  unsigned char* bufReceive = NULL;
  int nReceiveBufferSize = 0;
  int nSendBufferSize = 0;
  tSmbNtlmAuthRequest   sTmpReq;
  tSmbNtlmAuthChallenge sTmpChall;
  tSmbNtlmAuthResponse  sTmpResp;
  unsigned char* szTmpBuf = NULL;
  unsigned char* szTmpBuf64 = NULL;

  writeError(ERR_DEBUG_MODULE, "[%s] Initiating NTLM Authentication Attempt.", MODULE_NAME);

  /* --- Send Base-64 encoded Type-1 message --- */

  buildAuthRequest(&sTmpReq, 0, NULL, NULL);

  szTmpBuf64 = malloc(2 * SmbLength(&sTmpReq) + 2);
  memset(szTmpBuf64, 0, 2 * SmbLength(&sTmpReq) + 2);

  base64_encode((char *)&sTmpReq, SmbLength(&sTmpReq), (char *)szTmpBuf64);
  writeError(ERR_DEBUG_MODULE, "[%s] Sending initial challenge (B64 Encoded): %s", MODULE_NAME, szTmpBuf64);

  nSendBufferSize = strlen((char *)szTmpBuf64) + 2;
  bufSend = malloc(10 + nSendBufferSize + 1);
  memset(bufSend, 0, 10 + nSendBufferSize + 1);
  sprintf((char *)bufSend, "AUTH NTLM %s\r\n", szTmpBuf64);

  FREE(szTmpBuf64);

  if (medusaSend(hSocket, bufSend, strlen((char *)bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "[%s] failed: medusaSend was not successful", MODULE_NAME);
    return FAILURE;
  }
  FREE(bufSend);

  /* Server should respond with a Base-64 encoded Type-2 challenge message. The challenge response format is 
     "334", followed by a space, followed by the challenge message. */
  nReceiveBufferSize = 0;
  if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "^334 .*\r\n") == FAILURE) || (bufReceive == NULL))
  {
    writeError(ERR_ERROR, "[%s] Server did not send valid Type-2 challenge response.", MODULE_NAME);
    FREE(bufReceive);
    return FAILURE;
  }

  szTmpBuf = (unsigned char *)index((char *)bufReceive, '\r');
  szTmpBuf[0] = '\0';

  writeError(ERR_DEBUG_MODULE, "[%s] NTLM Challenge (B64 Encoded): %s", MODULE_NAME, bufReceive + 4);
  base64_decode((char *)bufReceive + 4, (char *)&sTmpChall);

  FREE(bufReceive);

  /* --- Calculate and send Base-64 encoded Type 3 response --- */
  buildAuthResponse(&sTmpChall, &sTmpResp, 0, szLogin, szPassword, _psSessionData->szDomain, NULL);

  szTmpBuf64 = malloc(2 * SmbLength(&sTmpResp) + 2);
  memset(szTmpBuf64, 0, 2 * SmbLength(&sTmpResp) + 2);

  base64_encode((char *)&sTmpResp, SmbLength(&sTmpResp), (char *)szTmpBuf64);
  writeError(ERR_DEBUG_MODULE, "[%s] NTLM Response (B64 Encoded): %s", MODULE_NAME, szTmpBuf64);

  nSendBufferSize = strlen((char *)szTmpBuf64) + 2;
  bufSend = malloc(nSendBufferSize + 1);
  memset(bufSend, 0, nSendBufferSize + 1);
  sprintf((char *)bufSend, "%s\r\n", szTmpBuf64);

  if (medusaSend(hSocket, bufSend, nSendBufferSize, 0) < 0)
  {
    writeError(ERR_ERROR, "[%s] failed: medusaSend was not successful", MODULE_NAME);
    return FAILURE;
  }

  FREE(szTmpBuf64);
  FREE(bufSend);

  return SUCCESS;
}

int tryLogin(int hSocket, sLogin** psLogin, _MODULE_DATA* _psSessionData, char* szLogin, char* szPassword)
{
  int nRet = FAILURE;
  unsigned char* bufReceive = NULL;
  int nReceiveBufferSize = 0;

  switch(_psSessionData->nAuthType)
  {
    case AUTH_PLAIN:
      writeError(ERR_DEBUG_MODULE, "[%s] Sending PLAIN Authentication.", MODULE_NAME);
      nRet = sendAuthPLAIN(hSocket, szLogin, szPassword);
      break;
    case AUTH_LOGIN:
      writeError(ERR_DEBUG_MODULE, "[%s] Sending LOGIN Authentication.", MODULE_NAME);
      nRet = sendAuthLOGIN(hSocket, _psSessionData, szLogin, szPassword);
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

  writeError(ERR_DEBUG_MODULE, "[%s] Retrieving server response.", MODULE_NAME);

  nReceiveBufferSize = 0;
  if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "^[0-9]{3,3} .*\r\n") == FAILURE) || (bufReceive == NULL))
  {
    writeError(ERR_ERROR, "[%s] Unknown SMTP server response: %s", MODULE_NAME, bufReceive);
    (*psLogin)->iResult = LOGIN_RESULT_ERROR;
    nRet = MSTATE_EXITING;
  }

  if (strstr((char *)bufReceive, "235 ") != NULL)
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Login attempt successful.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
    nRet = MSTATE_EXITING;
  }
  /* 435 Unable to authenticate at present: Authentication Failure */
  else if (strstr((char *)bufReceive, "435 ") != NULL)
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Login attempt failed (435).", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_FAIL;
    nRet = MSTATE_RUNNING;
  }
  /* GroupWise - 501 Authentication failed! */
  else if (strstr((char *)bufReceive, "501 ") != NULL)
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Login attempt failed (501).", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_FAIL;
    nRet = MSTATE_RUNNING;
  }
  else if (strstr((char *)bufReceive, "535 ") != NULL)
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Login attempt failed (535).", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_FAIL;
    nRet = MSTATE_RUNNING;
  }
  else
  {
    writeError(ERR_ERROR, "[%s] Unknown SMTP server response: %s", MODULE_NAME, bufReceive);
    (*psLogin)->iResult = LOGIN_RESULT_ERROR;
    nRet = MSTATE_EXITING;
  }

  FREE(bufReceive);
  setPassResult((*psLogin), szPassword);
  
  return(nRet);
}
