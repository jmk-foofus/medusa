/*
**   POP3 Password Checking Medusa Module
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
**
*/

#include <sys/types.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "module.h"
#include "ntlm.h"

#define MODULE_NAME    "pop3.mod"
#define MODULE_AUTHOR  "JoMo-Kun <jmk@foofus.net>"
#define MODULE_SUMMARY_USAGE  "Brute force module for POP3 sessions"
#define MODULE_VERSION    "2.0"
#define MODULE_VERSION_SVN "$Id: pop3.c 9217 2015-05-07 18:07:03Z jmk $"
#define MODULE_SUMMARY_FORMAT  "%s : version %s"

#define BUF_SIZE 300 

#define PORT_POP3  110
#define PORT_POP3S 995

#define MODE_NORMAL 0
#define MODE_AS400 1

#define AUTH_UNKNOWN 0
#define AUTH_USER 1
#define AUTH_PLAIN 2
#define AUTH_LOGIN 3
#define AUTH_NTLM 4

typedef struct __MODULE_DATA {
  int nMode;
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
int getAuthType(int hSocket, _MODULE_DATA* _psSessionData);
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
  writeVerbose(VB_NONE, "  MODE:? (NORMAL, AS400) [optional]");
  writeVerbose(VB_NONE, "    Sets the mode for error detection.");
  writeVerbose(VB_NONE, " AUTH:? (Authentication Type (USER/PLAIN/LOGIN/NTLM). Default: automatic)");
  writeVerbose(VB_NONE, "    Module will query service for accepted methods via an \"AUTH\" request.");
  writeVerbose(VB_NONE, "    USER (clear-text), SASL PLAIN, SASL LOGIN, and SASL NTLM authentication methods are supported.");
  writeVerbose(VB_NONE, "  DOMAIN:? [optional]");
  writeVerbose(VB_NONE, "    AUTH USER - Appends domain to username (e.g. user@domain.com).");
  writeVerbose(VB_NONE, "    AUTH NTLM - Supplies specified domain during NTLM authentication. The default");
  writeVerbose(VB_NONE, "                behaviour is to use the server supplied domain value.");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "  Usage example: ");
  writeVerbose(VB_NONE, "    \"medusa -M pop3 -m MODE:AS400 -U accounts.txt -p password\"");
  writeVerbose(VB_NONE, "    \"medusa -M pop3 -m DOMAIN:foo.com -U accounts.txt -p password\"");
  writeVerbose(VB_NONE, "");
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
    writeError(ERR_DEBUG_MODULE, "OMG teh %s module has been called!!", MODULE_NAME);

    for (i=0; i<argc; i++) {
      pOptTmp = malloc( strlen(argv[i]) + 1);
      memset(pOptTmp, 0, strlen(argv[i]) + 1);
      strncpy(pOptTmp, argv[i], strlen(argv[i]));
      writeError(ERR_DEBUG_MODULE, "Processing complete option: %s", pOptTmp);
      pOpt = strtok_r(pOptTmp, ":", &strtok_ptr);
      writeError(ERR_DEBUG_MODULE, "Processing option: %s", pOpt);

      if (strcmp(pOpt, "MODE") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if (pOpt == NULL)
          writeError(ERR_WARNING, "Method MODE requires value to be set.");
        else if (strcmp(pOpt, "AS400") == 0)
          psSessionData->nMode = MODE_AS400;
        else
          writeError(ERR_WARNING, "Invalid value for method MODE.");
      }
      else if (strcmp(pOpt, "AUTH") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if (pOpt == NULL)
          writeError(ERR_WARNING, "Method AUTH requires value to be set.");
        else if (strcmp(pOpt, "USER") == 0)
          psSessionData->nAuthType = AUTH_USER;
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
  unsigned char bufSend[BUF_SIZE];
  unsigned char* bufReceive;
  int nReceiveBufferSize = 0;
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
    params.nPort = PORT_POP3S;
  else
    params.nPort = PORT_POP3;
  initConnectionParams(psLogin, &params);

  while (nState != MSTATE_COMPLETE)
  {  
    switch (nState)
    {
      case MSTATE_NEW:
        // Already have an open socket - close it
        if (hSocket > 0)
          medusaDisconnect(hSocket);

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

        /* establish initial connection */
        nReceiveBufferSize = 0;
        if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "\\+OK.*\r\n") == FAILURE) || (bufReceive == NULL))
        {
          writeError(ERR_DEBUG_MODULE, "%s failed: Server did not respond with '+OK'. Exiting...", MODULE_NAME);
          psLogin->iResult = LOGIN_RESULT_UNKNOWN;
          nState = MSTATE_EXITING;
        }
        else
        {
          writeError(ERR_DEBUG_MODULE, "Connected");
          nState = MSTATE_RUNNING;
        }

        /* POP3 STARTTLS Extension
           http://www.faqs.org/rfcs/rfc2595.html
        */

        /* The capability name "STLS" indicates this command is present and 
           permitted in the current state. "CAPA" can be used to test for its
           presence. Are there cases where "STLS" may not be implemented?
        */

        /* Initiate STLS only if we don't already have a SSL connection */
        if (psLogin->psServer->psHost->iUseSSL == 0)
        {
          memset(bufSend, 0, BUF_SIZE);
          sprintf((char*)bufSend, "STLS\r\n");
          if (medusaSend(hSocket, bufSend, strlen((char*)bufSend), 0) < 0)
          {
            writeError(ERR_ERROR, "[%s] failed: medusaSend was not successful", MODULE_NAME);
            return FAILURE;
          }
  
          nReceiveBufferSize = 0;
          if (medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "\\+OK.*\r\n|-ERR.*\r\n") == FAILURE)
          {
            writeError(ERR_ERROR, "[%s] Failed: Unexpected or no data received: %s", MODULE_NAME, bufReceive);
            return FAILURE;
          }
          /*
            [SUPPORTED]     +OK Begin TLS negotiation / +OK Ready to start TLS
            [NOT SUPPORTED] +OK STLS completed
            [ERROR]         -ERR Command not permitted when TLS active
          */
          else if (strstr((char*)bufReceive, "+OK") != NULL)
          {
            FREE(bufReceive);
  
            writeError(ERR_DEBUG_MODULE, "[%s] Starting TLS negotiation.", MODULE_NAME);
            params.nSSLVersion = 3.1; /* Force the use of TLSv1 */
            if (medusaConnectSocketSSL(&params, hSocket) < 0)
            {
              writeError(ERR_ERROR, "[%s] Failed to establish SSLv3 connection.", MODULE_NAME);
              return FAILURE;
            }
          }
          else
          {
            writeError(ERR_DEBUG_MODULE, "[%s] TLS negotiation not available.", MODULE_NAME);
            FREE(bufReceive);
          }
        }
  
        /* Query service for accepted authentication methods */
        if (_psSessionData->nAuthType == AUTH_UNKNOWN)
        {
          getAuthType(hSocket, _psSessionData);

          if (_psSessionData->nAuthType == AUTH_UNKNOWN)
          {
            psLogin->iResult = LOGIN_RESULT_UNKNOWN;
            return FAILURE;
          }
        }
 
        break;
      case MSTATE_RUNNING:
        /* The POP3 service may be configured to drop connections after an arbitrary number of failed
           logon attempts. We will reuse the established connection to send authentication attempts 
           until that disconnect happens. At that point the connection should be reestablished. */
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

int getAuthType(int hSocket, _MODULE_DATA* _psSessionData)
{
  unsigned char* bufReceive;
  unsigned char* bufSend;
  int nReceiveBufferSize = 0;

  bufSend = malloc(6 + 1);
  memset(bufSend, 0, 6 + 1);
  sprintf((char*)bufSend, "CAPA\r\n");

  if (medusaSend(hSocket, bufSend, strlen((char*)bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
    return FAILURE;
  }
  FREE(bufSend);

  if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "\\+OK.*\r\n\\.*\r\n|-ERR.*\r\n") == FAILURE) || (bufReceive == NULL))
  {
    writeError(ERR_ERROR, "[%s] Failed: Server did not respond that it supported any of the authentication types we handle (USER, LOGIN, and NTLM). Use the AUTH module option to force the use of an authentication type: %s", MODULE_NAME, bufReceive);
    return FAILURE;
  }
  else if ((strstr((char*)bufReceive, "USER") != NULL))
  {
    writeError(ERR_DEBUG_MODULE, "Server requested authentication type: USER (clear-text)");
    _psSessionData->nAuthType = AUTH_USER;
  }
  else if ((strstr((char*)bufReceive, "SASL") != NULL))
  {
    if ((strstr((char*)bufReceive, "PLAIN") != NULL))
    {
      writeError(ERR_DEBUG_MODULE, "Server requested authentication type: SASL PLAIN");
      _psSessionData->nAuthType = AUTH_PLAIN;
    }
    else if ((strstr((char*)bufReceive, "LOGIN") != NULL))
    {
      writeError(ERR_DEBUG_MODULE, "Server requested authentication type: SASL LOGIN");
      _psSessionData->nAuthType = AUTH_LOGIN;
    }
    else if ((strstr((char*)bufReceive, "NTLM") != NULL))
    {
      writeError(ERR_DEBUG_MODULE, "Server requested authentication type: SASL NTLM");
      _psSessionData->nAuthType = AUTH_NTLM;
    }
    else
    {
      writeError(ERR_ERROR, "[%s] Server requested unsupported SASL method.", MODULE_NAME);
      return FAILURE;
    }
  }
  else if ((strstr((char*)bufReceive, "-ERR") != NULL))
  {
    writeError(ERR_ERROR, "[%s] Server did not understand CAPA request. Defaulting to USER authentication type, use \"-m AUTH\" option to specify alternative method.", MODULE_NAME);
    _psSessionData->nAuthType = AUTH_USER;
  }

  return SUCCESS;
}

int sendAuthUSER(int hSocket, _MODULE_DATA* _psSessionData, char* szLogin, char* szPassword)
{
  unsigned char bufSend[BUF_SIZE];
  unsigned char* bufReceive = NULL;
  int nReceiveBufferSize = 0;
  int nRet = FAILURE;

  writeError(ERR_DEBUG_MODULE, "[%s] Initiating USER (clear-text) Authentication Attempt.", MODULE_NAME);
  
  /* send username */
  memset(bufSend, 0, sizeof(bufSend));

  if (_psSessionData->szDomain)
    sprintf((char*)bufSend, "USER %.100s@%.150s\r\n", szLogin, _psSessionData->szDomain);
  else
    sprintf((char*)bufSend, "USER %.250s\r\n", szLogin);

  if (medusaSend(hSocket, bufSend, strlen((char*)bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
  }
 
  nReceiveBufferSize = 0;
  if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "\\+OK.*\r\n|-ERR.*\r\n") == FAILURE) || (bufReceive == NULL))
  {
    writeError(ERR_ERROR, "[%s] Failed: Server did not respond as expected to USER authentication attempt: %s", MODULE_NAME, bufReceive);
    return FAILURE;
  }
  else if (strstr((char*)bufReceive, " signing off."))
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Server informed us it was signing off. Restarting connection.", MODULE_NAME);
    nRet = MSTATE_NEW;
    return(nRet);
  }
  else if (strstr((char*)bufReceive, "ERR Cleartext login on this server requires the use of transport level security (SSL/TLS)"))
  {
    writeError(ERR_ERROR, "[%s] Server requires use of SSL/TLS.", MODULE_NAME);
    return FAILURE;
  }
  else if (strstr((char*)bufReceive, "ERR Clear text passwords have been disabled for this protocol."))
  {
    writeError(ERR_ERROR, "[%s] Server does not accept clear-text password authentication.", MODULE_NAME);
    return FAILURE;
  }
 
  /* send password */
  memset(bufSend, 0, sizeof(bufSend));
  sprintf((char*)bufSend, "PASS %.250s\r\n", szPassword);

  if (medusaSend(hSocket, bufSend, strlen((char*)bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
  }

  return SUCCESS;
}

/*
  PLAIN SASL Mechanism
  http://tools.ietf.org/html/rfc5034
  http://tools.ietf.org/html/rfc4616

  Example:
    AUTH PLAIN dGVzdAB0ZXN0AHRlc3Q=
*/
int sendAuthPLAIN(int hSocket, char* szLogin, char* szPassword)
{
  unsigned char* bufSend = NULL;
  char* szTmpBuf = NULL;
  char* szTmpBuf64 = NULL;
  int nSendBufferSize = 0;

  writeError(ERR_DEBUG_MODULE, "[%s] Initiating PLAIN Authentication Attempt.", MODULE_NAME);

  /* AUTH PLAIN B64(USERNAME\0USERNAME\0PASSWORD) */
  nSendBufferSize = strlen(szLogin) + 1 + strlen(szLogin) + 1 + strlen(szPassword);
  szTmpBuf = malloc(nSendBufferSize + 1);
  memset(szTmpBuf, 0, nSendBufferSize + 1);
  strncpy(szTmpBuf, szLogin, strlen(szLogin));
  strncpy(szTmpBuf + strlen(szLogin) + 1, szLogin, strlen(szLogin));
  strncpy(szTmpBuf + strlen(szLogin) + 1 + strlen(szLogin) + 1, szPassword, strlen(szPassword));

  szTmpBuf64 = malloc((2 * nSendBufferSize + 2) + 1);
  memset(szTmpBuf64, 0, (2 * nSendBufferSize + 2) + 1);
  base64_encode(szTmpBuf, nSendBufferSize, szTmpBuf64);
  FREE(szTmpBuf);

  bufSend = malloc(11 + strlen(szTmpBuf64) + 2 + 1); 
  memset(bufSend, 0, 11 + strlen(szTmpBuf64) + 2 + 1);

  sprintf((char*)bufSend, "AUTH PLAIN %s\r\n", szTmpBuf64);
  FREE(szTmpBuf64);

  if (medusaSend(hSocket, bufSend, strlen((char*)bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "[%s] Failed: medusaSend was not successful", MODULE_NAME);
  }
  FREE(bufSend);

  return SUCCESS;
}

/*
  AUTH LOGIN method base64-encodes both prompts and credentials.
  For example:
      AUTH LOGIN
      + VXNlcm5hbWU6      (Username:)
      Zm9v                (foo)
      + UGFzc3dvcmQ6      (Password:)
      YmFy                (bar)
*/
int sendAuthLOGIN(int hSocket, char* szLogin, char* szPassword)
{
  unsigned char* bufReceive = NULL;
  unsigned char* bufSend = NULL;
  char* szPrompt = NULL;
  char* szTmpBuf = NULL;
  int nReceiveBufferSize = 0;

  writeError(ERR_DEBUG_MODULE, "[%s] Initiating LOGIN Authentication Attempt.", MODULE_NAME);

  /* --- Send initial AUTH LOGIN command --- */
  bufSend = malloc(12 + 1);
  memset(bufSend, 0, 12 + 1);
  sprintf((char*)bufSend, "AUTH LOGIN\r\n");

  if (medusaSend(hSocket, bufSend, strlen((char*)bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "[%s] Failed: medusaSend was not successful", MODULE_NAME);
  }
  FREE(bufSend);

  /* Server should respond with a base64-encoded username prompt */
  nReceiveBufferSize = 0;
  if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "\\+ .*\r\n|-ERR.*\r\n") == FAILURE) || (bufReceive == NULL))
  {
    writeError(ERR_ERROR, "[%s] POP3 server did not respond with \"+ \" to AUTH LOGIN request.", MODULE_NAME);
    return FAILURE;
  }
  else if (strstr((char*)bufReceive,"-ERR The specified authentication package is not supported.") != NULL) 
  {
    writeError(ERR_ERROR, "[%s] Server response: The specified authentication package is not supported.", MODULE_NAME);
    return FAILURE;
  }

  szTmpBuf = index((char*)bufReceive, '\r');
  szTmpBuf[0] = '\0';
  szPrompt = malloc(strlen((char*)bufReceive + 2) + 1);
  memset(szPrompt, 0, strlen((char*)bufReceive + 2) + 1);
  
  base64_decode((char*)bufReceive + 2, szPrompt);
  FREE(bufReceive);

  writeError(ERR_DEBUG_MODULE, "[%s] POP3 server sent the following prompt: %s", MODULE_NAME, szPrompt); 
  FREE(szPrompt);

  /* --- Send username --- */

  /* Base64 encoded value can be up to 2x+2 original text. Leave additional space for "\r\n" and NULL */
  bufSend = malloc((2 * strlen(szLogin) + 2) + 2 + 1);
  memset(bufSend, 0, (2 * strlen(szLogin) + 2) + 2 + 1);
  base64_encode(szLogin, strlen(szLogin), (char*)bufSend);
  strncat((char*)bufSend, "\r\n", 2);   
 
  if (medusaSend(hSocket, bufSend, strlen((char*)bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "[%s] Failed: medusaSend was not successful", MODULE_NAME);
  }

  /* Server should respond with a base64-encoded password prompt */
  nReceiveBufferSize = 0;
  if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "\\+ .*\r\n") == FAILURE) || (bufReceive == NULL))
  {
    writeError(ERR_ERROR, "[%s] POP3 server did not respond with \"+ \" to AUTH LOGIN request.", MODULE_NAME);
    return FAILURE;
  }

  szTmpBuf = index((char*)bufReceive, '\r');
  szTmpBuf[0] = '\0';
  szPrompt = malloc(strlen((char*)bufReceive + 2) + 1);
  memset(szPrompt, 0, strlen((char*)bufReceive + 2) + 1);
  
  base64_decode((char*)bufReceive + 2, szPrompt);
  FREE(bufReceive);

  writeError(ERR_DEBUG_MODULE, "[%s] POP3 server sent the following prompt: %s", MODULE_NAME, szPrompt); 
  FREE(szPrompt);

  /* --- Send password --- */

  /* Base64 encoded value can be up to 2x+2 original text. Leave additional space for "\r\n" and NULL */
  bufSend = malloc((2 * strlen(szPassword) + 2) + 2 + 1);
  memset(bufSend, 0, (2 * strlen(szPassword) + 2) + 2 + 1);
  base64_encode(szPassword, strlen(szPassword), (char*)bufSend);
  strncat((char*)bufSend, "\r\n", 2);

  if (medusaSend(hSocket, bufSend, strlen((char*)bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "[%s] Failed: medusaSend was not successful", MODULE_NAME);
  }

  return SUCCESS;
}

/*
  NTLM POP3 Authentication
  Based on:
    http://curl.haxx.se/rfc/ntlm.html#ntlmPop3Authentication
    http://src.opensolaris.org/source/xref/sfw/usr/src/cmd/fetchmail/fetchmail-6.3.8/README.NTLM
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
  char* szTmpBuf = NULL;
  char* szTmpBuf64 = NULL;

  writeError(ERR_DEBUG_MODULE, "[%s] Initiating NTLM Authentication Attempt.", MODULE_NAME);

  /* --- Send initial AUTHENTICATE NTLM command --- */
  bufSend = malloc(11 + 1);
  memset(bufSend, 0, 11 + 1);
  sprintf((char*)bufSend, "AUTH NTLM\r\n");

  if (medusaSend(hSocket, bufSend, strlen((char*)bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
  }
  FREE(bufSend);

  /* Server should respond with an empty challenge, consisting simply of a "+" */
  nReceiveBufferSize = 0;
  if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "\\+ *OK.*\r\n") == FAILURE) || (bufReceive == NULL))
  {
    writeError(ERR_ERROR, "[%s] POP3 server did not respond with \"+ OK\" to AUTH NTLM request.", MODULE_NAME);
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
  base64_decode((char*)bufReceive + 2, (char *)&sTmpChall);

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
     e.g. +OK User successfully logged on */

  return SUCCESS;
}

int tryLogin(int hSocket, sLogin** psLogin, _MODULE_DATA* _psSessionData, char* szLogin, char* szPassword)
{
  int nRet = FAILURE;
  unsigned char* bufReceive = NULL;
  int nReceiveBufferSize = 0;

  switch(_psSessionData->nAuthType)
  {
    case AUTH_USER:
      writeError(ERR_DEBUG_MODULE, "[%s] Sending USER (clear-text) Authentication.", MODULE_NAME);
      nRet = sendAuthUSER(hSocket, _psSessionData, szLogin, szPassword);
      break;
    case AUTH_PLAIN:
      writeError(ERR_DEBUG_MODULE, "[%s] Sending PLAIN Authentication.", MODULE_NAME);
      nRet = sendAuthPLAIN(hSocket, szLogin, szPassword);
      break;
    case AUTH_LOGIN:
      writeError(ERR_DEBUG_MODULE, "[%s] Sending LOGIN Authentication.", MODULE_NAME);
      nRet = sendAuthLOGIN(hSocket, szLogin, szPassword);
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
  if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "\\+OK.*\r\n|-ERR.*\r\n") == FAILURE) || (bufReceive == NULL))
  {
    /* The POP3 service may be configured to drop connections after an arbitrary number of failed
       logon attempts. We will reuse the established connection to send authentication attempts 
       until that disconnect happens.
 
       A default install of Debian (6.0.3 Squeeze) and the Courier Mail Server (0.65) was found 
       to drop connections immediately after the 8th failed attempt.
    */
    if ( medusaCheckSocket(hSocket, (*psLogin)->psServer->psAudit->iSocketWait) )
    {
      writeError(ERR_ERROR, "[%s] Failed: Unexpected or no data received.", MODULE_NAME);
      (*psLogin)->iResult = LOGIN_RESULT_ERROR;
      return FAILURE;
    }
    else
    {
      writeError(ERR_NOTICE, "[%s] Socket is no longer valid. Server likely dropped connection. Establishing new session.", MODULE_NAME);
      (*psLogin)->iResult = LOGIN_RESULT_FAIL;
      nRet = MSTATE_NEW;
    }
  }
  else if (bufReceive[0] == '+')
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Login attempt successful.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
    nRet = MSTATE_EXITING;
  }
  else if (strstr((char*)bufReceive, "-ERR The specified authentication package is not supported.") != NULL) 
  {
    writeError(ERR_ERROR, "[%s] Server response: The specified authentication package is not supported.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_ERROR;
    nRet = MSTATE_EXITING;
  }
  else
  {
    if (_psSessionData->nMode == MODE_AS400)
    {
      /* 
        www.venera.com/downloads/Enumeration_of_AS400_users_via_pop3.pdf 
        Example: -ERR Logon attempt invalid CPF2204
      */
      if (strstr((char*)bufReceive, "CPF2204"))
      {
        writeError(ERR_ERROR, "[%s] User profile was not found.", MODULE_NAME);
        (*psLogin)->iResult = LOGIN_RESULT_ERROR;
        nRet = MSTATE_EXITING;
      }
      else if (strstr((char*)bufReceive, "CPF22E2"))
      {
        writeError(ERR_DEBUG_MODULE, "[%s] Valid user, incorrect password.", MODULE_NAME);
        (*psLogin)->iResult = LOGIN_RESULT_FAIL;
        nRet = MSTATE_NEW;
      }
      else if (strstr((char*)bufReceive, "CPF22E3"))
      {
        writeError(ERR_ERROR, "[%s] Valid user, but profile is disabled.", MODULE_NAME);
        (*psLogin)->iResult = LOGIN_RESULT_ERROR;
        nRet = MSTATE_EXITING;
      }
      else if (strstr((char*)bufReceive, "CPF22E4"))
      {
        writeError(ERR_ERROR, "[%s] Valid user, but password for profile has expired.", MODULE_NAME);
        (*psLogin)->iResult = LOGIN_RESULT_ERROR;
        nRet = MSTATE_EXITING;
      }
      else if (strstr((char*)bufReceive, "CPF22E5"))
      {
        writeError(ERR_ERROR, "[%s] Valid user, but no password associated with user profile.", MODULE_NAME);
        (*psLogin)->iResult = LOGIN_RESULT_ERROR;
        nRet = MSTATE_EXITING;
      }
      else if (strstr((char*)bufReceive, "-ERR Logon attempt invalid"))
      {
        writeError(ERR_DEBUG_MODULE, "[%s] Generic POP3 invalid attempt message. AS/400 may not be configured for verbose messages.", MODULE_NAME);
        (*psLogin)->iResult = LOGIN_RESULT_FAIL;
        nRet = MSTATE_EXITING;
      }
      else
      {
        writeError(ERR_ERROR, "[%s] Unknown AS/400 error message: %s", MODULE_NAME, bufReceive);
        (*psLogin)->iResult = LOGIN_RESULT_ERROR;
        nRet = MSTATE_EXITING;
      }
    }
    else
    {
      writeError(ERR_DEBUG_MODULE, "[%s] Login attempt failed.", MODULE_NAME);
      (*psLogin)->iResult = LOGIN_RESULT_FAIL;
      //nRet = MSTATE_RUNNING;
      nRet = MSTATE_NEW;
    }
  }
 
  FREE(bufReceive);
  setPassResult((*psLogin), szPassword);

  return(nRet);
}
