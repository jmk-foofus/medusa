/*
**   SMTP Verification (VRFY/EXPN/RCPT TO) Medusa Module
**
**   ------------------------------------------------------------------------
**    Copyright (C) 2015 JoMo-Kun
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

#define MODULE_NAME    "smtp-vrfy.mod"
#define MODULE_AUTHOR  "JoMo-Kun <jmk@foofus.net>"
#define MODULE_SUMMARY_USAGE  "Brute force module for verifying SMTP accounts (VRFY/EXPN/RCPT TO)"
#define MODULE_VERSION    "2.1"
#define MODULE_VERSION_SVN "$Id: smtp-vrfy.c 9261 2015-05-28 14:18:21Z jmk $"
#define MODULE_SUMMARY_FORMAT  "%s : version %s"
#define MODULE_SUMMARY_FORMAT_WARN  "%s : version %s (%s)"

#define PORT_SMTP 25
#define PORT_SMTPS 465

#define BUF_SIZE 300

#define RECEIVE_DELAY_1 20 * 1000000
#define RECEIVE_DELAY_2 0.5 * 1000000

#define HELO_NONE 0
#define HELO_HELO 1
#define HELO_EHLO 2

#define VERB_NONE 0
#define VERB_VRFY 1
#define VERB_EXPN 2
#define VERB_RCPT 3

typedef struct __MODULE_DATA {
  int nHELO;
  char *szHELO;
  char *szMAILFROM;
  int nVerb;
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
  writeVerbose(VB_NONE, " HELO [optional] ");
  writeVerbose(VB_NONE, "    Use HELO command. Default: EHLO");
  writeVerbose(VB_NONE, " HELODOMAIN:? [optional] ");
  writeVerbose(VB_NONE, "    Specify the HELO/EHLO domain. Default: server.domain");
  writeVerbose(VB_NONE, " MAILFROM:? [optional] ");
  writeVerbose(VB_NONE, "    Specify the MAIL FROM address. Default: doesnotexist@foofus.net");
  writeVerbose(VB_NONE, " VERB:? (Verb/Command: VRFY/EXPN/RCPT TO. Default: RCPT TO");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "*** NOTE: Target address domain should be specified within password field. ***");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "  Usage example: ");
  writeVerbose(VB_NONE, "    \"medusa -M smtp-vrfy -m VERB:VRFY -U accounts.txt -p domain.com\"");
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

  if ((argc < 0) || (argc > 4))
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

      if (strcmp(pOpt, "HELO") == 0)
      {
        psSessionData->nHELO = HELO_HELO;
      }
      else if (strcmp(pOpt, "VERB") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if (pOpt == NULL)
          writeError(ERR_WARNING, "Method VERB requires value to be set.");
        else if (strcmp(pOpt, "VRFY") == 0)
          psSessionData->nVerb = VERB_VRFY;
        else if (strcmp(pOpt, "EXPN") == 0)
          psSessionData->nVerb = VERB_EXPN;
        else if (strcmp(pOpt, "RCPT") == 0)
          psSessionData->nVerb = VERB_RCPT;
        else
          writeError(ERR_WARNING, "Invalid value for method VERB.");
      }
      else if (strcmp(pOpt, "HELODOMAIN") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if ( pOpt )
        {
          psSessionData->szHELO = malloc(strlen(pOpt));
          strncpy((char *) psSessionData->szHELO, pOpt, strlen(pOpt));
        }
        else
          writeError(ERR_WARNING, "Method HELODOMAIN requires value to be set.");
      }
      else if (strcmp(pOpt, "MAILFROM") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if ( pOpt )
        {
          psSessionData->szMAILFROM = malloc(strlen(pOpt));
          strncpy((char *) psSessionData->szMAILFROM, pOpt, strlen(pOpt));
        }
        else
          writeError(ERR_WARNING, "Method MAILFROM requires value to be set.");
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
  if (_psSessionData->nHELO == 0)
    _psSessionData->nHELO = HELO_EHLO;

  /* set HELO domain, if not specified by user */
  if (_psSessionData->szHELO == NULL)
  {
    _psSessionData->szHELO = malloc(14);
    memset(_psSessionData->szHELO, 0, 14);
    sprintf(_psSessionData->szHELO, "server.domain");
  }
 
  /* set MAILFROM, if not specified by user */
  if (_psSessionData->szMAILFROM == NULL)
  {
    _psSessionData->szMAILFROM = malloc(24);
    memset(_psSessionData->szMAILFROM, 0, 24);
    sprintf(_psSessionData->szMAILFROM, "doesnotexist@foofus.net");
  }
 
  /* Default verb/command is RCPT TO */ 
  if (_psSessionData->nVerb == VERB_NONE)
  {
    _psSessionData->nVerb = VERB_RCPT;
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
  writeError(ERR_DEBUG_MODULE, "[%s] Sending SMTP HELO greeting.", MODULE_NAME);  
  nSendBufferSize = 5 + strlen(_psSessionData->szHELO) + 2;
  bufSend = malloc(nSendBufferSize + 1);
  memset(bufSend, 0, nSendBufferSize + 1);

  if (_psSessionData->nHELO == HELO_HELO) 
    sprintf((char *)bufSend, "HELO %s\r\n", _psSessionData->szHELO);
  else  
    sprintf((char *)bufSend, "EHLO %s\r\n", _psSessionData->szHELO);

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
  
      /* Resend HELO greeting as the AUTH types may have changed. */
      writeError(ERR_DEBUG_MODULE, "[%s] Sending SMTP HELO greeting.", MODULE_NAME);  
      nSendBufferSize = 5 + strlen(_psSessionData->szHELO) + 2;
      bufSend = malloc(nSendBufferSize + 1);
      memset(bufSend, 0, nSendBufferSize + 1);
      sprintf((char *)bufSend, "HELO %s\r\n", _psSessionData->szHELO);
  
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

  /* Process SMTP supported verbs */
  if (strstr((char *)bufReceive, "VRFY") != NULL)
    writeError(ERR_DEBUG_MODULE, "Detected verb: VFRY");
  else if (strstr((char *)bufReceive, "RCPT") != NULL)
    writeError(ERR_DEBUG_MODULE, "Detected verb: RCPT");
  
  FREE(bufReceive);

  /* Send MAIL FROM to SMTP server (required for RCPT TO) */
  writeError(ERR_DEBUG_MODULE, "[%s] Sending SMTP MAIL FROM command.", MODULE_NAME);  
  nSendBufferSize = 12 + strlen(_psSessionData->szMAILFROM) + 3;
  bufSend = malloc(nSendBufferSize + 1);
  memset(bufSend, 0, nSendBufferSize + 1);
  sprintf((char *)bufSend, "MAIL FROM: <%s>\r\n", _psSessionData->szMAILFROM);
  
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
  FREE(bufReceive);
  
  return SUCCESS;
}


int tryLogin(int hSocket, sLogin** psLogin, _MODULE_DATA* _psSessionData, char* szAccount, char* szDomain)
{
  int nRet = FAILURE;
  unsigned char* bufReceive = NULL;
  int nReceiveBufferSize = 0;
  unsigned char bufSend[BUF_SIZE];
  char szVerb[9];

  memset(szVerb, 0, 9);
  switch(_psSessionData->nVerb)
  {
    case VERB_VRFY:
      writeError(ERR_DEBUG_MODULE, "[%s] Using VRFY command.", MODULE_NAME);
      strncpy(szVerb, "VRFY", 4);
      break;
    case VERB_EXPN:
      writeError(ERR_DEBUG_MODULE, "[%s] Using EXPN command.", MODULE_NAME);
      strncpy(szVerb, "EXPN", 4);
      break;
    case VERB_RCPT:
      writeError(ERR_DEBUG_MODULE, "[%s] Using RCPT command.", MODULE_NAME);
      strncpy(szVerb, "RCPT TO:", 8);
      break;
    default:
      break;
  }

  if (strlen(szDomain) > 0)
  {
    sprintf((char *)bufSend, "%s %.250s@%.250s\r\n", szVerb, szAccount, szDomain);
  }
  else
  {
    sprintf((char *)bufSend, "%s %.250s\r\n", szVerb, szAccount);
  }

  if (medusaSend(hSocket, bufSend, strlen((char *)bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "[%s] Failed during sending of authentication data.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_UNKNOWN;
    setPassResult(*psLogin, szDomain);
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

  if (strstr((char *)bufReceive, "250 ") != NULL)
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Found valid account: %s", MODULE_NAME, szAccount);
    (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
    nRet = MSTATE_RUNNING;
  }
  else if (strstr((char *)bufReceive, "252 ") != NULL)
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Found valid account: %s", MODULE_NAME, szAccount);
    (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
    nRet = MSTATE_RUNNING;
  }
  else if (strstr((char *)bufReceive, "550 Too many invalid recipients") != NULL)
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Too many invalid recipients: %s", MODULE_NAME, szAccount);
    (*psLogin)->iResult = LOGIN_RESULT_ERROR;
    nRet = MSTATE_EXITING;
  }
  else if (strstr((char *)bufReceive, "550 ") != NULL)
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Non-existant account: %s", MODULE_NAME, szAccount);
    (*psLogin)->iResult = LOGIN_RESULT_FAIL;
    nRet = MSTATE_RUNNING;
  }
  else if (strstr((char *)bufReceive, "557 ") != NULL) /* 557 5.5.2 String does not match anything. */
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Non-existant account: %s", MODULE_NAME, szAccount);
    (*psLogin)->iResult = LOGIN_RESULT_FAIL;
    nRet = MSTATE_RUNNING;
  }
  else if (strstr((char *)bufReceive, "554 ") != NULL)
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Invalid domain name: %s", MODULE_NAME, szAccount);
    (*psLogin)->iResult = LOGIN_RESULT_ERROR;
    nRet = MSTATE_EXITING;
  }
  else
  {
    writeError(ERR_ERROR, "[%s] Unknown SMTP server response: %s", MODULE_NAME, bufReceive);
    (*psLogin)->iResult = LOGIN_RESULT_ERROR;
    nRet = MSTATE_EXITING;
  }

  /* check if more data is waiting */
  if (medusaDataReadyTimed(hSocket, 0, 20000) > 0)
    bufReceive = medusaReceiveLineDelay(hSocket, &nReceiveBufferSize, RECEIVE_DELAY_1, RECEIVE_DELAY_2);

  if (strstr((char *)bufReceive, "421 Error: too many errors"))
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Too many errors. Restarting connection.", MODULE_NAME);
    nRet = MSTATE_NEW;
  }

  FREE(bufReceive);
  setPassResult((*psLogin), szDomain);
  
  return(nRet);
}
