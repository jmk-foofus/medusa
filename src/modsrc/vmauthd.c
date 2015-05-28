/*
**   VMware Authentication Daemon Password Checking Medusa Module
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
**    Based on code from:
**      Hydra 5.2 [van Hauser <vh@thc.org>/ David Maciejak <david.maciejak@kyxar.fr>]
**
*/

#include <sys/types.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "module.h"

#define MODULE_NAME    "vmauthd.mod"
#define MODULE_AUTHOR  "JoMo-Kun <jmk@foofus.net>"
#define MODULE_SUMMARY_USAGE  "Brute force module for the VMware Authentication Daemon"
#define MODULE_VERSION    "2.0"
#define MODULE_VERSION_SVN "$Id: vmauthd.c 9217 2015-05-07 18:07:03Z jmk $"
#define MODULE_SUMMARY_FORMAT  "%s : version %s"
#define MODULE_SUMMARY_FORMAT_WARN  "%s : version %s (%s)"

#define PORT_VMAUTHD 902

// Tells us whether we are to continue processing or not
enum MODULE_STATE
{
  MSTATE_NEW,
  MSTATE_RUNNING,
  MSTATE_EXITING,
  MSTATE_COMPLETE
};

// Forward declarations
int initConnection(int hSocket, sConnectParams *params);
int tryLogin(int hSocket, sLogin** login, char* szLogin, char* szPassword);
int initModule(sLogin* login);

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
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "The VMware Authentication Daemon listens on TCP port 902 and may or may not");
  writeVerbose(VB_NONE, "require a SSL-encrypted connection. This module connects to the service using");
  writeVerbose(VB_NONE, "non-SSL and will automatically switch to SSL if required.");
  writeVerbose(VB_NONE, "");
}

// The "main" of the medusa module world - this is what gets called to actually do the work
int go(sLogin* logins, int argc, char *argv[] __attribute__((unused)))
{
  if (argc != 0)
  {
    writeError(ERR_ERROR, "%s: Incorrect number of parameters passed to module (%d). Use \"-q\" option to display module usage.", MODULE_NAME, argc);
    return FAILURE;
  }
  else 
  {
    writeError(ERR_DEBUG_MODULE, "OMG teh %s module has been called!!", MODULE_NAME);
    initModule(logins);
  }  

  return SUCCESS;
}

int initModule(sLogin* psLogin)
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
  else
    params.nPort = PORT_VMAUTHD;
   params.nSSLVersion = 3; /* VMware Authentication Daemon requires SSLv3 */
   initConnectionParams(psLogin, &params);

  while (nState != MSTATE_COMPLETE)
  {  
    switch (nState)
    {
      case MSTATE_NEW:
        if (hSocket > 0)
          medusaDisconnect(hSocket);
  
        hSocket = medusaConnect(&params);
        if (hSocket < 0) 
        {
          writeError(ERR_NOTICE, "[%s] failed to connect, port %d was not open on %s", MODULE_NAME, params.nPort, psLogin->psServer->pHostIP);
          psLogin->iResult = LOGIN_RESULT_UNKNOWN;
          return FAILURE;
        }

        if (initConnection(hSocket, &params) == FAILURE)
        {
          psLogin->iResult = LOGIN_RESULT_UNKNOWN;
          return FAILURE;
        }

        writeError(ERR_DEBUG_MODULE, "Connected");

        nState = MSTATE_RUNNING;
        break;
      case MSTATE_RUNNING:
        nState = tryLogin(hSocket, &psLogin, psCredSet->psUser->pUser, psCredSet->pPass);

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
       
/* Module specific functions */

/*
    220 VMware Authentication Daemon Version 1.00
    220 VMware Authentication Daemon Version 1.10: SSL Required
*/
int initConnection(int hSocket, sConnectParams *params)
{ 
  unsigned char* bufReceive = NULL;
  int nReceiveBufferSize;
  
  nReceiveBufferSize = 0;
  if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "^220 .*\r\n") == FAILURE) || (bufReceive == NULL))
  {
    writeError(ERR_ERROR, "[%s] Incorrect VMware authentication protocol or service shutdown: %s.", MODULE_NAME, bufReceive);
    FREE(bufReceive);
    return FAILURE;
  }
 
  if (strstr((char *)bufReceive, "SSL Required"))
  {
    writeError(ERR_INFO, "[%s] SSL Required for VMware authentication. Proceeding using SSL.", MODULE_NAME);
  
    if (medusaConnectSocketSSL(params, hSocket) < 0)
    {
      writeError(ERR_ERROR, "[%s] Failed to establish SSLv3 connection.", MODULE_NAME);
      FREE(bufReceive);
      return FAILURE;
    }
  }
  
  FREE(bufReceive);

  return SUCCESS;
}

int tryLogin(int hSocket, sLogin** psLogin, char* szLogin, char* szPassword)
{
  int iRet;
  unsigned char* bufSend = NULL;
  unsigned char* bufReceive = NULL;
  int nReceiveBufferSize = 0;
  
  bufSend = malloc(strlen(szLogin) + 7 + 1);
  memset(bufSend, 0, strlen(szLogin) + 7 + 1);
  sprintf((char *)bufSend, "USER %s\r\n", szLogin);
 
  if (medusaSend(hSocket, bufSend, strlen((char *)bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "[%s] failed: medusaSend was not successful", MODULE_NAME);
    FREE(bufSend);
    return FAILURE;
  }
  FREE(bufSend);

  /* 331 Password required for USERNAME.[0D][0A] */
  nReceiveBufferSize = 0;
  if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "^331 .*\r\n") == FAILURE) || (bufReceive == NULL))
  {
    writeError(ERR_ERROR, "[%s] VMware authentication protocol error or service shutdown: %s.\n", MODULE_NAME, bufReceive);
    FREE(bufReceive);
    return FAILURE;
  }
  FREE(bufReceive);
  
  bufSend = malloc(strlen(szPassword) + 7 + 1);
  memset(bufSend, 0, strlen(szPassword) + 7 + 1);
  sprintf((char *)bufSend, "PASS %s\r\n", szPassword);
  
  if (medusaSend(hSocket, bufSend, strlen((char *)bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "[%s] failed: medusaSend was not successful", MODULE_NAME);
    FREE(bufSend);
    return FAILURE;
  }
  FREE(bufSend);

  nReceiveBufferSize = 0;
  if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "^[0-9]{3,3} .*\r\n") == FAILURE) || (bufReceive == NULL))
  {
    writeError(ERR_ERROR, "[%s] VMware authentication protocol error or service shutdown: %s.\n", MODULE_NAME, bufReceive);
    FREE(bufReceive);
    return FAILURE;
  }

  /* 230 User USERNAME logged in.[0D][0A] */
  if (strncmp((char *)bufReceive, "230 ", 4) == 0)
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Login attempt successful.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
    iRet = MSTATE_EXITING;
  }
  /* 530 Login incorrect.[0D][0A] */
  else if (strncmp((char *)bufReceive, "530 ", 4) == 0)
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Login attempt failed.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_FAIL;
    iRet = MSTATE_NEW;
  }
  else
  {
    writeError(ERR_ERROR, "[%s] Unknown error occurred during authentication: %s", MODULE_NAME, bufReceive);
    (*psLogin)->iResult = LOGIN_RESULT_ERROR;
    iRet = MSTATE_EXITING;
  }
  FREE(bufReceive);
  
  setPassResult((*psLogin), szPassword);

  return(iRet);
}
