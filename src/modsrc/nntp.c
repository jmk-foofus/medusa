/*
**   NNTP Password Checking Medusa Module
**
**    Original AUTHINFO Mode
**    http://www.mibsoftware.com/userkt/nntpext/0032.htm
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

#define MODULE_NAME    "nntp.mod"
#define MODULE_AUTHOR  "JoMo-Kun <jmk@foofus.net>"
#define MODULE_SUMMARY_USAGE  "Brute force module for NNTP sessions"
#define MODULE_VERSION    "2.0"
#define MODULE_VERSION_SVN "$Id: nntp.c 9217 2015-05-07 18:07:03Z jmk $"
#define MODULE_SUMMARY_FORMAT  "%s : version %s"

#define BUF_SIZE 300 

#define PORT_NNTP  119
#define PORT_NNTPS 563

typedef struct __MODULE_DATA {
  int nMode;
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
int initConnection(int hSocket, sLogin** psLogin);
int terminateConnection(int hSocket);
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
  writeVerbose(VB_NONE, "  Usage example: \"-M nntp -U accounts.txt -p password\"");
  writeVerbose(VB_NONE, "");
}

// The "main" of the medusa module world - this is what gets called to actually do the work
int go(sLogin* logins, int argc, char *argv[] __attribute__((unused)))
{
  _MODULE_DATA *psSessionData;

  psSessionData = malloc(sizeof(_MODULE_DATA));
  memset(psSessionData, 0, sizeof(_MODULE_DATA));

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

  FREE(psSessionData);
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
  else if (psLogin->psServer->psHost->iUseSSL > 0)
    params.nPort = PORT_NNTPS;
  else
    params.nPort = PORT_NNTP;
  initConnectionParams(psLogin, &params);

  while (nState != MSTATE_COMPLETE)
  {  
    switch(nState)
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
          writeError(ERR_NOTICE, "[%s] failed to connect, port %d was not open on %s", MODULE_NAME, params.nPort, psLogin->psServer->pHostIP);
          psLogin->iResult = LOGIN_RESULT_UNKNOWN;
          return FAILURE;
        }
        
        nState = initConnection(hSocket, &psLogin);
 
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
          terminateConnection(hSocket);
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
int terminateConnection(int hSocket)
{
  unsigned char bufSend[BUF_SIZE];

  memset(bufSend, 0, sizeof(bufSend));
  sprintf((char*)bufSend, "QUIT\r\n");

  if (medusaSend(hSocket, bufSend, strlen((char*)bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "[%s] failed: medusaSend was not successful", MODULE_NAME);
  }

  medusaDisconnect(hSocket);
  return SUCCESS;
}

int initConnection(int hSocket, sLogin** psLogin)
{
  int iRet;
  unsigned char bufSend[BUF_SIZE];
  unsigned char* bufReceive;
  int nReceiveBufferSize = 0;

  /* Retrieve NNTP server banner */
  nReceiveBufferSize = 0;
  bufReceive = medusaReceiveRaw(hSocket, &nReceiveBufferSize);
  if (bufReceive == NULL)
  {
    writeError(ERR_ERROR, "[%s] failed: medusaReceive returned no data. Exiting...", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_UNKNOWN;
    return MSTATE_EXITING;
  }
  else if ((strstr((char*)bufReceive,"200") != NULL)) 
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Retrieved NNTP service banner.", MODULE_NAME);
  }
  /* 400 Too Many Connections */
  else if ((strstr((char*)bufReceive,"400") != NULL)) 
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Too many connections from host recieved by server.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_UNKNOWN;
    return MSTATE_EXITING;
  }
  else
  {
    writeError(ERR_ERROR, "[%s] Failed to retrieve NNTP service banner.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_UNKNOWN;
    return MSTATE_EXITING;
  }
     
  /* Verify that authentication is required */ 
  memset(bufSend, 0, sizeof(bufSend));
  sprintf((char*)bufSend, "HELP\r\n");

  if (medusaSend(hSocket, bufSend, strlen((char*)bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "[%s] failed: medusaSend was not successful", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_UNKNOWN;
    return MSTATE_EXITING;
  }
 
  nReceiveBufferSize = 0;
  bufReceive = medusaReceiveRaw(hSocket, &nReceiveBufferSize);
  if (bufReceive == NULL)
  {
    writeError(ERR_ERROR, "[%s] failed: medusaReceive returned no data.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_UNKNOWN;
    iRet = MSTATE_EXITING;
  }
  /* 480 Authentication Required */ 
  else if (strstr((char*)bufReceive, "480") != NULL) 
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Server requires authentication.", MODULE_NAME);
    iRet = MSTATE_RUNNING;
  }
  else
  {
    writeError(ERR_ERROR, "[%s] Server does not appear to require authentication.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
    iRet = MSTATE_EXITING;
  }

  return iRet;
}


int tryLogin(int hSocket, sLogin** psLogin, char* szLogin, char* szPassword)
{
  int iRet;
  unsigned char bufSend[BUF_SIZE];
  unsigned char* bufReceive;
  int nReceiveBufferSize = 0;

  /* send username */
  memset(bufSend, 0, sizeof(bufSend));
  sprintf((char*)bufSend, "AUTHINFO USER %.250s\r\n", szLogin);

  if (medusaSend(hSocket, bufSend, strlen((char*)bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "[%s] failed: medusaSend was not successful", MODULE_NAME);
  }
 
  nReceiveBufferSize = 0;
  bufReceive = medusaReceiveRaw(hSocket, &nReceiveBufferSize);
  if (bufReceive == NULL)
  {
    writeError(ERR_ERROR, "[%s] failed: medusaReceive returned no data.", MODULE_NAME);
    return FAILURE;
  }
  /* 381 More Authentication Required */
  else if (strstr((char*)bufReceive,"381") != NULL) 
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Receive 381 response requesting user password.", MODULE_NAME);
  }
  else
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Server did not send a 381 response. Password authentication for user may not be required.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
    iRet = MSTATE_EXITING;
  }
 
  /* send password */
  memset(bufSend, 0, sizeof(bufSend));
  
  if (strlen((char*)szPassword) == 0) 
    sprintf((char*)bufSend, "AUTHINFO PASS \"\"\r\n");
  else
    sprintf((char*)bufSend, "AUTHINFO PASS %.250s\r\n", szPassword);

  if (medusaSend(hSocket, bufSend, strlen((char*)bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "[%s] failed: medusaSend was not successful", MODULE_NAME);
  }

  nReceiveBufferSize = 0;
  bufReceive = medusaReceiveRaw(hSocket, &nReceiveBufferSize);
  if (bufReceive == NULL)
  {
    writeError(ERR_ERROR, "[%s] failed: medusaReceive returned no data.", MODULE_NAME);
    return FAILURE;
  }
  /* 281 Authentication accepted */
  else if (strstr((char*)bufReceive, "281") != NULL)
  {
    writeError(ERR_ERROR, "[%s] Login attempt successful.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
    iRet = MSTATE_EXITING;
  }
  /* 482 Authentication rejected */
  else if (strstr((char*)bufReceive, "482") != NULL)
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Login attempt rejected.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_FAIL;
    iRet = MSTATE_RUNNING;
  }
  /* 501 Bad Command Usage */
  else if (strstr((char*)bufReceive, "501") != NULL)
  {
    writeError(ERR_ERROR, "[%s] Bad command usage.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_FAIL;
    iRet = MSTATE_RUNNING;
  }
  /* 502 Authentication Failed */
  else if (strstr((char*)bufReceive, "502") != NULL)
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Login attempt failed.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_FAIL;
    iRet = MSTATE_RUNNING;
  }
  else
  {
    writeError(ERR_ERROR, "[%s] Unknown server response.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_UNKNOWN;
    iRet = MSTATE_RUNNING;
  }
 
  FREE(bufReceive);
  setPassResult((*psLogin), szPassword);

  return(iRet);
}
