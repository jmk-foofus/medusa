/*
**   REXEC Password Checking Medusa Module
**
**   ------------------------------------------------------------------------
**    Copyright (C) 2009 pMonkey
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
**
*/

#include <sys/types.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "module.h"

#define MODULE_NAME    "rexec.mod"
#define MODULE_AUTHOR  "pMonkey <pmonkey@foofus.net>"
#define MODULE_SUMMARY_USAGE  "Brute force module for REXEC sessions"
#define MODULE_VERSION    "2.0"
#define MODULE_VERSION_SVN "$Id: rexec.c 9217 2015-05-07 18:07:03Z jmk $"
#define MODULE_SUMMARY_FORMAT  "%s : version %s"
#define MODULE_SUMMARY_FORMAT_WARN  "%s : version %s (%s)"

#define PORT_REXEC 512
#define RECEIVE_DELAY 1000000 /* Response wait time (usec) */

// Tells us whether we are to continue processing or not
enum MODULE_STATE
{
  MSTATE_NEW,
  MSTATE_RUNNING,
  MSTATE_EXITING,
  MSTATE_COMPLETE
};

// Forward declarations
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
  else if (psLogin->psServer->psHost->iUseSSL > 0)
    writeError(ERR_ERROR, "[%s] module asked for REXEC with SSL. Don't know if such a thing exists...\n");
  else
    params.nPort = PORT_REXEC;

  params.nSourcePort = 1023;
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

/* Module Specific Functions */

int tryLogin(int hSocket, sLogin** psLogin, char* szLogin, char* szPassword)
{
  int iRet;
  unsigned char* bufSend;
  unsigned char* bufReceive;
  int nReceiveBufferSize = 0;
  int nSendBufferSize = 0;

  /* send: 0x00/username/0x00/password/0x00/id/0x00 */
  nSendBufferSize = 1 + strlen(szLogin) + 1 + strlen(szPassword) + 1 + 2 + 1;
  bufSend = malloc(nSendBufferSize);
  memset(bufSend, 0, nSendBufferSize);
  memcpy(bufSend + 1, szLogin, strlen(szLogin));
  memcpy(bufSend + 1 + strlen(szLogin) + 1, szPassword, strlen(szPassword));
  strcpy(bufSend + 1 + strlen(szLogin) + 1 + strlen(szPassword) + 1, "id");

  if (medusaSend(hSocket, bufSend, nSendBufferSize, 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
  }
  FREE(bufSend);
 
  nReceiveBufferSize = 0;
  bufReceive = medusaReceiveRawDelay(hSocket, &nReceiveBufferSize, RECEIVE_DELAY, RECEIVE_DELAY);  
  if (bufReceive == NULL)
  {
    writeError(ERR_ERROR, "%s failed: medusaReceive returned no data.", MODULE_NAME);
    return FAILURE;
  }
  /* response starts with null */
  else if ((nReceiveBufferSize > 1) && (strstr((char *)bufReceive + 1, "uid") != NULL))
  {
    writeError(ERR_DEBUG_MODULE, "%s : Login attempt successful.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
    iRet = MSTATE_EXITING;
  }
  else if ((nReceiveBufferSize > 1) && (strstr((char *)bufReceive + 1, "Command ID in library") != NULL))
  {
    writeError(ERR_DEBUG_MODULE, "%s : AS/400 Login attempt successful.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
    iRet = MSTATE_EXITING;
  }
  else
  {
    writeError(ERR_DEBUG_MODULE, "%s : Login attempt failed.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_FAIL;
    iRet = MSTATE_NEW;
  }
 
  FREE(bufReceive);
  setPassResult((*psLogin), szPassword);

  return(iRet);
}
