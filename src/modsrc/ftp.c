/*
**   FTP Password Checking Medusa Module
**
**   ------------------------------------------------------------------------
**    Copyright (C) 2009 pMonkey
**    pMonkey <pmonkey@foofus.net>
**
**    CHANGE LOG
**    09/2007 - FTPS Support Added by JoMo-Kun
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
*/

#include <sys/types.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "module.h"

#define MODULE_NAME    "ftp.mod"
#define MODULE_AUTHOR  "pMonkey <pmonkey@foofus.net>"
#define MODULE_SUMMARY_USAGE  "Brute force module for FTP/FTPS sessions"
#define MODULE_VERSION    "2.1"
#define MODULE_VERSION_SVN "$Id: ftp.c 1876 2014-03-03 22:16:20Z jmk $"
#define MODULE_SUMMARY_FORMAT  "%s : version %s"

#define BUF_SIZE 300

#define PORT_FTP  21
#define PORT_FTPS 990

#define AUTH_NORMAL 0
#define AUTH_EXPLICIT 1
#define AUTH_IMPLICIT 2

typedef struct __MODULE_DATA {
  sConnectParams *params;
  int nAuthType;
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
int initAuthSSL(int hSocket, _MODULE_DATA* _psSessionData);
int tryLogin(int hSocket, sLogin** login, _MODULE_DATA* _psSessionData, char* szLogin, char* szPassword);
int initModule(sLogin* login, _MODULE_DATA* _psSessionData);

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
  writeVerbose(VB_NONE, "MODE:? (NORMAL*, EXPLICIT, IMPLICIT)");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "  EXPLICIT: AUTH TLS Mode as defined in RFC 4217");
  writeVerbose(VB_NONE, "     Explicit FTPS (FTP/SSL) connects to a FTP service in the clear. Prior to");
  writeVerbose(VB_NONE, "     sending any credentials, however, an \"AUTH TLS\" command is issued and a");
  writeVerbose(VB_NONE, "     SSL session is negotiated.");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "  IMPLICIT: FTP over SSL (990/tcp)");
  writeVerbose(VB_NONE, "     Implicit FTPS requires a SSL handshake to be performed before any FTP");
  writeVerbose(VB_NONE, "     commands are sent. This service typically resides on tcp/990. If the user");
  writeVerbose(VB_NONE, "     specifies this option or uses the \"-n\" (SSL) option, the module will");
  writeVerbose(VB_NONE, "     default to this mode and tcp/990.");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "  NORMAL");
  writeVerbose(VB_NONE, "     The default behaviour if no MODE is specified. Authentication is attempted");
  writeVerbose(VB_NONE, "     in the clear. If the server requests encryption for the given user,");
  writeVerbose(VB_NONE, "     Explicit FTPS is utilized.");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "Example Usage:");
  writeVerbose(VB_NONE, "    medusa -M ftp -h host -u username -p password");
  writeVerbose(VB_NONE, "    medusa -M ftp -s -h host -u username -p password");
  writeVerbose(VB_NONE, "    medusa -M ftp -m MODE:EXPLICIT -h host -u username -p password");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "(*) Default value");
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

  if ((argc < 0) || (argc > 1))
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
        else if (strcmp(pOpt, "EXPLICIT") == 0)
          psSessionData->nAuthType = AUTH_EXPLICIT;
        else if (strcmp(pOpt, "IMPLICIT") == 0)
          psSessionData->nAuthType = AUTH_IMPLICIT;
        else if (strcmp(pOpt, "NORMAL") == 0)
          psSessionData->nAuthType = AUTH_NORMAL;
        else
          writeError(ERR_WARNING, "Invalid value for method MODE.");
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
  unsigned char* bufReceive;
  int nReceiveBufferSize = 0;
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

  _psSessionData->params = malloc( sizeof(sConnectParams) );
  memset(_psSessionData->params, 0, sizeof(sConnectParams));
  
  if (_psSessionData->nAuthType == AUTH_IMPLICIT)
  {
    psLogin->psServer->psHost->iUseSSL = 1;
    _psSessionData->params->nPort = PORT_FTPS;
  }
  else
  {
    _psSessionData->params->nPort = PORT_FTP;
  }  

  if (psLogin->psServer->psAudit->iPortOverride > 0)
    _psSessionData->params->nPort = psLogin->psServer->psAudit->iPortOverride;
  else if (psLogin->psServer->psHost->iUseSSL > 0)
    _psSessionData->params->nPort = PORT_FTPS;

  initConnectionParams(psLogin, _psSessionData->params);

  while (nState != MSTATE_COMPLETE)
  {  
    switch (nState)
    {
      case MSTATE_NEW:
        // Already have an open socket - close it
        if (hSocket > 0)
          medusaDisconnect(hSocket);

        if (psLogin->psServer->psHost->iUseSSL > 0)
          hSocket = medusaConnectSSL(_psSessionData->params);
        else
          hSocket = medusaConnect(_psSessionData->params);
        
        if (hSocket < 0) 
        {
          writeError(ERR_NOTICE, "%s: failed to connect, port %d was not open on %s", MODULE_NAME, _psSessionData->params->nPort, psLogin->psServer->pHostIP);
          psLogin->iResult = LOGIN_RESULT_UNKNOWN;
          return FAILURE;
        }

        /* establish initial connection */
      
        /*  http://www.faqs.org/rfcs/rfc959.html
          
            Thus the format for multi-line replies is that the first line
            will begin with the exact required reply code, followed
            immediately by a Hyphen, "-" (also known as Minus), followed by
            text.  The last line will begin with the same code, followed
            immediately by Space <SP>, optionally some text, and the Telnet
            end-of-line code.
        */
        writeError(ERR_DEBUG_MODULE, "[%s] Retrieving FTP banner.", MODULE_NAME);
        bufReceive = NULL;
        nReceiveBufferSize = 0;
        
        /* Grab entire banner and verify format */
        if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "^[0-9]{3,3}-.*\r\n[0-9]{3,3} .*\r\n|^[0-9]{3,3} .*\r\n") == FAILURE) || (bufReceive == NULL))
        {
          writeError(ERR_DEBUG_MODULE, "[%s] failed: Server sent unknown response. Exiting...", MODULE_NAME);
          FREE(bufReceive);
          return FAILURE;
        }

        if (strncmp((char*)bufReceive, "220", 3) == 0)
        {
          writeError(ERR_DEBUG_MODULE, "[%s] Server sent 220 response.", MODULE_NAME);
          FREE(bufReceive);
        }
        else if (strncmp((char*)bufReceive, "421", 3) == 0)
        {
          writeError(ERR_ERROR, "[%s] Server sent 421 response (too many connections).", MODULE_NAME);
          FREE(bufReceive);
          return FAILURE;
        }
        else
        {
          writeError(ERR_ERROR, "[%s] Server sent unknown response code: %c%c%c", MODULE_NAME, bufReceive[0], bufReceive[1], bufReceive[2]);
          FREE(bufReceive);
          return FAILURE;
        }          

        /* Establish Explicit FTPS mode authentication if requested */ 
        if (_psSessionData->nAuthType == AUTH_EXPLICIT)
        {
          if (initAuthSSL(hSocket, _psSessionData) == FAILURE)
          {
            psLogin->iResult = LOGIN_RESULT_UNKNOWN;
            nState = MSTATE_EXITING;
          }
        }

        nState = MSTATE_RUNNING;

        break;
      case MSTATE_RUNNING:
        /* The FTP service may be configured to drop connections after an arbitrary number of failed
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

int initAuthSSL(int hSocket, _MODULE_DATA* _psSessionData)
{
  unsigned char bufSend[BUF_SIZE];
  unsigned char* bufReceive = NULL;
  int nReceiveBufferSize;

  writeError(ERR_NOTICE, "[%s] Establishing Explicit FTPS (FTP/SSL) session.", MODULE_NAME);

  memset(bufSend, 0, BUF_SIZE);
  sprintf((char*)bufSend, "AUTH TLS\r\n");
  if (medusaSend(hSocket, bufSend, strlen((char*)bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "[%s] failed: medusaSend was not successful", MODULE_NAME);
    return FAILURE;
  }

  nReceiveBufferSize = 0;
  if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "^[0-9]{3,3}-.*\r\n[0-9]{3,3} .*\r\n|^[0-9]{3,3} .*\r\n") == FAILURE) || (bufReceive == NULL))
  {
    writeError(ERR_DEBUG_MODULE, "[%s] failed: Server sent unknown or no response. Exiting...", MODULE_NAME);
    FREE(bufReceive);
    return FAILURE;
  }

  /* 234 Proceed with negotiation. */
  if (strncmp((char*)bufReceive, "234 ", 4) == 0)
  {
    FREE(bufReceive);

    if (medusaConnectSocketSSL(_psSessionData->params, hSocket) < 0)
    {
      writeError(ERR_ERROR, "[%s] Failed to establish SSL connection.", MODULE_NAME);
      return FAILURE;
    }
  }
  else
  {
    writeError(ERR_ERROR, "[%s] Failed to establish SSL connection. Server sent response: %c%c%c", MODULE_NAME, bufReceive[0], bufReceive[1], bufReceive[2]);
    return FAILURE;
  }

  return SUCCESS;
}

int tryLogin(int hSocket, sLogin** psLogin, _MODULE_DATA* _psSessionData, char* szLogin, char* szPassword)
{
  int iRet;
  unsigned char bufSend[BUF_SIZE];
  unsigned char* bufReceive = NULL;
  int nReceiveBufferSize = 0;

  /* send username */
  memset(bufSend, 0, sizeof(bufSend));
  sprintf((char*)bufSend, "USER %.250s\r\n", szLogin);

  if (medusaSend(hSocket, bufSend, strlen((char*)bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
  }
 
  nReceiveBufferSize = 0;
  if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "^[0-9]{3,3}-.*\r\n[0-9]{3,3} .*\r\n|^[0-9]{3,3} .*\r\n") == FAILURE) || (bufReceive == NULL))
  {
    writeError(ERR_ERROR, "[%s] failed: Server sent unknown or no response. Server may have dropped connection due to lack of encryption or due to anti-bruteforce measures. Enabling EXPLICIT mode may help with the former cause and increasing the socket check delay (e.g. -c 1000) may help with the later.", MODULE_NAME);
    return FAILURE;
  }

  /* FTP service may be configured to require protected authentication for specific users */
  if ( (strstr((char*)bufReceive, "530 Non-anonymous sessions must use encryption.") != NULL) ||
       (strstr((char*)bufReceive, "331 Non-anonymous sessions must use encryption.") != NULL) || 
       (strstr((char*)bufReceive, "331 Rejected--secure connection required") != NULL) )
  {
    writeError(ERR_NOTICE, "[%s] FTP server (%s) appears to require SSL for specified user.", MODULE_NAME, (*psLogin)->psServer->pHostIP);
    
    FREE(bufReceive);
    
    if ( medusaCheckSocket(hSocket, (*psLogin)->psServer->psAudit->iSocketWait) )
    {
      writeError(ERR_DEBUG_MODULE, "[%s] Checking socket status: OK", MODULE_NAME);
      if (initAuthSSL(hSocket, _psSessionData) == FAILURE)
        return FAILURE;
    }
    else
    {
      writeError(ERR_DEBUG_MODULE, "[%s] Checking socket status: FAIL - restart connection", MODULE_NAME);
      _psSessionData->nAuthType = AUTH_EXPLICIT;      
      return MSTATE_NEW;
    }

    /* re-send username */
    memset(bufSend, 0, sizeof(bufSend));
    sprintf((char*)bufSend, "USER %.250s\r\n", szLogin);

    if (medusaSend(hSocket, bufSend, strlen((char*)bufSend), 0) < 0)
    {
      writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
    }
 
    nReceiveBufferSize = 0;
    if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "^[0-9]{3,3}-.*\r\n[0-9]{3,3} .*\r\n|^[0-9]{3,3} .*\r\n") == FAILURE) || (bufReceive == NULL))
    {
      writeError(ERR_ERROR, "[%s] failed: Server sent unknown or no response. Exiting...", MODULE_NAME);
      return FAILURE;
    }
  }  

  /* Standard FTP [PR85] specifies a 530 response to the USER command when
     the username is rejected. "Not logged in." */
  if (strncmp((char*)bufReceive, "530 ", 4) == 0) 
  {
    writeError(ERR_ERROR, "[%s] Server sent 530 response (rejected username).", MODULE_NAME);
    FREE(bufReceive);
    return FAILURE;
  }
  /* 421 There are too many connections from your internet address. */
  else if (strncmp((char*)bufReceive, "421 ", 4) == 0) 
  {
    writeError(ERR_ERROR, "[%s] Server sent 421 response (too many connections).", MODULE_NAME);
    FREE(bufReceive);
    return MSTATE_EXITING;
  }
  /* Expect: "331 Please specify the password." */
  else if (strncmp((char*)bufReceive, "331 ", 4) != 0) 
  {
    writeError(ERR_ERROR, "[%s] failed: Server did not respond with a '331'.", MODULE_NAME);
    FREE(bufReceive);
    return FAILURE;
  }
  
  FREE(bufReceive);

  /* send password */
  memset(bufSend, 0, sizeof(bufSend));
  sprintf((char*)bufSend, "PASS %.250s\r\n", szPassword);

  if (medusaSend(hSocket, bufSend, strlen((char*)bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
  }

  nReceiveBufferSize = 0;
  if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "^[0-9]{3,3}-.*\r\n[0-9]{3,3} .*\r\n|^[0-9]{3,3} .*\r\n") == FAILURE) || (bufReceive == NULL))
  {
    writeError(ERR_ERROR, "%s failed: medusaReceive returned no data.", MODULE_NAME);
    return FAILURE;
  }
  
  if (bufReceive[0] == '2')
  {
    writeError(ERR_DEBUG_MODULE, "%s : Login attempt successful.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
    iRet = MSTATE_EXITING;
  }
  else
  {
    writeError(ERR_DEBUG_MODULE, "%s : Login attempt failed.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_FAIL;
    /* Restarting session for now as it's currently faster when dealing with anti-bruteforce services */
    iRet = MSTATE_NEW;
  }
  
  FREE(bufReceive);
  setPassResult((*psLogin), szPassword);

  return(iRet);
}
