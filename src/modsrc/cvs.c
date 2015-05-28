/*
**   CVS pserver Password Checking Medusa Module
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
**      Hydra 5.2 [van Hauser <vh@thc.org>]
**
*/

#include <sys/types.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "module.h"

#define MODULE_NAME    "cvs.mod"
#define MODULE_AUTHOR  "JoMo-Kun <jmk@foofus.net>"
#define MODULE_SUMMARY_USAGE  "Brute force module for CVS sessions"
#define MODULE_VERSION    "2.0"
#define MODULE_VERSION_SVN "$Id: cvs.c 9207 2015-04-16 19:19:33Z jmk $"
#define MODULE_SUMMARY_FORMAT  "%s : version %s"
#define MODULE_SUMMARY_FORMAT_WARN  "%s : version %s (%s)"

#define PORT_CVS 2401

typedef struct __CVS_DATA {
  char *szDir;
} _CVS_DATA;

// Tells us whether we are to continue processing or not
enum MODULE_STATE
{
  MSTATE_NEW,
  MSTATE_RUNNING,
  MSTATE_EXITING,
  MSTATE_COMPLETE
};

// Forward declarations
int tryLogin(int hSocket, sLogin** login, _CVS_DATA* _psSessionData, char* szLogin, char* szPassword);
int initModule(sLogin* login, _CVS_DATA *_psSessionData);

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
  writeVerbose(VB_NONE, "  DIR:? ");
  writeVerbose(VB_NONE, "    Sets target directory name. If left unset, the default is \"/root\"");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "  Usage example: \"-M cvs -m DIR:/some_project\"");
  writeVerbose(VB_NONE, "");
}

// The "main" of the medusa module world - this is what gets called to actually do the work
int go(sLogin* logins, int argc, char *argv[])
{
  int i;
  char *strtok_ptr, *pOpt, *pOptTmp;
  _CVS_DATA *psSessionData;
  
  psSessionData = malloc(sizeof(_CVS_DATA));
  memset(psSessionData, 0, sizeof(_CVS_DATA));

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

      if (strcmp(pOpt, "DIR") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if ( pOpt )
        {
          psSessionData->szDir = malloc(strlen(pOpt) + 1);
          memset(psSessionData->szDir, 0, (strlen(pOpt) + 1));
          strncpy((char *)psSessionData->szDir, pOpt, strlen(pOpt));
        }
        else
          writeError(ERR_WARNING, "Method DIR requires value to be set.");
      }
      else
         writeError(ERR_WARNING, "Invalid method: %s.", pOpt);

      free(pOptTmp);
    }

    initModule(logins, psSessionData);
  }  

  FREE(psSessionData);
  return 0;
}

int initModule(sLogin* psLogin, _CVS_DATA *_psSessionData)
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
    params.nPort = PORT_CVS;
  
  initConnectionParams(psLogin, &params);

  /* set directory name, if not specified by user */
  if (_psSessionData->szDir == NULL)
  {
    _psSessionData->szDir = malloc(6);
    memset(_psSessionData->szDir, 0, 6);
    sprintf(_psSessionData->szDir, "/root");
  }
  
  writeError(ERR_DEBUG_MODULE, "[%s] Set directory name: %s", MODULE_NAME, _psSessionData->szDir);

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
          writeError(ERR_NOTICE, "%s: failed to connect, port %d was not open on %s", MODULE_NAME, params.nPort, psLogin->psServer->pHostIP);
          psLogin->iResult = LOGIN_RESULT_UNKNOWN;
          return FAILURE;
        }

        writeError(ERR_DEBUG_MODULE, "Connected");
        nState = MSTATE_RUNNING;

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

/* Module Specific Functions */

int tryLogin(int hSocket, sLogin** psLogin, _CVS_DATA* _psSessionData, char* szLogin, char* szPassword)
{
  int iRet, nSendBufferSize, nReceiveBufferSize;
  unsigned int i;
  unsigned char* bufReceive;
  char *szAuth, *szPassTmp;

  /* evil cvs encryption sheme...
          0 111           P 125           p  58
  ! 120   1  52   A  57   Q  55   a 121   q 113
  "  53   2  75   B  83   R  54   b 117   r  32
          3 119   C  43   S  66   c 104   s  90
          4  49   D  46   T 124   d 101   t  44
  % 109   5  34   E 102   U 126   e 100   u  98
  &  72   6  82   F  40   V  59   f  69   v  60
  ' 108   7  81   G  89   W  47   g  73   w  51
  (  70   8  95   H  38   X  92   h  99   x  33
  )  64   9  65   I 103   Y  71   i  63   y  97
  *  76   : 112   J  45   Z 115   j  94   z  62
  +  67   ;  86   K  50           k  93
  , 116   < 118   L  42           l  39
  -  74   = 110   M 123           m  37
  .  68   > 122   N  91           n  61
  /  87   ? 105   O  35   _  56   o  48
  */

  char key[] =
  { 0, 120, 53, 0, 0, 109, 72, 108, 70, 64, 76, 67, 116, 74, 68, 87,
    111, 52, 75, 119, 49, 34, 82, 81, 95, 65, 112, 86, 118, 110, 122, 105,
    0, 57, 83, 43, 46, 102, 40, 89, 38, 103, 45, 50, 42, 123, 91, 35,
    125, 55, 54, 66, 124, 126, 59, 47, 92, 71, 115, 0, 0, 0, 0, 56,
    0, 121, 117, 104, 101, 100, 69, 73, 99, 63, 94, 93, 39, 37, 61, 48,
    58, 113, 32, 90, 44, 98, 60, 51, 33, 97, 62
  }; /* 92 characters */
  
  if (strlen(szPassword) > 92)
  {
    writeError(ERR_ERROR, "[%s] Password must be limited to 92 or less characters.", MODULE_NAME);
    return FAILURE;
  }

  szPassTmp = malloc(strlen(szPassword) + 1);
  memset(szPassTmp, 0, strlen(szPassword) + 1);
  strncpy(szPassTmp, szPassword, strlen(szPassword));

  for (i = 0; i < strlen(szPassTmp); i++)
    szPassTmp[i] = key[szPassTmp[i] - 0x20];

  nSendBufferSize = strlen(_psSessionData->szDir) + strlen(szLogin) + strlen(szPassTmp) + 56;
  szAuth = malloc(nSendBufferSize + 1);
  memset(szAuth, 0, nSendBufferSize + 1);
  sprintf(szAuth, "BEGIN VERIFICATION REQUEST\n%s\n%s\nA%s\nEND VERIFICATION REQUEST\n", _psSessionData->szDir, szLogin, szPassTmp);

  if (medusaSend(hSocket, (unsigned char*)szAuth, nSendBufferSize, 0) < 0)
  {
    writeError(ERR_ERROR, "[%s] failed: medusaSend was not successful", MODULE_NAME);
    return FAILURE;
  }

  nReceiveBufferSize = 0;
  bufReceive = medusaReceiveRaw(hSocket, &nReceiveBufferSize);
  if (bufReceive == NULL)
    return FAILURE;

  if (strstr((char*)bufReceive, "I LOVE YOU\n"))
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Login attempt successful.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
    iRet = MSTATE_EXITING;
  }
  else if (strstr((char*)bufReceive, "E PAM start error: Critical error - immediate abort\n"))
  {
    writeError(ERR_ERROR, "[%s] User (%s) does not exist.", MODULE_NAME, szLogin);
    (*psLogin)->iResult = LOGIN_RESULT_ERROR;
    iRet = MSTATE_EXITING;
  } 
  else if (strstr((char*)bufReceive, "I HATE YOU\n"))
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Login attempt failed.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_FAIL;
    iRet = MSTATE_NEW;
  }
  else
  {
    writeError(ERR_ERROR, "[%s] Unknown Error Message: %s", MODULE_NAME, bufReceive);
    (*psLogin)->iResult = LOGIN_RESULT_ERROR;
    iRet = MSTATE_EXITING;
  } 
 
  setPassResult((*psLogin), szPassword);

  free(szPassTmp);
  free(szAuth);

  return(iRet);
}
