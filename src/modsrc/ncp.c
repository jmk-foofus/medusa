/*
**   NCP Password/HASH Checking Medusa Module
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
**   Based on code from: ncpfs/nwauth
**   ftp://platan.vc.cvut.cz/pub/linux/ncpfs/
**
**   Username format: BLAH.OU=Servers.O=foofus

  // found in current context.\nTrying server context
*/

#include <sys/types.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "module.h"

#define MODULE_NAME    "ncp.mod"
#define MODULE_AUTHOR  "JoMo-Kun <jmk@foofus.net>"
#define MODULE_SUMMARY_USAGE  "Brute force module for NCP sessions"
#define MODULE_VERSION    "2.0"
#define MODULE_VERSION_SVN "$Id: ncp.c 9217 2015-05-07 18:07:03Z jmk $"
#define MODULE_SUMMARY_FORMAT  "%s : version %s"
#define MODULE_SUMMARY_FORMAT_WARN  "%s : version %s (%s)"
#define LIBNCP_WARNING "No usable LIBNCP. Module disabled."

#ifdef HAVE_LIBNCP

#include <ncp/nwcalls.h>

typedef struct __NCP_DATA {
  struct ncp_conn_spec spec;
  struct ncp_conn *conn;
  char *context;
} _NCP_DATA;

// Tells us whether we are to continue processing or not
enum MODULE_STATE
{
  MSTATE_NEW,
  MSTATE_RUNNING,
  MSTATE_EXITING,
  MSTATE_COMPLETE
};

// Forward declarations
int tryLogin(sLogin** login, _NCP_DATA* _psSessionData, char* szPassword);
int initModule(sLogin* login, _NCP_DATA *_psSessionData);

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
  writeVerbose(VB_NONE, "  CONTEXT:? ");
  writeVerbose(VB_NONE, "    Sets user context information.");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "It should be noted that libncp does not by default automatically specific a user context.");
  writeVerbose(VB_NONE, "If it fails to resolve the name provided it appends the server's context to the username and attempts");
  writeVerbose(VB_NONE, "to resolve that value. It is advised that users specify a context for each account being tested.");
  writeVerbose(VB_NONE, "A global context can be specified using the CONTEXT option. A per-user context can be defined");
  writeVerbose(VB_NONE, "as part of the account name within a file containing usernames or the username passed via the ");
  writeVerbose(VB_NONE, "command-line.");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "  Usage example: \"-M ncp -m CONTEXT:.OU=administrators.O=foofus -u username\"");
  writeVerbose(VB_NONE, "  Usage example: \"-M ncp -u username.OU=administrators.O=foofus\"");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "Libncp, by default, also uses both the NDS and BIND authenticators. Unfortunately, the only");
  writeVerbose(VB_NONE, "error message returned to the module is that of the BIND authenticator. These messages are not");
  writeVerbose(VB_NONE, "as descriptive as NDS and only seem to report success or failure. In order to have more useful");
  writeVerbose(VB_NONE, "messages (account disabled/max logons exceeded/etc.), create a ~/.nwclient or /etc/ncpfs.conf");
  writeVerbose(VB_NONE, "file with the following text:");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "  [Requester]");
  writeVerbose(VB_NONE, "  NetWare Protocol = NDS");
  writeVerbose(VB_NONE, "");
}

// The "main" of the medusa module world - this is what gets called to actually do the work
int go(sLogin* logins, int argc, char *argv[])
{
  int i;
  char *strtok_ptr, *pOpt, *pOptTmp;
  _NCP_DATA *psSessionData;
  psSessionData = malloc(sizeof(_NCP_DATA));  
  memset(psSessionData, 0, sizeof(_NCP_DATA));

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

      if (strcmp(pOpt, "CONTEXT") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if ( pOpt )
        {
          psSessionData->context = malloc(strlen(pOpt));
          strncpy((char *)psSessionData->context, pOpt, strlen(pOpt));
        }
        else
          writeError(ERR_WARNING, "Method CONTEXT requires value to be set.");
      }
      else
         writeError(ERR_WARNING, "Invalid method: %s.", pOpt);
      
      FREE(pOptTmp);
    }
 
    initModule(logins, psSessionData);
  }  

  FREE(psSessionData);
  return SUCCESS;
}

int initModule(sLogin* psLogin, _NCP_DATA *_psSessionData)
{
  enum MODULE_STATE nState = MSTATE_NEW;
  char *szUserContext = NULL;
  long NCPErrorCode;
  sCredentialSet *psCredSet = NULL;
  int i = 0;

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

  while (nState != MSTATE_COMPLETE)
  {  
    switch (nState)
    {
      case MSTATE_NEW:
        FREE(szUserContext);
        if (_psSessionData->context != NULL)
        {
          szUserContext = malloc(strlen(psCredSet->psUser->pUser) + strlen(_psSessionData->context) + 1);
          memset(szUserContext, 0, strlen(psCredSet->psUser->pUser) + strlen(_psSessionData->context) + 1);
          strncpy(szUserContext, psCredSet->psUser->pUser, strlen(psCredSet->psUser->pUser));
          strncpy(szUserContext + strlen(psCredSet->psUser->pUser), _psSessionData->context, strlen(_psSessionData->context));
        }
        else
          szUserContext = psCredSet->psUser->pUser;
        
        writeError(ERR_DEBUG_MODULE, "[%s] Set user context: %s", MODULE_NAME, szUserContext);

        NCPErrorCode = ncp_find_conn_spec3(psLogin->psServer->pHostIP, szUserContext, "", 1, 1 ? ~0U : getuid(), 0, &_psSessionData->spec);
        if (NCPErrorCode)
        {
          writeError(ERR_ERROR, "[%s] Failed to find an appropriate connection: %d.", MODULE_NAME, NCPErrorCode);
          psLogin->iResult = LOGIN_RESULT_UNKNOWN;
          return FAILURE;
        }

        /* Initiate NCP session connection - retry if necessary */ 
        writeError(ERR_DEBUG_MODULE, "Attempting to establish connection with NCP server.");
        for (i = 1; i <= psLogin->psServer->psHost->iRetries + 1; i++) 
        {

          NCPErrorCode = NWCCOpenConnByName(NULL, _psSessionData->spec.server, NWCC_NAME_FORMAT_BIND, NWCC_OPEN_NEW_CONN, NWCC_RESERVED, &_psSessionData->conn);
          if (NCPErrorCode)
          {
            writeError(ERR_ERROR, "[%s] Failed establishing NCP session (%d/%d): Error Code: %d Host: %s User: %s Pass: %s", MODULE_NAME, i, psLogin->psServer->psHost->iRetries + 1, NCPErrorCode, psLogin->psServer->pHostIP, psCredSet->psUser->pUser, psCredSet->pPass);

            if (i == psLogin->psServer->psHost->iRetries + 1) {
              psLogin->iResult = LOGIN_RESULT_UNKNOWN;
              return FAILURE;
            }
          }
        }

        writeError(ERR_DEBUG_MODULE, "Connected");
        nState = MSTATE_RUNNING;
        break;
      case MSTATE_RUNNING:
        nState = tryLogin(&psLogin, _psSessionData, psCredSet->pPass);

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
        ncp_close(_psSessionData->conn);
        nState = MSTATE_COMPLETE;
        break;
      default:
        writeError(ERR_CRITICAL, "Unknown %s module (%d) state %d host: %s", MODULE_NAME, psLogin->iId, nState, psLogin->psServer->pHostIP);
        psLogin->iResult = LOGIN_RESULT_UNKNOWN;
        return FAILURE;
    }  
  }
 
  if (_psSessionData->context != NULL)
    if (szUserContext != NULL) FREE(szUserContext);
  
  FREE(psCredSet);
  return SUCCESS;
}

int tryLogin(sLogin** psLogin, _NCP_DATA* _psSessionData, char* szPassword)
{
  unsigned int i;
  int iRet;
  short int NCPErrorCode = 0;
  char *pErrorMsg = NULL;
  char ErrorCode[12];
  int object_type = NCP_BINDERY_USER;
  char *szTemp = NULL;

  short int ncpErrorCode[] = {
    0xFFFF,       /* UNKNOWN_ERROR_CODE */
    0x0000,       /* STATUS_SUCCESS */
    0xFD63,       /* STATUS_LOGON_FAILURE */
    0xFDA7,       /* SPECIFIED_BINARY_OBJECT_DOES_NOT_EXIST */

    /* include/ncp/ncplib.h */
    0x8998,       /* NWE_VOL_INVALID */
    0x899B,       /* NWE_DIRHANDLE_INVALID */
    0x89C5,       /* NWE_LOGIN_LOCKOUT */
    0x89D3,       /* NWE_Q_NO_RIGHTS */
    0x89D5,       /* NWE_Q_NO_JOB */
    //0x89D6,       /* NWE_Q_NO_JOB_RIGHTS */
    0x89D6,       /* NWE_PASSWORD_UNENCRYPTED */
    0x89D7,       /* NWE_PASSWORD_NOT_UNIQUE */
    0x89D8,       /* NWE_PASSWORD_TOO_SHORT */
    0x89D9,       /* NWE_LOGIN_MAX_EXCEEDED */
    0x89DA,       /* NWE_LOGIN_UNAUTHORIZED_TIME */
    0x89DB,       /* NWE_LOGIN_UNAUTHORIZED_STATION */
    0x89DC,       /* NWE_ACCT_DISABLED */
    0x89DE,       /* NWE_PASSWORD_INVALID */
    0x89DF,       /* NWE_PASSWORD_EXPIRED */
    0x89E9,       /* NWE_BIND_MEMBER_ALREADY_EXISTS */
    0x89FB,       /* NWE_NCP_NOT_SUPPORTED */
    0x89FC,       /* NWE_SERVER_UNKNOWN */
    0x89FD,       /* NWE_CONN_NUM_INVALID */
    0x89FF,       /* NWE_SERVER_FAILURE */
};

  char *ncpErrorMsg[] = {
    "UNKNOWN_ERROR_CODE",
    "STATUS_SUCCESS",
    "STATUS_LOGON_FAILURE",
    "SPECIFIED_BINARY_OBJECT_DOES_NOT_EXIST",
    "NWE_VOL_INVALID",
    "NWE_DIRHANDLE_INVALID",
    "NWE_LOGIN_LOCKOUT",
    "NWE_Q_NO_RIGHTS",
    "NWE_Q_NO_JOB",
    //"NWE_Q_NO_JOB_RIGHTS",
    "NWE_PASSWORD_UNENCRYPTED",
    "NWE_PASSWORD_NOT_UNIQUE",
    "NWE_PASSWORD_TOO_SHORT",
    "NWE_LOGIN_MAX_EXCEEDED",
    "NWE_LOGIN_UNAUTHORIZED_TIME",
    "NWE_LOGIN_UNAUTHORIZED_STATION",
    "NWE_ACCT_DISABLED",
    "NWE_PASSWORD_INVALID",
    "NWE_PASSWORD_EXPIRED",
    "NWE_BIND_MEMBER_ALREADY_EXISTS",
    "NWE_NCP_NOT_SUPPORTED",
    "NWE_SERVER_UNKNOWN",
    "NWE_CONN_NUM_INVALID",
    "NWE_SERVER_FAILURE"
  };

  memset(&ErrorCode, 0, 12);

  // NCP_BINDERY_NAME_LEN   48
  // NCPFS_MAX_CFG_USERNAME 256
  // NetWare 5 case insensitive???

  size_t l = strlen(szPassword);
  if (l >= sizeof(_psSessionData->spec.password)) {
    ncp_close(_psSessionData->conn);
    writeError(ERR_ERROR, "[%s] Password too long. Max length 48 characters.", MODULE_NAME);
    iRet = MSTATE_EXITING;
    return(iRet);
  }

  memset(_psSessionData->spec.password, 0, sizeof(_psSessionData->spec.password));
  memcpy(_psSessionData->spec.password, szPassword, l);

  /* Upper-case password */
  szTemp = _psSessionData->spec.password;
  while(*szTemp != '\0')
  {
      *szTemp = toupper((unsigned char) *szTemp);
      szTemp++;
  }

  NCPErrorCode = ncp_login_conn(_psSessionData->conn, _psSessionData->spec.user, object_type, _psSessionData->spec.password);

  /* Locate appropriate NCP code message */
  pErrorMsg = ncpErrorMsg[0]; /* UNKNOWN_ERROR_CODE */
  for (i = 0; i < sizeof(ncpErrorCode)/2; i++) {
    if (NCPErrorCode == ncpErrorCode[i]) {
      pErrorMsg = ncpErrorMsg[i];
      break;
    }
  }

  switch (NCPErrorCode & 0x0000FFFF)
  {
    case 0x0000:  /* Success */
      (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
      iRet = MSTATE_EXITING;
      break;
    case 0x89F0:  /* Incorrect password - BIND Authenticator */
    case 0x89FF:  /* Incorrect password - NWE_SERVER_FAILURE */
    case 0xFD63:  /* Incorrect password - NDS Authenticator */
      writeError(ERR_DEBUG_MODULE, "[%s] Incorrect password. Error code: %X", MODULE_NAME, NCPErrorCode);
      (*psLogin)->iResult = LOGIN_RESULT_FAIL;
      iRet = MSTATE_RUNNING;
      break;
    default:
      writeError(ERR_DEBUG_MODULE, "[%s] Failed to open connection. Error code: %X", MODULE_NAME, NCPErrorCode);
      sprintf(ErrorCode, "0x%8.8X:", NCPErrorCode);
      (*psLogin)->pErrorMsg = malloc( strlen(ErrorCode) + strlen(pErrorMsg) + 1);
      memset((*psLogin)->pErrorMsg, 0, strlen(ErrorCode) + strlen(pErrorMsg) + 1);
      strncpy((*psLogin)->pErrorMsg, ErrorCode, strlen(ErrorCode));
      strncat((*psLogin)->pErrorMsg, pErrorMsg, strlen(pErrorMsg));
      (*psLogin)->iResult = LOGIN_RESULT_ERROR;
      iRet = MSTATE_EXITING;
      break;
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
    iLength = strlen(MODULE_SUMMARY_USAGE) + strlen(MODULE_VERSION) + strlen(MODULE_SUMMARY_FORMAT) + strlen(LIBNCP_WARNING) + 1;
    *ppszSummary = (char*)malloc(iLength);
    memset(*ppszSummary, 0, iLength);
    snprintf(*ppszSummary, iLength, MODULE_SUMMARY_FORMAT_WARN, MODULE_SUMMARY_USAGE, MODULE_VERSION, LIBNCP_WARNING);
  }
  else
  {
    writeError(ERR_ERROR, "%s reports an error in summaryUsage() : ppszSummary must be NULL when called", MODULE_NAME);
  }
}

void showUsage()
{
  writeVerbose(VB_NONE, "%s (%s) %s :: %s\n", MODULE_NAME, MODULE_VERSION, MODULE_AUTHOR, MODULE_SUMMARY_USAGE);
  writeVerbose(VB_NONE, "** Module was not properly built. Are the ncpfs headers and static library installed correctly? **");
  writeVerbose(VB_NONE, "");
}

int go(sLogin* logins, int argc, char *argv[])
{
  writeVerbose(VB_NONE, "%s (%s) %s :: %s\n", MODULE_NAME, MODULE_VERSION, MODULE_AUTHOR, MODULE_SUMMARY_USAGE);
  writeVerbose(VB_NONE, "** Module was not properly built. Are the ncpfs headers and static library installed correctly? **");
  writeVerbose(VB_NONE, "");
  return FAILURE;
}

#endif
