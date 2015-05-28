/*
**   Apple Filing Protocol AFP Password Checking Medusa Module
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
**   Module designed using afpfs-ng 0.8.1
**   AFPFS-NG: http://alexthepuffin.googlepages.com/home
**
**   The following steps needed to be performed:
**    copy afpfs-ng-0.8.1/include to /usr/include/afpfs-ng
**
**   NOTE: autoconf is currently hard-coded to use /usr/lib/libafpclient.so.0.
**   This may need to be tweaked if afpfs-ng is installed to some other
**   location.
**
*/

#include <sys/types.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "module.h"

#define MODULE_NAME    "afp.mod"
#define MODULE_AUTHOR  "pMonkey <pmonkey@foofus.net>"
#define MODULE_SUMMARY_USAGE  "Brute force module for AFP sessions"
#define MODULE_VERSION    "2.0"
#define MODULE_VERSION_SVN "$Id: afp.c 9240 2015-05-22 17:42:18Z jmk $"
#define MODULE_SUMMARY_FORMAT  "%s : version %s"
#define MODULE_SUMMARY_FORMAT_WARN  "%s : version %s (%s)"
#define LIBAFP_WARNING "No usable LIBAFPFS. Module disabled."

#ifdef HAVE_LIBAFPFS

#include <afpfs-ng/afp.h>
#include <afpfs-ng/afp_protocol.h>

#define PORT_AFP  548

typedef struct __MODULE_DATA {
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
int tryLogin(sLogin** login, char* szLogin, char* szPassword);
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
int go(sLogin* logins, int argc, char *argv[])
{
  int i;
  char *strtok_ptr, *pOpt, *pOptTmp;
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
    // Parameters are good - make module go now
    writeError(ERR_DEBUG_MODULE, "OMG teh %s module has been called!!", MODULE_NAME);

    for (i=0; i<argc; i++) {
      pOptTmp = malloc( strlen(argv[i]) + 1);
      memset(pOptTmp, 0, strlen(argv[i]) + 1);
      strncpy(pOptTmp, argv[i], strlen(argv[i]));
      writeError(ERR_DEBUG_MODULE, "Processing complete option: %s", pOptTmp);
      pOpt = strtok_r(pOptTmp, ":", &strtok_ptr);
      writeError(ERR_DEBUG_MODULE, "Processing option: %s", pOpt);
      FREE(pOptTmp);
    }

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
  else
    params.nPort = PORT_AFP;
  
  initConnectionParams(psLogin, &params);

  while (nState != MSTATE_COMPLETE)
  {  
    switch(nState)
    {
      case MSTATE_NEW:
        // Already have an open socket - close it
        if (hSocket > 0)
          medusaDisconnect(hSocket);

        hSocket = medusaConnect(&params);
        if (hSocket < 0) 
        {
          writeError(ERR_NOTICE, "[%s] failed to connect, port %d was not open on %s", MODULE_NAME, params.nPort, psLogin->psServer->pHostIP);
          psLogin->iResult = LOGIN_RESULT_UNKNOWN;
          return FAILURE;
        }

        nState = MSTATE_RUNNING;
        break;
      case MSTATE_RUNNING:
        nState = tryLogin(&psLogin, psCredSet->psUser->pUser, psCredSet->pPass);

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

static int server_subconnect(struct afp_url url)
{
  struct afp_connection_request *conn_req;
  struct afp_server * server = NULL;

  conn_req = malloc( sizeof(struct afp_connection_request) );
  server = malloc( sizeof(struct afp_server) );
 
  memset(conn_req, 0, sizeof(struct afp_connection_request));

  conn_req->url=url;
  conn_req->url.requested_version=31;

  writeError(ERR_DEBUG_MODULE, "[%s] AFP connection - username: %s password: %s server: %s", MODULE_NAME, url.username, url.password, url.servername); 

  if (strlen(url.uamname) > 0) 
  {
    if ((conn_req->uam_mask = find_uam_by_name(url.uamname)) == 0) {
      writeError(ERR_ERROR, "[%s] Unknown UAM: %s", MODULE_NAME, url.uamname); 
      FREE(conn_req);
      FREE(server);
      return FAILURE;
    }
  } 
  else 
  {
    conn_req->uam_mask=default_uams_mask();
  }

  writeError(ERR_DEBUG_MODULE, "[%s] Initiating connection attempt.", MODULE_NAME);
  if ((server = afp_server_full_connect(NULL, conn_req)) == NULL) 
  {
    FREE(conn_req);
    FREE(server);
    return FAILURE;
  }

  writeError(ERR_DEBUG_MODULE, "[%s] Connected to server: %s via UAM: %s", MODULE_NAME, server->server_name_printable, uam_bitmap_to_string(server->using_uam));

  FREE(conn_req);
  FREE(server);

  return SUCCESS;
}

/* This is to replace the afp library log callback function with a more medusa friendly one */
void stdout_log_for_medusa(void * priv __attribute__((unused)), enum loglevels loglevel __attribute__((unused)), int logtype __attribute__((unused)), const char *message)
{
  writeError(ERR_DEBUG_MODULE, "[%s] libafpclient message: %s", MODULE_NAME, message);
}

static struct libafpclient afpclient = {
        .unmount_volume = NULL,
        .log_for_client = stdout_log_for_medusa,
        .forced_ending_hook = NULL,
        .scan_extra_fds = NULL,
        .loop_started = NULL ,
};

int tryLogin(sLogin** psLogin, char* szLogin, char* szPassword)
{
  int iRet;
  struct afp_url tmpurl;
 
  /* Build AFP authentication request */ 
  libafpclient_register(&afpclient);  
  afp_main_quick_startup(NULL);  
  init_uams();
  afp_default_url(&tmpurl);

  memcpy(&tmpurl.servername, (*psLogin)->psServer->pHostIP, AFP_SERVER_NAME_LEN); 
  memcpy(&tmpurl.username, szLogin, AFP_MAX_USERNAME_LEN);
  memcpy(&tmpurl.password, szPassword, AFP_MAX_PASSWORD_LEN);

  if ( server_subconnect(tmpurl) == SUCCESS )
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Login attempt successful.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
    iRet = MSTATE_EXITING;
  } 
  else
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Login attempt failed.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_FAIL;
    iRet = MSTATE_RUNNING;
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
    iLength = strlen(MODULE_SUMMARY_USAGE) + strlen(MODULE_VERSION) + strlen(MODULE_SUMMARY_FORMAT) + strlen(LIBAFP_WARNING) + 1;
    *ppszSummary = (char*)malloc(iLength);
    memset(*ppszSummary, 0, iLength);
    snprintf(*ppszSummary, iLength, MODULE_SUMMARY_FORMAT_WARN, MODULE_SUMMARY_USAGE, MODULE_VERSION, LIBAFP_WARNING);
  } 
  else
  {
    writeError(ERR_ERROR, "%s reports an error in summaryUsage() : ppszSummary must be NULL when called", MODULE_NAME);
  }
}   
  
void showUsage()
{
  writeVerbose(VB_NONE, "%s (%s) %s :: %s\n", MODULE_NAME, MODULE_VERSION, MODULE_AUTHOR, MODULE_SUMMARY_USAGE);
  writeVerbose(VB_NONE, "** Module was not properly built. Are the afpfs-ng headers and static library installed correctly? **");
  writeVerbose(VB_NONE, "");
} 

int go(sLogin* logins, int argc, char *argv[])
{
  writeVerbose(VB_NONE, "%s (%s) %s :: %s\n", MODULE_NAME, MODULE_VERSION, MODULE_AUTHOR, MODULE_SUMMARY_USAGE);
  writeVerbose(VB_NONE, "** Module was not properly built. Are the afpfs-ng headers and static library installed correctly? **");
  writeVerbose(VB_NONE, "");
  return FAILURE;
}

#endif
