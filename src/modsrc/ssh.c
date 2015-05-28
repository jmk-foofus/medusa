/*
**   SSH v2 Password Checking Medusa Module
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
**    This module requires libssh2 (www.libssh2.org).
**
*/

#include <sys/types.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "module.h"

#define MODULE_NAME    "ssh.mod"
#define MODULE_AUTHOR  "JoMo-Kun <jmk@foofus.net>"
#define MODULE_SUMMARY_USAGE  "Brute force module for SSH v2 sessions"
#define MODULE_VERSION    "2.1"
#define MODULE_VERSION_SVN "$Id: ssh.c 9260 2015-05-27 21:52:57Z jmk $"
#define MODULE_SUMMARY_FORMAT  "%s : version %s"
#define MODULE_SUMMARY_FORMAT_WARN  "%s : version %s (%s)"
#define LIBSSH2_WARNING "No usable LIBSSH2. Module disabled."

#ifdef HAVE_LIBSSH2

#include <libssh2.h>

#define PORT_SSH 22
#define SSH_AUTH_UNDEFINED 1
#define SSH_AUTH_KBDINT 2
#define SSH_AUTH_PASSWORD 3
#define SSH_AUTH_ERROR 4
#define SSH_CONN_UNKNOWN 1
#define SSH_CONN_ESTABLISHED 2

typedef struct __SSH2_DATA {
  char *szBannerMsg;
  int iConnectionStatus;
} _SSH2_DATA;

typedef struct __ssh2_session_data {
  char *pPass;
  int iAnswerCount;
} _ssh2_session_data;
  
// Tells us whether we are to continue processing or not
enum MODULE_STATE
{
  MSTATE_NEW,
  MSTATE_RUNNING,
  MSTATE_EXITING,
  MSTATE_COMPLETE
};

// Forward declarations
int tryLogin(_SSH2_DATA* _psSessionData, LIBSSH2_SESSION *session, sLogin** login, char* szLogin, char* szPassword);
int initModule(sLogin* login, _SSH2_DATA *_psSessionData);

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
  writeVerbose(VB_NONE, "  BANNER:? (Libssh client banner. Default SSH-2.0-MEDUSA.)");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "Usage example: \"-M ssh -m BANNER:SSH-2.0-FOOBAR\"");
}

// The "main" of the medusa module world - this is what gets called to actually do the work
int go(sLogin* logins, int argc, char *argv[])
{
  int i;
  char *strtok_ptr, *pOpt, *pOptTmp;
  _SSH2_DATA *psSessionData = NULL;
  psSessionData = malloc(sizeof(_SSH2_DATA));
  memset(psSessionData, 0, sizeof(_SSH2_DATA));

  if ((argc < 0) || (argc > 1))
  {
    writeError(ERR_ERROR, "%s: Incorrect number of parameters passed to module (%d). Use \"-q\" option to display module usage.", MODULE_NAME, argc);
    return FAILURE;
  }
  else 
  {
    writeError(ERR_DEBUG_MODULE, "OMG teh %s module has been called!!", MODULE_NAME);

    for (i=0; i<argc; i++) {
      writeError(ERR_DEBUG_MODULE, "Processing option: %s", argv[i]);
      pOptTmp = malloc( strlen(argv[i]) + 1);
      memset(pOptTmp, 0, strlen(argv[i]) + 1);
      strncpy(pOptTmp, argv[i], strlen(argv[i]));
      pOpt = strtok_r(pOptTmp, ":", &strtok_ptr);

      if (strcmp(pOpt, "BANNER") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);

        if ( pOpt )
        {
          psSessionData->szBannerMsg = malloc(strlen(pOpt));
          strncpy((char *) psSessionData->szBannerMsg, pOpt, strlen(pOpt));
        }
        else
        {
          writeError(ERR_WARNING, "Method BANNER requires value to be set.");
        }
      }
      else 
      {
        writeError(ERR_WARNING, "Invalid method: %s.", pOpt);
      }
      
      free(pOptTmp);
    }

    initModule(logins, psSessionData);
  }  

  FREE(psSessionData);
  return SUCCESS;
}

int initModule(sLogin* psLogin, _SSH2_DATA *_psSessionData)
{
  int hSocket = -1;
  enum MODULE_STATE nState = MSTATE_NEW;
  int i = 0;
  sCredentialSet *psCredSet = NULL;
  sConnectParams params;
  LIBSSH2_SESSION *session = NULL;
  char *pErrorMsg;
  int iErrorMsg;

  _psSessionData->iConnectionStatus = SSH_CONN_UNKNOWN;
  
  _ssh2_session_data ssh2_session_data;
  ssh2_session_data.pPass = NULL;
  ssh2_session_data.iAnswerCount = 0;

  memset(&params, 0, sizeof(sConnectParams));
 
  if (psLogin->psServer->psAudit->iPortOverride > 0)
    params.nPort = psLogin->psServer->psAudit->iPortOverride;
  else
    params.nPort = PORT_SSH;
 
  initConnectionParams(psLogin, &params);

  /* Retrieve next available credential set to test */
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
    writeError(ERR_DEBUG_MODULE, "[%s] module started for host: %s - no more available users to test.", MODULE_NAME, psLogin->psServer->pHostIP);
    nState = MSTATE_COMPLETE;
  }
  
  /* libssh2_init uses a global state, and is not thread safe */      
  pthread_mutex_lock(&psLogin->psServer->psAudit->ptmMutex);
  
  if (libssh2_init(0))
  {
    writeError(ERR_ERROR, "%s: Failed initiating SSH library: Host: %s User: %s Pass: %s", MODULE_NAME, psLogin->psServer->pHostIP, psCredSet->psUser->pUser, psCredSet->pPass);
    psLogin->iResult = LOGIN_RESULT_UNKNOWN;
    return FAILURE;
  }

  pthread_mutex_unlock(&psLogin->psServer->psAudit->ptmMutex);

  while (nState != MSTATE_COMPLETE)
  {  
    switch (nState)
    {
      case MSTATE_NEW:
        /*
          Create a session instance and start it up
          This will trade welcome banners, exchange keys, and setup crypto, compression, and MAC layers
        */
        if (session)
        {
          writeError(ERR_DEBUG_MODULE, "%s: Destroying previous SSH session structure: Host: %s User: %s", MODULE_NAME, psLogin->psServer->pHostIP, psCredSet->psUser->pUser);
          libssh2_session_disconnect(session, "");
          libssh2_session_free(session);
          session = NULL;
        }
        
        session = libssh2_session_init_ex(NULL, NULL, NULL, &ssh2_session_data);
        if (!session)
        {
          writeError(ERR_ERROR, "%s: Failed initiating SSH session: Host: %s User: %s Pass: %s", MODULE_NAME, psLogin->psServer->pHostIP, psCredSet->psUser->pUser, psCredSet->pPass);
          psLogin->iResult = LOGIN_RESULT_UNKNOWN;
          return FAILURE;
        }        

        /* Set client SSH banner */
        if (_psSessionData->szBannerMsg) {
          if ((strncmp(_psSessionData->szBannerMsg, "SSH-2.0-", 8) != 0) || (strlen(_psSessionData->szBannerMsg) > 253)) {
            writeError(ERR_ERROR, "[%s] The selected banner could be rejected be some SSH servers. The banner should begin with \"SSH-2.0-\" and be shorter than 253 characters.", MODULE_NAME);
          } 
        } 
        else {
          _psSessionData->szBannerMsg = malloc(20);
          memset(_psSessionData->szBannerMsg, 0, 20);
          sprintf(_psSessionData->szBannerMsg, "SSH-2.0-MEDUSA_1.0");
        }
        
        writeError(ERR_DEBUG_MODULE, "Attempting to set banner: %s", _psSessionData->szBannerMsg);
        if ( libssh2_banner_set(session, _psSessionData->szBannerMsg) ) {
           writeError(ERR_DEBUG_MODULE, "Failed to set libssh banner.");
        }
       
        /* Initiate SSH session connection - retry if necessary */ 
        writeError(ERR_DEBUG_MODULE, "Attempting to initiate SSH session.");
        for (i = 1; i <= psLogin->psServer->psHost->iRetries + 1; i++) {
          if (hSocket > 0) {
            medusaDisconnect(hSocket);
          }
        
          hSocket = medusaConnect(&params);
          if ( hSocket < 0 ) {
            writeError(ERR_NOTICE, "%s: failed to connect, port %d was not open on %s", MODULE_NAME, params.nPort, psLogin->psServer->pHostIP);
            
            if (session)
            {
              libssh2_session_disconnect(session, "");
              libssh2_session_free(session);
              session = NULL;
            }
            
            psLogin->iResult = LOGIN_RESULT_UNKNOWN;
            return FAILURE;
          }
          
          if (libssh2_session_startup(session, hSocket)) {
            writeError(ERR_ERROR, "%s: Failed establishing SSH session (%d/%d): Host: %s User: %s Pass: %s", MODULE_NAME, i, psLogin->psServer->psHost->iRetries + 1, psLogin->psServer->pHostIP, psCredSet->psUser->pUser, psCredSet->pPass);
          
            libssh2_session_last_error(session, &pErrorMsg, &iErrorMsg, 1);
            if ( (pErrorMsg) && (strstr(pErrorMsg, "Unable to exchange encryption keys")) ) {
              writeError(ERR_ERROR, "[%s] Failed to exchange encryption keys. Are you sure this is a SSHv2 server?", MODULE_NAME);
              i = psLogin->psServer->psHost->iRetries + 1;
            }
            else if (pErrorMsg) {
              writeError(ERR_DEBUG_MODULE, "libssh2 Error Message: %s", pErrorMsg);
            }

            if (i == psLogin->psServer->psHost->iRetries + 1) {
              
              if (addMissedCredSet(psLogin, psCredSet) == SUCCESS)
                writeError(ERR_ERROR, "%s: Failed establishing SSH session. The following credentials have been added to the missed queue for later testing: Host: %s User: %s Pass: %s", MODULE_NAME, psLogin->psServer->pHostIP, psCredSet->psUser->pUser, psCredSet->pPass);
              else
                writeError(ERR_ERROR, "%s: Failed establishing SSH session. The following credentials were NOT tested: Host: %s User: %s Pass: %s", MODULE_NAME, psLogin->psServer->pHostIP, psCredSet->psUser->pUser, psCredSet->pPass);

              if (session)
              {
                libssh2_session_disconnect(session, "");
                libssh2_session_free(session);
                session = NULL;
              }              

              if (hSocket > 0)
                medusaDisconnect(hSocket);
              hSocket = -1;
              psLogin->iResult = LOGIN_RESULT_UNKNOWN;
              return FAILURE;
            }
        
            sleep(psLogin->psServer->psHost->iRetryWait);
          }
          else { break; }
        }
        
        writeError(ERR_DEBUG_MODULE, "Id: %d successfully established connection.", psLogin->iId);
        nState = MSTATE_RUNNING;
        break;
      case MSTATE_RUNNING:
        ssh2_session_data.pPass = psCredSet->pPass;
        ssh2_session_data.iAnswerCount = 0;
        nState = tryLogin(_psSessionData, session, &psLogin, psCredSet->psUser->pUser, psCredSet->pPass);

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
        if (session)
        {
          libssh2_session_disconnect(session, "");
          libssh2_session_free(session);
          session = NULL;
        }

        if (hSocket > 0)
        {
          medusaDisconnect(hSocket);
          hSocket = -1;
        }
        nState = MSTATE_COMPLETE;
        break;
      default:
        writeError(ERR_CRITICAL, "Unknown %s module state %d", MODULE_NAME, nState);

        if (session)
        {
          libssh2_session_disconnect(session, "");
          libssh2_session_free(session);
          session = NULL;
        }

        if (hSocket > 0)
        {
          medusaDisconnect(hSocket);
          hSocket = -1;
        }

        psLogin->iResult = LOGIN_RESULT_UNKNOWN;
        return FAILURE;
    }  
  }

  FREE(psCredSet);
  return SUCCESS;
}

void response_callback(const char* name, int name_len, const char* instruction, int instruction_len, int num_prompts, const LIBSSH2_USERAUTH_KBDINT_PROMPT* prompts, LIBSSH2_USERAUTH_KBDINT_RESPONSE* responses, void **abstract)
{
  (void) name;
  (void) name_len;
  (void) instruction;
  (void) instruction_len;
  int i;
  char *pPass = ((_ssh2_session_data*)(*abstract))->pPass;

  if (((_ssh2_session_data*)(*abstract))->iAnswerCount > 0)
  {
    writeError(ERR_DEBUG_MODULE, "libssh2 response_callback: sshd asked a question, but we've already given out answer.");
  }
  else {
    for (i=0; i<num_prompts; i++)
    {
      writeError(ERR_DEBUG_MODULE, "libssh2 response_callback: prompt[%d/%d]: %s (%d)", i + 1, num_prompts, prompts[i].text, prompts[i].length);
 
      // libssh2 1.5.0 contains a bug with extracting the server prompt. This is a temporay fix for it. 
      // https://trac.libssh2.org/changeset/fe3e23022b174b796b74afe5633796fc967e02e3/libssh2
      //if ( strcasestr(prompts[i].text, "Password:") != NULL ) {
      if ( ((strcasestr(prompts[i].text, "") != NULL ) && ((prompts[i].length == 9) || (prompts[i].length == 10)) ) || ( strcasestr(prompts[i].text, "Password:") != NULL ) ) {
        responses[i].text = malloc( strlen(pPass) );
        memset(responses[i].text, 0, strlen(pPass));
        strncpy(responses[i].text, pPass, strlen(pPass));
        responses[i].length = strlen(pPass);
        writeError(ERR_DEBUG_MODULE, "libssh2 response_callback set password response: %s", pPass);
        ((_ssh2_session_data*)(*abstract))->iAnswerCount++;
      }
      else
      {
        writeError(ERR_ERROR, "%s received an unknown SSH prompt: %s", MODULE_NAME, prompts[i].text);
      }
    }
  }
}

int tryLogin(_SSH2_DATA* _psSessionData, LIBSSH2_SESSION *session, sLogin** psLogin, char* szLogin, char* szPassword)
{
  char *pErrorMsg = NULL;
  int iErrorMsg, iAuthMode, iRet;
  void (*pResponseCallback) ();
  char *strtok_ptr = NULL;
  char *pAuth = NULL;
  pResponseCallback = response_callback;

  /*
    Password authentication failure delay: 2
    Password authentication maximum tries: 3
    Keyboard-interactive authentication failure delay: 2
    Keyboard-interactive authentication maximum tries: 3
  */

  /* libssh2 supports: none, password, publickey, hostbased, keyboard-interactive */
  iAuthMode = SSH_AUTH_UNDEFINED;
  /*  libssh2_userauth_list returns session->userauth_list_data 
      libssh2_session_free() call will handle releasing all session data, 
      including userauth_list_data */
  pErrorMsg = libssh2_userauth_list(session, szLogin, strlen(szLogin));
  if (pErrorMsg)
  {
    writeError(ERR_DEBUG_MODULE, "Supported user-auth modes: %s.", pErrorMsg);
    pAuth = strtok_r(pErrorMsg, ",", &strtok_ptr);

    while (pAuth) {
      if (strcmp(pAuth, "password") == 0) {
        writeError(ERR_DEBUG_MODULE, "Server supports user-auth type: password");
        iAuthMode = SSH_AUTH_PASSWORD;
        _psSessionData->iConnectionStatus = SSH_CONN_ESTABLISHED;
        break;
      }
      else if (strcmp(pAuth, "keyboard-interactive") == 0) {
        writeError(ERR_DEBUG_MODULE, "Server supports user-auth type: keyboard-interactive");
        iAuthMode = SSH_AUTH_KBDINT;
        _psSessionData->iConnectionStatus = SSH_CONN_ESTABLISHED;
        break;
      }

      pAuth = strtok_r(NULL, ",", &strtok_ptr);
    }
  }
  else if (_psSessionData->iConnectionStatus == SSH_CONN_ESTABLISHED)
  {
    writeError(ERR_DEBUG_MODULE, "Failed to retrieve supported authentication modes. Since previous connections worked, restarting entire session and attempting again.");
    (*psLogin)->iResult = LOGIN_RESULT_UNKNOWN;
    iRet = MSTATE_NEW;
    return(iRet);
  }
  else {
    writeError(ERR_ERROR, "Failed to retrieve supported authentication modes. Aborting...");
    (*psLogin)->iResult = LOGIN_RESULT_UNKNOWN;
    iRet = MSTATE_EXITING;
  }
 
  switch (iAuthMode)
  {
    case SSH_AUTH_KBDINT:
      if (libssh2_userauth_keyboard_interactive(session, szLogin, pResponseCallback) ) 
      {
        writeError(ERR_DEBUG_MODULE, "Keyboard-Interactive authentication failed: Host: %s User: %s Pass: %s", (*psLogin)->psServer->pHostIP, szLogin, szPassword);
        (*psLogin)->iResult = LOGIN_RESULT_FAIL;
        iRet = MSTATE_NEW;
      }
      else {
        writeError(ERR_DEBUG_MODULE, "Keyboard-Interactive authentication succeeded: Host: %s User: %s Pass: %s", (*psLogin)->psServer->pHostIP, szLogin, szPassword);
        (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
        iRet = MSTATE_EXITING;
      }
      break;
      
    case SSH_AUTH_PASSWORD:
      if (libssh2_userauth_password(session, szLogin, szPassword))
      {
        libssh2_session_last_error(session, &pErrorMsg, &iErrorMsg, 1);
        writeError(ERR_DEBUG_MODULE, "Password-based authentication failed: %s: Host: %s User: %s Pass: %s", pErrorMsg, (*psLogin)->psServer->pHostIP, szLogin, szPassword);
        (*psLogin)->iResult = LOGIN_RESULT_FAIL;
        iRet = MSTATE_RUNNING;
      }
      else
      {
        writeError(ERR_DEBUG_MODULE, "Password-based authentication succeeded: Host: %s User: %s Pass: %s", (*psLogin)->psServer->pHostIP, szLogin, szPassword);
        (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
        iRet = MSTATE_EXITING;
      }
      break;
    default:
      writeError(ERR_ERROR, "No supported authentication methods located.");
      (*psLogin)->iResult = LOGIN_RESULT_UNKNOWN;
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
    iLength = strlen(MODULE_SUMMARY_USAGE) + strlen(MODULE_VERSION) + strlen(MODULE_SUMMARY_FORMAT) + strlen(LIBSSH2_WARNING) + 1;
    *ppszSummary = (char*)malloc(iLength);
    memset(*ppszSummary, 0, iLength);
    snprintf(*ppszSummary, iLength, MODULE_SUMMARY_FORMAT_WARN, MODULE_SUMMARY_USAGE, MODULE_VERSION, LIBSSH2_WARNING);
  } 
  else 
  {
    writeError(ERR_ERROR, "%s reports an error in summaryUsage() : ppszSummary must be NULL when called", MODULE_NAME);
  }
}

void showUsage()
{
  writeVerbose(VB_NONE, "%s (%s) %s :: %s\n", MODULE_NAME, MODULE_VERSION, MODULE_AUTHOR, MODULE_SUMMARY_USAGE);
  writeVerbose(VB_NONE, "** Module was not properly built. Is libssh2 (www.libssh2.org) installed correctly? **");
  writeVerbose(VB_NONE, "");
}

int go(sLogin* logins, int argc, char *argv[])
{
  writeVerbose(VB_NONE, "%s (%s) %s :: %s\n", MODULE_NAME, MODULE_VERSION, MODULE_AUTHOR, MODULE_SUMMARY_USAGE);
  writeVerbose(VB_NONE, "** Module was not properly built. Is libssh2 (www.libssh2.org) installed correctly? **");
  writeVerbose(VB_NONE, "");
  return FAILURE;
}

#endif
