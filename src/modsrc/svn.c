/*
**   Subversion Password Checking Medusa Module
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
**   Based on code from:
**    Subversion (1.2.3):/tools/examples/minimal_client.c
**
*/

#include <sys/types.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "module.h"

#define MODULE_NAME    "svn.mod"
#define MODULE_AUTHOR  "JoMo-Kun <jmk@foofus.net>"
#define MODULE_SUMMARY_USAGE  "Brute force module for Subversion sessions"
#define MODULE_VERSION    "2.1"
#define MODULE_VERSION_SVN "$Id: svn.c 9235 2015-05-18 22:07:45Z jmk $"
#define MODULE_SUMMARY_FORMAT  "%s : version %s"
#define MODULE_SUMMARY_FORMAT_WARN  "%s : version %s (%s)"
#define LIBSVN_WARNING "No usable LIBSVN. Module disabled."

#ifdef HAVE_LIBSVN_CLIENT_1

#include "subversion-1/svn_client.h"
#include "subversion-1/svn_pools.h"
#include "subversion-1/svn_config.h"
#include "subversion-1/svn_cmdline.h"
#include "subversion-1/svn_dirent_uri.h"

#define PORT_SVN 3690

typedef struct __SVN_DATA {
  char *szURL;
  char *szBranch;
} _SVN_DATA;

/* Tells us whether we are to continue processing or not */
enum MODULE_STATE
{
  MSTATE_NEW,
  MSTATE_RUNNING,
  MSTATE_EXITING,
  MSTATE_COMPLETE
};

/* Forward declarations */
int tryLogin(sLogin** login, _SVN_DATA* _psSessionData, char* szLogin, char* szPassword);
int initModule(sLogin* login, _SVN_DATA *_psSessionData);

/* Tell medusa how many parameters this module allows */
int getParamNumber()
{
  return 0;    // we don't need no stinking parameters
}

/* Displays information about the module and how it must be used */
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
  writeVerbose(VB_NONE, "  BRANCH:? ");
  writeVerbose(VB_NONE, "    Sets URL branch to authenticate against. For example, svn://host/branch.");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "  Usage example: \"-M svn -m BRANCH:test_project\"");
  writeVerbose(VB_NONE, "");
}

// The "main" of the medusa module world - this is what gets called to actually do the work
int go(sLogin* logins, int argc, char *argv[])
{
  int i;
  char *strtok_ptr, *pOpt, *pOptTmp;
  _SVN_DATA *psSessionData;
  
  psSessionData = malloc(sizeof(_SVN_DATA));
  memset(psSessionData, 0, sizeof(_SVN_DATA));

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

      if (strcmp(pOpt, "BRANCH") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if ( pOpt )
        {
          psSessionData->szBranch = malloc(strlen(pOpt) + 1);
          memset(psSessionData->szBranch, 0, strlen(pOpt) + 1);
          strncpy((char *)psSessionData->szBranch, pOpt, strlen(pOpt));
        }
        else
          writeError(ERR_WARNING, "Method BRANCH requires value to be set.");
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

int initModule(sLogin* psLogin, _SVN_DATA *_psSessionData)
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
  params.nPort = PORT_SVN;
  initConnectionParams(psLogin, &params);

  /* set URL - branch, if not specified by user */
  if (_psSessionData->szBranch == NULL)
  {
    //_psSessionData->szBranch = malloc(6);
    //memset(_psSessionData->szBranch, 0, 6);
    //sprintf(_psSessionData->szBranch, "trunk");
    _psSessionData->szBranch = malloc(2);
    memset(_psSessionData->szBranch, 0, 2);
    sprintf(_psSessionData->szBranch, "/");
  }

  _psSessionData->szURL = malloc(strlen(psLogin->psServer->pHostIP) + log(params.nPort) + strlen(_psSessionData->szBranch) + 10);
  memset(_psSessionData->szURL, 0, strlen(psLogin->psServer->pHostIP) + log(params.nPort) + strlen(_psSessionData->szBranch) + 10);
  sprintf(_psSessionData->szURL, "svn://%s:%d/%s", psLogin->psServer->pHostIP, params.nPort, _psSessionData->szBranch);

  writeError(ERR_DEBUG_MODULE, "[%s] Set URL: %s", MODULE_NAME, _psSessionData->szURL);

  while (nState != MSTATE_COMPLETE)
  {  
    switch (nState)
    {
      case MSTATE_NEW:
        /* simply check if server exists */ 
        if (hSocket > 0)
          medusaDisconnect(hSocket);

        hSocket = medusaConnect(&params);
        if (hSocket < 0) 
        {
          writeError(ERR_NOTICE, "%s: failed to connect, port %d was not open on %s", MODULE_NAME, params.nPort, psLogin->psServer->pHostIP);
          psLogin->iResult = LOGIN_RESULT_UNKNOWN;
          return FAILURE;
        }
        
        /* close the connection since libsvn does its own thing */
        medusaDisconnect(hSocket);
        hSocket = -1;

        writeError(ERR_DEBUG_MODULE, "Connected");
        nState = MSTATE_RUNNING;

        break;
      case MSTATE_RUNNING:
        nState = tryLogin(&psLogin, _psSessionData, psCredSet->psUser->pUser, psCredSet->pPass);

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
        nState = MSTATE_COMPLETE;
        break;
      default:
        writeError(ERR_CRITICAL, "Unknown %s module state %d", MODULE_NAME, nState);
        psLogin->iResult = LOGIN_RESULT_UNKNOWN;
        return FAILURE;
    }  
  }

  FREE(_psSessionData->szURL);
  FREE(_psSessionData->szBranch);
  FREE(psCredSet);
  
  return SUCCESS;
}

/* Module Specific Functions */

static svn_error_t * svn_prompt_callback (svn_auth_cred_simple_t **cred, void *baton __attribute__((unused)), const char *realm __attribute__((unused)),
                                          const char *username __attribute__((unused)), svn_boolean_t may_save __attribute__((unused)), apr_pool_t *pool)
{
  svn_auth_cred_simple_t *ret = apr_pcalloc (pool, sizeof (*ret));
  *cred = ret;
  return SVN_NO_ERROR;
}

static svn_error_t * print_dirent(void *baton __attribute__((unused)),
             const char *path __attribute__((unused)),
             const svn_dirent_t *dirent __attribute__((unused)),
             const svn_lock_t *lock __attribute__((unused)),
             const char *abs_path __attribute__((unused)),
             const char *external_parent_url __attribute__((unused)),
             const char *external_target __attribute__((unused)),
             apr_pool_t *pool __attribute__((unused)))
{
  return SVN_NO_ERROR;
}

int tryLogin(sLogin** psLogin, _SVN_DATA* _psSessionData, char* szLogin, char* szPassword)
{
  int iRet;
  apr_pool_t *pool;
  svn_error_t *err;
  svn_opt_revision_t revision;
  svn_client_ctx_t *ctx;
  const char *canonical;

  /* Initialize the application. Send all error messages to 'stderr'. */
  if (svn_cmdline_init("MEDUSA", stderr) != EXIT_SUCCESS)
  {
    writeError(ERR_ERROR, "[%s] LIBSVN svn_cmdline_init() Function Failed.", MODULE_NAME);
    return(FAILURE);
  }

  /* Create top-level memory pool. -- must this be thread-safe??? */
  pool = svn_pool_create(NULL);

  /* Initialize and allocate the client_ctx object. */
#ifdef HAVE_SVN_CLIENT_LIST3
  if ((err = svn_client_create_context2(&ctx, NULL, pool)))
#else
  if ((err = svn_client_create_context (&ctx, pool)))
#endif
  {
    writeError(ERR_ERROR, "[%s] LIBSVN svn_client_create_context() Function Failed.", MODULE_NAME);
    //svn_handle_error2 (err, stderr, FALSE, "MEDUSA: ");
    return(FAILURE);
  }

  svn_auth_provider_object_t *provider;
  apr_array_header_t *providers = apr_array_make(pool, 1, sizeof (svn_auth_provider_object_t *));

  /* Set callback to not retry authentication */
  svn_auth_get_simple_prompt_provider(&provider, svn_prompt_callback, NULL, 0, pool);
  APR_ARRAY_PUSH (providers, svn_auth_provider_object_t *) = provider;

  /* Register the auth-providers into the context's auth_baton. */
  svn_auth_open (&ctx->auth_baton, providers, pool);

  /* Set logon credentials using the auth_baton's run-time parameter hash */
  svn_auth_set_parameter(ctx->auth_baton, SVN_AUTH_PARAM_DEFAULT_USERNAME, szLogin);
  svn_auth_set_parameter(ctx->auth_baton, SVN_AUTH_PARAM_DEFAULT_PASSWORD, szPassword);

  /* Set revision to be the HEAD revision. */
  revision.kind = svn_opt_revision_head;

  /* Main call into libsvn_client does all the work. */
#ifdef HAVE_SVN_CLIENT_LIST3
  canonical = svn_uri_canonicalize(_psSessionData->szURL, pool);
  writeError(ERR_DEBUG_MODULE, "[%s] Canonicalized URL: %s", MODULE_NAME, canonical);
  err = svn_client_list3(canonical, &revision, &revision, svn_depth_empty, SVN_DIRENT_ALL, FALSE, FALSE, print_dirent, &ctx->auth_baton, ctx, pool);
#else
  err = svn_client_list2(_psSessionData->szURL, &revision, &revision, svn_depth_empty, SVN_DIRENT_ALL, FALSE, NULL, &ctx->auth_baton, ctx, pool);
#endif

  if ((err !=NULL) && err->apr_err == 170001)
  {
    if (strstr(err->message, "Username not found"))
    {
      writeError(ERR_ERROR, "[%s] The following SVN user does not appear to exist: %s", MODULE_NAME, szLogin);
      (*psLogin)->iResult = LOGIN_RESULT_ERROR;
      iRet = MSTATE_EXITING;
    }
    else if (strstr(err->message, "Password incorrect"))
    {
      writeError(ERR_DEBUG_MODULE, "[%s] Login attempt failed.", MODULE_NAME);
      (*psLogin)->iResult = LOGIN_RESULT_FAIL;
      iRet = MSTATE_NEW;
    }
    else
    {
      writeError(ERR_DEBUG_MODULE, "[%s] Access refused. Unknown error: %s", MODULE_NAME, err->message);
      (*psLogin)->iResult = LOGIN_RESULT_FAIL;
      iRet = MSTATE_NEW;
    }
  }
  else if (err != NULL)
  {
    writeError(ERR_ERROR, "[%s] Authentication Error (%d): %s.", MODULE_NAME, err->apr_err, err->message);
    (*psLogin)->iResult = LOGIN_RESULT_ERROR;
    iRet = MSTATE_EXITING;
  }
  else
  {
    writeError(ERR_DEBUG_MODULE, "%s : Login attempt successful.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
    iRet = MSTATE_EXITING;
  }
  
  setPassResult((*psLogin), szPassword);

  svn_pool_clear(pool);
  svn_pool_destroy(pool);
  
  return(iRet);
}

#else

void summaryUsage(char **ppszSummary)
{
  // Memory for ppszSummary will be allocated here - caller is responsible for freeing it
  int  iLength = 0;


  if (*ppszSummary == NULL)
  {
    iLength = strlen(MODULE_SUMMARY_USAGE) + strlen(MODULE_VERSION) + strlen(MODULE_SUMMARY_FORMAT) + strlen(LIBSVN_WARNING) + 1;
    *ppszSummary = (char*)malloc(iLength);
    memset(*ppszSummary, 0, iLength);
    snprintf(*ppszSummary, iLength, MODULE_SUMMARY_FORMAT_WARN, MODULE_SUMMARY_USAGE, MODULE_VERSION, LIBSVN_WARNING);
  }
  else
  {
    writeError(ERR_ERROR, "%s reports an error in summaryUsage() : ppszSummary must be NULL when called", MODULE_NAME);
  }
}

void showUsage()
{
  writeVerbose(VB_NONE, "%s (%s) %s :: %s\n", MODULE_NAME, MODULE_VERSION, MODULE_AUTHOR, MODULE_SUMMARY_USAGE);
  writeVerbose(VB_NONE, "** Module was not properly built. Is LIBSVN installed correctly? **");
  writeVerbose(VB_NONE, "");
}

int go(sLogin* logins, int argc, char *argv[])
{
  writeVerbose(VB_NONE, "%s (%s) %s :: %s\n", MODULE_NAME, MODULE_VERSION, MODULE_AUTHOR, MODULE_SUMMARY_USAGE);
  writeVerbose(VB_NONE, "** Module was not properly built. Is LIBSVN installed correctly? **");
  writeVerbose(VB_NONE, "");
  return FAILURE;
}

#endif
