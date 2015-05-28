/*
**   Generic Wrapper Medusa Module
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

#define MODULE_NAME    "wrapper.mod"
#define MODULE_AUTHOR  "JoMo-Kun <jmk@foofus.net>"
#define MODULE_SUMMARY_USAGE  "Generic Wrapper Module"
#define MODULE_VERSION    "2.0"
#define MODULE_VERSION_SVN "$Id: wrapper.c 9217 2015-05-07 18:07:03Z jmk $"
#define MODULE_SUMMARY_FORMAT  "%s : version %s"
#define MODULE_SUMMARY_FORMAT_WARN  "%s : version %s (%s)"

#define PARENT_READ   iReadPipe[0]
#define CHILD_WRITE   iReadPipe[1]
#define CHILD_READ    iWritePipe[0]
#define PARENT_WRITE  iWritePipe[1]

#define TYPE_SINGLE 1
#define TYPE_STDIN 2

typedef struct __MODULE_DATA {
  char *szCmd;
  char *szCmdFull;
  char *szCmdParam;
  char *szCmdParamFull;
  int iReadPipe[2];
  int iWritePipe[2];
  int nType;
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
int tryLogin(_MODULE_DATA* _psSessionData, sLogin** login, char* szPassword);
int initModule(_MODULE_DATA* _psSessionData, sLogin* login);
int initProcess(_MODULE_DATA* _psSessionData);
int closeProcess(_MODULE_DATA* _psSessionData);

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
  writeVerbose(VB_NONE, "  TYPE:? (SINGLE, STDIN)");
  writeVerbose(VB_NONE, "    Option sets type of script being called by module. See included sample scripts");
  writeVerbose(VB_NONE, "    for ideas how to use this module.");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "    SINGLE: Script expects all user input comes from original command line.");
  writeVerbose(VB_NONE, "    STDIN:  Host and user information passed to script via command line.");
  writeVerbose(VB_NONE, "            Passwords to test are passed via STDIN to script.");
  writeVerbose(VB_NONE, " ");
  writeVerbose(VB_NONE, "  PROG:? ");
  writeVerbose(VB_NONE, "    Option for setting path to executable file.");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "  ARGS:? ");
  writeVerbose(VB_NONE, "    Option for setting executable parameters. The following substitutions can be used:");
  writeVerbose(VB_NONE, "    %H:  Replaced with target IP address.");
  writeVerbose(VB_NONE, "    %U:  Replaced with username to test.");
  writeVerbose(VB_NONE, "    %P:  Replaced with password to test.");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "Usage example: \'-M wrapper -m TYPE:SINGLE -m PROG:./foo.pl -m ARGS:\"-h %H -u %U -p %P\"\'");
  writeVerbose(VB_NONE, "Usage example: \'-M wrapper -m TYPE:STDIN  -m PROG:./bar.pl -m ARGS:\"--host %H --user %U\"\'");
}

// The "main" of the medusa module world - this is what gets called to actually do the work
int go(sLogin* logins, int argc, char *argv[])
{
  int i, iRet;
  char *strtok_ptr, *pOpt, *pOptTmp;
  _MODULE_DATA *psSessionData;
  psSessionData = malloc(sizeof(_MODULE_DATA));
  memset(psSessionData, 0, sizeof(_MODULE_DATA));

  if ((argc < 0) || (argc > 3))
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

      if (strcmp(pOpt, "TYPE") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if (pOpt == NULL)
          writeError(ERR_WARNING, "Method TYPE requires value to be set.");
        else if (strcmp(pOpt, "SINGLE") == 0)
          psSessionData->nType = TYPE_SINGLE;
        else if (strcmp(pOpt, "STDIN") == 0)
          psSessionData->nType = TYPE_STDIN;
        else
          writeError(ERR_WARNING, "Invalid value for method TYPE.");
      }
      else if (strcmp(pOpt, "PROG") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if ( pOpt )
        {
          psSessionData->szCmd = malloc(strlen(pOpt) + 1);
          memset(psSessionData->szCmd, 0, strlen(pOpt) + 1);
          strncpy((char *)psSessionData->szCmd, pOpt, strlen(pOpt) + 1);
        }
        else
          writeError(ERR_WARNING, "Method PROG requires value to be set.");
      }
      else if (strcmp(pOpt, "ARGS") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if ( pOpt )
        {
          psSessionData->szCmdParam = malloc(strlen(pOpt) + 1);
          memset(psSessionData->szCmdParam, 0, strlen(pOpt) + 1);
          strncpy((char *)psSessionData->szCmdParam, pOpt, strlen(pOpt) + 1);
        }
        else
          writeError(ERR_WARNING, "Method ARGS requires value to be set.");
      }
      else
      {
        writeError(ERR_WARNING, "Invalid method: %s.", pOpt);
      }
      
      free(pOptTmp);
    }
 
    initModule(psSessionData, logins);
    iRet = SUCCESS;
  }

  FREE(psSessionData);
  return iRet;
}

int initModule(_MODULE_DATA *_psSessionData, sLogin* psLogin)
{
  enum MODULE_STATE nState = MSTATE_NEW;
  char *szTmp = NULL;
  char *szCmdTmp = NULL;
  int iRet, nCmdLength;
  int64_t nCmdPartLength;
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

  while (nState != MSTATE_COMPLETE)
  {  
    switch (nState)
    {
      case MSTATE_NEW:
        /* perform parameter substitution -- this is messy... */
        writeError(ERR_DEBUG_MODULE, "User-supplied parameters: %s", _psSessionData->szCmdParam);

        /* --host %H --user %U --pass %P */
        if (_psSessionData->nType == TYPE_SINGLE)
        {
          nCmdLength = strlen(_psSessionData->szCmdParam);
          nCmdLength -= 6;
          nCmdLength += strlen(psLogin->psServer->pHostIP);
          nCmdLength += strlen(psCredSet->psUser->pUser);
          nCmdLength += strlen(psCredSet->pPass);
        }
        /* --host %H --user %U */
        else
        {
          nCmdLength = strlen(_psSessionData->szCmdParam);
          nCmdLength -= 4;
          nCmdLength += strlen(psLogin->psServer->pHostIP);
          nCmdLength += strlen(psCredSet->psUser->pUser);
        }
       
        /* adding in 6 characters to temporarily account for %H %U %P values - needed if 
           username/password are shorter than 2 characters each */
        _psSessionData->szCmdParamFull = malloc(nCmdLength + 6 + 1);
        memset(_psSessionData->szCmdParamFull, 0, nCmdLength + 6 + 1);
        szCmdTmp = malloc(nCmdLength + 6 + 1);
        memset(szCmdTmp, 0, nCmdLength + 6 + 1);
       
        if ((szTmp = strstr(_psSessionData->szCmdParam, "%H")) != NULL)
        {
          nCmdPartLength = (int64_t) szTmp - (int64_t) _psSessionData->szCmdParam;
          writeError(ERR_DEBUG_MODULE, "Processing \%H... Copying (%d) parameter characters.", nCmdPartLength);
          strncpy(szCmdTmp, _psSessionData->szCmdParam, nCmdPartLength); 
          strncpy(szCmdTmp + nCmdPartLength, psLogin->psServer->pHostIP, strlen(psLogin->psServer->pHostIP)); 
          strncpy(szCmdTmp + nCmdPartLength + strlen(psLogin->psServer->pHostIP), szTmp + 2, strlen(szTmp) - 2);
        }
        else
        {
          writeError(ERR_ERROR, "Invalid command parameter format. Missing %H format.");            
          psLogin->iResult = LOGIN_RESULT_UNKNOWN;
          FREE(szCmdTmp);
          nState = MSTATE_EXITING;
          break;
        }
        
        writeError(ERR_DEBUG_MODULE, "Parameters (pass 1): %s", szCmdTmp);
        
        if ((szTmp = strstr(szCmdTmp, "%U")) != NULL)
        {
          nCmdPartLength = (int64_t) szTmp - (int64_t) szCmdTmp;
          writeError(ERR_DEBUG_MODULE, "Processing \%U... Copying (%d) parameter characters.", nCmdPartLength);
          strncpy(_psSessionData->szCmdParamFull, szCmdTmp, nCmdPartLength); 
          strncpy(_psSessionData->szCmdParamFull + nCmdPartLength, psCredSet->psUser->pUser, strlen(psCredSet->psUser->pUser)); 
          strncpy(_psSessionData->szCmdParamFull + nCmdPartLength + strlen(psCredSet->psUser->pUser), szTmp + 2, strlen(szTmp) - 2); 
        }
        else
        {
          writeError(ERR_ERROR, "Invalid command parameter format. Missing %U format.");
          psLogin->iResult = LOGIN_RESULT_UNKNOWN;
          nState = MSTATE_EXITING;
          FREE(szCmdTmp);
          break;
        }

        writeError(ERR_DEBUG_MODULE, "Parameters (pass 2): %s", _psSessionData->szCmdParamFull);

        if ((_psSessionData->nType == TYPE_SINGLE) && (szTmp = strstr(_psSessionData->szCmdParamFull, "%P")))
        {
          nCmdPartLength = (int64_t) szTmp - (int64_t) _psSessionData->szCmdParamFull;
          writeError(ERR_DEBUG_MODULE, "Processing \%P... Copying (%d) parameter characters.", nCmdPartLength);
          strncpy(szCmdTmp, _psSessionData->szCmdParamFull, nCmdPartLength); 
          strncpy(szCmdTmp + nCmdPartLength, psCredSet->pPass, strlen(psCredSet->pPass)); 
          strncpy(szCmdTmp + nCmdPartLength + strlen(psCredSet->pPass), szTmp + 2, strlen(szTmp) - 2); 

          strncpy(_psSessionData->szCmdParamFull, szCmdTmp, nCmdLength + 1);
        }
        else if (_psSessionData->nType == TYPE_SINGLE)
        {
          writeError(ERR_ERROR, "Invalid command parameter format. Missing %P format.");
          psLogin->iResult = LOGIN_RESULT_UNKNOWN;
          nState = MSTATE_EXITING;
          FREE(szCmdTmp);
          break;
        }

        /* clean-up any extra characters left over from %H %U %P */
        memset(_psSessionData->szCmdParamFull + nCmdLength, 0, 6 + 1);

        FREE(szCmdTmp);
        writeError(ERR_DEBUG_MODULE, "Parameters (pass 3): %s", _psSessionData->szCmdParamFull);
        
        _psSessionData->szCmdFull = malloc(strlen(_psSessionData->szCmd) + strlen(_psSessionData->szCmdParamFull) + 7);
        memset(_psSessionData->szCmdFull, 0, strlen(_psSessionData->szCmd) + strlen(_psSessionData->szCmdParamFull) + 7);
        strncpy(_psSessionData->szCmdFull, _psSessionData->szCmd, strlen(_psSessionData->szCmd));
        strncat(_psSessionData->szCmdFull, " ", 1);
        strncat(_psSessionData->szCmdFull, _psSessionData->szCmdParamFull, strlen(_psSessionData->szCmdParamFull));
        strncat(_psSessionData->szCmdFull, " 1>&2", 5);
        
        writeError(ERR_DEBUG_MODULE, "Command line: %s", _psSessionData->szCmdFull);
        /* end command-line argument parsing */

        iRet = initProcess(_psSessionData);
        if (iRet == FAILURE)
        {
          writeError(ERR_ERROR, "[%s] Failed to initialize process.", MODULE_NAME);
          nState = MSTATE_EXITING;
        } 
        else 
          nState = MSTATE_RUNNING;

        break;
      case MSTATE_RUNNING:
        nState = tryLogin(_psSessionData, &psLogin, psCredSet->pPass);

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
        iRet = closeProcess(_psSessionData);
        nState = MSTATE_COMPLETE;
        break;
      default:
        writeError(ERR_CRITICAL, "Unknown %s module state %d", MODULE_NAME, nState);
        psLogin->iResult = LOGIN_RESULT_UNKNOWN;
        return FAILURE;
    }  
  }
 
  closeProcess(_psSessionData);

  /* clean up memory */
  FREE(_psSessionData->szCmd);
  FREE(_psSessionData->szCmdFull);
  FREE(_psSessionData->szCmdParam);
  FREE(_psSessionData->szCmdParamFull);
  FREE(psCredSet);
 
  return SUCCESS;
}

/* Module Specific Functions */
int initProcess(_MODULE_DATA* _psSessionData)
{
  pid_t fork_result;

  if ((pipe(_psSessionData->iReadPipe) == 0) && (pipe(_psSessionData->iWritePipe) == 0)) {
    fork_result = fork();
    if (fork_result == (pid_t)-1) {
      writeError(ERR_ERROR, "Failed to fork management process.");            
      return(FAILURE);
    }
    
    if (fork_result == (pid_t)0) {
      writeError(ERR_DEBUG_MODULE, "Child process sucessfully forked");            
  
      /* connect parent pipes */
      close(_psSessionData->PARENT_WRITE);
      close(_psSessionData->PARENT_READ);
      
      /* connect pipes to STDIN/STDOUT */
      if (dup2(_psSessionData->CHILD_READ, STDIN_FILENO) < 0)
      {
        writeError(ERR_ERROR, "dup2() Mapping pipe to child's STDIN failed.");            
        exit(EXIT_FAILURE);
      }

      if (dup2(_psSessionData->CHILD_WRITE, STDERR_FILENO) < 0)
      {
        writeError(ERR_ERROR, "dup2() Mapping pipe to child's STDOUT failed.");            
        exit(EXIT_FAILURE);
      }

      if (dup2(_psSessionData->CHILD_WRITE, STDOUT_FILENO) < 0)
      {
        writeError(ERR_ERROR, "dup2() Mapping pipe to child's STDOUT failed.");            
        exit(EXIT_FAILURE);
      }

      /*
        STDOUT issue: STDOUT is buffered, while STDERR is not. The child process
        doesn't send any of its STDOUT down the pipe until it terminates. How
        does one get rid of this buffering? The following doesn't seem to work
        like one would think it should:
        
        setlinebuf(stdout);

        writeError() below does not function since STDOUT is directed through the pipe.
        No real way to tell the user that the child failed...
      */
      
      /* close old pipes */
      close(_psSessionData->CHILD_READ);
      close(_psSessionData->CHILD_WRITE);

      /* check if file exists */
      if ((fopen(_psSessionData->szCmd, "r")) == NULL)
      {
        //writeError(ERR_DEBUG_MODULE, "Failed to open file %s - %s", _psSessionData->szCmd, strerror( errno ) );
        fprintf(stderr, "LOGIN_CHILD_FILE_ERROR\n");
      }
      else
      {
        /* launch application */
        //execlp(_psSessionData->szCmd, _psSessionData->szCmd, _psSessionData->szCmdParamFull, (char *)0);
        if (system(_psSessionData->szCmdFull) < 0)
          writeError(ERR_ERROR, "[%s] system() call return error", MODULE_NAME);            
      }
     
      /* give the parent a chance to read the error message */
      sleep(5);

      exit(0);
    }
    else {
      writeError(ERR_DEBUG_MODULE, "Parent process sucessfully forked");            
      
      /* connect child pipes */
      close(_psSessionData->CHILD_WRITE);
      close(_psSessionData->CHILD_READ);
    }
  }
  else
  {
    writeError(ERR_FATAL, "Failed to create communication pipes.");            
  }
  
  return(SUCCESS);
}

int closeProcess(_MODULE_DATA* _psSessionData)
{
  writeError(ERR_DEBUG_MODULE, "Parent process completed. Closing communication pipes.");

  close(_psSessionData->PARENT_WRITE);
  close(_psSessionData->PARENT_READ);

  return SUCCESS;
}

int tryLogin(_MODULE_DATA* _psSessionData, sLogin** psLogin, char* szPassword)
{
  int iRet, iDataProcessed;
  int nDone = 0;
  char buffer[BUFSIZ + 1];
  char *bufSend;
  char *strtok_ptr, *pBuf, *pBufTmp;

  if (_psSessionData->nType == TYPE_STDIN)
  {
    bufSend = malloc(strlen(szPassword) + 2);
    memset(bufSend, 0, strlen(szPassword) + 2);
    sprintf(bufSend, "%s\n", szPassword);
    iDataProcessed = write(_psSessionData->PARENT_WRITE, bufSend, strlen(bufSend));
    writeError(ERR_DEBUG_MODULE, "Sending account login credentials to child process: %s (%d)", bufSend, iDataProcessed);

    if (iDataProcessed < 0)
    {
      writeError(ERR_ERROR, "Error writing to child process buffer.");
      (*psLogin)->iResult = LOGIN_RESULT_ERROR;
      iRet = MSTATE_EXITING;
      nDone = 1;
    }
  }

  writeError(ERR_DEBUG_MODULE, "Reading data from child process.");
  while (!nDone)
  {
    iDataProcessed = read(_psSessionData->PARENT_READ, buffer, BUFSIZ);

    if (iDataProcessed <= 0)
    {
      writeError(ERR_ERROR, "Error reading from child process buffer.");
      (*psLogin)->iResult = LOGIN_RESULT_ERROR;
      iRet = MSTATE_EXITING;
      nDone = 1;
    }
    else
    {
      writeError(ERR_DEBUG_MODULE, "Processing child process buffer.");
      
      if (strstr(buffer, "LOGIN_RESULT_FAIL"))
      {
        writeError(ERR_DEBUG_MODULE, "Child process responded with: LOGIN_RESULT_FAIL.");
        (*psLogin)->iResult = LOGIN_RESULT_FAIL;
      
        if (_psSessionData->nType == TYPE_STDIN)
          iRet = MSTATE_RUNNING;
        else
          iRet = MSTATE_NEW;
      
        nDone = 1;
      }
      else if (strstr(buffer, "LOGIN_RESULT_SUCCESS"))
      {
        writeError(ERR_DEBUG_MODULE, "Child process responded with: LOGIN_RESULT_SUCCESS.");
        (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
        iRet = MSTATE_EXITING;
        nDone = 1;
      }
      else if (strstr(buffer, "LOGIN_RESULT_ERROR"))
      {
        /* Allow simple error messages to be passed back to Medusa */
        pBufTmp = malloc( sizeof(buffer) );
        memset(pBufTmp, 0, sizeof(buffer));
        strncpy(pBufTmp, buffer, sizeof(buffer));
        pBuf = strtok_r(pBufTmp, ":", &strtok_ptr);
        pBuf = strtok_r(NULL, "\n", &strtok_ptr);
        writeError(ERR_ERROR, "Child process responded with: LOGIN_RESULT_ERROR (%s).", pBuf);
        FREE(pBufTmp);
        
        (*psLogin)->iResult = LOGIN_RESULT_ERROR;
        iRet = MSTATE_EXITING;
        nDone = 1;
      }
      else if (strstr(buffer, "LOGIN_CHILD_FILE_ERROR"))
      {
        writeError(ERR_ERROR, "Child process failed to execute file: %s", _psSessionData->szCmd);
        (*psLogin)->iResult = LOGIN_RESULT_ERROR;
        iRet = MSTATE_EXITING;
        nDone = 1;
      }
      else
      {
        writeError(ERR_DEBUG_MODULE, "Child process: %s", buffer);
      }
    }
  }
 
  setPassResult((*psLogin), szPassword);
  return(iRet);
}
