/***************************************************************************
 *   telnet.c                                                              *
 *   Copyright (C) 2009 by fizzgig                                         *
 *   fizzgig@foofus.net                                                    *
 *                                                                         *
 *   Implementation of a telnet brute force module for                     *
 *   medusa. Module concept by the one-and-only Foofus.                    *
 *   Protocol stuff based on the original hydra telnet code by             *
 *   VanHauser and the good folks at thc (vh@thc.org)                      *
 *                                                                         *
 *                                                                         *
 *   CHANGE LOG                                                            *
 *   04/05/2005 - Created by fizzgig (fizzgig@foofus.net)                  *
 *   All other changes are in the Subversion comments                      *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License version 2,       *
 *   as published by the Free Software Foundation                          *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   http://www.gnu.org/licenses/gpl.txt                                   *
 *                                                                         *
 *   This program is released under the GPL with the additional exemption  *
 *   that compiling, linking, and/or using OpenSSL is allowed.             *
 *                                                                         *
 *   Tested on so far:                                                     *
 *       Jetdirect cards (woo!)                                            *
 *       HP switches using basic auth                                      *
 *       Cisco switches using vty auth                                     *
 *                                                                         *
 *    Support for hosts w/o username prompt added by pMonkey/JoMo-Kun      *
 *                                                                         *
 ***************************************************************************/

#include <sys/types.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/telnet.h>
#include "module.h"

#define MODULE_NAME    "telnet.mod"
#define MODULE_AUTHOR  "fizzgig <fizzgig@foofus.net>"
#define MODULE_SUMMARY_USAGE  "Brute force module for telnet sessions"
#define MODULE_VERSION    "2.0"
#define MODULE_VERSION_SVN "$Id: telnet.c 9217 2015-05-07 18:07:03Z jmk $"
#define MODULE_SUMMARY_FORMAT  "%s : version %s"

#define PORT_TELNET 23
#define PORT_TELNETS 992

#define PROMPT_UNKNOWN 0
#define PROMPT_LOGIN_PASSWORD 1
#define PROMPT_PASSWORD 2

#define RECEIVE_DELAY_1 20 * 1000000
#define RECEIVE_DELAY_2 0.5 * 1000000

#define MODE_NORMAL 0
#define MODE_AS400 1

typedef struct __MODULE_DATA {
  int nMode;
} _MODULE_DATA;

const unsigned int BUFFER_SIZE = 300;
const char* KNOWN_PROMPTS = ">#$%/?";  // Each character represents a known telnet prompt - feel free to add a new one if desired

const int KNOWN_PWD_SIZE = 4;  // Make sure to keep this in sync with the size of the array below!!
const char* KNOWN_PWD_PROMPTS[] = { "assword", "asscode", "ennwort", "ASSWORD" };  // Complete/partial lines that indicate a password request

const int KNOWN_LOGIN_SIZE = 3;  // Make sure to keep this in sync with the size of the array below!!
const char* KNOWN_LOGIN_PROMPTS[] = { "login:", "sername:", "User" }; // Complete/partial lines that request a user name

// Tells us whether we are to continue processing or not
enum MODULE_STATE
{
  MSTATE_NEW,
  MSTATE_RUNNING,
  MSTATE_EXITING,
  MSTATE_COMPLETE
};

// Forward declarations
int tryLogin(int hSocket, sLogin** login, _MODULE_DATA* _psSessionData, char* szLogin, char* szPassword, int nFoundPrompt);
int tryLoginAS400(int hSocket, sLogin** login, char* szLogin, char* szPassword);
int initModule(sLogin* login, _MODULE_DATA* _psSessionData);
int processIAClogout(int hSocket, _MODULE_DATA* _psSessionData);
void processIAC(int hSocket, _MODULE_DATA* _psSessionData, unsigned char** buffer, int* nBufferSize);

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
  writeVerbose(VB_NONE, "  MODE:? (NORMAL, AS400) [optional]");
  writeVerbose(VB_NONE, "    Sets the mode for error detection.");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "  Usage example: \"-M telnet -m MODE:AS400 -U accounts.txt -p password\"");
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
        else if (strcmp(pOpt, "AS400") == 0)
          psSessionData->nMode = MODE_AS400;
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

int initModule(sLogin* _psLogin, _MODULE_DATA *_psSessionData)
{
  int hSocket = -1;
  enum MODULE_STATE nState = MSTATE_NEW;
  unsigned char* bufReceive;
  int nReceiveBufferSize = 0, nFoundPrompt = PROMPT_UNKNOWN;
  int i = 0;
  sCredentialSet *psCredSet = NULL;
  sConnectParams params;

  psCredSet = malloc( sizeof(sCredentialSet) );
  memset(psCredSet, 0, sizeof(sCredentialSet));

  if (getNextCredSet(_psLogin, psCredSet) == FAILURE)
  {
    writeError(ERR_ERROR, "[%s] Error retrieving next credential set to test.", MODULE_NAME);
    nState = MSTATE_COMPLETE;
  }
  else if (psCredSet->psUser)
  {
    writeError(ERR_DEBUG_MODULE, "[%s] module started for host: %s user: %s", MODULE_NAME, _psLogin->psServer->pHostIP, psCredSet->psUser->pUser);
  }
  else
  {
    writeError(ERR_DEBUG_MODULE, "[%s] module started for host: %s - no more available users to test.", MODULE_NAME);
    nState = MSTATE_COMPLETE;
  }

  memset(&params, 0, sizeof(sConnectParams));
  if (_psLogin->psServer->psAudit->iPortOverride > 0)
    params.nPort = _psLogin->psServer->psAudit->iPortOverride;
  else if (_psLogin->psServer->psHost->iUseSSL > 0)
    params.nPort = PORT_TELNETS;
  else
    params.nPort = PORT_TELNET;
  initConnectionParams(_psLogin, &params);

  while (nState != MSTATE_COMPLETE)
  {
    switch (nState)
    {
    case MSTATE_NEW:
      // Already have an open socket - close it
      if (hSocket > 0)
        medusaDisconnect(hSocket);

      if (_psLogin->psServer->psHost->iUseSSL > 0)
        hSocket = medusaConnectSSL(&params);
      else 
        hSocket = medusaConnect(&params);
      
      if (hSocket <= 0)
      {
        writeError(ERR_ERROR, "[%s] Failed to connect, port %d was not open on %s", MODULE_NAME, params.nPort, _psLogin->psServer->pHostIP);
        _psLogin->iResult = LOGIN_RESULT_UNKNOWN;
        setPassResult(_psLogin, psCredSet->pPass);
        return FAILURE;
      }

      writeError(ERR_DEBUG_MODULE, "Connected");

      // Examine the first line returned
      nReceiveBufferSize = 0;
      bufReceive = medusaReceiveLineDelay(hSocket, &nReceiveBufferSize, RECEIVE_DELAY_1, RECEIVE_DELAY_2);
      if (bufReceive == NULL)
        return FAILURE;

      bufReceive[nReceiveBufferSize] = 0;  // Make certain buffer is null-terminated

      if (bufReceive == NULL)
      {
        writeError(ERR_ERROR, "[%s] null response was unexpected from a telnet server (is one running?)", MODULE_NAME);
        _psLogin->iResult = LOGIN_RESULT_UNKNOWN;
        setPassResult(_psLogin, psCredSet->pPass);
        return FAILURE;
      }

      // Telnet protocol negotiation
      do
      {
        nFoundPrompt = PROMPT_UNKNOWN;
        processIAC(hSocket, _psSessionData, &bufReceive, &nReceiveBufferSize);

        if (bufReceive != NULL && bufReceive[0] != 0 && (unsigned char)bufReceive[0] != IAC)
          makeToLower((char *)bufReceive);

        if (bufReceive != NULL)
        {
          writeError(ERR_DEBUG_MODULE, "Looking for login prompts");

          if (_psSessionData->nMode == MODE_AS400)
          {
            if (strcasestr((char *)bufReceive, (char *)"Sign On") != '\0')
            {
              writeError(ERR_INFO, "[%s] Detected AS/400 Sign On Screen.", MODULE_NAME);
              nFoundPrompt = PROMPT_LOGIN_PASSWORD;
              
              FREE(bufReceive);
              if (medusaDataReadyTimed(hSocket, 0, 20000) > 0)
              {
                // More data waiting
                bufReceive = medusaReceiveLineDelay(hSocket, &nReceiveBufferSize, RECEIVE_DELAY_1, RECEIVE_DELAY_2);
                if (bufReceive != NULL)
                  bufReceive[nReceiveBufferSize] = 0;  // Make certain buffer is null-terminated
              }
 
              break;
            }

            /*
            Sign On
            System  . . . . . :   TSTDBS16
            Subsystem . . . . :   QINTER
            Display . . . . . :   QPADEV0001
            */
          }
          else
          {
            // Look for known login prompts
            for (i = 0; i < KNOWN_LOGIN_SIZE; i++)
            {
              if (strcasestr((char *)bufReceive, KNOWN_LOGIN_PROMPTS[i]) != '\0')
              {
                // Do we have a prompt?
                writeError(ERR_DEBUG_MODULE, "Found login prompt...");
                nFoundPrompt = PROMPT_LOGIN_PASSWORD;
                break;
              }
            }
          
            /* Some systems do not provide a login prompt and go right to password */
            for (i = 0; i < KNOWN_PWD_SIZE; i++)
            {
              if (strcasestr((char *)bufReceive, KNOWN_PWD_PROMPTS[i]) != '\0')
              {
                // Do we have a prompt?
                writeError(ERR_DEBUG_MODULE, "Found a password prompt already...");
                nFoundPrompt = PROMPT_PASSWORD;
                
                if (_psLogin->psServer->iLoginsDone < 1 && _psLogin->iId == 0)
                  writeVerbose(VB_NONE_FILE, "Password Prompt Only: %s\n", _psLogin->psServer->pHostIP);
                
                break;
              }
            }
          
            if (nFoundPrompt == PROMPT_UNKNOWN)
            {
              FREE(bufReceive);
              if (medusaDataReadyTimed(hSocket, 0, 20000) > 0)
              {
                // More data waiting
                bufReceive = medusaReceiveLineDelay(hSocket, &nReceiveBufferSize, RECEIVE_DELAY_1, RECEIVE_DELAY_2);
                if (bufReceive != NULL)
                  bufReceive[nReceiveBufferSize] = 0;  // Make certain buffer is null-terminated
              } 
            }
          }
        }
      }
      while (bufReceive != NULL && (unsigned char)bufReceive[0] == IAC && nFoundPrompt == PROMPT_UNKNOWN);

      FREE(bufReceive);

      if (nFoundPrompt == PROMPT_UNKNOWN)
      {
        writeError(ERR_ERROR, "[%s] Failed to identify logon prompt.", MODULE_NAME); 
        _psLogin->iResult = LOGIN_RESULT_UNKNOWN;
        setPassResult(_psLogin, psCredSet->pPass);
        return FAILURE;
      }
      else
        nState = MSTATE_RUNNING;
      
      break;

    case MSTATE_RUNNING:
      if (_psSessionData->nMode == MODE_AS400)
        nState = tryLoginAS400(hSocket, &_psLogin, psCredSet->psUser->pUser, psCredSet->pPass);
      else
        nState = tryLogin(hSocket, &_psLogin, _psSessionData, psCredSet->psUser->pUser, psCredSet->pPass, nFoundPrompt);

      if (_psLogin->iResult != LOGIN_RESULT_UNKNOWN) 
      {
        if (processIAClogout(hSocket, _psSessionData) == FAILURE)
        {
          writeError(ERR_ERROR, "[%s] Failed to close existing Telnet session.", MODULE_NAME);
        }
        medusaDisconnect(hSocket);
        hSocket = -1;
        
        /*
          Cisco devices appear to keep sessions open for a brief time after we terminate 
          the connection. They also seem to ignore "IAC DO LOGOUT" commands. Adding a 
          sleep() hack here, to give them some time to clean-up. 
        */
        sleep(3);

        if (getNextCredSet(_psLogin, psCredSet) == FAILURE)
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
      writeError(ERR_CRITICAL, "Unknown %s module (%d) state %d host: %s", MODULE_NAME, _psLogin->iId, nState, _psLogin->psServer->pHostIP);
      _psLogin->iResult = LOGIN_RESULT_UNKNOWN;
    }
  }

  FREE(psCredSet);
  return SUCCESS;
}

int tryLogin(int hSocket, sLogin** login, _MODULE_DATA* _psSessionData, char* szLogin, char* szPassword, int nFoundPrompt)
{
  // This function should return MSTATE_RUNNING to continue or MSTATE_EXITING to terminate the module
  unsigned char bufSend[BUFFER_SIZE];
  unsigned char* bufReceive;
  int nSendBufferSize = 0, nReceiveBufferSize = 0;
  int nContinue = 0, i = 0;

  // Check the socket and such
  if (hSocket <= 0)
  {
    writeError(ERR_ERROR, "%s failed: socket was invalid", MODULE_NAME);
    (*login)->iResult = LOGIN_RESULT_UNKNOWN;
    setPassResult(*login, szPassword);
    return MSTATE_EXITING;    // No good socket
  }

  if (nFoundPrompt == PROMPT_LOGIN_PASSWORD)
  {
    // Set up the send buffer
    memset(bufSend, 0, BUFFER_SIZE);
    sprintf((char *)bufSend, "%s\r", szLogin);
    nSendBufferSize = strlen((char *)bufSend) + 1;  // Count the null terminator

    if (medusaSend(hSocket, bufSend, nSendBufferSize, 0) < 0)
    {
      writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
      (*login)->iResult = LOGIN_RESULT_UNKNOWN;
      setPassResult(*login, szPassword);
      return MSTATE_EXITING;
    }

    do
    {
      // Look for a return
      bufReceive = medusaReceiveLineDelay(hSocket, &nReceiveBufferSize, RECEIVE_DELAY_1, RECEIVE_DELAY_2);
      if (bufReceive == NULL)
      {
        // Found a prompt - telnet appears to be alive, keep going
        writeError(ERR_ERROR, "%s: Telnet did not respond to the sending of the user name '%s' in a timely fashion - is it down or refusing connections?", MODULE_NAME, szLogin);
        (*login)->iResult = LOGIN_RESULT_UNKNOWN;
        setPassResult(*login, szPassword);
        return MSTATE_EXITING;
      }

      bufReceive[nReceiveBufferSize] = 0;  // Make certain buffer is null-terminated

      // Do we have a prompt?
      if (strcspn((char *)bufReceive, KNOWN_PROMPTS) != strlen((char *)bufReceive))
      {
        (*login)->iResult = LOGIN_RESULT_SUCCESS;
        setPassResult(*login, szPassword);
        free(bufReceive);
        return MSTATE_EXITING;
      }

      makeToLower((char *)bufReceive);

      // Are we at a known password prompt?
      for (i = 0; i < KNOWN_PWD_SIZE; i++)
      {
        if (strcasestr((char *)bufReceive, KNOWN_PWD_PROMPTS[i]) != '\0')
        {
          nContinue = 1;
          break;
        }
      }

      // Look for known login prompts
      if (nContinue == 0)
      {
        for (i = 0; i < KNOWN_LOGIN_SIZE; i++)
        {
          if (strcasestr((char *)bufReceive, KNOWN_LOGIN_PROMPTS[i]) != '\0')
          {
            free(bufReceive);
            (*login)->iResult = LOGIN_RESULT_FAIL;
            setPassResult(*login, szPassword);
            return MSTATE_RUNNING;
          }
        }
      }

      free(bufReceive);
    }
    while(nContinue == 0);
  }
  else if (nFoundPrompt == PROMPT_PASSWORD)
  {
    writeError(ERR_DEBUG_MODULE, "[%s] we are skipping a username", MODULE_NAME);
  }
  else
  {
    writeError(ERR_ERROR, "[%s] No login prompt detected.", MODULE_NAME);
    return FAILURE;
  }

  // Send the password
  memset(bufSend, 0, BUFFER_SIZE);
  sprintf((char *)bufSend, "%s\r", szPassword);
  nSendBufferSize = strlen((char *)bufSend) + 1;  // Count the null terminator

  if (medusaSend(hSocket, bufSend, nSendBufferSize, 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
    (*login)->iResult = LOGIN_RESULT_UNKNOWN;
    setPassResult(*login, szPassword);
    return MSTATE_EXITING;
  }

  // Look for a return
  bufReceive = medusaReceiveLineDelay(hSocket, &nReceiveBufferSize, RECEIVE_DELAY_1, RECEIVE_DELAY_2);
  if (bufReceive == NULL)
  {
    writeError(ERR_ERROR, "timeout waiting for response from server after sending password");
    (*login)->iResult = LOGIN_RESULT_UNKNOWN;
    setPassResult(*login, szPassword);
    return MSTATE_EXITING;
  }

  bufReceive[nReceiveBufferSize] = 0;  // Make certain buffer is null-terminated

  // It's possible that some telnet servers (like Microsoft's) may send some more IAC commands at this point
  // Take care of zem!
  processIAC(hSocket, _psSessionData, &bufReceive, &nReceiveBufferSize);

  if (bufReceive == NULL)
    bufReceive = medusaReceiveLineDelay(hSocket, &nReceiveBufferSize, RECEIVE_DELAY_1, RECEIVE_DELAY_2);

  // Do we have a prompt?
  while (bufReceive != NULL)
  {
    /* check for known failures */
    if (strstr((char *)bufReceive, "Authentication failed"))
    {
      writeError(ERR_DEBUG_MODULE, "Server responded with Cisco \"Authentication failed.\" message.");
      (*login)->iResult = LOGIN_RESULT_FAIL;
      setPassResult(*login, szPassword);
      return MSTATE_NEW;
    }
    if (strstr((char *)bufReceive, "Login invalid"))
    {
      writeError(ERR_DEBUG_MODULE, "Server responded with Cisco \"Login invalid\" message.");
      (*login)->iResult = LOGIN_RESULT_FAIL;
      setPassResult(*login, szPassword);
      return MSTATE_NEW;
    }
    else if (strcspn((char *)bufReceive, KNOWN_PROMPTS) != strlen((char *)bufReceive))
    {
      // Found a prompt - telnet appears to be alive
      free(bufReceive);
      (*login)->iResult = LOGIN_RESULT_SUCCESS;
      setPassResult(*login, szPassword);
      return MSTATE_EXITING;
    }
    else
    {
      if (nFoundPrompt == PROMPT_LOGIN_PASSWORD) {
        // If we have a login prompt, we have failed
        for (i = 0; i < KNOWN_LOGIN_SIZE; i++)
        {
          if (strcasestr((char *)bufReceive, KNOWN_LOGIN_PROMPTS[i]) != '\0')
          {
            free(bufReceive);
            writeError(ERR_DEBUG_MODULE, "unsuccessful login - user '%s' with a password of '%s'", szLogin, szPassword);
            (*login)->iResult = LOGIN_RESULT_FAIL;
            setPassResult(*login, szPassword);
            return MSTATE_NEW;
          }
        }
      } 
      else 
      {
        // We are operating on a non-login telnet setup
        for (i = 0; i < KNOWN_PWD_SIZE; i++)
        {
          if (strcasestr((char *)bufReceive, KNOWN_PWD_PROMPTS[i]) != '\0')
          {
            free(bufReceive);
            writeError(ERR_DEBUG_MODULE, "unsuccessful login with a password of '%s'", szPassword);
            (*login)->iResult = LOGIN_RESULT_FAIL;
            setPassResult(*login, szPassword);
            return MSTATE_NEW;
          }
        }
      }
    }

    free(bufReceive);
    bufReceive = medusaReceiveLineDelay(hSocket, &nReceiveBufferSize, RECEIVE_DELAY_1, RECEIVE_DELAY_2);
  }

  (*login)->iResult = LOGIN_RESULT_FAIL;
  setPassResult(*login, szPassword);

  return MSTATE_NEW;
}

int tryLoginAS400(int hSocket, sLogin** psLogin, char* szLogin, char* szPassword)
{
  unsigned char bufSend[BUFFER_SIZE];
  unsigned char* bufReceive;
  int nSendBufferSize = 0, nReceiveBufferSize = 0;
  int iRet = FAILURE;
  char szUser[10 + 1];
  char szPass[128 + 1];
  char szErrorMsg[100];

  if (hSocket <= 0)
  {
    writeError(ERR_ERROR, "%s failed: socket was invalid", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_UNKNOWN;
    setPassResult(*psLogin, szPassword);
    return MSTATE_EXITING;
  }

  /* Send username and password */
  /* USERNAME \t (0x09) PASSWORD \r (0x0D) \0 (0x00) */

  /* Password Policy Information
    http://publib.boulder.ibm.com/iseries/v5r1/ic2924/index.htm?info/rzakz/rzakzqpwdlvl.htm

    Short passwords: The AS/400 "short" passwords are 0-10 characters in length. They
    allow the following characters: A-Z 0-9 $ @ # _
  
    Long passwords: The AS/400 "long" passwords are 0-128 characters in length. Upper and
    lower case passwords consisting of any characters are allowed.

    Usernames appear to be limited to 10 characters in length and use upper-case. 
    ** This has not been fully verified. **

    http://download.oracle.com/docs/html/B10256_01/ch2.htm
    IBM DB2/400 V4R5 object names can be up to 10 alphanumeric characters in length, 
    beginning with a letter or a national character.
  */

  memset(bufSend, 0, BUFFER_SIZE);
  memset(szUser, 0, 10 + 1);
  memset(szPass, 0, 128 + 1);
  
  strncpy(szUser, szLogin, 10);
  strncpy(szPass, szPassword, 128);

  sprintf((char *)bufSend, "%s\t%s\r", szUser, szPass);
  nSendBufferSize = strlen((char *)bufSend) + 1;

  if (medusaSend(hSocket, bufSend, nSendBufferSize, 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_UNKNOWN;
    setPassResult(*psLogin, szPassword);
    return MSTATE_EXITING;
  }

  /* Process server response */
  bufReceive = medusaReceiveLineDelay(hSocket, &nReceiveBufferSize, RECEIVE_DELAY_1, RECEIVE_DELAY_2);
  if (bufReceive == NULL)
  {
    writeError(ERR_ERROR, "[%s] Timeout waiting for response from server after sending password", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_UNKNOWN;
    setPassResult(*psLogin, szPassword);
    return MSTATE_EXITING;
  }

  if (strstr((char *)bufReceive, "CPF1120") != NULL)
  {
    sprintf(szErrorMsg, "CPF1120 - User %s does not exist.", szUser); 
    writeError(ERR_ERROR, "[%s] %s", MODULE_NAME, szErrorMsg);
    (*psLogin)->pErrorMsg = malloc( strlen(szErrorMsg) + 1 );
    memset((*psLogin)->pErrorMsg, 0, strlen(szErrorMsg) + 1 );
    strncpy((*psLogin)->pErrorMsg, szErrorMsg, strlen(szErrorMsg));
    (*psLogin)->iResult = LOGIN_RESULT_ERROR;
    iRet = MSTATE_EXITING;
  }
  else if (strstr((char *)bufReceive, "CPF1116") != NULL)
  {
    strcpy(szErrorMsg, "CPF1116 - Next not valid sign-on attempt varies off device."); 
    writeError(ERR_ERROR, "[%s] %s", MODULE_NAME, szErrorMsg);
    (*psLogin)->pErrorMsg = malloc( strlen(szErrorMsg) + 1 );
    memset((*psLogin)->pErrorMsg, 0, strlen(szErrorMsg) + 1 );
    strncpy((*psLogin)->pErrorMsg, szErrorMsg, strlen(szErrorMsg));
    (*psLogin)->iResult = LOGIN_RESULT_FAIL;
    iRet = MSTATE_NEW;
  }
  else if (strstr((char *)bufReceive, "CPF1392") != NULL)
  {
    strcpy(szErrorMsg, "CPF1392 - Next not valid sign-on disables user profile."); 
    writeError(ERR_ERROR, "[%s] %s", MODULE_NAME, szErrorMsg);
    (*psLogin)->pErrorMsg = malloc( strlen(szErrorMsg) + 1 );
    memset((*psLogin)->pErrorMsg, 0, strlen(szErrorMsg) + 1 );
    strncpy((*psLogin)->pErrorMsg, szErrorMsg, strlen(szErrorMsg));
    (*psLogin)->iResult = LOGIN_RESULT_ERROR;
    iRet = MSTATE_EXITING;
  }
  /*
  http://archive.midrange.com/midrange-l/200507/msg01092.html
  
  Cause . . . . . :   User profile &1 has reached the maximum number of
                      sign-on attempts and has been disabled, or the STATUS 
                      parameter has been changed to *DISABLED on the Create 
                      User Profile (CRTUSRPRF) or Change User Profile
                      (CHGUSRPRF) command.
  
  Recovery  . . . :   To enable the user profile, have the security officer
                      change the STATUS parameter to *ENABLED on the Change 
                      User Profile (CHGUSRPRF) command.
  */
  else if (strstr((char *)bufReceive, "CPF1394") != NULL)
  {
    sprintf(szErrorMsg, "CPF1394 - User profile %s cannot sign on.", szUser); 
    writeError(ERR_ERROR, "[%s] %s", MODULE_NAME, szErrorMsg);
    (*psLogin)->pErrorMsg = malloc( strlen(szErrorMsg) + 1 );
    memset((*psLogin)->pErrorMsg, 0, strlen(szErrorMsg) + 1 );
    strncpy((*psLogin)->pErrorMsg, szErrorMsg, strlen(szErrorMsg));
    (*psLogin)->iResult = LOGIN_RESULT_ERROR;
    iRet = MSTATE_EXITING;
  }
  else if (strstr((char *)bufReceive, "CPF1118") != NULL)
  {
    sprintf(szErrorMsg, "CPF1118 - No password associated with user %s.", szUser); 
    writeError(ERR_ERROR, "[%s] %s", MODULE_NAME, szErrorMsg);
    (*psLogin)->pErrorMsg = malloc( strlen(szErrorMsg) + 1 );
    memset((*psLogin)->pErrorMsg, 0, strlen(szErrorMsg) + 1 );
    strncpy((*psLogin)->pErrorMsg, szErrorMsg, strlen(szErrorMsg));
    (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
    iRet = MSTATE_EXITING;
  }
  else if (strstr((char *)bufReceive, "CPF1109") != NULL)
  {
    strcpy(szErrorMsg, "CPF1109 - Not authorized to subsystem."); 
    writeError(ERR_ERROR, "[%s] %s", MODULE_NAME, szErrorMsg);
    (*psLogin)->pErrorMsg = malloc( strlen(szErrorMsg) + 1 );
    memset((*psLogin)->pErrorMsg, 0, strlen(szErrorMsg) + 1 );
    strncpy((*psLogin)->pErrorMsg, szErrorMsg, strlen(szErrorMsg));
    (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
    iRet = MSTATE_EXITING;
  }
  else if (strstr((char *)bufReceive, "CPF1110") != NULL)
  {
    strcpy(szErrorMsg, "CPF1110 - Not authorized to work station."); 
    writeError(ERR_ERROR, "[%s] %s", MODULE_NAME, szErrorMsg);
    (*psLogin)->pErrorMsg = malloc( strlen(szErrorMsg) + 1 );
    memset((*psLogin)->pErrorMsg, 0, strlen(szErrorMsg) + 1 );
    strncpy((*psLogin)->pErrorMsg, szErrorMsg, strlen(szErrorMsg));
    (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
    iRet = MSTATE_EXITING;
  }
  else if (strstr((char *)bufReceive, "CPF1107") != NULL)
  {
    writeError(ERR_INFO, "[%s] CPF1107 - Password not correct for user profile.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_FAIL;
    iRet = MSTATE_NEW;
  }
  else if (strstr((char *)bufReceive, "Access Denied") != NULL)
  {
    writeError(ERR_INFO, "[%s] Access Denied", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_FAIL;
    iRet = MSTATE_NEW;
  }
  else
  {
    (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
    iRet = MSTATE_EXITING;
  }
  
  setPassResult((*psLogin), szPass);

  return iRet;
}

/*
   The sender of this command REQUESTS that the receiver forcibly log
   off the user process at the receiver's end, or confirms that the
   receiver has its permission to do so.
*/
int processIAClogout(int hSocket, _MODULE_DATA* _psSessionData __attribute__((unused)))
{
  unsigned char bufSend[] = { 0xFF, 0xFD, 0x12 }; /* IAC DO LOGOUT */
  //char* bufReceive = NULL;
  //int nReceiveBufferSize = 0;

  writeError(ERR_DEBUG_MODULE, "[%s] Sending IAC DO LOGOUT command.", MODULE_NAME);
  if (medusaSend(hSocket, bufSend, 3, 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
    return FAILURE;
  }

  /* Receive any remaining IAC commands */
  /*
  bufReceive = medusaReceiveLineDelay(hSocket, &nReceiveBufferSize, RECEIVE_DELAY_1, RECEIVE_DELAY_2);
  if (bufReceive == NULL)
    return FAILURE;

  processIAC(hSocket, _psSessionData, &bufReceive, &nReceiveBufferSize);
  */

  return SUCCESS;
}

void processIAC(int hSocket, _MODULE_DATA* _psSessionData, unsigned char** buffer, int* nReceiveBufferSize)
{
  unsigned char* bufTemp = *buffer;

  /* We're not that friendly. Refuse to do anything asked of us. */
  while (*bufTemp == IAC) /* IAC (0xFF) */
  {
    writeError(ERR_DEBUG_MODULE, "Handling IAC Command...");

    if ((bufTemp[1] == 0xfc || bufTemp[1] == 0xfe) && bufTemp[2] == 0x22)
    {
      writeError(ERR_DEBUG_MODULE, "TELNETD peer does not like linemode");
    }

    if (bufTemp[1] == WILL) /* WILL (0xFB), WONT (0xFC) */
    {
      /* AS/400 devices appear to request and require "Echo" and "Suppress Go Ahead" */
      if (_psSessionData->nMode == MODE_AS400)
        if ((bufTemp[2] == TELOPT_ECHO) || (bufTemp[2] == TELOPT_SGA))
          bufTemp[1] = DO;
        else
          bufTemp[1] = DONT;
      else
        bufTemp[1] = DONT;

      medusaSend(hSocket, bufTemp, 3, 0);
    }
    else if (bufTemp[1] == DO) /* DO (0xFD), DONT (0xFE) */
    {
      bufTemp[1] = WONT;
      medusaSend(hSocket, bufTemp, 3, 0);
    }

    bufTemp += 3; /* Process three bytes at a time */
  }

  if (*bufTemp == 0)
  {
    writeError(ERR_DEBUG_MODULE, "Getting more data");
    free(*buffer);

    *nReceiveBufferSize = 0;
    *buffer = medusaReceiveLineDelay(hSocket, nReceiveBufferSize, RECEIVE_DELAY_1, RECEIVE_DELAY_2);
    if (*buffer != NULL)
      (*buffer)[*nReceiveBufferSize] = 0;  // Make certain buffer is null-terminated
    else
    {
      // No data
      *buffer = NULL;
      return;
    }

    writeError(ERR_DEBUG_MODULE, "Next pass buffer: %s", *buffer);
    if ((unsigned char)*buffer[0] == IAC)
    {
      writeError(ERR_DEBUG_MODULE, "More commands waiting...");
    }
  }
}
