/*
**   PcAnywhere Password Checking Medusa Module
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
**   pcaEncrypt() based on code from:
**     Hydra 5.0 [David Maciejak <david.maciejak@kyxar.fr>]
**
**   Based on packet captures from:
**   Server Version 10.5.1
**   Client 10.0.2
**
**   PCA Authentication Methods:
**    ADS (Active Directory Services) [1]
**    FTP                             [2]
**    HTTP                            [2]
**    HTTPS                           [2]
**    Microsoft LDAP                  [2]
**    Netscape LDAP                   [2]
**    Novell LDAP                     [2]
**    NT                              [1]
**    pcAnywhere                      [1]
**    Windows                         [3]
**
**      [1] Verified working
**      [2] Untested
**      [3] Verified to work when PcAnywhere host authenticates against domain accounts.
**          Authentication fails for local accounts with both the module and the PcAnywhere
**          client. Not sure what's going on...
**
*/

#include <sys/types.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "module.h"

#define MODULE_NAME    "pcanywhere.mod"
#define MODULE_AUTHOR  "JoMo-Kun <jmk@foofus.net>"
#define MODULE_SUMMARY_USAGE  "Brute force module for PcAnywhere sessions"
#define MODULE_VERSION    "2.0"
#define MODULE_VERSION_SVN "$Id: pcanywhere.c 9217 2015-05-07 18:07:03Z jmk $"
#define MODULE_SUMMARY_FORMAT  "%s : version %s"

#define PORT_PCA  5631
#define BUF_SIZE 300

typedef struct __PCA_DATA {
  char domain[17];
} _PCA_DATA;

// Tells us whether we are to continue processing or not
enum MODULE_STATE
{
  MSTATE_NEW,
  MSTATE_RUNNING,
  MSTATE_EXITING,
  MSTATE_COMPLETE
};

// Forward declarations
int tryLogin(int hSocket, sLogin** login, _PCA_DATA* _psSessionData, char* szLogin, char* szPassword);
int initModule(sLogin* login, _PCA_DATA *_psSessionData);

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
  writeVerbose(VB_NONE, "NOTE: PcAnywhere allows only one connection at a time. Running multiple threads per target");
  writeVerbose(VB_NONE, "      may not work well.");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "Available module options:");
  writeVerbose(VB_NONE, "  DOMAIN:?");
  writeVerbose(VB_NONE, "    Option allows manual setting of domain to check against when host uses NT authentication.");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "Usage example: \"-M pcanywhere -m DOMAIN:FOODOM\"");
}

// The "main" of the medusa module world - this is what gets called to actually do the work
int go(sLogin* logins, int argc, char *argv[])
{
  int i;
  char *strtok_ptr, *pOpt, *pOptTmp;
  _PCA_DATA *psSessionData;
  psSessionData = malloc(sizeof(_PCA_DATA));
  memset(psSessionData, 0, sizeof(_PCA_DATA));

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

      if (strcmp(pOpt, "DOMAIN") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if ( pOpt )
        {
          strncpy(psSessionData->domain, pOpt, 16);
          memset(psSessionData->domain + strlen(psSessionData->domain) + 1, 0x5C, 1); // '\'
        }
        else
          writeError(ERR_WARNING, "Method DOMAIN requires value to be set.");
      }
      else
      {
        writeError(ERR_WARNING, "Invalid method: %s.", pOpt);
      }

      FREE(pOptTmp);
    }
 
    initModule(logins, psSessionData);
  }  

  FREE(psSessionData);
  return SUCCESS;
}

int initModule(sLogin* psLogin, _PCA_DATA *_psSessionData)
{
  int hSocket = -1;
  enum MODULE_STATE nState = MSTATE_NEW;
  int nFirstPass = 0;
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
    params.nPort = PORT_PCA;
  initConnectionParams(psLogin, &params);

  while (nState != MSTATE_COMPLETE)
  {  
    switch(nState)
    {
      case MSTATE_NEW:
        // Already have an open socket - close it
        if (hSocket > 0)
          medusaDisconnect(hSocket);

        /* When not running in debug mode, we are failing to get the initial prompt from the
           server on connections after our initial attempt. Using the following sleep seems 
           to fix the issue. Not sure if there is a disconnect command or something that we
           could send the server to make this a non-issue. */
        if (nFirstPass != 0)
          sleep(1);
        nFirstPass = 1;
        
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

/* encrypt/decrypt: Symantec 31337 Crypto */
void pcaEncrypt(char *plaintext, char *ciphertext, int key, int offset)
{
  unsigned int i;

  writeError(ERR_DEBUG_MODULE, "pcaEncrypt [plaintext]: %s", plaintext);
 
  if (strlen(plaintext) > 0)
  {
    ciphertext[0] = plaintext[0] ^ key;
  
    for (i = 1; i < strlen(plaintext); i++)
      ciphertext[i] = ciphertext[i-1] ^ plaintext[i] ^ (i - offset);
  
  }
  writeError(ERR_DEBUG_MODULE, "pcaEncrypt [ciphertext]: %s", ciphertext);
}

int pcaUserAuth(int hSocket, char* szDomain, char* szLogin, char* szPassword)
{
  unsigned char bufSend[MAX_BUF];
  int nSendBufferSize = 0;
  unsigned char bufSend1[] = { 0x6f, 0x62, 0x01, 0x02, 0x00, 0x00, 0x00 };
  int nSendBufferSize1 = 7;
  unsigned char* bufReceive;
  int nReceiveBufferSize = 0;
  char* szTmp;
  
  char clogin[128]="";
  char cpass[128]="";
  
  /* retrieve logon prompt */
  // SEND: 6f 62 01 02 00 00 00
  // RECV: 00 7d 08 
  // RECV: 00 7c 08 20 0d 0a 45 6e 74 65 72 20 6c 6f 67 69 6e 20 6e 61 6d 65 3a 20
  writeError(ERR_DEBUG_MODULE, "%s: Retrieving login prompt.", MODULE_NAME);
  if (medusaSend(hSocket, bufSend1, nSendBufferSize1, 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
    return FAILURE;
  }

  /*
    When not running in debug mode, we are failing to get the login prompt from the
    server. Using the following sleep seems to fix the issue. This is probably just
    hiding some bug in the module code...
  */
  sleep(1);
  
  nReceiveBufferSize = 0;
  bufReceive = medusaReceiveRaw(hSocket, &nReceiveBufferSize);
  if (bufReceive == NULL)
  {
    writeError(ERR_ERROR, "%s failed: medusaReceive returned no data.", MODULE_NAME);
    return FAILURE;
  }
  else if (strstr((char*)bufReceive + 6, "Enter login name:"))
  {
    writeError(ERR_INFO, "%s: Host sent native PcAnywhere authentication prompt.", MODULE_NAME);
    pcaEncrypt(szLogin, clogin, 0xAB, 1);
    pcaEncrypt(szPassword, cpass, 0xAB, 1);
    
    memset(bufSend, 0, BUF_SIZE);
    bufSend[0] = 0x06;
    bufSend[1] = strlen(clogin);
    strncpy((char*)bufSend + 2, clogin, BUF_SIZE - 3);
    nSendBufferSize = strlen(clogin) + 2;
  }
  else if (strstr((char*)bufReceive + 6, "Enter user name:"))
  {
    writeError(ERR_INFO, "%s: Host sent NT authentication prompt.", MODULE_NAME);
    if (strlen(szDomain) > 0) {
      // FOODOM\administrator
      //0000001C  06                                               .
      //0000001D  14 ed a2 ec aa e6 af f6  91 f2 97 f7 93 f1 8e f7 ........ ........
      //0000002D  8b e5 81 ff 9f                                   ..... 
    
      szTmp = malloc(strlen(szDomain) + 1 + strlen(szLogin) + 1);
      memset(szTmp, 0, strlen(szDomain) + 1 + strlen(szLogin) + 1);
      strncpy(szTmp, szDomain, strlen(szDomain));
      memset(szTmp + strlen(szDomain), '\\', 1);
      strncpy(szTmp + strlen(szDomain) + 1, szLogin, strlen(szLogin));
      pcaEncrypt(szTmp, clogin, 0xAB, 1);
      writeError(ERR_DEBUG_MODULE, "%s: Setting domain\\user value: %s", MODULE_NAME, szTmp);
      FREE(szTmp);
      
      memset(bufSend, 0, BUF_SIZE);
      bufSend[0] = 0x06;
      bufSend[1] = strlen(clogin);
      strncpy((char*)bufSend + 2, clogin, BUF_SIZE - 3);
      nSendBufferSize = strlen(clogin) + 2;
    }
    else
    {
      pcaEncrypt(szLogin, clogin, 0xF7, 0);
      
      memset(bufSend, 0, BUF_SIZE);
      bufSend[0] = 0x06;
      bufSend[1] = strlen(clogin) + 1;
      bufSend[2] = 0xf7;
      strncpy((char*)bufSend + 3, clogin, BUF_SIZE - 4);
      nSendBufferSize = strlen(clogin) + 3;
    }
    
    pcaEncrypt(szPassword, cpass, 0xAB, 1);
  }
  else if (bufReceive + 6)
  {
    writeError(ERR_ERROR, "%s: Server responded with unknown login prompt: %s", MODULE_NAME, bufReceive + 6);
    FREE(bufReceive);
    return FAILURE;
  }
  else
  {
    writeError(ERR_ERROR, "%s: Server failed to respond with login prompt.", MODULE_NAME);
    FREE(bufReceive);
    return FAILURE;
  }
  
  FREE(bufReceive);

  /* send username */
  writeError(ERR_DEBUG_MODULE, "%s: Sending username.", MODULE_NAME);
  if (medusaSend(hSocket, bufSend, nSendBufferSize, 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
    return FAILURE;
  }

  /* retrieve password prompt */
  // RECV: 00 3a 08 20 0d 0a 45 6e 74 65 72 20 70 61 73 73 77 6f 72 64 3a 20
  // SEND: 2 + strlen(login) bytes
  nReceiveBufferSize = 0;
  bufReceive = medusaReceiveRaw(hSocket, &nReceiveBufferSize);
  if (bufReceive == NULL)
  {
    writeError(ERR_ERROR, "%s failed: medusaReceive returned no data.", MODULE_NAME);
    return FAILURE;
  }
  else if (strstr((char*)bufReceive + 6, "Enter password:"))
  {
    writeError(ERR_DEBUG_MODULE, "%s: Retrieved \"Enter password:\"", MODULE_NAME);
  }
  else
  {
    writeError(ERR_ERROR, "%s: Server did not send: \"Enter password:\"", MODULE_NAME);
    FREE(bufReceive);
    return FAILURE;
  }
  
  FREE(bufReceive);

  /* send encrypted password */
  memset(bufSend, 0, BUF_SIZE);
  bufSend[0] = 0x06;
  bufSend[1] = strlen(cpass);
  strncpy((char*)bufSend + 2, cpass, BUF_SIZE - 3);
  nSendBufferSize = strlen(cpass) + 2;
  
  writeError(ERR_DEBUG_MODULE, "%s: Sending password.", MODULE_NAME);
  if (medusaSend(hSocket, bufSend, nSendBufferSize, 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
    return FAILURE;
  }

  return SUCCESS;
}

int pcaNegCrypt(int hSocket)
{
  unsigned char bufSend[] = { 0x6f, 0x61, 0x00, 0x09, 0x00, 0xfe, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 };
  int nSendBufferSize = 14;
  unsigned char* bufReceive;
  int nReceiveBufferSize = 0;
  
  /* Testing encryption level. Only the default <none> is currently supported. */
  // SEND: 6f 61 00 09 00 fe 00 00 ff ff 00 00 00 00
  // RECV: 1b 62 00 02 00 00 00
  writeError(ERR_DEBUG_MODULE, "%s: Checking encryption level.", MODULE_NAME);
  if (medusaSend(hSocket, bufSend, nSendBufferSize, 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
    return FAILURE;
  }

  nReceiveBufferSize = 0;
  bufReceive = medusaReceiveRaw(hSocket, &nReceiveBufferSize);
  if (bufReceive == NULL)
  {
    writeError(ERR_ERROR, "%s failed: medusaReceive returned no data.", MODULE_NAME);
    return FAILURE;
  }
  else if (strstr((char*)bufReceive + 28, "Host is denying connection"))
  {
    writeError(ERR_ERROR, "%s: PcAnywhere host denied connection. Host requires encryption which is currently not supported.", MODULE_NAME);
    FREE(bufReceive);
    return FAILURE;
  }

  FREE(bufReceive);
  return SUCCESS;
}

int pcaSessionInit(int hSocket)
{
  unsigned char bufSend1[] = { 0x00, 0x00, 0x00, 0x00 };
  int nSendBufferSize1 = 4;
  unsigned char bufSend2[] = { 0x6f, 0x06, 0xff };
  int nSendBufferSize2 = 3;
  unsigned char* bufReceive;
  int nReceiveBufferSize = 0;
  
  /* Initial connection. Retrieve PCA banner */
  // SEND: 00 00 00 00
  // RECV: 50 6c 65 61 73 65 20 70 72 65 73 73 20 3c 45 6e 74 65 72 3e 2e 2e 2e 0d 0a
  writeError(ERR_DEBUG_MODULE, "%s: Retrieving RCA banner.", MODULE_NAME);
  if (medusaSend(hSocket, bufSend1, nSendBufferSize1, 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
    return FAILURE;
  }

  nReceiveBufferSize = 0;
  bufReceive = medusaReceiveRaw(hSocket, &nReceiveBufferSize);
  if (bufReceive == NULL)
  {
    /* can we not perform more than a single thread per host? */
    writeError(ERR_ERROR, "%s: Failed to retrieve host banner. Is someone currently connected via PcAnywhere?", MODULE_NAME);
    return FAILURE;
  }
  else if (strstr((char*)bufReceive + 11, "Please press <Enter>..."))
  {
    writeError(ERR_DEBUG_MODULE, "%s: Retrieved \"Please press <Enter>...\"", MODULE_NAME);
  }
  else
  {
    writeError(ERR_ERROR, "%s: Server did not send: \"Please press <Enter>...\"", MODULE_NAME);
    FREE(bufReceive);
    return FAILURE;
  }
  
  FREE(bufReceive);

  /* Unknown negotiation */
  // SEND: 6f 06 ff
  // RECV: 78 02 1b 61 01 09 00 ff 00 00 ff 00 00 00 00 00 
  writeError(ERR_DEBUG_MODULE, "%s: Sending unknown packet.", MODULE_NAME);
  if (medusaSend(hSocket, bufSend2, nSendBufferSize2, 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
    return FAILURE;
  }

  nReceiveBufferSize = 0;
  bufReceive = medusaReceiveRaw(hSocket, &nReceiveBufferSize);
  if (bufReceive == NULL)
  {
    writeError(ERR_ERROR, "%s failed: medusaReceive returned no data.", MODULE_NAME);
    return FAILURE;
  }

  FREE(bufReceive);
  return SUCCESS;
}

int tryLogin(int hSocket, sLogin** psLogin, _PCA_DATA* _psSessionData, char* szLogin, char* szPassword)
{
  int iRet;
  unsigned char* bufReceive;
  int nReceiveBufferSize = 0;

  writeError(ERR_DEBUG_MODULE, "%s: Initializing PcAnywhere connection.", MODULE_NAME);
  iRet = pcaSessionInit(hSocket);
  if (iRet == FAILURE)
  {
    writeError(ERR_ERROR, "%s: Failed to initialize PcAnywhere connection.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_ERROR;
    iRet = MSTATE_EXITING;
    return FAILURE;
  }
  
  writeError(ERR_DEBUG_MODULE, "%s: Negotiating encryption level.", MODULE_NAME);
  iRet = pcaNegCrypt(hSocket);
  if (iRet == FAILURE)
  {
    writeError(ERR_ERROR, "%s: Failed to negotiate encryption level.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_ERROR;
    iRet = MSTATE_EXITING;
    return FAILURE;
  }
                  
  /* check if authentication was successful */
  // RECV: (success)
  //   XX XX 1b 49 00 50 6a 6d 6b 00 00 00 00 00 00 00  .M.I.Pjmk.......
  //   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  //   00 00 00 00 0f 00 00 00 00 00 00 00 58 50 43 4c  ............XPCL
  //   49 45 4e 54 30 31 00 00 00 00 00 00 00 00 00 00  IENT01..........
  //   00 00 00 00 00 00 00 00 00 00 00 00 05 00 36 83  ..............6.
  //   33 0a 00 00 00 00 14                             3......
  // RECV: (failure)
  //   XX XX 0d 0a 00 7b 08 49 6e 76 61 6c 69 64 20 6c  .....{.Invalid l
  //   6f 67 69 6e 2e 20 50 6c 65 61 73 65 20 74 72 79  ogin. Please try
  //   20 61 67 61 69 6e 2e                              again.
  
  writeError(ERR_DEBUG_MODULE, "%s: Attempting PcAnywhere user authentication.", MODULE_NAME);
  iRet = pcaUserAuth(hSocket, _psSessionData->domain, szLogin, szPassword);
  if (iRet == FAILURE)
  {
    writeError(ERR_ERROR, "%s: Failed to send authentication information to PcAnywhere host.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_ERROR;
    iRet = MSTATE_EXITING;
    return FAILURE;
  }

  nReceiveBufferSize = 0;
  bufReceive = medusaReceiveRaw(hSocket, &nReceiveBufferSize);
  if (bufReceive == NULL)
  {
    writeError(ERR_ERROR, "%s failed: medusaReceive returned no data.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_ERROR;
    iRet = MSTATE_EXITING;
    return FAILURE;
  }
  else if (strstr((char*)bufReceive + 5, "Invalid login") || strstr((char*)bufReceive + 6, "Enter password"))
  {
    writeError(ERR_DEBUG_MODULE, "%s : Login attempt failed.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_FAIL;
    iRet = MSTATE_NEW;
  }
  else
  {
    writeError(ERR_DEBUG_MODULE, "%s : Login attempt successful.", MODULE_NAME);
    writeError(ERR_INFO, "%s : Machine name: %s Current logged on user: %s.", MODULE_NAME, bufReceive + 42, bufReceive + 4);
    (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
    iRet = MSTATE_EXITING;
  }

  FREE(bufReceive);
  setPassResult((*psLogin), szPassword);

  return(iRet);
}
