/***************************************************************************
 *   http.c                                                                *
 *   Copyright (C) 2009 by fizzgig                                         *
 *   fizzgig@foofus.net                                                    *
 *                                                                         *
 *   Implementation of a HTTP brute force module for Medusa.               *
 *                                                                         *
 *   CHANGE LOG                                                            *
 *   04/15/2005 - Created by fizzgig (fizzgig@foofus.net)                  *
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
 *   Modifications: (JoMo-Kun)                                             *
 *      Support for user specified URL/User-Agent                          *
 *      Replaced Base64 function from Hydra with Wget version              *
 *        Hydra Base64 appears partially broken...                         *
 *      Added NTLM authentication using code from Wget                     *
 *      Wget can be found here: http://wget.sunsite.dk/                   *
 *                                                                         *
 ***************************************************************************/

#include "module.h"

#define	MODULE_NAME		"http.mod"
#define MODULE_AUTHOR  "fizzgig <fizzgig@foofus.net>"
#define	MODULE_SUMMARY_USAGE	"Brute force module for HTTP"
#define MODULE_VERSION		"2.1"
#define MODULE_VERSION_SVN "$Id: http.c 9260 2015-05-27 21:52:57Z jmk $"
#define MODULE_SUMMARY_FORMAT	"%s : version %s"
#define MODULE_SUMMARY_FORMAT_WARN  "%s : version %s (%s)"
#define OPENSSL_WARNING "No usable OPENSSL. Module disabled."

#ifdef HAVE_LIBSSL

#include "ntlm.h"
#include "http-digest.h"

#define PORT_HTTP 80
#define PORT_HTTPS 443

#define AUTH_UNKNOWN 0
#define AUTH_NONE 1
#define AUTH_BASIC 2
#define AUTH_NTLM 3
#define AUTH_DIGEST 4

typedef struct __MODULE_DATA {
  char *szDomain;
  char *szDir;
  char *szHostHeader;
  char *szUserAgent;
  char *szCustomHeader;
  int nAuthType;
} _MODULE_DATA;

// Tells us whether we are to continue processing or not
enum HTTP_STATE
{
  MSTATE_NEW,
  MSTATE_RUNNING,
  MSTATE_EXITING,
  MSTATE_COMPLETE
};

// Forward declarations
int getAuthType(int hSocket, _MODULE_DATA* _psSessionData);
int tryLogin(int hSocket, _MODULE_DATA* _psSessionData, sLogin** login, char* szLogin, char* szPassword);
int initModule(_MODULE_DATA* _psSessionData, sLogin* login);

// Tell medusa how many parameters this module allows
int getParamNumber()
{
  return 0;		// we don't need no stinking parameters
}

// Displays information about the module and how it must be used
void summaryUsage(char **ppszSummary)
{
  // Memory for ppszSummary will be allocated here - caller is responsible for freeing it
  int	iLength = 0;

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
  writeVerbose(VB_NONE, "  USER-AGENT:? (User-Agent. Default: Mozilla/1.22 (compatible; MSIE 10.0; Windows 3.1))");
  writeVerbose(VB_NONE, "  DIR:? (Target directory. Default \"/\")");
  writeVerbose(VB_NONE, "  AUTH:? (Authentication Type (BASIC/DIGEST/NTLM). Default: automatic)");
  writeVerbose(VB_NONE, "  DOMAIN:? [optional]");
  writeVerbose(VB_NONE, "  CUSTOM-HEADER:?    Additional HTTP header.");
  writeVerbose(VB_NONE, "                     More headers can be defined by using this option several times.");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "Usage example: \"-M http -m USER-AGENT:\"g3rg3 gerg\" -m DIR:exchange/\"");
  writeVerbose(VB_NONE, "Usage example: \"-M http -m CUSTOM-HEADER:\"Cookie: SMCHALLENGE=YES\"");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "Note: The default behavior of NTLM authentication is to use the server supplied");
  writeVerbose(VB_NONE, "domain name. In order to target local accounts, and not domain, use the DOMAIN");
  writeVerbose(VB_NONE, "option to reference the local system: \"-m DOMAIN:127.0.0.1\".");
}

// The "main" of the medusa module world - this is what gets called to actually do the work
int go(sLogin* logins, int argc, char *argv[])
{
  int i;
  int nCustomHeadersSize = 0;
  char *strtok_ptr, *pOpt, *pOptTmp;
  _MODULE_DATA *psSessionData;

  psSessionData = malloc(sizeof(_MODULE_DATA));
  memset(psSessionData, 0, sizeof(_MODULE_DATA));

  if ((argc < 0) || (argc > 4))
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

      if (strcmp(pOpt, "DIR") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if ( pOpt )
        {
          psSessionData->szDir = malloc(strlen(pOpt) + 1);
          memset(psSessionData->szDir, 0, strlen(pOpt) + 1);
          strncpy(psSessionData->szDir, pOpt, strlen(pOpt) + 1);
        }
        else
          writeError(ERR_WARNING, "Method DIR requires value to be set.");
      }
      else if (strcmp(pOpt, "USER-AGENT") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if ( pOpt )
        {
          psSessionData->szUserAgent = malloc(strlen(pOpt) + 1);
          memset(psSessionData->szUserAgent, 0, strlen(pOpt) + 1);
          strncpy(psSessionData->szUserAgent, pOpt, strlen(pOpt) + 1);
        }
        else
          writeError(ERR_WARNING, "Method USER-AGENT requires value to be set.");
      }
      else if (strcmp(pOpt, "CUSTOM-HEADER") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if ( pOpt )
        {
          if ( nCustomHeadersSize == 0 )
            psSessionData->szCustomHeader = malloc(strlen(pOpt) + 3);
          else
            psSessionData->szCustomHeader = realloc(psSessionData->szCustomHeader, nCustomHeadersSize + strlen(pOpt) + 3);

          memset(psSessionData->szCustomHeader + nCustomHeadersSize, 0, strlen(pOpt) + 3);
          strncpy(psSessionData->szCustomHeader + nCustomHeadersSize, pOpt, strlen(pOpt));
          strncpy(psSessionData->szCustomHeader + nCustomHeadersSize + strlen(pOpt), "\r\n", 2);
          nCustomHeadersSize = strlen(psSessionData->szCustomHeader);
        }
        else
          writeError(ERR_WARNING, "Method CUSTOM-HEADER requires value to be set.");
      }
      else if (strcmp(pOpt, "AUTH") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if (pOpt == NULL)
          writeError(ERR_WARNING, "Method AUTH requires value to be set.");
        else if (strcmp(pOpt, "BASIC") == 0)
          psSessionData->nAuthType = AUTH_BASIC;
        else if (strcmp(pOpt, "DIGEST") == 0)
          psSessionData->nAuthType = AUTH_DIGEST;
        else if (strcmp(pOpt, "NTLM") == 0)
          psSessionData->nAuthType = AUTH_NTLM;
        else
          writeError(ERR_WARNING, "Invalid value for method AUTH.");
      }
      else if (strcmp(pOpt, "DOMAIN") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if ( pOpt )
        {
          psSessionData->szDomain = malloc(strlen(pOpt) + 1);
          memset(psSessionData->szDomain, 0, strlen(pOpt) + 1);
          strncpy((char *) psSessionData->szDomain, pOpt, strlen(pOpt));
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

    initModule(psSessionData, logins);
  }

  FREE(psSessionData->szDir);
  FREE(psSessionData->szUserAgent);
  FREE(psSessionData->szDomain);
  FREE(psSessionData->szCustomHeader);
  FREE(psSessionData);
  return SUCCESS;
}

int initModule(_MODULE_DATA *_psSessionData, sLogin* _psLogin)
{
  int hSocket = -1;
  enum HTTP_STATE nState = MSTATE_NEW;
  int nBufLength = 0;
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
    writeError(ERR_DEBUG_MODULE, "[%s] module started for host: %s - no more available users to test.", MODULE_NAME, _psLogin->psServer->pHostIP);
    nState = MSTATE_COMPLETE;
  }

  memset(&params, 0, sizeof(sConnectParams));
  if (_psLogin->psServer->psAudit->iPortOverride > 0)
    params.nPort = _psLogin->psServer->psAudit->iPortOverride;
  else if (_psLogin->psServer->psHost->iUseSSL > 0)
    params.nPort = PORT_HTTPS;
  else
    params.nPort = PORT_HTTP; 
  initConnectionParams(_psLogin, &params);

  /* Set request parameters */
  if (!_psSessionData->szDir)
  {
    _psSessionData->szDir = malloc(1);
    memset(_psSessionData->szDir, 0, 1);
  }

  if (!_psSessionData->szHostHeader)
  {
    nBufLength = strlen(_psLogin->psServer->psHost->pHost) + 1 + log(params.nPort) + 1;
    _psSessionData->szHostHeader = malloc(nBufLength + 1);
    memset(_psSessionData->szHostHeader, 0, nBufLength + 1);
    sprintf(_psSessionData->szHostHeader, "%s:%d", _psLogin->psServer->psHost->pHost, params.nPort);
  }

  if (!_psSessionData->szUserAgent)
  {
    _psSessionData->szUserAgent = malloc(50);
    memset(_psSessionData->szUserAgent, 0, 50);
    sprintf(_psSessionData->szUserAgent, "Mozilla/1.22 (compatible; MSIE 10.0; Windows 3.1)");
  }
      
  if (!_psSessionData->szCustomHeader) {
    _psSessionData->szCustomHeader = malloc(1);
    memset(_psSessionData->szCustomHeader, 0, 1);
  }

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

      if (hSocket < 0)
      {
        writeError(ERR_NOTICE, "%s: failed to connect, port %d was not open on %s", MODULE_NAME, params.nPort, _psLogin->psServer->pHostIP);
        _psLogin->iResult = LOGIN_RESULT_UNKNOWN;
        return FAILURE;
      }

      /* Get required authorization method */
      if (_psSessionData->nAuthType == AUTH_UNKNOWN)
      {
        if ((getAuthType(hSocket, _psSessionData) == FAILURE) || (_psSessionData->nAuthType == AUTH_UNKNOWN))
        {
          _psLogin->iResult = LOGIN_RESULT_UNKNOWN;
          return FAILURE;
        }

        nState = MSTATE_NEW;
      }
      else
        nState = MSTATE_RUNNING;

      break;
    case MSTATE_RUNNING:
      nState = tryLogin(hSocket, _psSessionData, &_psLogin, psCredSet->psUser->pUser, psCredSet->pPass);

      if (_psLogin->iResult != LOGIN_RESULT_UNKNOWN)
      {
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
      writeError(ERR_CRITICAL, "Unknown HTTP module state (%d). Exiting...", nState);
      _psLogin->iResult = LOGIN_RESULT_UNKNOWN;
      nState = MSTATE_EXITING;
      break;
    }
  }

  FREE(psCredSet);
  return SUCCESS;
}

/* Module Specific Functions */

int getAuthType(int hSocket, _MODULE_DATA* _psSessionData)
{
  unsigned char* bufSend = NULL;
  unsigned char* bufReceive = NULL;
  int nReceiveBufferSize = 0;
  int nSendBufferSize = 0;

  nSendBufferSize = 5 + strlen(_psSessionData->szDir) + 17 + strlen(_psSessionData->szHostHeader) +
                    14 + strlen(_psSessionData->szUserAgent) + 2 + strlen(_psSessionData->szCustomHeader) + 2; 

  bufSend = malloc(nSendBufferSize + 1);
  memset(bufSend, 0, nSendBufferSize + 1);

  sprintf((char*)bufSend, "GET /%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n%s\r\n", 
          _psSessionData->szDir, _psSessionData->szHostHeader, _psSessionData->szUserAgent, _psSessionData->szCustomHeader);

  writeError(ERR_DEBUG_MODULE, "[%s] Sending initial non-authentication request: %s", MODULE_NAME, bufSend);
  if (medusaSend(hSocket, bufSend, nSendBufferSize, 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
    FREE(bufSend);
    return FAILURE;
  }

  FREE(bufSend);

  if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "HTTP/1.* .*\r\n") == FAILURE) || (bufReceive == NULL))
  {
    writeError(ERR_ERROR, "[%s] Failed: Unexpected or no data received: %s", MODULE_NAME, bufReceive);
    return FAILURE;
  }

  writeError(ERR_DEBUG_MODULE, "[%s] Parsing authentication header: %s", MODULE_NAME, bufReceive);
  if ((strcasestr((char*)bufReceive, "WWW-Authenticate: Basic")) || (strcasestr((char*)bufReceive, "WWW-Authenticate:Basic")))
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Server requested basic authentication.", MODULE_NAME);
    _psSessionData->nAuthType = AUTH_BASIC;
  }
  else if ((strcasestr((char*)bufReceive, "WWW-Authenticate: NTLM")) || (strcasestr((char*)bufReceive, "WWW-Authenticate:NTLM")))
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Server requested integrated windows authentication.", MODULE_NAME);
    _psSessionData->nAuthType = AUTH_NTLM;
  }
  else if ((strcasestr((char*)bufReceive, "WWW-Authenticate: Digest")) || strcasestr((char*)bufReceive, "WWW-Authenticate:Digest"))
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Server requested digest authentication.", MODULE_NAME);
    _psSessionData->nAuthType = AUTH_DIGEST;
  }
  else if (strcasestr((char*)bufReceive, "WWW-Authenticate:"))
  {
    writeError(ERR_ERROR, "[%s] Server requested unknown authentication type.", MODULE_NAME);
    _psSessionData->nAuthType = AUTH_UNKNOWN;
  }
  else
  {
    writeError(ERR_DEBUG_MODULE, "[%s] No authentication header located.", MODULE_NAME);
    _psSessionData->nAuthType = AUTH_NONE;
  }

  FREE(bufReceive);
  return(SUCCESS);
}

int sendAuthBasic(int hSocket, _MODULE_DATA* _psSessionData, char* szLogin, char* szPassword)
{
  unsigned char* bufSend = NULL;
  char* szEncodedAuth = NULL;
  char* szLoginDomain = NULL;
  int nSendBufferSize = 0;
  int nRet = SUCCESS;

  if (_psSessionData->szDomain)
  {
    /* DOMAIN\USERNAME */
    szLoginDomain = malloc(strlen(_psSessionData->szDomain) + 1 + strlen(szLogin) + 1);
    memset(szLoginDomain, 0, strlen(_psSessionData->szDomain) + 1 + strlen(szLogin) + 1);
    sprintf(szLoginDomain, "%s\\%s", _psSessionData->szDomain, szLogin);
  }
  else
    szLoginDomain = szLogin;

  writeError(ERR_DEBUG_MODULE, "[%s] Base64 encoding: %s:%s", MODULE_NAME, szLoginDomain, szPassword);
  szEncodedAuth = basic_authentication_encode(szLoginDomain, szPassword);
  writeError(ERR_DEBUG_MODULE, "[%s] Base64 encoded data is: %s", MODULE_NAME, szEncodedAuth);

  if (_psSessionData->szDomain)
    FREE(szLoginDomain);

  nSendBufferSize = 5 + strlen(_psSessionData->szDir) + 17 + strlen(_psSessionData->szHostHeader) +
                    14 + strlen(_psSessionData->szUserAgent) + 23 + strlen(szEncodedAuth) + 
                    2 + strlen(_psSessionData->szCustomHeader) + 2;

  bufSend = malloc(nSendBufferSize + 1);
  memset(bufSend, 0, nSendBufferSize + 1);

  sprintf((char*)bufSend, "GET /%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAuthorization: Basic %s\r\n%s\r\n", 
          _psSessionData->szDir, _psSessionData->szHostHeader, _psSessionData->szUserAgent, szEncodedAuth, _psSessionData->szCustomHeader);

  if (medusaSend(hSocket, bufSend, nSendBufferSize, 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
    nRet = FAILURE;  
  }

  FREE(szEncodedAuth);
  FREE(bufSend);
  return nRet;
}

int sendAuthNTLM(int hSocket, _MODULE_DATA* _psSessionData, char* szLogin, char* szPassword)
{
  unsigned char* bufSend = NULL;
  unsigned char* bufReceive = NULL;
  int nReceiveBufferSize = 0;
  int nSendBufferSize = 0;
  tSmbNtlmAuthRequest   sTmpReq;
  tSmbNtlmAuthChallenge sTmpChall;
  tSmbNtlmAuthResponse  sTmpResp;
  char *szTmpBuf = NULL;
  char *szTmpBuf64 = NULL;

  /* --- Send Type-1 NTLM request --- */

  /* Enable NTLM2 Session Response */
  buildAuthRequest(&sTmpReq, 0x0008b207, NULL, NULL);
  //buildAuthRequest(&sTmpReq, 0, NULL, NULL);

  szTmpBuf64 = malloc(2 * SmbLength(&sTmpReq) + 2);
  memset(szTmpBuf64, 0, 2 * SmbLength(&sTmpReq) + 2);

  base64_encode((char *)&sTmpReq, SmbLength(&sTmpReq), szTmpBuf64);
  writeError(ERR_DEBUG_MODULE, "[%s] Sending initial challenge (B64 Encoded): %s", MODULE_NAME, szTmpBuf64);

  nSendBufferSize = 5 + strlen(_psSessionData->szDir) + 17 + strlen(_psSessionData->szHostHeader) +
                    14 + strlen(_psSessionData->szUserAgent) + 22 + strlen(szTmpBuf64) + 26 +
                    strlen(_psSessionData->szCustomHeader) + 2;

  bufSend = malloc(nSendBufferSize + 1);
  memset(bufSend, 0, nSendBufferSize + 1);

  sprintf((char*)bufSend, "GET /%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAuthorization: NTLM %s\r\nConnection: keep-alive\r\n%s\r\n", 
          _psSessionData->szDir, _psSessionData->szHostHeader, _psSessionData->szUserAgent, szTmpBuf64, _psSessionData->szCustomHeader);

  if (medusaSend(hSocket, bufSend, nSendBufferSize, 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
    return FAILURE;
  }

  FREE(szTmpBuf64);
  FREE(bufSend);

  /* --- Retrieve NTLM challenge from server --- */
  if ((medusaReceiveRegex(hSocket, &bufReceive, &nReceiveBufferSize, "HTTP/1.* .*WWW-Authenticate.*\r\n") == FAILURE) || (bufReceive == NULL))
  {
    writeError(ERR_ERROR, "[%s] Failed: Unexpected or no data received: %s", MODULE_NAME, bufReceive);
    return FAILURE;
  }

  if (bufReceive[0] == '\0')
  {
    writeError(ERR_ERROR, "[%s] Service did not respond to our authentication request.", MODULE_NAME);
    return FAILURE;
  }

  /* --- Extract NTLM challenge from Type-2 NTLM response --- */

  szTmpBuf64 = strcasestr((char*)bufReceive, "WWW-Authenticate: NTLM ");
  if (szTmpBuf64 == NULL)
  {
    writeError(ERR_ERROR, "[%s] Failed to locate NTLM challenge within server response.", MODULE_NAME);
    return FAILURE;
  }

  szTmpBuf = index(szTmpBuf64, '\r');

  if (szTmpBuf)
    szTmpBuf[0] = '\0';
  else  
    writeError(ERR_ERROR, "[%s] Failed to identify complete NTLM challenge.", MODULE_NAME);

  writeError(ERR_DEBUG_MODULE, "[%s] NTLM Challenge (B64 Encoded): %s", MODULE_NAME, szTmpBuf64 + 23);
  base64_decode(szTmpBuf64 + 23, (char *)&sTmpChall);

  FREE(bufReceive);

  /* --- Send Type-3 NTLM reply --- */

  buildAuthResponse(&sTmpChall, &sTmpResp, 0, szLogin, szPassword, _psSessionData->szDomain, NULL);

  szTmpBuf64 = malloc(2 * SmbLength(&sTmpResp) + 2);
  memset(szTmpBuf64, 0, 2 * SmbLength(&sTmpResp) + 2);

  base64_encode((char *)&sTmpResp, SmbLength(&sTmpResp), szTmpBuf64);
  writeError(ERR_DEBUG_MODULE, "[%s] NTLM Response (B64 Encoded): %s", MODULE_NAME, szTmpBuf64);

  nSendBufferSize = 5 + strlen(_psSessionData->szDir) + 17 + strlen(_psSessionData->szHostHeader) +
                    14 + strlen(_psSessionData->szUserAgent) + 22 + strlen(szTmpBuf64) + 21 + 
                    strlen(_psSessionData->szCustomHeader) + 2;

  bufSend = malloc(nSendBufferSize + 1);
  memset(bufSend, 0, nSendBufferSize + 1);

  sprintf((char*)bufSend, "GET /%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAuthorization: NTLM %s\r\nConnection: close\r\n%s\r\n", 
          _psSessionData->szDir, _psSessionData->szHostHeader, _psSessionData->szUserAgent, szTmpBuf64, _psSessionData->szCustomHeader);

  if (medusaSend(hSocket, bufSend, nSendBufferSize, 0) < 0)
  {
    writeError(ERR_ERROR, "[%s] failed: medusaSend was not successful", MODULE_NAME);
    return FAILURE;
  }

  FREE(szTmpBuf64);
  FREE(bufSend);

  return SUCCESS;
}

/* http://www.ietf.org/rfc/rfc2617.txt */
int sendAuthDigest(int hSocket, _MODULE_DATA* _psSessionData, char* szLogin, char* szPassword)
{
  unsigned char* bufSend = NULL;
  unsigned char* bufReceive = NULL;
  int nReceiveBufferSize = 0;
  int nSendBufferSize = 0;
  char *szTmp = NULL;
  char *szTmp1 = NULL;
  char *szAuthenticate = NULL;
  char *szAuthorization = NULL;

  char *szNonce = NULL;
  char *szCNonce = "31337";
  char *szRealm = NULL; 
  char *szAlg = NULL;
  char  szNonceCount[9] = "00000001";
  char *szMethod = "GET";
  char *szQop = NULL;
  char *szURI = NULL;
  char *szOpaque = NULL;
  HASHHEX HA1;
  HASHHEX HA2 = "";
  HASHHEX Response;

  /* URI should start with a "/" */
  if (strncmp(_psSessionData->szDir, "/", 1) == 0) 
  {
    szURI = malloc(strlen(_psSessionData->szDir) + 1);
    memset(szURI, 0, strlen(_psSessionData->szDir) + 1);
    strncat(szURI, _psSessionData->szDir, strlen(_psSessionData->szDir));
  }
  else
  {
    szURI = malloc(1 + strlen(_psSessionData->szDir) + 1);
    memset(szURI, 0, 1 + strlen(_psSessionData->szDir) + 1);
    strncat(szURI, "/", 1);
    strncat(szURI, _psSessionData->szDir, strlen(_psSessionData->szDir));
  }

  /* Send initial request */
  writeError(ERR_DEBUG_MODULE, "[%s] Sending initial request for digest authentication.", MODULE_NAME);

  nSendBufferSize = 5 + strlen(_psSessionData->szDir) + 17 + strlen(_psSessionData->szHostHeader) +
                    14 + strlen(_psSessionData->szUserAgent) + 26 + strlen(_psSessionData->szCustomHeader) + 2;

  bufSend = malloc(nSendBufferSize + 1);
  memset(bufSend, 0, nSendBufferSize + 1);

  sprintf((char*)bufSend, "GET /%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: keep-alive\r\n%s\r\n", 
          _psSessionData->szDir, _psSessionData->szHostHeader, _psSessionData->szUserAgent, _psSessionData->szCustomHeader);

  if (medusaSend(hSocket, bufSend, nSendBufferSize, 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
    return FAILURE;
  }

  FREE(bufSend);

  /* Retrieve digest challenge from server */
  bufReceive = medusaReceiveLine(hSocket, &nReceiveBufferSize);
  if (bufReceive == NULL)
  {
    writeError(ERR_ERROR, "[%s] No data received", MODULE_NAME);
    return FAILURE;
  }

  if (bufReceive[0] == '\0')
  {
    writeError(ERR_ERROR, "[%s] Failed to locate digest challenge.", MODULE_NAME);
    return FAILURE;
  }

  /* Parse WWW-Authenticate Digest Response */
  /* Example: WWW-Authenticate: Digest realm="Inter-Tel 5000 (00103605AB8A)", nonce="86591bebf1330b5e57b8de2e4ac216b2", qop="auth" */
  if ( (szTmp = strcasestr((char*)bufReceive, "WWW-Authenticate: Digest ")) != NULL )
  {
    szTmp += 18;
  }
  else if ( (szTmp = strcasestr((char*)bufReceive, "WWW-Authenticate:Digest ")) != NULL )
  {
    szTmp += 17;
  }
  else
  {
    writeError(ERR_ERROR, "[%s] Failed to locate digest challenge.", MODULE_NAME);
    return FAILURE;
  }
  szTmp1 = index(szTmp, '\r');

  szAuthenticate = malloc(szTmp1 - szTmp + 1);
  memset(szAuthenticate, 0, szTmp1 - szTmp + 1);
  strncpy(szAuthenticate, szTmp, szTmp1 - szTmp);

  FREE(bufReceive);

  writeError(ERR_DEBUG_MODULE, "[%s] Server WWW-Authenticate Digest Response: %s", MODULE_NAME, szAuthenticate);

  /* Extract Digest Algorithm, if Specified */
  /* We currently only support MD5 and MD5-Sess (session) - Do others exist? */
  if ( strcasestr(szAuthenticate, "algorithm=MD5-sess") || strcasestr(szAuthenticate, "algorithm=\"MD5-sess\"") )
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Server requested Digest MD5-sess algorithm.", MODULE_NAME);
    szAlg = malloc(9);
    memset(szAlg, 0, 9);
    sprintf(szAlg, "MD5-sess"); 
  }
  else if ( strcasestr(szAuthenticate, "algorithm=MD5") || strcasestr(szAuthenticate, "algorithm=\"MD5\"") )
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Server requested Digest MD5 algorithm.", MODULE_NAME);
    szAlg = malloc(4);
    memset(szAlg, 0, 4);
    sprintf(szAlg, "MD5"); 
  }
  else if ( strcasestr(szAuthenticate, "algorithm=") )
  {
    writeError(ERR_ERROR, "[%s] Server requested unknown Digest algorithm.", MODULE_NAME);
    return FAILURE;
  }
  else
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Server did not specify a Digest algorithm, so we're assuming MD5.", MODULE_NAME);
    szAlg = malloc(4);
    memset(szAlg, 0, 4);
    sprintf(szAlg, "MD5"); 
  }

  /* Extract Digest Realm */
  szTmp = strcasestr(szAuthenticate, "realm=\"");
  if (szTmp)
  {
    szTmp += 7;
    szTmp1 = ((char*)index(szTmp, '"'));

    szRealm = malloc (szTmp1 - szTmp + 1);
    memset(szRealm, 0, szTmp1 - szTmp + 1);
    strncpy(szRealm, szTmp, szTmp1 - szTmp);
    writeError(ERR_DEBUG_MODULE, "[%s] Extracted Realm Response: %s", MODULE_NAME, szRealm);
  }
  else
  {
    writeError(ERR_ERROR, "[%s] Failed to extract server Realm response.", MODULE_NAME);
    szRealm = malloc(1);
    memset(szRealm, 0, 1);
  }

  /* Extract Digest Server Nonce */
  szTmp = strcasestr(szAuthenticate, "nonce=\"");
  if (szTmp)
  {
    szTmp += 7;
    szTmp1 = index(szTmp, '"');

    szNonce = malloc (szTmp1 - szTmp + 1);
    memset(szNonce, 0, szTmp1 - szTmp + 1);
    strncpy(szNonce, szTmp, szTmp1 - szTmp);
    writeError(ERR_DEBUG_MODULE, "[%s] Extracted Nonce Response: %s", MODULE_NAME, szNonce);
  }
  else
  {
    writeError(ERR_ERROR, "[%s] Failed to extract server Nonce response.", MODULE_NAME);
    szNonce = malloc(1);
    memset(szNonce, 0, 1);
  }

  /* Extract Digest Quality of Protection (QoP) - If Specified */
  szTmp = strcasestr(szAuthenticate, "qop=\"");
  if (szTmp)
  {
    szTmp += 5;
    szTmp1 = index(szTmp, '"');

    szQop = malloc (szTmp1 - szTmp + 1);
    memset(szQop, 0, szTmp1 - szTmp + 1);
    strncpy(szQop, szTmp, szTmp1 - szTmp);
    writeError(ERR_DEBUG_MODULE, "[%s] Extracted Quality of Protection (QoP) Response: %s", MODULE_NAME, szQop);
  }
  else
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Failed to extract server Quality of Protection (QoP) response.", MODULE_NAME);
    szQop = NULL;
  }

  /* Extract Digest Opaque Value - If Specified */
  szTmp = strcasestr(szAuthenticate, "opaque=\"");
  if (szTmp)
  {
    szTmp += 8;
    szTmp1 = index(szTmp, '"');

    szOpaque = malloc(szTmp1 - szTmp + 1);
    memset(szOpaque, 0, szTmp1 - szTmp + 1);
    strncpy(szOpaque, szTmp, szTmp1 - szTmp);
    writeError(ERR_DEBUG_MODULE, "[%s] Extracted Server Opaque Value: %s", MODULE_NAME, szOpaque);
  }
  else
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Failed to extract server Opaque value.", MODULE_NAME);
    szOpaque = NULL;
  }

  FREE(szAuthenticate);

  /* Send digest response */
  /* Example: Authorization: Digest username="it5k", realm="Inter-Tel 5000 (00103605AB8A)", nonce="94144a2abae7411d0f6af2b533425497", uri="/", 
                             response="b9c3980ae4e7fb69796772a3bacc5c18"\r\n */

  writeError(ERR_DEBUG_MODULE, "[%s] szAlg: %s", MODULE_NAME, szAlg);
  writeError(ERR_DEBUG_MODULE, "[%s] szLogin: %s", MODULE_NAME, szLogin);
  writeError(ERR_DEBUG_MODULE, "[%s] szRealm: %s", MODULE_NAME, szRealm);
  writeError(ERR_DEBUG_MODULE, "[%s] szPassword: %s", MODULE_NAME, szPassword);
  writeError(ERR_DEBUG_MODULE, "[%s] szNonce: %s", MODULE_NAME, szNonce);
  writeError(ERR_DEBUG_MODULE, "[%s] szCNonce: %s", MODULE_NAME, szCNonce);
  writeError(ERR_DEBUG_MODULE, "[%s] szNonceCount: %s", MODULE_NAME, szNonceCount);
  writeError(ERR_DEBUG_MODULE, "[%s] szQop: %s", MODULE_NAME, szQop);
  writeError(ERR_DEBUG_MODULE, "[%s] szOpaque: %s", MODULE_NAME, szOpaque);
  writeError(ERR_DEBUG_MODULE, "[%s] szMethod: %s", MODULE_NAME, szMethod);
  writeError(ERR_DEBUG_MODULE, "[%s] szURI: %s", MODULE_NAME, szURI);

  DigestCalcHA1(szAlg, szLogin, szRealm, szPassword, szNonce, szCNonce, HA1);
  DigestCalcResponse(HA1, szNonce, szNonceCount, szCNonce, szQop, szMethod, szURI, HA2, Response);
  writeError(ERR_DEBUG_MODULE, "[%s] Calculated Digest Response: %s", MODULE_NAME, Response);

  /*
    BASE:   Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", algorithm=\"%s\", response=\"%s\"
    QOP:    , qop=%s, nc=%s, cnonce=\"%s\"
    OPAQUE: , opaque=\"%s\"
  */

  nSendBufferSize = 17 + strlen(szLogin) + 10 + strlen(szRealm) + 10 + strlen(szNonce) + 8 + strlen(szURI) + 14 + strlen(szAlg) + 13 + strlen((char*)Response);

  /* If the server specified a QoP, the client must use a cnonce */
  if ( strcasestr(szQop, "auth-int") )
  {
    writeError(ERR_ERROR, "[%s] Integrity protection (i.e. qop: auth-int) is currently not supported.", MODULE_NAME);
    return FAILURE;
  }
  else if ( strcasestr(szQop, "auth") )
  {
    nSendBufferSize += 7 + strlen(szQop) + 5 + strlen(szNonceCount) + 10 + strlen(szCNonce) + 1;
  }

  /* If the server specified an opaque value, that same value should be included in our response. */
  if ( szOpaque )
  {
    nSendBufferSize += 10 + strlen(szOpaque) + 1; 
  }

  szAuthorization = malloc(nSendBufferSize + 1);
  memset(szAuthorization, 0, nSendBufferSize + 1);

  if ( (szQop != NULL) && (szOpaque != NULL) )
    sprintf(szAuthorization, "Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", algorithm=%s, response=\"%s\", qop=%s, nc=00000001, cnonce=\"%s\", opaque=\"%s\"",
                             szLogin, szRealm, szNonce, szURI, szAlg, Response, szQop, szCNonce, szOpaque);
  else if (szQop != NULL)
    sprintf(szAuthorization, "Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", algorithm=%s, response=\"%s\", qop=%s, nc=00000001, cnonce=\"%s\"",
                             szLogin, szRealm, szNonce, szURI, szAlg, Response, szQop, szCNonce);
  else if (szOpaque != NULL)
    sprintf(szAuthorization, "Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", algorithm=%s, response=\"%s\", opaque=\"%s\"",
                             szLogin, szRealm, szNonce, szURI, szAlg, Response, szOpaque);
  else
    sprintf(szAuthorization, "Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", algorithm=%s, response=\"%s\"",
                             szLogin, szRealm, szNonce, szURI, szAlg, Response);

  FREE(szAlg);
  FREE(szRealm);
  FREE(szNonce);
  FREE(szQop);
  FREE(szOpaque);
  FREE(szURI);

  nSendBufferSize = 5 + strlen(_psSessionData->szDir) + 17 + strlen(_psSessionData->szHostHeader) +
                    14 + strlen(_psSessionData->szUserAgent) + 17 + strlen(szAuthorization) + 26 +
                    strlen(_psSessionData->szCustomHeader) + 2;

  bufSend = malloc(nSendBufferSize + 1);
  memset(bufSend, 0, nSendBufferSize + 1);

  sprintf((char*)bufSend, "GET /%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAuthorization: %s\r\nConnection: keep-alive\r\n%s\r\n", 
          _psSessionData->szDir, _psSessionData->szHostHeader, _psSessionData->szUserAgent, szAuthorization, _psSessionData->szCustomHeader);

  if (medusaSend(hSocket, bufSend, nSendBufferSize, 0) < 0)
  {
    writeError(ERR_ERROR, "[%s] failed: medusaSend was not successful", MODULE_NAME);
    return FAILURE;
  }

  FREE(szAuthorization);
  FREE(bufSend);

  return SUCCESS;
}

int tryLogin(int hSocket, _MODULE_DATA* _psSessionData, sLogin** login, char* szLogin, char* szPassword)
{
  unsigned char* pReceiveBuffer = NULL;
  int nReceiveBufferSize = 0;
  int nRet = SUCCESS;
  char* pTemp = NULL;
  char szStatusCode[4];

  switch(_psSessionData->nAuthType)
  {
    case AUTH_NONE:
      writeError(ERR_DEBUG_MODULE, "[%s] No authentication required.", MODULE_NAME);
      (*login)->iResult = LOGIN_RESULT_SUCCESS;
      setPassResult(*login, szPassword);
      return MSTATE_NEW;  
      break;
    case AUTH_BASIC:
      writeError(ERR_DEBUG_MODULE, "[%s] Sending Basic Authentication.", MODULE_NAME);
      nRet = sendAuthBasic(hSocket, _psSessionData, szLogin, szPassword);
      break;
    case AUTH_NTLM:
      writeError(ERR_DEBUG_MODULE, "[%s] Sending Windows Integrated (NTLM) Authentication.", MODULE_NAME);
      nRet = sendAuthNTLM(hSocket, _psSessionData, szLogin, szPassword);
      break;
    case AUTH_DIGEST:
      writeError(ERR_DEBUG_MODULE, "[%s] Sending Digest Authentication.", MODULE_NAME);
      nRet = sendAuthDigest(hSocket, _psSessionData, szLogin, szPassword);
      break;
    default:
      break;
  }

  if (nRet == FAILURE)
  {
    writeError(ERR_ERROR, "[%s] Failed during sending of authentication data.", MODULE_NAME);
    (*login)->iResult = LOGIN_RESULT_UNKNOWN;
    setPassResult(*login, szPassword);
    return MSTATE_EXITING;  
  }

  writeError(ERR_DEBUG_MODULE, "[%s] Retrieving server response.", MODULE_NAME);
  nReceiveBufferSize = 0;
  if ((medusaReceiveRegex(hSocket, &pReceiveBuffer, &nReceiveBufferSize, "HTTP/1.* [0-9]{3,3} .*\r\n") == FAILURE) || (pReceiveBuffer == NULL))
  {
    writeError(ERR_ERROR, "[%s] Failed: Unexpected or no data received: %s", MODULE_NAME, pReceiveBuffer);
    return FAILURE;
  }

  pTemp = strstr((char*)pReceiveBuffer, "HTTP/1.");
  pTemp = index(pTemp, ' ') + 1;
  memset((char*)index(pTemp, 0x0d), 0, 1);
 
  memset(szStatusCode, 0, 4);
  strncpy(szStatusCode, pTemp, 3);

  switch (atoi(szStatusCode))
  {
    case 200:
      writeError(ERR_DEBUG_MODULE, "[%s] 200 OK", MODULE_NAME);
      (*login)->iResult = LOGIN_RESULT_SUCCESS;
      nRet = MSTATE_NEW; 
     break;
    case 301:
      writeError(ERR_DEBUG_MODULE, "[%s] 301 Moved Permanently", MODULE_NAME);
      (*login)->iResult = LOGIN_RESULT_SUCCESS;
      nRet = MSTATE_NEW; 
     break;
    case 302:
      writeError(ERR_DEBUG_MODULE, "[%s] 302 Found", MODULE_NAME);
      (*login)->iResult = LOGIN_RESULT_SUCCESS;
      nRet = MSTATE_NEW; 
      break;
    case 401:
      writeError(ERR_DEBUG_MODULE, "[%s] 401 Unauthorized", MODULE_NAME);
      (*login)->iResult = LOGIN_RESULT_FAIL;
      nRet = MSTATE_NEW; 
      break;
    case 403:
      writeError(ERR_DEBUG_MODULE, "[%s] 403 Forbidden", MODULE_NAME);
      (*login)->iResult = LOGIN_RESULT_SUCCESS;
      nRet = MSTATE_NEW; 
      break;
    case 404:
      writeError(ERR_DEBUG_MODULE, "[%s] 404 Not Found", MODULE_NAME);
      (*login)->iResult = LOGIN_RESULT_SUCCESS;
      nRet = MSTATE_NEW; 
      break;
    default:
      writeError(ERR_ERROR, "Unexpected return code for %s:%s (%s)", szLogin, szPassword, pTemp);

      (*login)->pErrorMsg = malloc( 24 + strlen(pTemp) + 1 );
      memset((*login)->pErrorMsg, 0, 24 + strlen(pTemp) + 1 );
      sprintf((*login)->pErrorMsg, "Unexpected return code: %s", pTemp);
      (*login)->iResult = LOGIN_RESULT_ERROR;
      nRet = MSTATE_EXITING; 
      break;
  }

  FREE(pReceiveBuffer);
  setPassResult(*login, szPassword);
  return nRet;  
}

#else

void summaryUsage(char **ppszSummary)
{
  // Memory for ppszSummary will be allocated here - caller is responsible for freeing it
  int  iLength = 0;

  if (*ppszSummary == NULL)
  {
    iLength = strlen(MODULE_SUMMARY_USAGE) + strlen(MODULE_VERSION) + strlen(MODULE_SUMMARY_FORMAT) + strlen(OPENSSL_WARNING) + 1;
    *ppszSummary = (char*)malloc(iLength);
    memset(*ppszSummary, 0, iLength);
    snprintf(*ppszSummary, iLength, MODULE_SUMMARY_FORMAT_WARN, MODULE_SUMMARY_USAGE, MODULE_VERSION, OPENSSL_WARNING);
  }
  else
  {
    writeError(ERR_ERROR, "%s reports an error in summaryUsage() : ppszSummary must be NULL when called", MODULE_NAME);
  }
}

void showUsage()
{
  writeVerbose(VB_NONE, "%s (%s) %s :: %s\n", MODULE_NAME, MODULE_VERSION, MODULE_AUTHOR, MODULE_SUMMARY_USAGE);
  writeVerbose(VB_NONE, "** Module was not properly built. Is OPENSSL installed correctly? **");
  writeVerbose(VB_NONE, "");
}

int go(sLogin* logins, int argc, char *argv[])
{
  writeVerbose(VB_NONE, "%s (%s) %s :: %s\n", MODULE_NAME, MODULE_VERSION, MODULE_AUTHOR, MODULE_SUMMARY_USAGE);
  writeVerbose(VB_NONE, "** Module was not properly built. Is OPENSSL installed correctly? **");
  writeVerbose(VB_NONE, "");
  return FAILURE;
}

#endif
