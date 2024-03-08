/***************************************************************************
 *   web-form.c                                                            *
 *   Copyright (C) 2007 by Luciano Bello                                   *
 *   luciano@debian.org.ar                                                 *
 *                                                                         *
 *   Implementation of a web form brute force module for                   *
 *   medusa. Module concept by the one-and-only Foofus.                    *
 *   Protocol stuff based on the original medusa http code by              *
 *   fizzgig (fizzgig@foofus.net).                                         *
 *                                                                         *
 *                                                                         *
 *   CHANGE LOG                                                            *
 *   08/10/2007 - Created by Luciano Bello (luciano@debian.org)            *
 *   08/24/2007 - Minor modification by JoMo-Kun                           *
 *   03/05/2024 - Added support for custom HTTP response codes by Martijn  *
 *                Fleuren. Also cleaned up the code a bit                  *
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
 ***************************************************************************/

#include "module.h"

#define MODULE_NAME    "web-form.mod"
#define MODULE_AUTHOR  "Luciano Bello <luciano@linux.org.ar>"
#define MODULE_SUMMARY_USAGE  "Brute force module for web forms"
#define MODULE_VERSION    "2.1"
#define MODULE_VERSION_SVN "$Id: web-form.c 9217 2015-05-07 18:07:03Z jmk $"
#define MODULE_SUMMARY_FORMAT  "%s : version %s"
#define MODULE_SUMMARY_FORMAT_WARN  "%s : version %s (%s)"
#define OPENSSL_WARNING "No usable OPENSSL. Module disabled."

#ifdef HAVE_LIBSSL

#define HTTP_PORT   80
#define HTTPS_PORT 443

typedef enum FormType {
    FORM_UNKNOWN
  , FORM_GET
  , FORM_POST
} FormTypeT;

typedef struct __MODULE_DATA {
  char *szDir;
  char *szHostHeader;
  char *szUserAgent;
  int nFormType;
  char *szDenySignal;
  char *szFormData;
  char *szFormRest;
  char *szFormUser;
  char *szFormPass;
  char *szCustomHeader;
  int nCustomHeaders;
} _MODULE_DATA;

// Tells us whether we are to continue processing or not
enum MODULE_STATE {
  MSTATE_NEW,
  MSTATE_RUNNING,
  MSTATE_EXITING,
  MSTATE_COMPLETE
};

// Incomplete list of HTTP status codes
typedef enum HttpStatusCode {
    HTTP_STATUS_PARSE_ERR   = -1  // This is not elegant but it works
  , HTTP_STATUS_NOT_IMPL    = -2  // This is not elegant but it works

  // Group 2xx
  , HTTP_OK                 = 200

  // Group 3xx
  , HTTP_MOVED_PERMANENTLY  = 301
  , HTTP_FOUND              = 302
  , HTTP_TEMPORARY_REDIRECT = 307
  , HTTP_PERMANENT_REDIRECT = 308

  // Group 4xx
  , HTTP_BAD_REQUEST        = 400
  , HTTP_UNAUTHORIZE        = 401
  , HTTP_FORBIDDEN          = 403
  , HTTP_NOT_FOUND          = 404

} HttpStatusCodeT;

/**
 * Given a string, attempt to parse the Http reponse code from it. We assume
 * that the string contains a HTTP response similar to
 *
 * HTTP/1.1 200 OK
 *
 * Or
 *
 * HTTP/<version> <statuscode> <statusname>
 *
 * NOTE: We can also use strtok() to perform parsing but it is MT-Unsafe so
 * therefore we avoid it.
 */
static HttpStatusCodeT parseHttpStatusCode(char * buf) {
  HttpStatusCodeT tmp = HTTP_STATUS_PARSE_ERR; // default is to error

  char * ptr = buf;

  if (buf != NULL) {
    // Find the first space and error out if the space was not found. Convert
    // the found ptr to a status code.
    ptr = strchr(buf, ' ');
    if (!ptr) return tmp;
    tmp = (HttpStatusCodeT) strtol(ptr, NULL, 10);

    // Basically a switch to either implement custom code per status code AND to
    // check whether we have actually defined the status code.
    switch (tmp) {
      // group 2xx
      case HTTP_OK:

      // group 3xx
      case HTTP_FOUND:
      case HTTP_TEMPORARY_REDIRECT:
      case HTTP_PERMANENT_REDIRECT:

      //group 4xx
      case HTTP_BAD_REQUEST:
      case HTTP_UNAUTHORIZE:
      case HTTP_FORBIDDEN:
      case HTTP_NOT_FOUND:
        break;

      // The last one for if we have not implemented the status code.
      default:
        tmp = HTTP_STATUS_NOT_IMPL;
        break;
    }
  }

  return tmp;
}

/**
 * Attempt to parse the value of the Location header field from a string,
 * contained at any position.
 *
 * Assumes that the location header format is: "Location: <string>\r\n" with
 * exactly one space.
 */
static void parseLocationHeaderValue(char * src, char ** dst) {

  // Find the location header position in src, determine its length. 10 is the
  // length of "Location: " which places the pointer at the beginning of the
  // value
  char * locationPtr = (char *) (10 + (long) strstr(src, "Location: "));
  char * crPtr     = strchr(locationPtr, '\r');

  // Copy the string to the destination, add the '\0' terminator at the end
  memcpy(*dst, locationPtr, crPtr - locationPtr + 1);
  (*dst)[crPtr - locationPtr] = '\0';
}

// Forward declarations
int tryLogin(int hSocket, _MODULE_DATA* _psSessionData, sLogin** login, char* szLogin, char* szPassword);
int initModule(_MODULE_DATA* _psSessionData, sLogin* login);

/**
 * Tell medusa how many parameters this module allows, which is 0.
 */
int getParamNumber() {
  return 0;
}

/**
 * Display module usage information
 */
void showUsage() {
  writeVerbose(VB_NONE, "%s (%s) %s :: %s\n", MODULE_NAME, MODULE_VERSION, MODULE_AUTHOR, MODULE_SUMMARY_USAGE);
  writeVerbose(VB_NONE, "Available module options:\n"
                        "  USER-AGENT:?       User-agent value. Default: \"I'm not Mozilla, I'm Ming Mong\".\n"
                        "  FORM:?             Target form to request. Default: \"/\"\n"
                        "  DENY-SIGNAL:?      Authentication failure message. Attempt flagged as successful if text is not present in\n"
                        "                     server response. Default: \"Login incorrect\"\n"
                        "  CUSTOM-HEADER:?    Custom HTTP header.\n"
                        "                     More headers can be defined by using this option several times.\n"
                        "  FORM-DATA:<METHOD>?<FIELDS>\n"
                        "                     Methods and fields to send to web service. Valid methods are GET and POST. The actual form\n"
                        "                     data to be submitted should also be defined here. Specifically, the fields: username and\n"
                        "                     password. The username field must be the first, followed by the password field.\n"
                        "                     Default: \"post?username=&password=\"\n"
                        "\n"
                        "Usage example: \"-M web-form -m USER-AGENT:\"g3rg3 gerg\" -m FORM:\"webmail/index.php\" -m DENY-SIGNAL:\"deny!\"\n"
                        "                 -m FORM-DATA:\"post?user=&pass=&submit=True\" -m CUSTOM-HEADER:\"Cookie: name=value\"\n");
}

// The "main" of the medusa module world - this is what gets called to actually do the work
int go(sLogin* logins, int argc, char *argv[])
{
  int i;
  char *strtok_ptr, *pOpt, *pOptTmp;
  _MODULE_DATA *psSessionData;
  psSessionData = malloc(sizeof(_MODULE_DATA));
  memset(psSessionData, 0, sizeof(_MODULE_DATA));

  if ((argc < 0) || (argc > 5))
  {
    writeError(ERR_ERROR, "%s: Incorrect number of parameters passed to module (%d). Use \"-q\" option to display module usage.", MODULE_NAME, argc);
    return FAILURE;
  }
  else
  {
    // Parameters are good - make module go now
    writeError(ERR_DEBUG_MODULE, "OMG teh %s module has been called!!", MODULE_NAME);

    for (i = 0; i<argc; i++) {
      pOptTmp = strdup(argv[i]);
      writeError(ERR_DEBUG_MODULE, "Processing complete option: %s", pOptTmp);
      pOpt = strtok_r(pOptTmp, ":", &strtok_ptr);
      writeError(ERR_DEBUG_MODULE, "Processing option: %s", pOpt);

      if (strcmp(pOpt, "FORM") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if ( pOpt )
        {
          psSessionData->szDir = strdup(pOpt);
        }
        else
          writeError(ERR_WARNING, "Method FORM requires value to be set.");
      }
      else if (strcmp(pOpt, "DENY-SIGNAL") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if ( pOpt )
        {
          psSessionData->szDenySignal= strdup(pOpt);
        }
        else
          writeError(ERR_WARNING, "Method DENY-SIGNAL requires value to be set.");
      }
      else if (strcmp(pOpt, "FORM-DATA") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if ( pOpt )
        {
          psSessionData->szFormData = strdup(pOpt);
        }
        else
          writeError(ERR_WARNING, "Method FORM-DATA requires value to be set.");
      }
      else if (strcmp(pOpt, "USER-AGENT") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if ( pOpt )
        {
          psSessionData->szUserAgent = strdup(pOpt);
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
          if ( psSessionData->nCustomHeaders == 0 )
          {
            psSessionData->szCustomHeader = malloc(strlen(pOpt) + 1);
            memset(psSessionData->szCustomHeader, 0, strlen(pOpt) + 3);
            strcpy(psSessionData->szCustomHeader, pOpt);
            strncpy(psSessionData->szCustomHeader + strlen(pOpt), "\r\n", 2);
            psSessionData->nCustomHeaders = 1;
          }
          else
          {
            int oldSize = strlen(psSessionData->szCustomHeader);
            psSessionData->szCustomHeader = realloc(psSessionData->szCustomHeader, oldSize + strlen(pOpt) + 3);
            memset(psSessionData->szCustomHeader + oldSize, 0, strlen(pOpt) + 3);
            strcpy(psSessionData->szCustomHeader + oldSize, pOpt);
            strncpy(psSessionData->szCustomHeader + oldSize + strlen(pOpt), "\r\n", 2);
            psSessionData->nCustomHeaders += 1;
          }
        }
        else
          writeError(ERR_WARNING, "Method CUSTOM-HEADER requires value to be set.");
      }
      else
      {
        writeError(ERR_WARNING, "Invalid method: %s.", pOpt);
      }

      free(pOptTmp);
    }
    initModule(psSessionData, logins);
  }

  free(psSessionData);
  return SUCCESS;
}

int initModule(_MODULE_DATA *_psSessionData, sLogin* _psLogin)
{
  int hSocket = -1;
  enum MODULE_STATE nState = MSTATE_NEW;
  char *pStrtokSavePtr = NULL;
  char * pTemp = NULL;
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
    writeError(ERR_DEBUG_MODULE, "[%s] module started for host: %s - no more available users to test.", MODULE_NAME);
    nState = MSTATE_COMPLETE;
  }

  memset(&params, 0, sizeof(sConnectParams));
  if (_psLogin->psServer->psAudit->iPortOverride > 0)
    params.nPort = _psLogin->psServer->psAudit->iPortOverride;
  else if (_psLogin->psServer->psHost->iUseSSL > 0)
    params.nPort = HTTPS_PORT;
  else
    params.nPort = HTTP_PORT;
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

        if (hSocket < 0)
        {
          writeError(ERR_NOTICE, "%s: failed to connect, port %d was not open on %s", MODULE_NAME, params.nPort, _psLogin->psServer->pHostIP);
          _psLogin->iResult = LOGIN_RESULT_UNKNOWN;
          setPassResult(_psLogin, psCredSet->pPass);
          return FAILURE;
        }

        /* Set request parameters */
        if (!_psSessionData->szDir) {
          _psSessionData->szDir = malloc(2);
          memset(_psSessionData->szDir, 0, 2);
          sprintf(_psSessionData->szDir, "/");
        }

        if (!_psSessionData->szHostHeader) {
          nBufLength = strlen(_psLogin->psServer->psHost->pHost) + 1 + log(params.nPort) + 1;
          _psSessionData->szHostHeader = malloc(nBufLength + 1);
          memset(_psSessionData->szHostHeader, 0, nBufLength + 1);
          sprintf(_psSessionData->szHostHeader, "%s:%d", _psLogin->psServer->psHost->pHost, params.nPort);
        }

        if (!_psSessionData->szFormData) {
          _psSessionData->szFormRest = malloc(1);
          memset(_psSessionData->szFormRest, 0, 1);

          _psSessionData->szFormUser = malloc(10);
          memset(_psSessionData->szFormUser, 0, 10);
          sprintf(_psSessionData->szFormUser, "username=");

          _psSessionData->szFormPass = malloc(10);
          memset(_psSessionData->szFormPass, 0, 10);
          sprintf(_psSessionData->szFormPass, "password=");

          _psSessionData->nFormType = FORM_POST;
        }
        else {
          /* Only set user-supplied form data on first pass */
          if (_psSessionData->szFormUser == NULL)
          {
            pTemp = strtok_r(_psSessionData->szFormData, "?", &pStrtokSavePtr);
            writeError(ERR_DEBUG_MODULE, "[%s] User-supplied Form Action Method: %s", MODULE_NAME, pTemp);
            if(strncasecmp(pTemp, "POST", 4) == 0)
              _psSessionData->nFormType = FORM_POST;
            else if(strncasecmp(pTemp, "GET", 3) == 0)
              _psSessionData->nFormType = FORM_GET;
            else
              _psSessionData->nFormType = FORM_UNKNOWN;

            pTemp = strtok_r(NULL, "&", &pStrtokSavePtr);
            if (pTemp != NULL)
            {
              _psSessionData->szFormUser = strdup(pTemp);
            }

            pTemp = strtok_r(NULL, "&", &pStrtokSavePtr);
            if (pTemp != NULL)
            {
              _psSessionData->szFormPass = strdup(pTemp);
            }

            pTemp = strtok_r(NULL, "", &pStrtokSavePtr);
            if (pTemp != NULL)
            {
              _psSessionData->szFormRest = strdup(pTemp);
            }
          }

          writeError(ERR_DEBUG_MODULE, "[%s] User-supplied Form User Field: %s", MODULE_NAME, _psSessionData->szFormUser);
          writeError(ERR_DEBUG_MODULE, "[%s] User-supplied Form Pass Field: %s", MODULE_NAME, _psSessionData->szFormPass);
          writeError(ERR_DEBUG_MODULE, "[%s] User-supplied Form Rest Field: %s", MODULE_NAME, _psSessionData->szFormRest);

          if ((_psSessionData->nFormType == FORM_UNKNOWN) || (_psSessionData->szFormUser == NULL) || (_psSessionData->szFormPass == NULL))
          {
            writeError(ERR_WARNING, "Invalid FORM-DATA format. Using default format: \"post?username=&password=\"");
            _psSessionData->szFormRest = malloc(1);
            memset(_psSessionData->szFormRest, 0, 1);

            _psSessionData->szFormUser = malloc(10);
            memset(_psSessionData->szFormUser, 0, 10);
            sprintf(_psSessionData->szFormUser, "username=");

            _psSessionData->szFormPass = malloc(10);
            memset(_psSessionData->szFormPass, 0, 10);
            sprintf(_psSessionData->szFormPass, "password=");

            _psSessionData->nFormType = FORM_POST;
          }
        }

        if (!_psSessionData->szUserAgent) {
          _psSessionData->szUserAgent = malloc(31);
          memset(_psSessionData->szUserAgent, 0, 31);
          sprintf(_psSessionData->szUserAgent, "I'm not Mozilla, I'm Ming Mong");
        }

        if (!_psSessionData->szDenySignal) {
          _psSessionData->szDenySignal = malloc(19);
          memset(_psSessionData->szDenySignal, 0, 19);
          sprintf(_psSessionData->szDenySignal, "Login Incorrect");
        }

        if (!_psSessionData->szCustomHeader) {
          _psSessionData->szCustomHeader = malloc(1);
          memset(_psSessionData->szCustomHeader, 0, 1);
        }

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
        break;
    }
  }

  /* clean up memory */
  free(_psSessionData->szDir);
  free(_psSessionData->szHostHeader);
  free(_psSessionData->szUserAgent);
  free(_psSessionData->szDenySignal);
  free(_psSessionData->szFormData);
  free(_psSessionData->szFormRest);
  free(_psSessionData->szFormUser);
  free(_psSessionData->szFormPass);
  free(_psSessionData->szCustomHeader);
  free(psCredSet);

  return SUCCESS;
}

/* Module Specific Functions */


/**
 * URL-encode a string. Returns a heap-allocated buffer containing the encoded
 * string. The caller is responsible for freeing that buffer when it's no longer
 * needed.
 */
char * urlencodeup(char * szStr){
  size_t iLen = strlen(szStr);

  // Assume the worst case scenario for buffer allocation, which is 3S+1 where S
  // is the length of the input string.
  char * szRet = (char *) calloc(((iLen * 3) + 1), sizeof(char));
  char c = szStr[0];

  size_t j = 0;
  for(size_t i = 0; i < iLen; ++i) {

    c = szStr[i];

#define BETWEEN(LO,X,HI) ((LO) <= (X) && (X) <= (HI))
    if (  BETWEEN('a', c, 'z')
       || BETWEEN('A', c, 'Z')
       || BETWEEN('0', c, '9')) {
      szRet[j] = c;
      j += 1;
    } else {
      snprintf(szRet+j, 4, "%%%02x", (unsigned long) c);
      j += 3;
    }
  }

  szRet[j] = '\0';

  return szRet;
}

int sendPost(int hSocket, _MODULE_DATA* _psSessionData, char* szLogin, char* szPassword)
{
  unsigned char* bufSend = NULL;
  char* bufForm = NULL;
  int nSendBufferSize = 0;
  int nFormBufferSize = 0;
  int nRet = SUCCESS;

  if ((_psSessionData->szFormRest == NULL) || (_psSessionData->szFormRest[0] == 0))
    nFormBufferSize = asprintf(&bufForm, "%s%s&%s%s", _psSessionData->szFormUser, szLogin, _psSessionData->szFormPass, szPassword);
  else
    nFormBufferSize = asprintf(&bufForm, "%s%s&%s%s&%s", _psSessionData->szFormUser, szLogin, _psSessionData->szFormPass, szPassword, _psSessionData->szFormRest);

  nSendBufferSize = asprintf((char **)&bufSend, "POST /%s HTTP/1.0\r\nHost: %s\r\nUser-Agent: %s\r\n%sConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %i\r\n\r\n%s", _psSessionData->szDir, _psSessionData->szHostHeader, _psSessionData->szUserAgent, _psSessionData->szCustomHeader, nFormBufferSize, bufForm);

  if (medusaSend(hSocket, bufSend, nSendBufferSize, 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
    nRet = FAILURE;
  }

  free(bufSend);
  free(bufForm);
  return nRet;
}

int sendGet(int hSocket, _MODULE_DATA* _psSessionData, char* szLogin, char* szPassword)
{
  unsigned char* bufSend = NULL;
  int nSendBufferSize = 0;
  int nRet = SUCCESS;

  if ((_psSessionData->szFormRest == NULL) || (_psSessionData->szFormRest[0] == 0))
    nSendBufferSize = asprintf((char **)&bufSend, "GET /%s?%s%s&%s%s HTTP/1.0\r\nHost: %s\r\nUser-Agent: %s\r\n%sConnection: close\r\n\r\n", _psSessionData->szDir, _psSessionData->szFormUser, szLogin, _psSessionData->szFormPass, szPassword, _psSessionData->szHostHeader, _psSessionData->szUserAgent, _psSessionData->szCustomHeader);
  else
    nSendBufferSize = asprintf((char **)&bufSend, "GET /%s?%s%s&%s%s&%s HTTP/1.0\r\nHost: %s\r\nUser-Agent: %s\r\n%sConnection: close\r\n\r\n", _psSessionData->szDir, _psSessionData->szFormUser, szLogin, _psSessionData->szFormPass, szPassword, _psSessionData->szFormRest, _psSessionData->szHostHeader, _psSessionData->szUserAgent, _psSessionData->szCustomHeader);

  if (medusaSend(hSocket, bufSend, nSendBufferSize, 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
    nRet = FAILURE;
  }

  free(bufSend);
  return nRet;
}

static enum MODULE_STATE _request(int hSocket, _MODULE_DATA* _psSessionData, sLogin ** login, char * szLogin, unsigned char ** pReceiveBuffer, int * nReceiveBufferSize, char * szPassword) {

  int nRet = FAILURE;

  char * szPasswordEncoded = urlencodeup(szPassword);

  switch(_psSessionData->nFormType) {
    case FORM_GET:
      writeError(ERR_DEBUG_MODULE, "[%s] Sending Web Form Authentication (GET).", MODULE_NAME);
      nRet = sendGet(hSocket, _psSessionData, szLogin, szPasswordEncoded);
      break;
    case FORM_POST:
      writeError(ERR_DEBUG_MODULE, "[%s] Sending Web Form Authentication (POST).", MODULE_NAME);
      nRet = sendPost(hSocket, _psSessionData, szLogin, szPasswordEncoded);
      break;
    default:
      break;
  }

  if (nRet == FAILURE) {
    writeError(ERR_ERROR, "[%s] Failed during sending of authentication data.", MODULE_NAME);
    (*login)->iResult = LOGIN_RESULT_UNKNOWN;
    setPassResult(*login, szPassword);
    return MSTATE_EXITING;
  }

  writeError(ERR_DEBUG_MODULE, "[%s] Retrieving server response.", MODULE_NAME);
  *pReceiveBuffer = medusaReceiveLine(hSocket, nReceiveBufferSize);

  if ((*pReceiveBuffer == NULL) || (*pReceiveBuffer[0] == '\0'))
  {
    writeError(ERR_ERROR, "[%s] No data received", MODULE_NAME);
    (*login)->iResult = LOGIN_RESULT_UNKNOWN;
    setPassResult(*login, szPassword);
    return MSTATE_EXITING;
  }

  free(szPasswordEncoded);
}

int tryLogin(int hSocket, _MODULE_DATA* _psSessionData, sLogin** login, char* szLogin, char* szPassword)
{
  unsigned char * pReceiveBuffer = NULL;
  int nReceiveBufferSize;
  int nRet = FAILURE;

  // Perform the request, error out when request failed
  enum MODULE_STATE requestState;
	requestState = _request(hSocket, _psSessionData, login, szLogin, &pReceiveBuffer, &nReceiveBufferSize, szPassword);
  if (requestState == MSTATE_EXITING) return requestState;

  HttpStatusCodeT statusCode = parseHttpStatusCode(pReceiveBuffer);
  writeError(ERR_DEBUG_MODULE, "[%s] HTTP Response code was %3d.", MODULE_NAME, statusCode);

  switch (statusCode) {
    // In this case we can continue as we used to because the 200 OK was
    // expected from the previous code.
    case HTTP_OK:
      break;

    // In this case we have to redo the request, this time requesting the page
    // that is specified in the Location header
    case HTTP_MOVED_PERMANENTLY:
    case HTTP_FOUND:
    case HTTP_TEMPORARY_REDIRECT:
    case HTTP_PERMANENT_REDIRECT:
      writeError(ERR_DEBUG_MODULE, "[%s] Following redicrect.", MODULE_NAME);

      // Get the value of the location header and set the directory to that
      // location, then perform the request again.
      parseLocationHeaderValue(pReceiveBuffer, &_psSessionData->szDir);
      _request(hSocket, _psSessionData, login, szLogin, &pReceiveBuffer, &nReceiveBufferSize, szPassword);

      if (requestState == MSTATE_EXITING)
        return requestState;

      break;

    // The default error case from the old code
    default:
        writeError(ERR_ERROR, "The answer was NOT successfully received, understood, and accepted while trying: user: \"%s\", pass: \"%s\", HTTP status code: %3d", szLogin, szPassword, statusCode);
        (*login)->iResult = LOGIN_RESULT_UNKNOWN;
        setPassResult(*login, szPassword);
        return MSTATE_EXITING;
      break;
  }

  while (pReceiveBuffer != NULL && (strcasestr((char *)pReceiveBuffer, _psSessionData->szDenySignal) == NULL) && (pReceiveBuffer[0] != '\0'))
  {
    free(pReceiveBuffer);
    pReceiveBuffer = medusaReceiveLine(hSocket, &nReceiveBufferSize);
  }

  if(pReceiveBuffer != NULL && strcasestr((char *)pReceiveBuffer, _psSessionData->szDenySignal) != NULL)
  {
    (*login)->iResult = LOGIN_RESULT_FAIL;
    setPassResult(*login, szPassword);
    return MSTATE_NEW;
  }

  writeError(ERR_DEBUG_MODULE, "Login Successful");
  (*login)->iResult = LOGIN_RESULT_SUCCESS;
  setPassResult(*login, szPassword);

  return MSTATE_NEW;
}

#else

/**
 * Memory for ppszSummary will be allocated here - caller is responsible for freeing it
 */

void showUsage() {
  writeVerbose(VB_NONE, "%s (%s) %s :: %s\n", MODULE_NAME, MODULE_VERSION, MODULE_AUTHOR, MODULE_SUMMARY_USAGE);
  writeVerbose(VB_NONE, "** Module was not properly built. Is OPENSSL installed correctly? **");
  writeVerbose(VB_NONE, "");
}

int go(sLogin* logins, int argc, char *argv[]) {
  writeVerbose(VB_NONE, "%s (%s) %s :: %s\n", MODULE_NAME, MODULE_VERSION, MODULE_AUTHOR, MODULE_SUMMARY_USAGE);
  writeVerbose(VB_NONE, "** Module was not properly built. Is OPENSSL installed correctly? **");
  writeVerbose(VB_NONE, "");

  return FAILURE;
}

#endif

void summaryUsage(char **ppszSummary) {
  int  iLength = 0;

  if (*ppszSummary == NULL) {
    iLength = strlen(MODULE_SUMMARY_USAGE MODULE_VERSION MODULE_SUMMARY_FORMAT OPENSSL_WARNING) + 1;
    *ppszSummary = (char *) calloc(iLength, sizeof(char));
    memset(*ppszSummary, 0, iLength);
    snprintf(*ppszSummary, iLength, MODULE_SUMMARY_FORMAT_WARN, MODULE_SUMMARY_USAGE, MODULE_VERSION, OPENSSL_WARNING);
  } else {
    writeError(ERR_ERROR, "%s reports an error in summaryUsage() : ppszSummary must be NULL when called", MODULE_NAME);
  }
}
