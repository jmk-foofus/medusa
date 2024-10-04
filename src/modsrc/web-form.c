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
 *                Fleuren. Also spent a few days as janitor to this code   *
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

#define MODULE_NAME                 "web-form.mod"
#define MODULE_AUTHOR               "Luciano Bello <luciano@linux.org.ar>"
#define MODULE_SUMMARY_USAGE        "Brute force module for web forms"
#define MODULE_VERSION              "3.0"
#define MODULE_SUMMARY_FORMAT       "%s : version %s%s"

#ifdef HAVE_LIBSSL
#define OPENSSL_WARNING             ""
#else
#define OPENSSL_WARNING             " (No usable OPENSSL. Module disabled.)"
#endif

#define HTTP_PORT   80
#define HTTPS_PORT 443

#define MODULE_DEFAULT_USER_AGENT   "I'm not Mozilla, I'm Ming Mong"
#define MODULE_DEFAULT_DENY_SIGNAL  "Login incorrect."
#define MODULE_DEFAULT_USERNAME_KEY "username="
#define MODULE_DEFAULT_PASSWORD_KEY "password="
#define MODULE_DEFAULT_FORM_TYPE    FORM_POST

#define GET_STR  "GET"
#define POST_STR "POST"

#if MODULE_DEFAULT_FORM_TYPE == FORM_POST
#define MODULE_DEFAULT_FORM_TYPE_STR POST_STR
#else
#define MODULE_DEFAULT_FORM_TYPE_STR GET_STR
#endif

// Macro definitions which improve code readability

// Inclusive range condition check: lo <= x <= hi
#define BETWEEN(LO,X,HI) ((LO) <= (X) && (X) <= (HI))

// Allocating char buffers of a certain length, this is common
#define charcalloc(n) (char *) calloc(n, sizeof(char))

// Bounded comparison of a string X to a constant string Y
#define EQ_TO_STR_CONST(X,Y) !strncmp((X), (Y), sizeof(Y))

#ifdef HAVE_LIBSSL

typedef enum FormType {
    FORM_UNKNOWN
  , FORM_GET
  , FORM_POST
} FormTypeT;

typedef struct ModuleData {
  FormTypeT formType;
  char * resourcePath;     // The path to the resource to which we send the login request
  char * hostHeader;       // Host: header value
  char * userAgentHeader;  // User-Agent: header value
  char * denySignal;       // String on which to _fail_ a login
  char * formData;         //
  char * formRest;         // Other form parameters irrelevant for brute force login
  char * formUserKey;      // String for the username key value of the form
  char * formPassKey;      // String for the password key value of the form
  char * customHeaders;    // Custom headers
  int nCustomHeaders;      // Number of custom headers
  int changedRequestType;
} ModuleDataT;

ModuleDataT * newModuleData() {
  return (ModuleDataT *) calloc(1, sizeof(ModuleDataT));
}

void freeModuleData(ModuleDataT * moduleData) {
  if (!moduleData) return;

  free(moduleData->resourcePath);
  free(moduleData->hostHeader);
  free(moduleData->userAgentHeader);
  free(moduleData->denySignal);
  free(moduleData->formData);
  free(moduleData->formRest);
  free(moduleData->formUserKey);
  free(moduleData->formPassKey);
  free(moduleData->customHeaders);

  free(moduleData);
}

// Tells us whether we are to continue processing or not
typedef enum ModuleState {
  MSTATE_INITIALIZE,
  MSTATE_NEW,
  MSTATE_RUNNING,
  MSTATE_EXITING,
  MSTATE_COMPLETE
} ModuleStateT;

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
  , HTTP_UNAUTHORIZED       = 401
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
  HttpStatusCodeT ret = HTTP_STATUS_PARSE_ERR; // default is to error

  if (buf) {

    char * ptr = buf;

    // Find the first space and error out if the space was not found. Convert
    // the found ptr to a status code.
    ptr = strchr(buf, ' ');
    if (!ptr) return ret;

    ret = (HttpStatusCodeT) strtol(ptr, NULL, 10);

    // Basically a switch to either implement custom code per status code AND to
    // check whether we have actually defined the status code.
    switch (ret) {
      // group 2xx
      case HTTP_OK:
        break;

      // group 3xx
      case HTTP_MOVED_PERMANENTLY:
      case HTTP_FOUND:
      case HTTP_TEMPORARY_REDIRECT:
      case HTTP_PERMANENT_REDIRECT:
        break;

      //group 4xx
      case HTTP_BAD_REQUEST:
      case HTTP_UNAUTHORIZED:
      case HTTP_FORBIDDEN:
      case HTTP_NOT_FOUND:
        break;

      // The last one for if we have not implemented the status code.
      default:
        ret = HTTP_STATUS_NOT_IMPL;
        break;
    }
  }

  return ret;
}

/**
 * Attempt to parse the value of a header field from a string, contained at any
 * position.
 *
 * Assumes that the header format is: "header-name: header-value\r\n" with
 * exactly one space.
 *
 * TODO: This is way stricter than specified in
 * https://www.rfc-editor.org/rfc/rfc2616#section-4.2
 *
 * NOTE: this is not really parsing, this is linear searching. Implement a
 * proper parser if you're going to use this often. Shlemiel the painter
 */
static char * _findHeaderValue(const char * header, char * src) {

  char * ret = NULL;

  if (src) {
    char * locationPtr = (char *) ((long) strcasestr(src, header) + strlen(header));
    char * valuePtr    = NULL;

    if (locationPtr) {
      // skip linear whitespace
      for ( ; isspace(*locationPtr); ++locationPtr);

      // consume non-whitespace characters
      for ( valuePtr = locationPtr; !isspace(*valuePtr); ++valuePtr);

      // NOTE: we don't have to check valueptr since it is set to locationPtr
      // (checked before to be nonzero) and only incremented afterwards.

      size_t size = valuePtr - locationPtr + 1;
      ret = charcalloc(size);
      memcpy(ret, locationPtr, size);
      ret[valuePtr - locationPtr] = '\0';
    }
  }

  return ret;
}

static char * findLocationHeaderValue(char * src) {
  return _findHeaderValue("\r\nLocation:", src);
}

// Forward declarations (mini .h file)
int tryLogin(int hSocket, ModuleDataT* _moduleData, sLogin ** login, char * szLogin, char * szPassword);
int initModule(ModuleDataT * _moduleData, sLogin * login);

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
                        "  USER-AGENT:?       User-agent value. Default: \"" MODULE_DEFAULT_USER_AGENT "\".\n"
                        "  FORM:?             Target form to request. Default: \"/\"\n"
                        "  DENY-SIGNAL:?      Authentication failure message. Attempt flagged as successful if text is not present in\n"
                        "                     server response. Default: \"" MODULE_DEFAULT_DENY_SIGNAL "\"\n"
                        "  CUSTOM-HEADER:?    Custom HTTP header.\n"
                        "                     More headers can be defined by using this option several times.\n"
                        "  FORM-DATA:<METHOD>?<FIELDS>\n"
                        "                     Methods and fields to send to web service. Valid methods are GET and POST. The actual form\n"
                        "                     data to be submitted should also be defined here. Specifically, the fields: username and\n"
                        "                     password. The username field must be the first, followed by the password field.\n"
                        "                     Default: \"post?" MODULE_DEFAULT_USERNAME_KEY "&" MODULE_DEFAULT_PASSWORD_KEY "\"\n"
                        "\n"
                        "Usage example: \"-M web-form -m USER-AGENT:\"g3rg3 gerg\" -m FORM:\"webmail/index.php\" -m DENY-SIGNAL:\"deny!\"\n"
                        "                 -m FORM-DATA:\"post?user=&pass=&submit=True\" -m CUSTOM-HEADER:\"Cookie: name=value\"\n");
}

/**
 * Set module command line options. This sets the values passed to the program
 * with the -m option. These are one of
 *
 *  option            value stored in struct field
 *  ----------------------------------------------
 *  FORM              resourcePath
 *  DENY-SIGNAL       denySignal
 *  FORM-DATA         formData
 *  USER-AGENT        userAgentHeader
 *  CUSTOM-HEADER     customHeaders
 *
 *  CUSTOM-HEADER is allowed to be specified multiple times
 */
static void setOption(char ** saveptr1, char ** dst, char * option) {

  char * optarg = strtok_r(NULL, "\0", saveptr1);
  writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", optarg);

  if (optarg) {
    *dst = strdup(optarg);
  } else {
    writeError(ERR_WARNING, "Option %s requires an argument.", option);
  }
}

/**
 * The "main" of the medusa module world - this is what gets called to actually
 * do the work
 */
int go(sLogin* logins, int argc, char * argv[]) {
  char * strtokPtr = NULL
     , * option    = NULL
     , * pOptTmp   = NULL
     ;

  ModuleDataT * moduleData = newModuleData();

  writeError(ERR_DEBUG_MODULE, "OMG teh %s module has been called!!", MODULE_NAME); // Funny artifact

  /**
   * Process module parameters, this is a poor-mans version of getopt for this
   * specific case.
   *
   * TODO: Why is argv[] duplicated per pass, can't the options just work on
   * the original arguments? ... figure out strtok
   */

  for (size_t i = 0; i < argc; ++i) {
    pOptTmp = strdup(argv[i]);
    writeError(ERR_DEBUG_MODULE, "Processing complete option: %s", pOptTmp);

    option = strtok_r(pOptTmp, ":", &strtokPtr);
    writeError(ERR_DEBUG_MODULE, "Processing option: %s", option);

    // FORM:<resource path>
    if (EQ_TO_STR_CONST(option, "FORM")) {
      setOption(&strtokPtr, &moduleData->resourcePath, "FORM");
    }

    // DENY-SIGNAL:<string to test for invalid logins>
    else if (EQ_TO_STR_CONST(option, "DENY-SIGNAL")) {
      setOption(&strtokPtr, &moduleData->denySignal, "DENY-SIGNAL");
    }

    // FORM-DATA:<method>?<username_key>=&<password_key>=&<form_rest>
    else if (EQ_TO_STR_CONST(option, "FORM-DATA")) {
      setOption(&strtokPtr, &moduleData->formData, "FORM-DATA");
    }

    // USER-AGENT:<user agent string>
    else if (EQ_TO_STR_CONST(option, "USER-AGENT")) {
      setOption(&strtokPtr, &moduleData->userAgentHeader, "USER-AGENT");
    }

    // CUSTOM-HEADER:<custom header>
    // This can be specified multiple times
    //
    // TODO: String copying should be bounded, but how much?
    else if (EQ_TO_STR_CONST(option, "CUSTOM-HEADER")) {
      option = strtok_r(NULL, "\0", &strtokPtr);
      writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", option);

      if (option != NULL) {
        if (moduleData->nCustomHeaders == 0) {
          // The first custom header
          moduleData->customHeaders = charcalloc(strlen(option) + 1);
          sprintf(moduleData->customHeaders, "%s\r\n", option);

        } else {
          // successive custom headers: Copy the old string, enlarge the
          // buffer and then reformat. man sprintf explicitly forbids reading
          // and writing to the same buffer, so we have to copy.
          char * tmp = strdup(moduleData->customHeaders);

          moduleData->customHeaders =
            (char *) reallocarray( moduleData->customHeaders
                                 , strlen(tmp) + strlen(option) + 3
                                 , sizeof(char));

          sprintf(moduleData->customHeaders, "%s%s\r\n", tmp, option);

          free(tmp);
        }

        ++moduleData->nCustomHeaders;

      } else {
        writeError(ERR_WARNING, "Method CUSTOM-HEADER requires value to be set.");
      }

    } else {
      writeError(ERR_WARNING, "Invalid method: %s.", option);
    }
    free(pOptTmp);
  }

  initModule(moduleData, logins);

  // clean up
  freeModuleData(moduleData);

  return SUCCESS;
}

/**
 * Helper macro for setting default string value key-value pairs if command
 * line arguments have not been set. Note that these should only be used on
 * ModuleDataT, because the freeModuleData() on the struct will also free the
 * content. If this is ussed anywhere else, then the programmer is responsible
 * for freeing the memory.
 */

#define _setDefaultOption(dst, value)  \
  *dst = charcalloc(sizeof(value)); \
  snprintf(*dst, sizeof(value) / sizeof(*value), "%s", value)

int initModule(ModuleDataT * _moduleData, sLogin * _psLogin) {

  int hSocket    = -1
    , nBufLength =  0
    ;

  char * pStrtokSavePtr = NULL
     , * pTemp          = NULL
     ;

  ModuleStateT nState = MSTATE_INITIALIZE;

  sConnectParams params;
  memset(&params, 0, sizeof(sConnectParams));

  sCredentialSet * psCredSet = NULL;
  psCredSet = (sCredentialSet *) calloc(1, sizeof(sCredentialSet));

  if (getNextCredSet(_psLogin, psCredSet) == FAILURE) {
    writeError(ERR_ERROR, "[%s] Error retrieving next credential set to test.", MODULE_NAME);
    nState = MSTATE_COMPLETE;
  } else if (psCredSet->psUser) {
    writeError(ERR_DEBUG_MODULE, "[%s] module started for host: %s user: %s", MODULE_NAME, _psLogin->psServer->pHostIP, psCredSet->psUser->pUser);
  } else {
    writeError(ERR_DEBUG_MODULE, "[%s] module started for host: %s - no more available users to test.", MODULE_NAME);
    nState = MSTATE_COMPLETE;
  }

  // Initialize connection parameters
  if (_psLogin->psServer->psAudit->iPortOverride > 0)
    params.nPort = _psLogin->psServer->psAudit->iPortOverride;
  else if (_psLogin->psServer->psHost->iUseSSL > 0)
    params.nPort = HTTPS_PORT;
  else
    params.nPort = HTTP_PORT;

  initConnectionParams(_psLogin, &params);

  // Choose which connect function to use based SSL/plain.
  int (*_connect)(sConnectParams *) =
    (_psLogin->psServer->psHost->iUseSSL > 0)
      ? &medusaConnectSSL : &medusaConnect;

  while (nState != MSTATE_COMPLETE) {

    switch (nState) {

      // Initialise _moduleData with user provided arguments, or with their
      // defaults.
      case MSTATE_INITIALIZE:

          /* Set request parameters */
          if (!_moduleData->resourcePath) {
            _setDefaultOption(&_moduleData->resourcePath, "/");
          }

          if (!_moduleData->hostHeader) {
            nBufLength = strlen(_psLogin->psServer->psHost->pHost) + 1 + log(params.nPort) + 1;
            _moduleData->hostHeader = charcalloc(nBufLength + 1);
            sprintf(_moduleData->hostHeader, "%s:%d", _psLogin->psServer->psHost->pHost, params.nPort);
          }

          // Set parameters to their defaults if they have not been provided on
          // the command line. String contsants for default username and password
          // keys are MODULE_DEFAULT_USERNAME_KEY and MODULE_DEFAULT_PASSWORD_KEY
          // respectively.
          if (!_moduleData->formData) {
            _setDefaultOption(&_moduleData->formRest, "");
            _setDefaultOption(&_moduleData->formUserKey, MODULE_DEFAULT_USERNAME_KEY);
            _setDefaultOption(&_moduleData->formPassKey, MODULE_DEFAULT_PASSWORD_KEY);
            _moduleData->formType = FORM_POST;

          // Otherwise, set the values to the user specified values.
          } else {

            if (!_moduleData->formUserKey) {
              pTemp = strtok_r(_moduleData->formData, "?", &pStrtokSavePtr);
              writeError(ERR_DEBUG_MODULE, "[%s] User-supplied Form Action Method: %s", MODULE_NAME, pTemp);

              if (!strncasecmp(pTemp, POST_STR, sizeof(POST_STR)))
                _moduleData->formType = FORM_POST;
              else if (!strncasecmp(pTemp, GET_STR, sizeof(GET_STR)))
                _moduleData->formType = FORM_GET;
              else
                _moduleData->formType = FORM_UNKNOWN;

              pTemp = strtok_r(NULL, "&", &pStrtokSavePtr);
              if (pTemp) {
                _moduleData->formUserKey = strdup(pTemp);
              }

              pTemp = strtok_r(NULL, "&", &pStrtokSavePtr);
              if (pTemp) {
                _moduleData->formPassKey = strdup(pTemp);
              }

              pTemp = strtok_r(NULL, "", &pStrtokSavePtr);
              if (pTemp) {
                _moduleData->formRest = strdup(pTemp);
              }
            }

            writeError(ERR_DEBUG_MODULE, "[%s] User-supplied Form User Field: %s", MODULE_NAME, _moduleData->formUserKey);
            writeError(ERR_DEBUG_MODULE, "[%s] User-supplied Form Pass Field: %s", MODULE_NAME, _moduleData->formPassKey);
            writeError(ERR_DEBUG_MODULE, "[%s] User-supplied Form Rest Field: %s", MODULE_NAME, _moduleData->formRest);

            if ((_moduleData->formType == FORM_UNKNOWN) || (_moduleData->formUserKey == NULL) || (_moduleData->formPassKey == NULL))
            {
              writeError(ERR_WARNING, "Invalid FORM-DATA format. Using default format: \"" MODULE_DEFAULT_FORM_TYPE_STR "?" MODULE_DEFAULT_USERNAME_KEY "&" MODULE_DEFAULT_PASSWORD_KEY "\"");
              _moduleData->formRest    = charcalloc(1);

              _moduleData->formUserKey = charcalloc(sizeof(MODULE_DEFAULT_USERNAME_KEY));
              snprintf(_moduleData->formUserKey, sizeof(MODULE_DEFAULT_USERNAME_KEY), MODULE_DEFAULT_USERNAME_KEY);

              _moduleData->formPassKey = charcalloc(sizeof(MODULE_DEFAULT_PASSWORD_KEY));
              snprintf(_moduleData->formPassKey, sizeof(MODULE_DEFAULT_PASSWORD_KEY), MODULE_DEFAULT_PASSWORD_KEY);

              _moduleData->formType = FORM_POST;
            }
          }

          if (!_moduleData->userAgentHeader) {
            _setDefaultOption(&_moduleData->userAgentHeader, MODULE_DEFAULT_USER_AGENT);
          }

          if (!_moduleData->denySignal) {
            _moduleData->denySignal = charcalloc(sizeof(MODULE_DEFAULT_DENY_SIGNAL));
            snprintf(_moduleData->denySignal, sizeof(MODULE_DEFAULT_DENY_SIGNAL), MODULE_DEFAULT_DENY_SIGNAL);
          }

          if (!_moduleData->customHeaders) {
            _moduleData->customHeaders = charcalloc(1);
          }

        nState = MSTATE_NEW;
        break;

      // Create a new connection and close the old one if there is still one
      // open.
      case MSTATE_NEW:

        if (hSocket > 0)
          medusaDisconnect(hSocket);

        // Reset from GET to POST if we had to follow a redirect on the previous
        // cycle
        if (_moduleData->changedRequestType) {
          _moduleData->changedRequestType = 0;
          _moduleData->formType = FORM_POST;
        }

        hSocket = _connect(&params);

        if (hSocket < 0) {
          writeError(ERR_NOTICE, "%s: failed to connect, port %d was not open on %s", MODULE_NAME, params.nPort, _psLogin->psServer->pHostIP);
          _psLogin->iResult = LOGIN_RESULT_UNKNOWN;
          setPassResult(_psLogin, psCredSet->pPass);
          return FAILURE;
        }

        nState = MSTATE_RUNNING;
        break;

      case MSTATE_RUNNING:

        nState = tryLogin(hSocket, _moduleData, &_psLogin, psCredSet->psUser->pUser, psCredSet->pPass);

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

  // clean up
  free(psCredSet);

  return SUCCESS;
}

/* Module Specific Functions */

/**
 * URL-encode a string. Returns a heap-allocated buffer containing the encoded
 * string. The caller is responsible for freeing that buffer when it's no longer
 * needed.
 *
 * NOTE: Only works for ascii, unicode is not yet supported.
 */
#define URL_ENCODE_BYTE_FMT "%%%02x"
char * urlencodeup(char * szStr) {
  size_t iLen = strlen(szStr);

  // Assume the worst case scenario for buffer allocation, which is 3S+1 where S
  // is the length of the input string.
  char * szRet = charcalloc(((iLen * 3) + 1));
  char c = szStr[0];

  size_t j = 0;
  for (size_t i = 0; i < iLen; ++i) {

    c = szStr[i];

    if (  BETWEEN('a', c, 'z')
       || BETWEEN('A', c, 'Z')
       || BETWEEN('0', c, '9')) {
      szRet[j] = c;
      j += 1;
    } else {
      snprintf(szRet+j, sizeof(URL_ENCODE_BYTE_FMT), URL_ENCODE_BYTE_FMT, (unsigned int) c);
      j += 3;
    }
  }

  szRet[j] = '\0';

  return szRet;
}

/**
 * Standard GET request format string. Parameters are:
 *
 *  1. %s, Resource to request
 *  2. %s, Get parameter string
 *  3. %s, Host header
 *  4. %s, User-agent header
 *  5. %s, A custom header
 */
#define GET_REQUEST_FMT_STR \
  "GET %s?%s HTTP/1.1\r\n" \
  "Host: %s\r\n" \
  "User-Agent: %s\r\n" \
  "Connection: close\r\n" \
  "%s" \
  "\r\n"

/**
 * Standard POST request format string. Parameters are:
 *
 *  1. %s, resource to request
 *  2. %s, host header
 *  3. %s, user-agent header
 *  4. %s, A custom header
 *  5. %s, Content length
 *  6. %s, POST body
 */
#define POST_REQUEST_FMT_STR \
  "POST %s HTTP/1.1\r\n" \
  "Host: %s\r\n" \
  "User-Agent: %s\r\n" \
  "Connection: close\r\n" \
  "%s" \
  "Content-Type: application/x-www-form-urlencoded\r\n" \
  "Content-Length: %i\r\n" \
  "\r\n" \
  "%s"

/**
 * Prepare the parameter string that will either go in the resource field for
 * get and the body for post. Passwords that are passed to this function will be
 * url-encoded before being added.
 */
int prepareRequestParamString(char ** dst, ModuleDataT * _moduleData, char * szLogin, char * szPassword) {
  int ret = 0;

  // url-encode the password.
  char * szPasswordEncoded = urlencodeup(szPassword);

  // Check whether there are any other form parameters to include in the
  // parameter string. If there are none then `formRest' expands to the empty
  // string.
  char * formRest = "";
  if (_moduleData->formRest && *_moduleData->formRest) {
    formRest = _moduleData->formRest;
  }

  ret = asprintf(dst, "%s%s&%s%s&%s", _moduleData->formUserKey   // username
                                    , szLogin
                                    , _moduleData->formPassKey   // password
                                    , szPasswordEncoded
                                    , formRest);                 // the rest

  // clean up
  free(szPasswordEncoded);

  return ret;
}

/**
 * Uses one of the template strings GET_REQUEST_FMT_STR or POST_REQUEST_FMT_STR,
 * depending on the form type specified in _moduleData to prepare a request
 * string and body. The formatted string is placed in the buffer pointed to by
 * @dst@.
 */
int prepareRequestString(char ** dst, ModuleDataT * _moduleData, char * szLogin, char * szPassword) {

  int ret         = 0
    , nParameters = 0
    ;

  char * parameters = NULL;

  // Prepare the parameter string which goes either in the resource for GET or
  // the body for POST.
  nParameters = prepareRequestParamString(&parameters, _moduleData, szLogin, szPassword);

  switch (_moduleData->formType) {
    case FORM_GET:
      ret = asprintf(dst, GET_REQUEST_FMT_STR, _moduleData->resourcePath
                                             , parameters
                                             , _moduleData->hostHeader
                                             , _moduleData->userAgentHeader
                                             , _moduleData->customHeaders
                                             );
      break;

    case FORM_POST:
      ret = asprintf(dst, POST_REQUEST_FMT_STR, _moduleData->resourcePath
                                              , _moduleData->hostHeader
                                              , _moduleData->userAgentHeader
                                              , _moduleData->customHeaders
                                              , nParameters
                                              , parameters
                                              );
      break;

    case FORM_UNKNOWN:
    default:
      break;
  }

  // Clean up.
  free(parameters);

  return ret;
}

/**
 * Prepare and send a request.
 */
static int _sendRequest(int hSocket, ModuleDataT* _moduleData, char* szLogin, char* szPassword) {

  int nRet        = SUCCESS
    , requestSize = 0
    ;

  // Allocated in prepareRequestString by asprintf, we are responsible for
  // freeing it here.
  char * request = NULL;

  requestSize = prepareRequestString(&request, _moduleData, szLogin, szPassword);

  if (medusaSend(hSocket, (unsigned char *) request, requestSize, 0) < 0) {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
    nRet = FAILURE;
  }

  // clean up
  free(request);

  return nRet;
}

static inline void _setPasswordHelper(sLogin ** login, char * password, int result) {
  (*login)->iResult = result;
  setPassResult(*login, password);
}

/**
 *
 */
static ModuleStateT _request(int hSocket, ModuleDataT * _moduleData, sLogin ** login, char * szLogin, char ** pReceiveBuffer, int * nReceiveBufferSize, char * szPassword) {

  ModuleStateT ret = MSTATE_RUNNING;

  switch (_moduleData->formType) {
    case FORM_GET:
      writeError(ERR_DEBUG_MODULE, "[%s] Sending Web Form Authentication (GET).", MODULE_NAME);
      break;
    case FORM_POST:
      writeError(ERR_DEBUG_MODULE, "[%s] Sending Web Form Authentication (POST)", MODULE_NAME);
      break;
    case FORM_UNKNOWN:
    default:
      writeError(ERR_ERROR, "[%s] Unknown form type", MODULE_NAME);
      return MSTATE_EXITING;
      break;
  }

  if(FAILURE == _sendRequest(hSocket, _moduleData, szLogin, szPassword)) {
    writeError(ERR_ERROR, "[%s] Failed during sending of authentication data.", MODULE_NAME);
    _setPasswordHelper(login, szPassword, LOGIN_RESULT_UNKNOWN);
    return MSTATE_EXITING;
  }

  writeError(ERR_DEBUG_MODULE, "[%s] Retrieving server response.", MODULE_NAME);

  *pReceiveBuffer = (char *) medusaReceiveLine(hSocket, nReceiveBufferSize);

  if (!*pReceiveBuffer) {
    writeError(ERR_ERROR, "[%s] No data received", MODULE_NAME);
    _setPasswordHelper(login, szPassword, LOGIN_RESULT_UNKNOWN);
    ret = MSTATE_EXITING;
  }

  return ret;
}

/**
 * Collection of values that reflect the different kinds of path we can deal
 * with.
 */
typedef enum PathType {
  PATHTYPE_UNKNOWN,
  PATHTYPE_URI,
  PATHTYPE_RELATIVE,
  PATHTYPE_ABSOLUTE
} PathTypeT;

/**
 * Guess the path type of the Location header value. If it starts with 'http',
 * case insensitive, then it is a URI. If it is not a URI, and it starts with a
 * '/', then it is absolute. In all other cases it is assumed to be relative.
 */
static PathTypeT _pathType(char * path) {

  PathTypeT ret = PATHTYPE_UNKNOWN;

  char tmp;
  char * isURI;

  if (path) {

    if (strlen(path) > 4) {
      tmp = path[4];
      path[4] = '\0';
      isURI = strcasestr(path, "http");
      path[4] = tmp;

      if (isURI) return PATHTYPE_URI;
    }

    // Definitely not a URI at this point, either ABS or REL
    switch (*path) {

      // absolute paths start with '/'
      case '/':
        ret = PATHTYPE_ABSOLUTE;
        break;

      // relative by default
      default:
        ret = PATHTYPE_RELATIVE;
        break;
    }
  }

  return ret;
}

/**
 * Resolve the path from the Location header with the old path and strip
 * request parameters.
 */
void _resolveLocationPath(char * newLocation, ModuleDataT * _moduleData) {

  char * hasParameters = strchr(newLocation, '?');

  // If there are parameters, we set shorten the string by converting the ? into
  // a \0.
  if (hasParameters)
    *hasParameters = '\0';

  char * buf = NULL
     , * end = NULL
     ;

  switch(_pathType(newLocation)) {
    case PATHTYPE_RELATIVE:
      // Yes, strings are hard. whatever.
      buf = charcalloc(2 * (strlen(newLocation) + strlen(_moduleData->resourcePath)));

      // concatenate the strings and let the server figure out the path
      // resolution
      end = stpcpy(buf, _moduleData->resourcePath);
      *(end++) = '/';
      strcpy(end, newLocation);

      free(_moduleData->resourcePath);
      _moduleData->resourcePath = buf;
      break;

    // break omitted on purpose!
    case PATHTYPE_URI:
      free(_moduleData->hostHeader);
      _moduleData->hostHeader = strdup(newLocation);
    case PATHTYPE_ABSOLUTE:
      free(_moduleData->resourcePath);
      _moduleData->resourcePath = strdup(newLocation);
      break;
     
    case PATHTYPE_UNKNOWN:
    default:
      writeError(ERR_ERROR, "[%s] Path type of \"%s\" is unknown", MODULE_NAME, newLocation);
      break;
  }
}

int tryLogin(int hSocket, ModuleDataT* _moduleData, sLogin** login, char* szLogin, char* szPassword) {
  char * pReceiveBuffer = NULL;
  int nReceiveBufferSize = 0;

  // Perform the request, error out when request failed
  ModuleStateT requestState;
  requestState = _request(hSocket, _moduleData, login, szLogin, &pReceiveBuffer, &nReceiveBufferSize, szPassword);

  if (requestState == MSTATE_EXITING) return requestState;

  // Attempt to parse the status code. Exit on error.
  HttpStatusCodeT statusCode = parseHttpStatusCode(pReceiveBuffer);
  if (statusCode == HTTP_STATUS_PARSE_ERR) {
    writeError(ERR_ERROR, "[%s] Error while parsing HTTP status code.", MODULE_NAME);
    return MSTATE_EXITING;
  }

  writeError(ERR_DEBUG_MODULE, "[%s] HTTP Response code was %3d.", MODULE_NAME, statusCode);

  switch (statusCode) {
    // In this case we can continue as we used to because the 200 OK was
    // expected from the previous code.
    case HTTP_OK:
      break;

    // In this case we have to redo the request, this time requesting the page
    // that is specified in the Location header.
    //  - For 301 Moved Permanently and 302 Found we are allowed to change the
    //    request method from POST to GET
    //  - For 307 Temporary Redirect and 308 Permanent Redirect the method SHOULD
    //    remain unaltered.
    case HTTP_MOVED_PERMANENTLY:
    case HTTP_FOUND:
    case HTTP_TEMPORARY_REDIRECT:
    case HTTP_PERMANENT_REDIRECT:
      writeError(ERR_DEBUG_MODULE, "[%s] Following redirect.", MODULE_NAME);

      // NOTE: findLocationHeaderValue allocates a string on the heap for
      // newLocation, we have to free it
      //
      // NOTE: This action will change the location permanently. The assumption
      // is that there will be only one redirect i.e. after resolving the
      // redirection, that path is used for all requests that follow it.
      char * newLocation = findLocationHeaderValue(pReceiveBuffer);

      // We cannot proceed if we have not found a Location header
      if (!newLocation) {
        writeError(ERR_ERROR, "Redirect could not be followed because the location header could not be found");
        _setPasswordHelper(login, szPassword, LOGIN_RESULT_UNKNOWN);
        return MSTATE_EXITING;
      }
      _resolveLocationPath(newLocation, _moduleData);
      free(newLocation);

      // Change the request method to GET for 301 and 302
      // NOTE: we have to reset it to POST on following requests
      if (_moduleData->formType == FORM_POST &&
        (statusCode == HTTP_MOVED_PERMANENTLY || statusCode == HTTP_FOUND)) {
        _moduleData->changedRequestType = 1;
        writeError(ERR_DEBUG_MODULE, "[%s] Changing request method to GET for redirect", MODULE_NAME);
        _moduleData->formType = FORM_GET;
      }

      // The redirect has now been resolved, we simply do not update the
      // username:password pair so that in the next iteration the combination
      // will be automatically tried again.
      return MSTATE_NEW;
      break;

    case HTTP_BAD_REQUEST:
    case HTTP_UNAUTHORIZED:
    case HTTP_FORBIDDEN:
    case HTTP_NOT_FOUND:
      writeError(ERR_ERROR, "Received HTTP status code: %d, cannot proceed.", statusCode);
      _setPasswordHelper(login, szPassword, LOGIN_RESULT_UNKNOWN);
      return MSTATE_EXITING;
      break;

    // The default error case from the old code
    default:
      writeError(ERR_ERROR, "The answer was NOT successfully received, understood, and accepted while trying: user: \"%s\", pass: \"%s\", HTTP status code: %3d", szLogin, szPassword, statusCode);
      _setPasswordHelper(login, szPassword, LOGIN_RESULT_UNKNOWN);
      return MSTATE_EXITING;
      break;
  }

  // Search for the deny signal.
  uint8_t denySignalFound = 0;

  while (pReceiveBuffer && *pReceiveBuffer) {
    if (strcasestr(pReceiveBuffer, _moduleData->denySignal)) {
      denySignalFound = 1;
      break;
    }

    free(pReceiveBuffer);
    pReceiveBuffer = (char *) medusaReceiveLine(hSocket, &nReceiveBufferSize);
  }

  if (denySignalFound) {
    (*login)->iResult = LOGIN_RESULT_FAIL;
  } else {
    (*login)->iResult = LOGIN_RESULT_SUCCESS;
    writeError(ERR_DEBUG_MODULE, "Login Successful");
  }

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

int go(/*@unused@*/ sLogin* logins, /*@unused@*/ int argc, /*@unused@*/ char *argv[]) {
  writeVerbose(VB_NONE, "%s (%s) %s :: %s\n", MODULE_NAME, MODULE_VERSION, MODULE_AUTHOR, MODULE_SUMMARY_USAGE);
  writeVerbose(VB_NONE, "** Module was not properly built. Is OPENSSL installed correctly? **");
  writeVerbose(VB_NONE, "");

  return FAILURE;
}

#endif

/**
 * MODULE_SUMMARY_USAGE, MODULE_VERSION and, OPENSSL_WARNING have a statically
 * known length.
 * MODULE_SUMMARY_FORMAT has three unbouded string formatting characters
 *
 * snprintf formats those strings to be the former three
 * so the length is
 *  MODULE_SUMMARY_FORMAT - 3 * 2 (for the %s)
 *    + MODULE_SUMMARY_USAGE
 *    + MODULE_VERSION
 *    + OPENSSL_WARNING
 *    + 1 (for the '\0')
 */

#define ILENGTH (size_t) sizeof(MODULE_SUMMARY_FORMAT MODULE_SUMMARY_USAGE MODULE_VERSION OPENSSL_WARNING) - 3 * 2 + 1

void summaryUsage(char ** ppszSummary) {

  // Sentinel
  if (*ppszSummary) {
    writeError(ERR_ERROR, "%s reports an error in summaryUsage() : ppszSummary must be NULL when called", MODULE_NAME);
  } else {
    // this is a bounded `asprintf'
    *ppszSummary = charcalloc(ILENGTH);
    snprintf(*ppszSummary, ILENGTH, MODULE_SUMMARY_FORMAT, MODULE_SUMMARY_USAGE, MODULE_VERSION, OPENSSL_WARNING);
  }
}
