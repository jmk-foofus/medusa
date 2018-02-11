/*
**   RDP Password Checking Medusa Module
**
**   ------------------------------------------------------------------------
**    Copyright (C) 2015 Joe Mondloch
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
**   FreeRDP/client/Sample/freerdp.c
 * FreeRDP: A Remote Desktop Protocol Implementation
 * FreeRDP Test UI
 * Copyright 2011 Marc-Andre Moreau <marcandre.moreau@gmail.com>
**
*/

#include <sys/types.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "module.h"

#include <freerdp/freerdp.h>
#include <freerdp/gdi/gdi.h>
#include <freerdp/channels/channels.h>

#define MODULE_NAME    "rdp.mod"
#define MODULE_AUTHOR  "JoMo-Kun <jmk@foofus.net>"
#define MODULE_SUMMARY_USAGE  "Brute force module for RDP (Microsoft Terminal Server) sessions"
#define MODULE_VERSION    "0.2"
#define MODULE_VERSION_SVN "$Id: ssh.c 1403 2010-09-01 21:41:00Z jmk $"
#define MODULE_SUMMARY_FORMAT  "%s : version %s"

#define PORT_RDP 3389
#define NTLM_HASH_BLANK "31D6CFE0D16AE931B73C59D7E0C089C0"

typedef struct __MODULE_DATA {
  char* szDomain;
  int isPassTheHash;
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
int tryLogin(_MODULE_DATA* _psSessionData, sLogin** login, freerdp* instance, char* szLogin, char* szPassword);
int initModule(sLogin* login, _MODULE_DATA *_psSessionData);

void initWLog();
static BOOL tf_context_new(freerdp* instance, rdpContext* context);
static void tf_context_free(freerdp* instance, rdpContext* context);
static BOOL tf_begin_paint(rdpContext* context);
static BOOL tf_end_paint(rdpContext* context);
int tf_pre_connect(freerdp* instance);
int tf_post_connect(freerdp* instance);

struct tf_context
{
  rdpContext _p;
};

typedef struct tf_context tfContext;

extern FREERDP_API int freerdp_channels_global_init(void);
extern FREERDP_API int freerdp_channels_global_uninit(void);

// Tell medusa how many parameters this module allows
int getParamNumber()
{
  return 0;
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
  writeVerbose(VB_NONE, "  DOMAIN:? [optional]");
  writeVerbose(VB_NONE, "  PASS:?  (PASSWORD*, HASH)");
  writeVerbose(VB_NONE, "    PASSWORD: Use normal password.");
  writeVerbose(VB_NONE, "    HASH:     Use a NTLM hash rather than a password.");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "Usage example: \"-M rdp\"");
  writeVerbose(VB_NONE, "Usage example: \"-M rdp -m PASS:HASH -u Administrator -p 31D78236327B9619B14ED8EC9AB454C1");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "Note: This module does NOT work against Microsoft Windows 2003/XP and earlier.");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "*** There appears to be thread-safety issues within the FreeRDP library and/or this module. ***");
  writeVerbose(VB_NONE, "*** It is recommended that you avoid using concurrent hosts/users (i.e., -T/-t).");
  writeVerbose(VB_NONE, "");
}

// The "main" of the medusa module world - this is what gets called to actually do the work
int go(sLogin* logins, int argc, char *argv[])
{
  int i;
  char *strtok_ptr, *pOpt, *pOptTmp;
  _MODULE_DATA *psSessionData = NULL;

  psSessionData = malloc(sizeof(_MODULE_DATA));
  memset(psSessionData, 0, sizeof(_MODULE_DATA));

  if ((argc < 0) || (argc > 2))
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
          psSessionData->szDomain = malloc(strlen(pOpt) + 1);
          memset(psSessionData->szDomain, 0, strlen(pOpt) + 1);
          strncpy((char *) psSessionData->szDomain, pOpt, strlen(pOpt));
        }
        else
          writeError(ERR_WARNING, "Method DOMAIN requires value to be set.");
      }
      else if (strcmp(pOpt, "PASS") == 0) {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if (pOpt == NULL)
          writeError(ERR_WARNING, "Method PASS requires value to be set.");
        else if (strcmp(pOpt, "PASSWORD") == 0)
          psSessionData->isPassTheHash = FALSE;
        else if (strcmp(pOpt, "HASH") == 0)
          psSessionData->isPassTheHash = TRUE;
        else
          writeError(ERR_WARNING, "Invalid value for method PASS.");
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

int initModule(sLogin* psLogin, _MODULE_DATA *_psSessionData)
{
  enum MODULE_STATE nState = MSTATE_NEW;
  sCredentialSet *psCredSet = NULL;
  freerdp* instance;

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

  while (nState != MSTATE_COMPLETE)
  {
    switch (nState)
    {
      case MSTATE_NEW:
        instance = freerdp_new();
        instance->PreConnect = (signed char (*)(struct rdp_freerdp *))tf_pre_connect;
        instance->PostConnect = (signed char (*)(struct rdp_freerdp *))tf_post_connect;
        instance->ContextSize = sizeof(tfContext);
        instance->ContextNew = tf_context_new;
        instance->ContextFree = tf_context_free;

        freerdp_context_new(instance);

        instance->settings->IgnoreCertificate = TRUE;
        instance->settings->AuthenticationOnly = TRUE;
        instance->settings->ServerHostname = psLogin->psServer->pHostIP;

        if (psLogin->psServer->psAudit->iPortOverride > 0)
          instance->settings->ServerPort = psLogin->psServer->psAudit->iPortOverride;
        else
          instance->settings->ServerPort = PORT_RDP;

        writeError(ERR_DEBUG_MODULE, "Id: %d initialized FreeRDP instance.", psLogin->iId);
        nState = MSTATE_RUNNING;
        break;
      case MSTATE_RUNNING:
        nState = tryLogin(_psSessionData, &psLogin, instance, psCredSet->psUser->pUser, psCredSet->pPass);

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

        break;
      case MSTATE_EXITING:
        freerdp_free(instance);
        nState = MSTATE_COMPLETE;
        break;
      default:
        writeError(ERR_CRITICAL, "Unknown %s module state %d", MODULE_NAME, nState);

        freerdp_free(instance);
        psLogin->iResult = LOGIN_RESULT_UNKNOWN;

        return FAILURE;
    }
  }

  FREE(psCredSet);
  return SUCCESS;
}

/* Module Specific Functions */

static BOOL tf_context_new(freerdp* instance, rdpContext* context)
{
  return TRUE;
}

static void tf_context_free(freerdp* instance, rdpContext* context)
{
}

static BOOL tf_begin_paint(rdpContext* context)
{
  rdpGdi* gdi = context->gdi;
  gdi->primary->hdc->hwnd->invalid->null = TRUE;
  return TRUE;
}

static BOOL tf_end_paint(rdpContext* context)
{
  rdpGdi* gdi = context->gdi;

  if (gdi->primary->hdc->hwnd->invalid->null)
    return TRUE;

  return TRUE;
}

int tf_pre_connect(freerdp* instance)
{
  rdpSettings* settings;
  settings = instance->settings;
  settings->OrderSupport[NEG_DSTBLT_INDEX] = TRUE;
  settings->OrderSupport[NEG_PATBLT_INDEX] = TRUE;
  settings->OrderSupport[NEG_SCRBLT_INDEX] = TRUE;
  settings->OrderSupport[NEG_OPAQUE_RECT_INDEX] = TRUE;
  settings->OrderSupport[NEG_DRAWNINEGRID_INDEX] = TRUE;
  settings->OrderSupport[NEG_MULTIDSTBLT_INDEX] = TRUE;
  settings->OrderSupport[NEG_MULTIPATBLT_INDEX] = TRUE;
  settings->OrderSupport[NEG_MULTISCRBLT_INDEX] = TRUE;
  settings->OrderSupport[NEG_MULTIOPAQUERECT_INDEX] = TRUE;
  settings->OrderSupport[NEG_MULTI_DRAWNINEGRID_INDEX] = TRUE;
  settings->OrderSupport[NEG_LINETO_INDEX] = TRUE;
  settings->OrderSupport[NEG_POLYLINE_INDEX] = TRUE;
  settings->OrderSupport[NEG_MEMBLT_INDEX] = TRUE;
  settings->OrderSupport[NEG_MEM3BLT_INDEX] = TRUE;
  settings->OrderSupport[NEG_SAVEBITMAP_INDEX] = TRUE;
  settings->OrderSupport[NEG_GLYPH_INDEX_INDEX] = TRUE;
  settings->OrderSupport[NEG_FAST_INDEX_INDEX] = TRUE;
  settings->OrderSupport[NEG_FAST_GLYPH_INDEX] = TRUE;
  settings->OrderSupport[NEG_POLYGON_SC_INDEX] = TRUE;
  settings->OrderSupport[NEG_POLYGON_CB_INDEX] = TRUE;
  settings->OrderSupport[NEG_ELLIPSE_SC_INDEX] = TRUE;
  settings->OrderSupport[NEG_ELLIPSE_CB_INDEX] = TRUE;
  return TRUE;
}

int tf_post_connect(freerdp* instance)
{
  if (!gdi_init(instance, PIXEL_FORMAT_XRGB32))
    return FALSE;

  instance->update->BeginPaint = tf_begin_paint;
  instance->update->EndPaint = tf_end_paint;

  return TRUE;
}

int tryLogin(_MODULE_DATA* _psSessionData, sLogin** psLogin, freerdp* instance, char* szLogin, char* szPassword)
{
  int SMBerr;
  char *pErrorMsg = NULL;
  char ErrorCode[12];
  int nRet;
  unsigned int i;
  int old_stderr;

  /* Nessus Plugins: smb_header.inc */
  /* Note: we are currently only examining the lower 2 bytes of data */
  int smbErrorCode[] = {
    0xFFFFFFFF,         /* UNKNOWN_ERROR_CODE */
    0x00000000,         /* STATUS_SUCCESS */
    0xC000000D,         /* STATUS_INVALID_PARAMETER */
    0xC000005E,         /* STATUS_NO_LOGON_SERVERS */
    0xC000006D,         /* STATUS_LOGON_FAILURE */
    0xC000006E,         /* STATUS_ACCOUNT_RESTRICTION */
    0xC000006F,         /* STATUS_INVALID_LOGON_HOURS */
    0x00C10002,         /* STATUS_INVALID_LOGON_HOURS (LM Authentication) */
    0xC0000070,         /* STATUS_INVALID_WORKSTATION */
    0x00C00002,         /* STATUS_INVALID_WORKSTATION (LM Authentication) */
    0xC0000071,         /* STATUS_PASSWORD_EXPIRED */
    0xC0000072,         /* STATUS_ACCOUNT_DISABLED */
    0xC000015B,         /* STATUS_LOGON_TYPE_NOT_GRANTED */
    0xC000018D,         /* STATUS_TRUSTED_RELATIONSHIP_FAILURE */
    0xC0000193,         /* STATUS_ACCOUNT_EXPIRED */
    0xC0000199,         /* STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT */
    0x00BF0002,         /* STATUS_ACCOUNT_EXPIRED_OR_DISABLED (LM Authentication) */
    0xC0000224,         /* STATUS_PASSWORD_MUST_CHANGE */
    0x00C20002,         /* STATUS_PASSWORD_MUST_CHANGE (LM Authentication) */
    0xC0000234,         /* STATUS_ACCOUNT_LOCKED_OUT (No LM Authentication Code) */
    0x00050001,         /* AS400_STATUS_LOGON_FAILURE */
    0x00000064,         /* The machine you are logging onto is protected by an authentication firewall. */
    0xC0000022,         /* STATUS_ACCESS_DENIED */
    0xC00000CC,         /* STATUS_BAD_NETWORK_NAME */
    0x0002000D          /* ERRCONNECT_CONNECT_TRANSPORT_FAILED */
  };

  char *smbErrorMsg[] = {
    "UNKNOWN_ERROR_CODE",
    "STATUS_SUCCESS",
    "STATUS_INVALID_PARAMETER",
    "STATUS_NO_LOGON_SERVERS",
    "STATUS_LOGON_FAILURE",
    "STATUS_ACCOUNT_RESTRICTION",
    "STATUS_INVALID_LOGON_HOURS",
    "STATUS_INVALID_LOGON_HOURS (LM)",
    "STATUS_INVALID_WORKSTATION",
    "STATUS_INVALID_WORKSTATION (LM)",
    "STATUS_PASSWORD_EXPIRED",
    "STATUS_ACCOUNT_DISABLED",
    "STATUS_LOGON_TYPE_NOT_GRANTED",
    "STATUS_TRUSTED_RELATIONSHIP_FAILURE",
    "STATUS_ACCOUNT_EXPIRED",
    "STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT",
    "STATUS_ACCOUNT_EXPIRED_OR_DISABLED (LM)",
    "STATUS_PASSWORD_MUST_CHANGE",
    "STATUS_PASSWORD_MUST_CHANGE (LM)",
    "STATUS_ACCOUNT_LOCKED_OUT",
    "AS400_STATUS_LOGON_FAILURE",
    "AUTHENTICATION_FIREWALL_PROTECTION",
    "STATUS_ACCESS_DENIED",
    "STATUS_BAD_NETWORK_NAME",
    "ERRCONNECT_CONNECT_TRANSPORT_FAILED"
  };

  instance->settings->Username = szLogin;

  /* If the domain is not defined, local accounts are targeted */
  if (_psSessionData->szDomain)
    instance->settings->Domain = _psSessionData->szDomain;

  /* Pass-the-hash support added to FreeRDP 1.2.x development tree */
  if (_psSessionData->isPassTheHash)
  {
    instance->settings->ConsoleSession = TRUE;
    instance->settings->RestrictedAdminModeRequired = TRUE;
    instance->settings->PasswordHash = szPassword;
  }
  else
    instance->settings->Password = szPassword;

  /* Blank password support
     FreeRDP does not support blank passwords. It attempts to pull credentials from a local
     SAM file if a password of length 0 is supplied. We're using pass-the-hash to get
     around this issue.
  */
  if (strlen(szPassword) == 0)
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Using pass-the-hash to test blank password.", MODULE_NAME);
    instance->settings->ConsoleSession = TRUE;
    instance->settings->RestrictedAdminModeRequired = TRUE;
    instance->settings->PasswordHash = NTLM_HASH_BLANK;
  }

  /* Suppress FreeRDP library FreeRDP output */
  if ((iVerboseLevel <= 5) && (iErrorLevel <= 5))
  {
    pthread_mutex_lock(&(*psLogin)->psServer->psAudit->ptmMutex);
    old_stderr = dup(1);
    (void)(freopen("/dev/null", "w", stderr) + 1); /* ignore return code */

    nRet = freerdp_connect(instance);

    fclose(stderr);
    stderr = fdopen(old_stderr, "w");
    pthread_mutex_unlock(&(*psLogin)->psServer->psAudit->ptmMutex);
  }
  else
    nRet = freerdp_connect(instance);

  writeError(ERR_DEBUG_MODULE, "[%s] freerdp_connect exit code: %d", MODULE_NAME, nRet);
  if (nRet == 1)
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Login attempt successful.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
    nRet = MSTATE_EXITING;
  }
  else
  {
    SMBerr = freerdp_get_last_error(instance->context);

    /* Locate appropriate SMB code message */
    pErrorMsg = smbErrorMsg[0]; /* UNKNOWN_ERROR_CODE */
    for (i = 0; i < sizeof(smbErrorCode)/4; i++) {
      if (SMBerr == (smbErrorCode[i] & 0xFFFFFFFF)) {
        pErrorMsg = smbErrorMsg[i];
        break;
      }
    }

    switch(SMBerr)
    {
      case 0x00020014:  /* ERRCONNECT_LOGON_FAILURE */
      case 0xC000006A:  /* STATUS_WRONG_PASSWORD */
      case 0xC000006D:  /* STATUS_LOGON_FAILURE */
        (*psLogin)->iResult = LOGIN_RESULT_FAIL;
        nRet = MSTATE_RUNNING;
        break;

      case 0xC0000022:  /* STATUS_ACCESS_DENIED */
      case 0xC0000071:  /* STATUS_PASSWORD_EXPIRED */
      case 0xC0000072:  /* STATUS_ACCOUNT_DISABLED */
      case 0xC0000224:  /* STATUS_PASSWORD_MUST_CHANGE */
      case 0xC000006E:  /* STATUS_ACCOUNT_RESTRICTION */
      case 0xC0000234:  /* STATUS_ACCOUNT_LOCKED_OUT  */
      case 0xC0000193:  /* STATUS_ACCOUNT_EXPIRED */
      case 0xC000015B:  /* STATUS_LOGON_TYPE_NOT_GRANTED */
      case 0x0002000D:  /* ERRCONNECT_CONNECT_TRANSPORT_FAILED */
        (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
        sprintf(ErrorCode, "0x%8.8X:", SMBerr);
        (*psLogin)->pErrorMsg = malloc( strlen(ErrorCode) + strlen(pErrorMsg) + 1);
        memset((*psLogin)->pErrorMsg, 0, strlen(ErrorCode) + strlen(pErrorMsg) + 1);
        strncpy((*psLogin)->pErrorMsg, ErrorCode, strlen(ErrorCode));
        strncat((*psLogin)->pErrorMsg, pErrorMsg, strlen(pErrorMsg));
        nRet = MSTATE_EXITING;
        break;

      default:
        sprintf(ErrorCode, "0x%8.8X:", SMBerr);
        (*psLogin)->pErrorMsg = malloc( strlen(ErrorCode) + strlen(pErrorMsg) + 1);
        memset((*psLogin)->pErrorMsg, 0, strlen(ErrorCode) + strlen(pErrorMsg) + 1);
        strncpy((*psLogin)->pErrorMsg, ErrorCode, strlen(ErrorCode));
        strncat((*psLogin)->pErrorMsg, pErrorMsg, strlen(pErrorMsg));
        (*psLogin)->iResult = LOGIN_RESULT_ERROR;
        nRet = MSTATE_EXITING;
        break;
    }
  }

  setPassResult((*psLogin), szPassword);
  return(nRet);
}
