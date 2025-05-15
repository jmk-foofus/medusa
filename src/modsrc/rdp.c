/*
**   RDP Password Checking Medusa Module
**
**   ------------------------------------------------------------------------
**    Copyright (C) 2025 Joe Mondloch
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
 * Copyright 2016,2018 Armin Novak <armin.novak@thincast.com>
 * Copyright 2016,2018 Thincast Technologies GmbH
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
#define MODULE_VERSION    "0.3"
#define MODULE_VERSION_SVN "$Id: ssh.c 1403 2010-09-01 21:41:00Z jmk $"
#define MODULE_SUMMARY_FORMAT  "%s : version %s"

#define PORT_RDP 3389
#define NTLM_HASH_BLANK "31D6CFE0D16AE931B73C59D7E0C089C0"

typedef struct __MODULE_DATA {
  char* szDomain;
  int isPassTheHash;
  int isBlankPassword;
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

static int RdpClientEntry(RDP_CLIENT_ENTRY_POINTS* pEntryPoints);
static BOOL tf_pre_connect(freerdp* instance);
static BOOL tf_post_connect(freerdp* instance);
static void tf_post_disconnect(freerdp* instance);

typedef struct
{
  rdpClientContext common;
  /* Channels */
} tfContext;

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
      pOptTmp = strdup(argv[i]);
      writeError(ERR_DEBUG_MODULE, "Processing complete option: %s", pOptTmp);
      pOpt = strtok_r(pOptTmp, ":", &strtok_ptr);
      writeError(ERR_DEBUG_MODULE, "Processing option: %s", pOpt);

      if (strcmp(pOpt, "DOMAIN") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if ( pOpt )
        {
          psSessionData->szDomain = strdup(pOpt);
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
  RDP_CLIENT_ENTRY_POINTS clientEntryPoints = { 0 };
  rdpContext* context;
  wLog *root;

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
        /* Suppress FreeRDP library FreeRDP output */
        root = WLog_GetRoot();
        if ((iVerboseLevel <= 5) && (iErrorLevel <= 5))
          WLog_SetStringLogLevel(root, "OFF");
        else
          WLog_SetStringLogLevel(root, "INFO");

        RdpClientEntry(&clientEntryPoints);
        context = freerdp_client_context_new(&clientEntryPoints);
        if (!context)
          writeError(ERR_FATAL, "[%s] freerdp_client_context_new failed.", MODULE_NAME);

        /* FreeRDP caches certificates in ~/.config/freerdp */
        if (!freerdp_settings_set_bool(context->settings, FreeRDP_IgnoreCertificate, TRUE))
          writeError(ERR_ERROR, "[%s] Failed to set: FreeeRDP_IgnoreCertificate", MODULE_NAME);

        if (!freerdp_settings_set_bool(context->settings, FreeRDP_AuthenticationOnly, TRUE))
          writeError(ERR_ERROR, "[%s] Failed to set: FreeeRDP_AuthenticationOnly", MODULE_NAME);

        if (!freerdp_settings_set_uint32(context->settings, FreeRDP_AuthenticationLevel, 2))
          writeError(ERR_ERROR, "[%s] Failed to set: FreeeRDP_AuthenticationLevel", MODULE_NAME);

        if (!freerdp_settings_set_bool(context->settings, FreeRDP_NegotiateSecurityLayer, TRUE))
          writeError(ERR_ERROR, "[%s] Failed to set: FreeeRDP_NegotiateSecurityLayer", MODULE_NAME);

        if (!freerdp_settings_set_string(context->settings, FreeRDP_ServerHostname, psLogin->psServer->pHostIP))
          writeError(ERR_ERROR, "[%s] Failed to set: FreeeRDP_ServerHostname", MODULE_NAME);

        if (psLogin->psServer->psAudit->iPortOverride > 0)
        {
          if (!freerdp_settings_set_uint32(context->settings, FreeRDP_ServerPort, psLogin->psServer->psAudit->iPortOverride))
            writeError(ERR_ERROR, "[%s] Failed to set: FreeeRDP_ServerPort", MODULE_NAME);
        }
        else
        {
          if (!freerdp_settings_set_uint32(context->settings, FreeRDP_ServerPort, PORT_RDP))
            writeError(ERR_ERROR, "[%s] Failed to set: FreeeRDP_ServerPort", MODULE_NAME);
        }

        writeError(ERR_DEBUG_MODULE, "Id: %d initialized FreeRDP instance.", psLogin->iId);
        nState = MSTATE_RUNNING;
        break;
      case MSTATE_RUNNING:
        nState = tryLogin(_psSessionData, &psLogin, context->instance, psCredSet->psUser->pUser, psCredSet->pPass);

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
            freerdp_client_context_free(context);
            nState = MSTATE_NEW;
          }
          else
          {
            writeError(ERR_DEBUG_MODULE, "[%s] Next credential set - user: %s password: %s", MODULE_NAME, psCredSet->psUser->pUser, psCredSet->pPass);

            /* FreeRDP session needs to be reset following pass-the-hash logon attempt. */
            if ((_psSessionData->isPassTheHash) || (_psSessionData->isBlankPassword)) {
              _psSessionData->isBlankPassword = FALSE;
              freerdp_client_context_free(context);
              nState = MSTATE_NEW;
            }
          }
        }

        break;
      case MSTATE_EXITING:
        nState = MSTATE_COMPLETE;
        freerdp_client_context_free(context);
        break;
      default:
        writeError(ERR_CRITICAL, "Unknown %s module state %d", MODULE_NAME, nState);
        freerdp_client_context_free(context);
        psLogin->iResult = LOGIN_RESULT_UNKNOWN;
        return FAILURE;
    }
  }

  FREE(psCredSet);
  return SUCCESS;
}

/* Module Specific Functions */

/* Optional: global initializer */
static BOOL tf_client_global_init(void)
{
  return TRUE;
}

/* Optional: global tear down */
static void tf_client_global_uninit(void)
{
}

static int tf_logon_error_info(freerdp* instance, UINT32 data, UINT32 type)
{
  tfContext* tf = NULL;
  const char* str_data = freerdp_get_logon_error_info_data(data);
  const char* str_type = freerdp_get_logon_error_info_type(type);

  if (!instance || !instance->context)
    return -1;

  tf = (tfContext*)instance->context;
  writeError(ERR_DEBUG_MODULE, "[%s] RDP logon error info: %s [%s]", MODULE_NAME, str_data, str_type);
  WINPR_UNUSED(tf);

  return 1;
}

static BOOL tf_client_new(freerdp* instance, rdpContext* context)
{
  tfContext* tf = (tfContext*)context;

  if (!instance || !context)
    return FALSE;

  instance->PreConnect = tf_pre_connect;
  instance->PostConnect = tf_post_connect;
  instance->PostDisconnect = tf_post_disconnect;
  instance->LogonErrorInfo = tf_logon_error_info;

  WINPR_UNUSED(tf);
  return TRUE;
}

static void tf_client_free(freerdp* instance, rdpContext* context)
{
  tfContext* tf = (tfContext*)instance->context;

  if (!context)
    return;

  WINPR_UNUSED(tf);
}

static int tf_client_start(rdpContext* context)
{
  WINPR_UNUSED(context);
  return 0;
}

static int tf_client_stop(rdpContext* context)
{
  WINPR_UNUSED(context);
  return 0;
}

static int RdpClientEntry(RDP_CLIENT_ENTRY_POINTS* pEntryPoints)
{
  WINPR_ASSERT(pEntryPoints);

  ZeroMemory(pEntryPoints, sizeof(RDP_CLIENT_ENTRY_POINTS));
  pEntryPoints->Version = RDP_CLIENT_INTERFACE_VERSION;
  pEntryPoints->Size = sizeof(RDP_CLIENT_ENTRY_POINTS_V1);
  pEntryPoints->GlobalInit = tf_client_global_init;
  pEntryPoints->GlobalUninit = tf_client_global_uninit;
  pEntryPoints->ContextSize = sizeof(tfContext);
  pEntryPoints->ClientNew = tf_client_new;
  pEntryPoints->ClientFree = tf_client_free;
  pEntryPoints->ClientStart = tf_client_start;
  pEntryPoints->ClientStop = tf_client_stop;
  return 0;
}

/* This function is called whenever a new frame starts.
 * It can be used to reset invalidated areas. */
static BOOL tf_begin_paint(rdpContext* context)
{
  rdpGdi* gdi = NULL;

  WINPR_ASSERT(context);

  gdi = context->gdi;
  WINPR_ASSERT(gdi);
  WINPR_ASSERT(gdi->primary);
  WINPR_ASSERT(gdi->primary->hdc);
  WINPR_ASSERT(gdi->primary->hdc->hwnd);
  WINPR_ASSERT(gdi->primary->hdc->hwnd->invalid);
  gdi->primary->hdc->hwnd->invalid->null = TRUE;
  return TRUE;
}

/* This function is called when the library completed composing a new
 * frame. Read out the changed areas and blit them to your output device.
 * The image buffer will have the format specified by gdi_init
 */
static BOOL tf_end_paint(rdpContext* context)
{
  rdpGdi* gdi = NULL;

  WINPR_ASSERT(context);

  gdi = context->gdi;
  WINPR_ASSERT(gdi);
  WINPR_ASSERT(gdi->primary);
  WINPR_ASSERT(gdi->primary->hdc);
  WINPR_ASSERT(gdi->primary->hdc->hwnd);
  WINPR_ASSERT(gdi->primary->hdc->hwnd->invalid);

  if (gdi->primary->hdc->hwnd->invalid->null)
    return TRUE;

  return TRUE;
}

/* Called before a connection is established.
 * Set all configuration options to support and load channels here. */
static BOOL tf_pre_connect(freerdp* instance)
{
  rdpSettings* settings = NULL;

  WINPR_ASSERT(instance);
  WINPR_ASSERT(instance->context);

  settings = instance->context->settings;
  WINPR_ASSERT(settings);

  /* If the callbacks provide the PEM all certificate options can be extracted, otherwise
   * only the certificate fingerprint is available. */
  if (!freerdp_settings_set_bool(settings, FreeRDP_CertificateCallbackPreferPEM, TRUE))
    return FALSE;

  /* Optional OS identifier sent to server */
  if (!freerdp_settings_set_uint32(settings, FreeRDP_OsMajorType, OSMAJORTYPE_UNIX))
    return FALSE;
  if (!freerdp_settings_set_uint32(settings, FreeRDP_OsMinorType, OSMINORTYPE_NATIVE_XSERVER))
    return FALSE;

  return TRUE;
}

/* Called after a RDP connection was successfully established.
 * Settings might have changed during negotiation of client / server feature
 * support.
 *
 * Set up local framebuffers and paing callbacks.
 * If required, register pointer callbacks to change the local mouse cursor
 * when hovering over the RDP window
 */
static BOOL tf_post_connect(freerdp* instance)
{
  rdpContext* context = NULL;

  if (!gdi_init(instance, PIXEL_FORMAT_XRGB32))
    return FALSE;

  context = instance->context;
  WINPR_ASSERT(context);
  WINPR_ASSERT(context->update);

  /* With this setting we disable all graphics processing in the library.
   *
   * This allows low resource (client) protocol parsing.
   */
  if (!freerdp_settings_set_bool(context->settings, FreeRDP_DeactivateClientDecoding, TRUE))
    return FALSE;

  context->update->BeginPaint = tf_begin_paint;
  context->update->EndPaint = tf_end_paint;
  return TRUE;
}

/* This function is called whether a session ends by failure or success.
 * Clean up everything allocated by pre_connect and post_connect.
 */
static void tf_post_disconnect(freerdp* instance)
{
  tfContext* context = NULL;

  if (!instance)
    return;

  if (!instance->context)
    return;

  context = (tfContext*)instance->context;

  gdi_free(instance);
  WINPR_UNUSED(context);
}

int tryLogin(_MODULE_DATA* _psSessionData, sLogin** psLogin, freerdp* instance, char* szLogin, char* szPassword)
{
  int SMBerr;
  char *pErrorMsg = NULL;
  char ErrorCode[12];
  int nRet;
  unsigned int i;
  int old_stderr;
  int old_stdout;
  unsigned char *p = NULL;
  //unsigned char *ntlm_hash = NULL;
  unsigned char ntlm_hash[33];

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
    0x0002000B,         /* ERRCONNECT_CONNECT_CANCELLED */
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
    "ERRCONNECT_CONNECT_CONNECT_CANCELLED",
    "ERRCONNECT_CONNECT_TRANSPORT_FAILED (Access Denied)"
  };

  if (!freerdp_settings_set_string(instance->context->settings, FreeRDP_Username, szLogin)) {
    writeError(ERR_ERROR, "[%s] Failed to set: FreeeRDP_Username", MODULE_NAME);
  }

  if (_psSessionData->szDomain) {
    writeError(ERR_DEBUG_MODULE, "[%s] Testing domain (%s) account.", MODULE_NAME, _psSessionData->szDomain);

    if (!freerdp_settings_set_string(instance->context->settings, FreeRDP_Domain, _psSessionData->szDomain))
      writeError(ERR_ERROR, "[%s] Failed to set: FreeeRDP_Domain", MODULE_NAME);
  }
  else {
    writeError(ERR_DEBUG_MODULE, "[%s] Testing local account.", MODULE_NAME);

    if (!freerdp_settings_set_string(instance->context->settings, FreeRDP_Domain, "."))
      writeError(ERR_ERROR, "[%s] Failed to set: FreeeRDP_Domain", MODULE_NAME);
  }

  /* Pass-the-hash support added to FreeRDP 1.2.x development tree */
  if (_psSessionData->isPassTheHash)
  {
    /* [PwDump File] D42E35E1A1E4C22BD32E2170E4857C20:5E20780DD45857A68402938C7629D3B2::: */
    /* [NTLM-only] 5E20780DD45857A68402938C7629D3B2 */
    memset(ntlm_hash, 0, 32 + 1);

    if (strlen(szPassword) == 32)
    {
      strncpy(ntlm_hash, szPassword, 32);
    }
    else if (strlen(szPassword) == 68)
    {
      strncpy(ntlm_hash, szPassword + 32 + 1, 32);
    }
    else
    {
      writeError(ERR_ERROR, "[%s] Invalid NTLM hash: %s", MODULE_NAME, szPassword);
      return FAILURE;
    }

    if (!freerdp_settings_set_bool(instance->context->settings, FreeRDP_ConsoleSession, TRUE))
      writeError(ERR_ERROR, "[%s] Failed to set: FreeeRDP_ConsoleSession", MODULE_NAME);

    if (!freerdp_settings_set_bool(instance->context->settings, FreeRDP_RestrictedAdminModeRequired, TRUE))
      writeError(ERR_ERROR, "[%s] Failed to set: FreeeRDP_RestrictedAdminModeRequired", MODULE_NAME);

    if (!freerdp_settings_set_string(instance->context->settings, FreeRDP_PasswordHash, ntlm_hash))
      writeError(ERR_ERROR, "[%s] Failed to set: FreeeRDP_PasswordHash", MODULE_NAME);
  }
  else
  {
    /* Blank password support
       FreeRDP does not support blank passwords. It attempts to pull credentials from a local
       SAM file if a password of length 0 is supplied. We're using pass-the-hash to get
       around this issue.
    */
    if (strlen(szPassword) == 0)
    {
      writeError(ERR_DEBUG_MODULE, "[%s] Using pass-the-hash to test blank password.", MODULE_NAME);

      if (!freerdp_settings_set_bool(instance->context->settings, FreeRDP_ConsoleSession, TRUE))
        writeError(ERR_ERROR, "[%s] Failed to set: FreeeRDP_ConsoleSession", MODULE_NAME);

      if (!freerdp_settings_set_bool(instance->context->settings, FreeRDP_RestrictedAdminModeRequired, TRUE))
        writeError(ERR_ERROR, "[%s] Failed to set: FreeeRDP_RestrictedAdminModeRequired", MODULE_NAME);

      if (!freerdp_settings_set_string(instance->context->settings, FreeRDP_PasswordHash, NTLM_HASH_BLANK))
        writeError(ERR_ERROR, "[%s] Failed to set: FreeeRDP_PasswordHash", MODULE_NAME);

      _psSessionData->isBlankPassword = TRUE;
    }
    /* Standard password */
    else
    {
      if (!freerdp_settings_set_string(instance->context->settings, FreeRDP_Password, szPassword))
        writeError(ERR_ERROR, "[%s] Failed to set: FreeeRDP_Password", MODULE_NAME);
    }
  }

  nRet = freerdp_client_start(instance->context);
  if (nRet != 0)
    writeError(ERR_FATAL, "[%s] freerdp_client_start exit code: %d", MODULE_NAME, nRet);

  if (freerdp_connect(instance))
    writeError(ERR_FATAL, "[%s] freerdp_connect failed.", MODULE_NAME);

  SMBerr = freerdp_get_last_error(instance->context);
  if (SMBerr == 0x00000000)
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Login attempt successful.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
    nRet = MSTATE_EXITING;
  }
  else
  {
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
      case 0x0002000B:  /* ERRCONNECT_CONNECT_CONNECT_CANCELLED */
      case 0x0002000D:  /* ERRCONNECT_CONNECT_TRANSPORT_FAILED */
        (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
        sprintf(ErrorCode, "0x%8.8X:", SMBerr);
        (*psLogin)->pErrorMsg = malloc( strlen(ErrorCode) + strlen(pErrorMsg) + 1);
        memset((*psLogin)->pErrorMsg, 0, strlen(ErrorCode) + strlen(pErrorMsg) + 1);
        strcpy((*psLogin)->pErrorMsg, ErrorCode);
        strcat((*psLogin)->pErrorMsg, pErrorMsg);
        nRet = MSTATE_EXITING;
        break;

      default:
        sprintf(ErrorCode, "0x%8.8X:", SMBerr);
        (*psLogin)->pErrorMsg = malloc( strlen(ErrorCode) + strlen(pErrorMsg) + 1);
        memset((*psLogin)->pErrorMsg, 0, strlen(ErrorCode) + strlen(pErrorMsg) + 1);
        strcpy((*psLogin)->pErrorMsg, ErrorCode);
        strcat((*psLogin)->pErrorMsg, pErrorMsg);
        (*psLogin)->iResult = LOGIN_RESULT_ERROR;
        nRet = MSTATE_EXITING;
        break;
    }
  }

  setPassResult((*psLogin), szPassword);
  return(nRet);
}
