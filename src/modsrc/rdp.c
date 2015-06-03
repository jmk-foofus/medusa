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

#ifndef HAVE_LIBFREERDP10
#include <freerdp/client/cmdline.h>
#endif

#define MODULE_NAME    "rdp.mod"
#define MODULE_AUTHOR  "JoMo-Kun <jmk@foofus.net>"
#define MODULE_SUMMARY_USAGE  "Brute force module for RDP (Microsoft Terminal Server) sessions"
#define MODULE_VERSION    "0.1"
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
void tf_context_new(freerdp* instance, rdpContext* context);
void tf_context_free(freerdp* instance, rdpContext* context);
void tf_begin_paint(rdpContext* context);
void tf_end_paint(rdpContext* context);
int tf_receive_channel_data(freerdp* instance, int channelId, unsigned char* data, int size, int flags, int total_size);
int tf_pre_connect(freerdp* instance);
int tf_post_connect(freerdp* instance);

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
#if defined(HAVE_LIBFREERDP12) || defined(HAVE_LIBFREERDP11PTH)
  writeVerbose(VB_NONE, "  PASS:?  (PASSWORD*, HASH)");
  writeVerbose(VB_NONE, "    PASSWORD: Use normal password.");
  writeVerbose(VB_NONE, "    HASH:     Use a NTLM hash rather than a password.");
#endif
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "Usage example: \"-M rdp\"");
#if defined(HAVE_LIBFREERDP12) || defined(HAVE_LIBFREERDP11PTH)
  writeVerbose(VB_NONE, "Usage example: \"-M rdp -m PASS:HASH -u Administrator -p 31D78236327B9619B14ED8EC9AB454C1");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "Note: This module does NOT work against Microsoft Windows 2003/XP and earlier.");
#endif
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
#if defined(HAVE_LIBFREERDP12) || defined(HAVE_LIBFREERDP11PTH)
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
#endif
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
    
#ifdef HAVE_LIBFREERDP12
        initWLog();
#else
        freerdp_channels_global_init();
#endif

	      instance = freerdp_new();
	      instance->PreConnect = tf_pre_connect;
	      instance->PostConnect = tf_post_connect;
	      instance->ReceiveChannelData = tf_receive_channel_data;

	      instance->ContextNew = (pContextNew)tf_context_new;
	      instance->ContextFree = tf_context_free;
	      freerdp_context_new(instance);

#ifdef HAVE_LIBFREERDP10
        instance->settings->ignore_certificate = TRUE;
        instance->settings->authentication_only = TRUE;
        instance->settings->hostname = psLogin->psServer->pHostIP;
#else
        instance->settings->IgnoreCertificate = TRUE;
        instance->settings->AuthenticationOnly = TRUE;
        instance->settings->ServerHostname = psLogin->psServer->pHostIP;
#endif       
 
        if (psLogin->psServer->psAudit->iPortOverride > 0)
#ifdef HAVE_LIBFREERDP10
          instance->settings->port = psLogin->psServer->psAudit->iPortOverride;
#else
          instance->settings->ServerPort = psLogin->psServer->psAudit->iPortOverride;
#endif
        else
#ifdef HAVE_LIBFREERDP10
          instance->settings->port = PORT_RDP;
#else
          instance->settings->ServerPort = PORT_RDP;
#endif

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
#ifdef HAVE_LIBFREERDP12
        freerdp_free(instance);
#else
        freerdp_channels_global_uninit();
#endif
        nState = MSTATE_COMPLETE;
        break;
      default:
        writeError(ERR_CRITICAL, "Unknown %s module state %d", MODULE_NAME, nState);

#ifdef HAVE_LIBFREERDP12
        freerdp_free(instance);
#else
        freerdp_channels_global_uninit();
#endif
        psLogin->iResult = LOGIN_RESULT_UNKNOWN;

        return FAILURE;
    }  
  }

  FREE(psCredSet);
  return SUCCESS;
}

/* Module Specific Functions */
#ifdef HAVE_LIBFREERDP12
void CallbackAppenderMessage(const wLogMessage *msg)
{
  writeError(ERR_DEBUG_MODULE, "[%s] FreeRDP: %s", MODULE_NAME, msg->TextString);
}

void CallbackAppenderData(const wLogMessage *msg)
{
  writeError(ERR_DEBUG_MODULE, "[%s] FreeRDP CallbackAppenderData()", MODULE_NAME);
}

void CallbackAppenderImage(const wLogMessage *msg)
{
  writeError(ERR_DEBUG_MODULE, "[%s] FreeRDP CallbackAppenderImage()", MODULE_NAME);
}

void CallbackAppenderPackage(const wLogMessage *msg)
{
  writeError(ERR_DEBUG_MODULE, "[%s] FreeRDP CallbackAppenderPackage()", MODULE_NAME);
}

void initWLog()
{
  wLog* root;
  wLogLayout* layout;
  wLogAppender* appender;

  WLog_Init();

  writeError(ERR_DEBUG_MODULE, "[%s] Initializing FreeRDP WLog", MODULE_NAME);

  root = WLog_GetRoot();

  WLog_SetLogAppenderType(root, WLOG_APPENDER_CALLBACK);

  appender = WLog_GetLogAppender(root);

  WLog_CallbackAppender_SetCallbacks(root, (wLogCallbackAppender*) appender,
    CallbackAppenderMessage, CallbackAppenderImage, CallbackAppenderPackage,
    CallbackAppenderData);

  layout = WLog_GetLogLayout(root);
  WLog_Layout_SetPrefixFormat(root, layout, "%mn");

  WLog_OpenAppender(root);
}
#endif

struct tf_info
{
	void* data;
};
typedef struct tf_info tfInfo;

struct tf_context
{
	rdpContext _p;

	tfInfo* tfi;
};
typedef struct tf_context tfContext;

void tf_context_new(freerdp* instance, rdpContext* context)
{
	context->channels = freerdp_channels_new();
}

void tf_context_free(freerdp* instance, rdpContext* context)
{

}

void tf_begin_paint(rdpContext* context)
{
	rdpGdi* gdi = context->gdi;
	gdi->primary->hdc->hwnd->invalid->null = 1;
}

void tf_end_paint(rdpContext* context)
{
	rdpGdi* gdi = context->gdi;

	if (gdi->primary->hdc->hwnd->invalid->null)
		return;
}

int tf_receive_channel_data(freerdp* instance, int channelId, unsigned char* data, int size, int flags, int total_size)
{
	return freerdp_channels_data(instance, channelId, data, size, flags, total_size);
}

int tf_pre_connect(freerdp* instance)
{
	tfInfo* tfi;
	tfContext* context;
	rdpSettings* settings;

	context = (tfContext*) instance->context;

	tfi = (tfInfo*) malloc(sizeof(tfInfo));
	memset(tfi, 0, sizeof(tfInfo));

	context->tfi = tfi;

	settings = instance->settings;

#ifdef HAVE_LIBFREERDP10
  settings->order_support[NEG_DSTBLT_INDEX] = TRUE;
  settings->order_support[NEG_PATBLT_INDEX] = TRUE;
  settings->order_support[NEG_SCRBLT_INDEX] = TRUE;
  settings->order_support[NEG_OPAQUE_RECT_INDEX] = TRUE;
  settings->order_support[NEG_DRAWNINEGRID_INDEX] = TRUE;
  settings->order_support[NEG_MULTIDSTBLT_INDEX] = TRUE;
  settings->order_support[NEG_MULTIPATBLT_INDEX] = TRUE;
  settings->order_support[NEG_MULTISCRBLT_INDEX] = TRUE;
  settings->order_support[NEG_MULTIOPAQUERECT_INDEX] = TRUE;
  settings->order_support[NEG_MULTI_DRAWNINEGRID_INDEX] = TRUE;
  settings->order_support[NEG_LINETO_INDEX] = TRUE;
  settings->order_support[NEG_POLYLINE_INDEX] = TRUE;
  settings->order_support[NEG_MEMBLT_INDEX] = TRUE;
  settings->order_support[NEG_MEM3BLT_INDEX] = TRUE;
  settings->order_support[NEG_SAVEBITMAP_INDEX] = TRUE;
  settings->order_support[NEG_GLYPH_INDEX_INDEX] = TRUE;
  settings->order_support[NEG_FAST_INDEX_INDEX] = TRUE;
  settings->order_support[NEG_FAST_GLYPH_INDEX] = TRUE;
  settings->order_support[NEG_POLYGON_SC_INDEX] = TRUE;
  settings->order_support[NEG_POLYGON_CB_INDEX] = TRUE;
  settings->order_support[NEG_ELLIPSE_SC_INDEX] = TRUE;
  settings->order_support[NEG_ELLIPSE_CB_INDEX] = TRUE;
#else
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
#endif

	freerdp_channels_pre_connect(instance->context->channels, instance);

	return TRUE;
}

int tf_post_connect(freerdp* instance)
{
	gdi_init(instance, CLRCONV_ALPHA | CLRCONV_INVERT | CLRBUF_16BPP | CLRBUF_32BPP, NULL);

	instance->update->BeginPaint = tf_begin_paint;
	instance->update->EndPaint = tf_end_paint;

	freerdp_channels_post_connect(instance->context->channels, instance);

	return TRUE;
}

int tryLogin(_MODULE_DATA* _psSessionData, sLogin** psLogin, freerdp* instance, char* szLogin, char* szPassword)
{
  int nRet;
  int old_stderr;

#ifdef HAVE_LIBFREERDP10
  instance->settings->username = szLogin;
#else
  instance->settings->Username = szLogin;
#endif

  /* If the domain is not defined, local accounts are targeted */
  if (_psSessionData->szDomain)
#ifdef HAVE_LIBFREERDP10
    instance->settings->domain = _psSessionData->szDomain;
#else
    instance->settings->Domain = _psSessionData->szDomain;
#endif

  /* Pass-the-hash support added to FreeRDP 1.2.x development tree */
#if defined(HAVE_LIBFREERDP12) || defined(HAVE_LIBFREERDP11PTH)
  if (_psSessionData->isPassTheHash)
  {
    instance->settings->ConsoleSession = TRUE;
    instance->settings->RestrictedAdminModeRequired = TRUE;
    instance->settings->PasswordHash = szPassword;
  }
  else
    instance->settings->Password = szPassword;
#elif HAVE_LIBFREERDP11
    instance->settings->Password = szPassword;
#else
    instance->settings->password = szPassword;
#endif

  /* Blank password support 

     FreeRDP does not support blank passwords. It attempts to pull credentials from a local
     SAM file if a password of length 0 is supplied. We're using pass-the-hash to get
     around this issue.
  */
  if (strlen(szPassword) == 0)
  {
#if defined(HAVE_LIBFREERDP12) || defined(HAVE_LIBFREERDP11PTH)
    writeError(ERR_DEBUG_MODULE, "[%s] Using pass-the-hash to test blank password.", MODULE_NAME);
    instance->settings->ConsoleSession = TRUE;
    instance->settings->RestrictedAdminModeRequired = TRUE;
    instance->settings->PasswordHash = NTLM_HASH_BLANK;
#else
    writeError(ERR_WARNING, "[%s] FreeRDP (version < 1.2) does not support blank passwords.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_UNKNOWN;
    nRet = MSTATE_RUNNING;
    setPassResult((*psLogin), szPassword);
    return(nRet);
#endif
  }

#ifndef HAVE_LIBFREERDP10
	freerdp_client_load_addins(instance->context->channels, instance->settings);
#endif 
 
#ifndef HAVE_LIBFREERDP12
  /* Suppress library FreeRDP pre-version 1.2 output */
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
#endif
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
    writeError(ERR_DEBUG_MODULE, "[%s] Login attempt failed.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_FAIL;
    nRet = MSTATE_NEW;
  }

  setPassResult((*psLogin), szPassword);
  return(nRet);
}
