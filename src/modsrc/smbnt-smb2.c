#include "smbnt.h"

#ifdef SMBNT_SMB2_SUPPORT_ENABLED 

#define SMBv2 16

/* libsmb2:include/libsmb2-private.h */
#ifndef SMB2_SEC_NTLMSSP
#define SMB2_SEC_UNDEFINED 0 /* use KRB if available, otherwise NTLM */
#define SMB2_SEC_NTLMSSP 1
#define SMB2_SEC_KRB5 2
#endif

/*
  https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/smbv1-not-installed-by-default-in-windows
  * 2020/07/01
  * New installations of Windows 10 and Server 2016 or later no longer support SMBv1.
*/
int SMB2NegProt(int hSocket, _SMBNT_DATA* _psSessionData)
{
  /* Dialect: SMB 2.??? (highest) */
  unsigned char buf[179] = {
    0x00, 0x00, 0x00, 0xaf, 0xff, 0x53, 0x4d, 0x42,
    0x72, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0x40,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x7d,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x8b, 0x00, 0x02,
    0x50, 0x43, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f,
    0x52, 0x4b, 0x20, 0x50, 0x52, 0x4f, 0x47, 0x52,
    0x41, 0x4d, 0x20, 0x31, 0x2e, 0x30, 0x00, 0x02,
    0x4d, 0x49, 0x43, 0x52, 0x4f, 0x53, 0x4f, 0x46,
    0x54, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f, 0x52,
    0x4b, 0x53, 0x20, 0x31, 0x2e, 0x30, 0x33, 0x00,
    0x02, 0x4d, 0x49, 0x43, 0x52, 0x4f, 0x53, 0x4f,
    0x46, 0x54, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f,
    0x52, 0x4b, 0x53, 0x20, 0x33, 0x2e, 0x30, 0x00,
    0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31,
    0x2e, 0x30, 0x00, 0x02, 0x4c, 0x4d, 0x31, 0x2e,
    0x32, 0x58, 0x30, 0x30, 0x32, 0x00, 0x02, 0x53,
    0x61, 0x6d, 0x62, 0x61, 0x00, 0x02, 0x4e, 0x54,
    0x20, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x20,
    0x31, 0x2e, 0x30, 0x00, 0x02, 0x4e, 0x54, 0x20,
    0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00,
    0x02, 0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x3f,
    0x3f, 0x3f, 0x00
  };

  unsigned char* bufReceive;
  int nReceiveBufferSize = 0;

  if (medusaSend(hSocket, buf, sizeof(buf), 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
  }

  nReceiveBufferSize = 0;
  bufReceive = medusaReceiveRaw(hSocket, &nReceiveBufferSize);
  if (bufReceive == NULL)
    return FAILURE;

  /* SMBv2 negotiation (SMBv1: 0xff) */
  if (bufReceive[4] == 0xfe) {
    writeVerbose(VB_GENERAL, "%s: Server negotiated SMBv2", MODULE_NAME);
    _psSessionData->smbVersion = SMBv2;

    _psSessionData->smb2 = smb2_init_context();
    if (_psSessionData->smb2 == NULL) {
      writeError(ERR_ERROR, "[%s] Failed to initialize context.", MODULE_NAME);
      return FAILURE;
    }

    smb2_set_authentication(_psSessionData->smb2, SMB2_SEC_NTLMSSP);
    smb2_set_security_mode(_psSessionData->smb2, SMB2_NEGOTIATE_SIGNING_ENABLED);

    return SUCCESS;
  }

  return FAILURE;
}

/*
  SMB2ConvertPassword
  Function: Prepare NTLM password hash for libsmb2.
*/
int SMB2ConvertPassword(_SMBNT_DATA *_psSessionData, unsigned char* szPassword, unsigned char** szPassword2)
{
  unsigned int i = 0;
  unsigned char *p = NULL;
  unsigned char NO_PASSWORD[1] = "";

  /* Use NTLM Hash instead of password */
  /* D42E35E1A1E4C22BD32E2170E4857C20:5E20780DD45857A68402938C7629D3B2::: */
  if (_psSessionData->hashFlag == HASH) {
    p = szPassword;
    while ((*p != '\0') && (i < 1)) {
      if (*p == ':')
        i++;
      p++;
    }
  }

  /* If "-e ns" was used, don't treat these values as hashes. */
  if ((_psSessionData->hashFlag == HASH) && (i >= 1)) {
    if (*p == '\0') {
      writeError(ERR_ERROR, "Error reading PwDump file.");
      return FAILURE;
    }
    else if (*p == 'N') {
      writeError(ERR_DEBUG_MODULE, "Found \"NO PASSWORD\" for NTLM Hash.");
      *szPassword2 = NO_PASSWORD;
    }
    else {
      memset(p + 32, '\0', 1);
      writeError(ERR_DEBUG_MODULE, "Prepare ASCII PwDump NTLM Hash (%s).", p);
      if (asprintf((char **)szPassword2, "ntlm:%s", p) < 0) { return FAILURE; }
    }
  } else {
    *szPassword2 = szPassword;
    writeError(ERR_DEBUG_MODULE, "[%s] Using standard password: %s", MODULE_NAME, *szPassword2);
  }

  return SUCCESS;
}

/*
  SMB2SessionSetup
*/
unsigned long SMB2SessionSetup(int hSocket, sLogin** psLogin, _SMBNT_DATA *_psSessionData, char* szLogin, char* szPassword)
{
  int SMBerr, SMBaction;
  unsigned long SMBSessionRet;
  const char *pErrorMsg = NULL;
  char ErrorCode[10];
  int iRet;
  unsigned int i;
  unsigned char* szPassword2 = NULL;

  regex_t preg;
  int errcode = REG_NOMATCH;
  char errmsg[512];
  size_t nmatch = 1;
  regmatch_t pmatch[1];

  if (_psSessionData->accntFlag == LOCAL) {
    strcpy((char *) _psSessionData->workgroup, ".");
  } else if (_psSessionData->accntFlag == BOTH) {
    memset(_psSessionData->workgroup, 0, 16);
  } else if (_psSessionData->accntFlag == OTHER) {
    strncpy(_psSessionData->workgroup, _psSessionData->workgroup_other, 16);
  }

  writeError(ERR_DEBUG_MODULE, "[%s] Set authentication request data.", MODULE_NAME);
  smb2_set_domain(_psSessionData->smb2, _psSessionData->workgroup);
  smb2_set_user(_psSessionData->smb2, szLogin);

  if (SMB2ConvertPassword(_psSessionData, szPassword, &szPassword2) == FAILURE) {
    writeError(ERR_ERROR, "Failed to prepare libsmb2 password.");
    return FAILURE;
  }

  smb2_set_password(_psSessionData->smb2, szPassword2);

  writeError(ERR_DEBUG_MODULE, "[%s] Initiate SMB2 connection.", MODULE_NAME);
  if (smb2_connect_share(_psSessionData->smb2, (*psLogin)->psServer->pHostIP, "ADMIN$", NULL) < 0) {

    pErrorMsg = smb2_get_error(_psSessionData->smb2);
    writeError(ERR_DEBUG_MODULE, "[%s] Failed to connect to ADMIN$: %s", MODULE_NAME, pErrorMsg);

    /* Extract error code from libsmb2 error message:
       ERROR: [smb2.mod] Failed to connect to ADMIN$: Session setup failed with (0xc000006d) STATUS_LOGON_FAILURE
    */
    errcode = regcomp(&preg, "0x[a-fA-F0-9]+", REG_EXTENDED|REG_ICASE);
    if (errcode)
    {
      memset(errmsg, 0, 512);
      regerror(errcode, &preg, errmsg, 512);
      writeError(ERR_ERROR, "Regex compilation failed: %s", errmsg);
      return FAILURE;
    }

    errcode = regexec(&preg, pErrorMsg, nmatch, pmatch, 0);
    if (errcode == REG_NOMATCH)
    {
      writeError(ERR_ERROR, "[%s] Regex failed to match smb2_connect_share error message.", MODULE_NAME);
      return FAILURE;
    }
    else {
      writeError(ERR_DEBUG_MODULE, "[%s] Regex successfully matched smb2_connect_share error message.", MODULE_NAME);

      memset(errmsg, 0, 512);
      memcpy(errmsg, pErrorMsg + pmatch[0].rm_so, pmatch[0].rm_eo - pmatch[0].rm_so);
      SMBSessionRet = (int)strtol(errmsg, NULL, 0);

      writeError(ERR_DEBUG_MODULE, "[%s] smb2_connect_share session return code: 0x%6.6X", MODULE_NAME, SMBSessionRet);
    }
  }
  else {
    writeError(ERR_DEBUG_MODULE, "[%s] smb2_connect_share returned without error.", MODULE_NAME);
    SMBSessionRet = 0x00000000;
    smb2_disconnect_share(_psSessionData->smb2);
  }

  return SMBSessionRet;
}

#else

int SMB2NegProt(int hSocket, _SMBNT_DATA* _psSessionData)
{
  writeVerbose(VB_NONE, "** Module was not built with LIBSMB2 support **");
  return FAILURE;
}

unsigned long SMB2SessionSetup(int hSocket, sLogin** psLogin, _SMBNT_DATA *_psSessionData, char* szLogin, char* szPassword)
{
  writeVerbose(VB_NONE, "** Module was not built with LIBSMB2 support **");
  return FAILURE;
}

#endif
