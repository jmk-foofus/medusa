/*
**   SMB LAN Manager Password/HASH Checking Medusa Module
**
**   ------------------------------------------------------------------------
**    Copyright (C) 2024 Joe Mondloch
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
**   Based on code from: SMB Auditing Tool
**   [Copyright (C) Patrik Karlsson 2001]
**
**   This code allows Medusa to directly test NTLM hashes against
**   a Windows host. This may be useful for an auditor who has aquired
**   a sam._ or pwdump file and would like to quickly determine
**   which are valid entries.
**
**   Several "-m 'METHOD:VALUE'" options can be used with this module. The
**   following are valid methods: GROUP, GROUP_OTHER, PASS, AUTH and MODE.
**   The following values are useful for these methods:
**
**   GROUP:?
**     LOCAL  == Check local account.
**     DOMAIN == Check credentials against this hosts primary
**               domain controller via this host.
**     BOTH   == Check both. This leaves the workgroup field set
**               blank and then attempts to check the credentials
**               against the host. If the account does not exist
**               locally on the host being tested, that host then
**               queries its domain controller.
**
**   GROUP_OTHER:?
**     Configure arbitrary domain for host to authenticate against.
**
**   PASS:?
**     PASSWORD == Use a normal password.
**     HASH     == Use a NTLM hash rather than a password.
**     MACHINE  == Use the Machine's NetBIOS name as the password.
**
**   AUTH:?
**     LM      == LM authentication (case-insensitive)
**     NTLM    == NTLMv1 authentication
**     LMv2    == LMv2 authentication
**     NTLMv2  == NTLMv2 authentication
**
**   MODE:?
**     AUTO    == Attempt SMBv1, SMBv2 and NetBIOS connections.
**     NETBIOS == Force NetBIOS-only mode (pre-Windows 2000 servers).
**     SMB2    == Force SMBv2-only mode (disable older modes).
**
**   Be careful of mass domain account lockout with this. For
**   example, assume you are checking several accounts against
**   many domain workstations. If you are not using the 'LOCAL'
**   option and these accounts do not exist locally on the
**   workstations, each workstation will in turn check their
**   respective domain controller. This could cause a bunch of
**   lockouts. Of course, it'd look like the workstations, not
**   you, were doing it. ;)
**
**   **FYI, this code is unable to test accounts on default XP
**   hosts which are not part of a domain and do not have normal
**   file sharing enabled. Default XP does not allow shares and
**   returns STATUS_LOGON_FAILED for both valid and invalid
**   credentials. XP with simple sharing enabled returns SUCCESS
**   for both valid and invalid credentials. If anyone knows a
**   way to test in these configurations...
**
**   See http://www.foofus.net/jmk/passhash.html for further
**   examples.
*/

#include "smbnt.h"

#ifdef HAVE_LIBSSL

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
  writeVerbose(VB_NONE, "  GROUP:? (DOMAIN, LOCAL*, BOTH)");
  writeVerbose(VB_NONE, "    Option sets NetBIOS workgroup field.");
  writeVerbose(VB_NONE, "    DOMAIN: Check credentials against this hosts primary domain controller via this host.");
  writeVerbose(VB_NONE, "    LOCAL:  Check local account.");
  writeVerbose(VB_NONE, "    BOTH:   Check both. This leaves the workgroup field set blank and then attempts to check");
  writeVerbose(VB_NONE, "            the credentials against the host. If the account does not exist locally on the ");
  writeVerbose(VB_NONE, "            host being tested, that host then queries its domain controller.");
  writeVerbose(VB_NONE, "  GROUP_OTHER:? ");
  writeVerbose(VB_NONE, "    Option allows manual setting of domain to check against. Use instead of GROUP.");
  writeVerbose(VB_NONE, "  PASS:?  (PASSWORD*, HASH, MACHINE)");
  writeVerbose(VB_NONE, "    PASSWORD: Use normal password.");
  writeVerbose(VB_NONE, "    HASH:     Use a NTLM hash rather than a password.");
  writeVerbose(VB_NONE, "    MACHINE:  Use the machine's NetBIOS name as the password.");
  writeVerbose(VB_NONE, "  AUTH:?  (LM, NTLM, LMv2*, NTLMv2)");
  writeVerbose(VB_NONE, "    Option sets LAN Manager Authentication level.");
  writeVerbose(VB_NONE, "    LM: ");
  writeVerbose(VB_NONE, "    NTLM: ");
  writeVerbose(VB_NONE, "    LMv2: ");
  writeVerbose(VB_NONE, "    NTLMv2: ");
  writeVerbose(VB_NONE, "  MODE:?  (AUTO*, NETBIOS, SMB2)");
  writeVerbose(VB_NONE, "    NETBIOS: Attempt NetBIOS-only connection (pre-Windows 2000).");
  writeVerbose(VB_NONE, "    SMB2:    Attempt SMBv2-only connection.");
  writeVerbose(VB_NONE, "    AUTO:    Attempt SMBv1, SMBv2 and NetBIOS (pre-Windows 2000).");
  writeVerbose(VB_NONE, "             SMB communications use either port 139 or 445/tcp. Pre-Windows 2000 connections");
  writeVerbose(VB_NONE, "             ran on top of NetBIOS using 139/tcp. Later versions of SMB use 445/tcp. The");
  writeVerbose(VB_NONE, "             default behavior for Medusa is to attempt to connect to 445/tcp. If successful,");
  writeVerbose(VB_NONE, "             Medusa will initiate an SMBv1 connection, followed by SMBv2. If the port is not");
  writeVerbose(VB_NONE, "             open, Medusa will attempt an SMBv1 connection to the NetBIOS port.");
  writeVerbose(VB_NONE, "\n(*) Default value");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "Usage examples:");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "1: Normal boring check...");
  writeVerbose(VB_NONE, "    medusa -M smbnt -h somehost -u someuser -p somepassword");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "2: Testing domain credentials against a client system...");
  writeVerbose(VB_NONE, "    medusa -M smbnt -h somehost -U users.txt -p password -m GROUP:DOMAIN");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "3: Testing each credential from a PwDump file against the target's domain via the target...");
  writeVerbose(VB_NONE, "    medusa -M smbnt -h somehost -C pwdump.txt -m PASS:HASH -m GROUP:DOMAIN");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "4: Testing each hash from a PwDump file against a specific user local to the target...");
  writeVerbose(VB_NONE, "    medusa -M smbnt -H hosts.txt -C pwdump.txt -u someuser -m PASS:HASH");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "5: Testing an individual NTLM hash...");
  writeVerbose(VB_NONE, "    medusa -M smbnt -H hosts.txt -u administrator -p 92D887C8010492C2944E2DF489A880E4:7A2EDE4F51BC5A03984C6BA2C239CF63::: -m PASS:HASH");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "Access level:");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "This module performs both an SMB authentication request (Session Setup AndX) and a ");
  writeVerbose(VB_NONE, "share connection request (Tree Connect AndX). The share connection request is for the ");
  writeVerbose(VB_NONE, "default hidden administrative share ADMIN$. The goal is to identify if the credentials ");
  writeVerbose(VB_NONE, "being tested have administrative rights to the target system. The following examples ");
  writeVerbose(VB_NONE, "highlight how to interrupt the responses.");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "  Valid administrative-level credentials: [SUCCESS (ADMIN$ - Access Allowed)]");
  writeVerbose(VB_NONE, "  Valid user-level credentials: [SUCCESS (ADMIN$ - Access Denied)]");
  writeVerbose(VB_NONE, "  Valid credentials, access level unknown: [SUCCESS (ADMIN$ - Share Unavailable)]");
  writeVerbose(VB_NONE, "");
}

// The "main" of the medusa module world - this is what gets called to actually do the work
int go(sLogin* logins, int argc, char *argv[])
{
  int i;
  char *strtok_ptr = NULL, *pOpt = NULL, *pOptTmp = NULL;
  _SMBNT_DATA *psSessionData = NULL;
  psSessionData = malloc(sizeof(_SMBNT_DATA));
  memset(psSessionData, 0, sizeof(_SMBNT_DATA));

  if ((argc < 0) || (argc > 5))
  {
    writeError(ERR_ERROR, "%s: Incorrect number of parameters passed to module (%d). Use \"-q\" option to display module usage.", MODULE_NAME, argc);
    return FAILURE;
  }
  else
  {
    writeError(ERR_DEBUG_MODULE, "OMG teh %s module has been called!!", MODULE_NAME);

    psSessionData->authLevel = AUTH_LMv2;
    psSessionData->accntFlag = LOCAL;
    psSessionData->hashFlag = PASSWORD;
    psSessionData->protoFlag = MODE_AUTO;

    for (i=0; i<argc; i++) {
      pOptTmp = strdup(argv[i]);
      writeError(ERR_DEBUG_MODULE, "Processing complete option: %s", pOptTmp);
      pOpt = strtok_r(pOptTmp, ":", &strtok_ptr);
      writeError(ERR_DEBUG_MODULE, "Processing option: %s", pOpt);

      if (strcmp(pOpt, "GROUP") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if (pOpt == NULL)
          writeError(ERR_WARNING, "Method GROUP requires value to be set.");
        else if (strcmp(pOpt, "LOCAL") == 0)
          psSessionData->accntFlag = LOCAL;
        else if (strcmp(pOpt, "DOMAIN") == 0)
          psSessionData->accntFlag = NTDOMAIN;
        else if (strcmp(pOpt, "BOTH") == 0)
          psSessionData->accntFlag = BOTH;
        else
          writeError(ERR_WARNING, "Invalid value for method GROUP.");
      }
      else if (strcmp(pOpt, "GROUP_OTHER") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if ( pOpt )
        {
          strncpy((char *) psSessionData->workgroup_other, pOpt, 16);
          psSessionData->accntFlag = OTHER;
        }
        else
          writeError(ERR_WARNING, "Method GROUP_OTHER requires value to be set.");
      }
      else if (strcmp(pOpt, "PASS") == 0) {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if (pOpt == NULL)
          writeError(ERR_WARNING, "Method PASS requires value to be set.");
        else if (strcmp(pOpt, "PASSWORD") == 0)
          psSessionData->hashFlag = PASSWORD;
        else if (strcmp(pOpt, "HASH") == 0)
          psSessionData->hashFlag = HASH;
        else if (strcmp(pOpt, "MACHINE") == 0)
          psSessionData->hashFlag = MACHINE_NAME;
        else
          writeError(ERR_WARNING, "Invalid value for method PASS.");
      }
      else if (strcmp(pOpt, "AUTH") == 0) {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if (pOpt == NULL)
          writeError(ERR_WARNING, "Method AUTH requires value to be set.");
        else if (strcmp(pOpt, "LM") == 0)
          psSessionData->authLevel = AUTH_LM;
        else if (strcmp(pOpt, "NTLM") == 0)
          psSessionData->authLevel = AUTH_NTLM;
        else if (strcmp(pOpt, "LMv2") == 0)
          psSessionData->authLevel = AUTH_LMv2;
        else if (strcmp(pOpt, "NTLMv2") == 0)
        {
          psSessionData->authLevel = AUTH_NTLMv2;
          /* NTLMv2 authentication is returning a STATUS_INVALID_PARAMETER response with 2012R2 servers. This issue pre-dates the AndX modification. */
          writeError(ERR_FATAL, "NTLMv2 support currently disabled. The default authentication mode of LMv2 should work in all cases that NTLMv2 is required.");
        }
        else
          writeError(ERR_WARNING, "Invalid value for method AUTH.");
      }
      else if (strcmp(pOpt, "MODE") == 0) {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if (pOpt == NULL)
          writeError(ERR_WARNING, "Method MODE requires value to be set.");
        else if (strcmp(pOpt, "AUTO") == 0)
          psSessionData->protoFlag = MODE_AUTO;
        else if (strcmp(pOpt, "NETBIOS") == 0)
          psSessionData->protoFlag = MODE_NETBIOS;
        else if (strcmp(pOpt, "SMB2") == 0)
          psSessionData->protoFlag = MODE_SMB2;
        else
          writeError(ERR_WARNING, "Invalid value for method MODE.");
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

int initModule(sLogin* psLogin, _SMBNT_DATA *_psSessionData)
{
  int hSocket = -1;
  enum MODULE_STATE nState = MSTATE_NEW;
  char *szUser = NULL;
  sConnectParams params;
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
    szUser = parseFullyQualifiedUsername(_psSessionData, psCredSet->psUser->pUser);
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
    params.nPort = PORT_SMBNT;

  initConnectionParams(psLogin, &params);

  while (nState != MSTATE_COMPLETE)
  {
    switch (nState)
    {
      case MSTATE_NEW:
        // Already have an open socket - close it
        if (hSocket > 0)
          medusaDisconnect(hSocket);

        if (params.nPort == PORT_SMBNT) {
          hSocket = medusaConnect(&params);
          if ( hSocket < 0 ) {
            writeError(ERR_NOTICE, "%s Failed to establish WIN2000_NATIVE mode. Attempting NetBIOS mode.)", MODULE_NAME);
            params.nPort = PORT_SMB;
            _psSessionData->protoFlag = MODE_NETBIOS;
            hSocket = medusaConnect(&params);
          }
        }
        else {
          hSocket = medusaConnect(&params);
        }

        if (hSocket < 0)
        {
          writeError(ERR_ERROR, "%s: failed to connect, port %d was not open on %s", MODULE_NAME, params.nPort, psLogin->psServer->pHostIP);
          psLogin->iResult = LOGIN_RESULT_UNKNOWN;
          return FAILURE;
        }

        writeError(ERR_DEBUG_MODULE, "Connected");

        if (NBSTATQuery(psLogin, _psSessionData) < 0) {
          writeError(ERR_ERROR, "NetBIOS Name Query Failed with host: %s (proceeding anyways).", psLogin->psServer->pHostIP);
        }

        if (NBSSessionRequest(hSocket, _psSessionData) < 0) {
          writeError(ERR_ERROR, "Session Setup Failed with host: %s. Is the server service running?", psLogin->psServer->pHostIP);
          psLogin->iResult = LOGIN_RESULT_UNKNOWN;
          return FAILURE;
        }

        switch (_psSessionData->protoFlag)
	{
          case MODE_NETBIOS:
            writeError(ERR_DEBUG_MODULE, "[%s] : Forcing NetBIOS mode: %s", MODULE_NAME, psLogin->psServer->pHostIP);
            if (SMBNegProt(hSocket, _psSessionData) < 0)
	    {
              writeError(ERR_ERROR, "NetBIOS protocol negotiation failed with host: %s", psLogin->psServer->pHostIP);
              psLogin->iResult = LOGIN_RESULT_UNKNOWN;

              if (hSocket > 0)
                medusaDisconnect(hSocket);

              return FAILURE;
            }

            break;
          case MODE_SMB2:
            writeError(ERR_DEBUG_MODULE, "[%s] : Forcing SMBv2 mode: %s", MODULE_NAME, psLogin->psServer->pHostIP);
            if (SMB2NegProt(hSocket, _psSessionData) < 0)
            {
              writeError(ERR_ERROR, "SMBv2 protocol negotiation failed with host: %s", psLogin->psServer->pHostIP);
              psLogin->iResult = LOGIN_RESULT_UNKNOWN;

              if (hSocket > 0)
                medusaDisconnect(hSocket);

              return FAILURE;
            }

            break;
          default:
            writeError(ERR_DEBUG_MODULE, "[%s] : Attempting automatic mode: %s", MODULE_NAME, psLogin->psServer->pHostIP);
            if (SMBNegProt(hSocket, _psSessionData) < 0)
            {
              writeError(ERR_DEBUG_MODULE, "[%s] SMBv1 protocol negotiation failed with host: %s. Attempting SMBv2 connection.", MODULE_NAME, psLogin->psServer->pHostIP);

              if (hSocket > 0)
                medusaDisconnect(hSocket);

              hSocket = medusaConnect(&params);

              if (SMB2NegProt(hSocket, _psSessionData) < 0)
              {
                writeError(ERR_ERROR, "SMBv2 protocol negotiation failed with host: %s", psLogin->psServer->pHostIP);
                psLogin->iResult = LOGIN_RESULT_UNKNOWN;

                return FAILURE;
              }
            }

            break;
        }

        nState = MSTATE_RUNNING;
        break;
      case MSTATE_RUNNING:
        nState = tryLogin(hSocket, &psLogin, _psSessionData, szUser, psCredSet->pPass);

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
              FREE(szUser);
              szUser = parseFullyQualifiedUsername(_psSessionData, psCredSet->psUser->pUser);
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
#ifdef SMBNT_SMB2_SUPPORT_ENABLED
        smb2_destroy_context(_psSessionData->smb2);
#endif
        nState = MSTATE_COMPLETE;
        break;
      default:
        writeError(ERR_CRITICAL, "Unknown %s module (%d) state %d host: %s", MODULE_NAME, psLogin->iId, nState, psLogin->psServer->pHostIP);
        if (hSocket > 0)
          medusaDisconnect(hSocket);
        hSocket = -1;
#ifdef SMBNT_SMB2_SUPPORT_ENABLED
        smb2_destroy_context(_psSessionData->smb2);
#endif
        psLogin->iResult = LOGIN_RESULT_UNKNOWN;
        return FAILURE;
    }
  }

  writeError(ERR_DEBUG_MODULE, "[%s] Exiting module...", MODULE_NAME);

  FREE(psCredSet);
  FREE(szUser);
  return SUCCESS;
}

int tryLogin(int hSocket, sLogin** psLogin, _SMBNT_DATA* _psSessionData, char* szLogin, char* szPassword)
{
  int SMBerr, SMBaction;
  unsigned long SMBSessionRet;
  char *pErrorMsg = NULL;
  char ErrorCode[10];
  int iRet;
  unsigned int i;

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
    0xC00000CC          /* STATUS_BAD_NETWORK_NAME */
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
    "STATUS_BAD_NETWORK_NAME"
  };

  memset(&ErrorCode, 0, 10);

  if (_psSessionData->smbVersion == SMBv2) {
    SMBSessionRet = SMB2SessionSetup(hSocket, psLogin, _psSessionData, szLogin, szPassword);
  } else {
    SMBSessionRet = SMBSessionSetup(hSocket, psLogin, _psSessionData, szLogin, szPassword);
  }

  SMBerr = (unsigned long) SMBSessionRet & 0x00FFFFFF;
  SMBaction = ((unsigned long) SMBSessionRet & 0xFF000000) >> 24;

  writeError(ERR_DEBUG_MODULE, "SMBSessionRet: %8.8X SMBerr: %4.4X SMBaction: %2.2X", SMBSessionRet, SMBerr, SMBaction);

  /* Locate appropriate SMB code message */
  pErrorMsg = smbErrorMsg[0]; /* UNKNOWN_ERROR_CODE */
  for (i = 0; i < sizeof(smbErrorCode)/4; i++) {
    if (SMBerr == (smbErrorCode[i] & 0x00FFFFFF)) {
      pErrorMsg = smbErrorMsg[i];
      break;
    }
  }

  switch (SMBerr)
  {
    case 0x000000:
      /*
        Non-domain connected XP and 2003 hosts map non-existant accounts to
        the anonymous user and return SUCCESS during password checks. Medusa
        will check the value of the ACTION flag in the target's response to
        determine if the account is a legitimate or anonymous success.
      */
      if (SMBaction == 0x01) {
        (*psLogin)->pErrorMsg = malloc( 40 + 1 );
        memset((*psLogin)->pErrorMsg, 0, 40 + 1 );
        sprintf((*psLogin)->pErrorMsg, "Non-existant account. Anonymous success.");
        (*psLogin)->iResult = LOGIN_RESULT_ERROR;
      }
      else
      {
        (*psLogin)->pErrorMsg = malloc( 23 + 1 );
        memset((*psLogin)->pErrorMsg, 0, 23 + 1 );
        sprintf((*psLogin)->pErrorMsg, "ADMIN$ - Access Allowed");
        (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
      }

      iRet = MSTATE_EXITING;
      break;
    case 0x00006F:  /* STATUS_INVALID_LOGON_HOURS - Valid password */
    case 0xC10002:  /* STATUS_INVALID_LOGON_HOURS - Valid password (LM) */
    case 0x000064:  /* Valid password, "The machine you are logging onto is protected by an
                       authentication firewall. The specificed account is not allowed to
                       authenticate to the machine." */
    case 0x000070:  /* STATUS_INVALID_WORKSTATION - Valid password */
    case 0xC00002:  /* STATUS_INVALID_WORKSTATION - Valid password (LM) */
    // TODO: Verify whether we can determine password validity from DISABLED. Win7 doesn't seem to tell us...
    //case 0x000072:  /* STATUS_ACCOUNT_DISABLED - Valid password */
    case 0x000193:  /* STATUS_ACCOUNT_EXPIRED - Valid password */
    case 0xBF0002:  /* STATUS_ACCOUNT_DISABLED or STATUS_ACCOUNT_EXPIRED - Valid password (LM) */
    case 0x000224:  /* STATUS_PASSWORD_MUST_CHANGE - Valid password */
    case 0xC20002:  /* STATUS_PASSWORD_MUST_CHANGE - Valid password (LM) */
    // TODO: Verify whether we can determine password validity from STATUS_ACCOUNT_RESTRICTION. Win7 doesn't seem to tell us...
    //case 0x00006E:  /* Valid password, GPO Disabling Remote Connections Using NULL Passwords */
    // TODO: Verify whether we can determine password validity from STATUS_ACCOUNT_RESTRICTION. Win7 doesn't seem to tell us...
    //case 0x00015B:  /* Valid password, GPO "Deny access to this computer from the network" */
    case 0x000071:  /* Valid password, password expired and must be changed on next logon */
      (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
      sprintf(ErrorCode, "0x%6.6X:", SMBerr);
      (*psLogin)->pErrorMsg = malloc( strlen(ErrorCode) + strlen(pErrorMsg) + 1);
      memset((*psLogin)->pErrorMsg, 0, strlen(ErrorCode) + strlen(pErrorMsg) + 1);
      strcpy((*psLogin)->pErrorMsg, ErrorCode);
      strcat((*psLogin)->pErrorMsg, pErrorMsg);
      iRet = MSTATE_EXITING;
      break;
    case 0x000022:  /* Valid password, no access to ADMIN$ (non-administative account) */
      (*psLogin)->pErrorMsg = malloc( 22 + 1 );
      memset((*psLogin)->pErrorMsg, 0, 22 + 1 );
      sprintf((*psLogin)->pErrorMsg, "ADMIN$ - Access Denied");
      (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
      iRet = MSTATE_EXITING;
      break;
    case 0x0000CC:  /* Valid password, but ADMIN$ not found (STATUS_BAD_NETWORK_NAME) */
      (*psLogin)->pErrorMsg = malloc( 26 + 1 );
      memset((*psLogin)->pErrorMsg, 0, 26 + 1 );
      sprintf((*psLogin)->pErrorMsg, "ADMIN$ - Share Unavailable");
      (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
      iRet = MSTATE_EXITING;
      break;
    case 0x050001:  /* AS/400 -- Incorrect password */
      writeError(ERR_DEBUG_MODULE, "[%s] AS/400 Access is Denied. Incorrect password or disabled account.", MODULE_NAME);
      (*psLogin)->iResult = LOGIN_RESULT_FAIL;
      iRet = MSTATE_RUNNING;
      break;
    case 0x00006D:  /* Incorrect password */
      (*psLogin)->iResult = LOGIN_RESULT_FAIL;
      iRet = MSTATE_RUNNING;
      break;
    default:
      sprintf(ErrorCode, "0x%6.6X:", SMBerr);
      (*psLogin)->pErrorMsg = malloc( strlen(ErrorCode) + strlen(pErrorMsg) + 1);
      memset((*psLogin)->pErrorMsg, 0, strlen(ErrorCode) + strlen(pErrorMsg) + 1);
      strcpy((*psLogin)->pErrorMsg, ErrorCode);
      strcat((*psLogin)->pErrorMsg, pErrorMsg);
      (*psLogin)->iResult = LOGIN_RESULT_ERROR;
      iRet = MSTATE_EXITING;
      break;
  }

  if (_psSessionData->hashFlag == MACHINE_NAME) {
    setPassResult((*psLogin), (char *)_psSessionData->machine_name);
    iRet = MSTATE_EXITING;
  }
  else {
    setPassResult((*psLogin), szPassword);
  }

  return(iRet);
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
