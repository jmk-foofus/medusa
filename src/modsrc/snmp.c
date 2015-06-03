/*
**   SNMPv1/2C Community String Checking Medusa Module
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
**    Based on ideas from:
**      Hydra 5.2 [van Hauser <vh@thc.org>]
**      onesixtyone [solareclipse@phreedom.org]
**
*/

#include <sys/types.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "module.h"

#define MODULE_NAME    "snmp.mod"
#define MODULE_AUTHOR  "JoMo-Kun <jmk@foofus.net>"
#define MODULE_SUMMARY_USAGE  "Brute force module for SNMP Community Strings"
#define MODULE_VERSION    "2.1"
#define MODULE_VERSION_SVN "$Id: snmp.c 9217 2015-05-07 18:07:03Z jmk $"
#define MODULE_SUMMARY_FORMAT  "%s : version %s"
#define MODULE_SUMMARY_FORMAT_WARN  "%s : version %s (%s)"

#define PORT_SNMP 161

#define SNMP_VER_V1 1
#define SNMP_VER_V2C 2
#define SNMP_READ 1
#define SNMP_WRITE 2
#define SNMP_SUCCESS_READ 1
#define SNMP_SUCCESS_WRITE 2

#define SEND_DELAY 200 /* Delay between sending SNMP requests (usec) */
#define RECEIVE_DELAY 5*1000000 /* Response wait time (usec) */

typedef struct __SNMP_DATA {
  int nVersion;
  int nReadWrite;
  int nReadTimeout;
  int nSendDelay;
} _SNMP_DATA;

// Tells us whether we are to continue processing or not
enum MODULE_STATE
{
  MSTATE_NEW,
  MSTATE_RUNNING,
  MSTATE_EXITING,
  MSTATE_COMPLETE,
  MSTATE_FAILURE
};

// Forward declarations
int sendRead(int hSocket, _SNMP_DATA* _psSessionData, char* szPassword);
int sendWrite(int hSocket, _SNMP_DATA* _psSessionData, char* szPassword, char* szLocation);
int receiveRequest(int hSocket, _SNMP_DATA* _psSessionData, int* nPassCount, char*** arrszPassList, char** szLocation);
int initModule(sLogin* login, _SNMP_DATA *_psSessionData);

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
  writeVerbose(VB_NONE, "  TIMEOUT:? ");
  writeVerbose(VB_NONE, "    Sets the number of seconds to wait for the UDP responses (default: 5 sec).");
  writeVerbose(VB_NONE, "  SEND_DELAY:? ");
  writeVerbose(VB_NONE, "    Sets the number of microseconds to wait between sending queries (default: 200 usec).");
  writeVerbose(VB_NONE, "  VERSION:? (1*, 2C)");
  writeVerbose(VB_NONE, "    Set the SNMP client version.");
  writeVerbose(VB_NONE, "  ACCESS:? (READ*, WRITE)");
  writeVerbose(VB_NONE, "    Set level of access to test for with the community string.");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "(*) Default value");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "It should be noted that when testing for WRITE capability, the module will read");
  writeVerbose(VB_NONE, "the current value of sysLocation and then write that same value back to the system.");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "Since SNMP is a UDP-based protocol, there is no handshaking between sending and "); 
  writeVerbose(VB_NONE, "receiving transport-layer entities. Due to this connectionless communication, about");
  writeVerbose(VB_NONE, "the only time we know a SNMP service exists, is if we send the correct community");
  writeVerbose(VB_NONE, "string and the server sends a response. All other queries result in no response");
  writeVerbose(VB_NONE, "whatsoever. The approach we use here is to initially just send all of our SNMP GET");
  writeVerbose(VB_NONE, "requests. After that completes, we wait TIMEOUT seconds for any responses. If we");
  writeVerbose(VB_NONE, "get any responses back, we examine them to see which community strings were successful.");
  writeVerbose(VB_NONE, "If ACCESS:WRITE was specified, we check for write access on each of the previously");
  writeVerbose(VB_NONE, "successful values. This techique should allow for quick brute forcing. However, one");
  writeVerbose(VB_NONE, "should take care with the TIMEOUT and SEND_DELAY values as to avoid causing issues");
  writeVerbose(VB_NONE, "with the target service or missing response data.");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "  Usage example: \"-M snmp -m TIMEOUT:2 -m ACCESS:WRITE\"");
  writeVerbose(VB_NONE, "");
}

// The "main" of the medusa module world - this is what gets called to actually do the work
int go(sLogin* logins, int argc, char *argv[])
{
  int i;
  char *strtok_ptr, *pOpt, *pOptTmp;
  _SNMP_DATA *psSessionData;
  
  psSessionData = malloc(sizeof(_SNMP_DATA));
  memset(psSessionData, 0, sizeof(_SNMP_DATA));

  psSessionData->nVersion = SNMP_VER_V1;
  psSessionData->nReadWrite = SNMP_READ;
  psSessionData->nReadTimeout = RECEIVE_DELAY;
  psSessionData->nSendDelay = SEND_DELAY;

  if ((argc < 0) || (argc > 4))
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
      writeError(ERR_DEBUG_MODULE, "Processing complete option (%d/%d): %s", i+1, argc, pOptTmp);
      pOpt = strtok_r(pOptTmp, ":", &strtok_ptr);
      writeError(ERR_DEBUG_MODULE, "Processing option: %s", pOpt);

      if (strcmp(pOpt, "TIMEOUT") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if ( pOpt )
          psSessionData->nReadTimeout = atoi(pOpt) * 1000000;
        else
          writeError(ERR_WARNING, "Method TIMEOUT requires value to be set.");
      }
      else if (strcmp(pOpt, "SEND_DELAY") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if ( pOpt )
          psSessionData->nSendDelay = atoi(pOpt);
        else
          writeError(ERR_WARNING, "Method TIMEOUT requires value to be set.");
      }
      else if (strcmp(pOpt, "VERSION") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if (pOpt == NULL)
          writeError(ERR_WARNING, "Method VERSION requires value to be set.");
        else if ( strcmp(pOpt, "1") == 0 )
          psSessionData->nVersion = SNMP_VER_V1;
        else if ( strcmp(pOpt, "2C") == 0 )
          psSessionData->nVersion = SNMP_VER_V2C;
        else
          writeError(ERR_WARNING, "Method VERSION requires a value of either \"1\" or \"2C\" to be set.");
      }
      else if (strcmp(pOpt, "ACCESS") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if (pOpt == NULL)
          writeError(ERR_WARNING, "Method ACCESS requires value to be set.");
        else if ( strcmp(pOpt, "READ") == 0 )
          psSessionData->nReadWrite = SNMP_READ;
        else if ( strcmp(pOpt, "WRITE") == 0 )
          psSessionData->nReadWrite = SNMP_WRITE;
        else
          writeError(ERR_WARNING, "Method ACCESS requires value of \"READ\" or \"WRITE\" to be set.");
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

int initModule(sLogin* psLogin, _SNMP_DATA *_psSessionData)
{
  int hSocket = -1;
  enum MODULE_STATE nState = MSTATE_NEW;
  int i = 0, nPassCount, nPassCountWrite;
  char **arrszPassList = NULL;
  char **arrszPassListWrite = NULL;
  char *szLocation = NULL;
  sCredentialSet *psCredSet = NULL;
  sUser *psUser = NULL;
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
  params.nPort = PORT_SNMP;
  initConnectionParams(psLogin, &params);

  writeError(ERR_DEBUG_MODULE, "[%s] module started for host: %s", MODULE_NAME, psLogin->psServer->pHostIP);

  while (nState != MSTATE_COMPLETE)
  {  
    switch (nState)
    {
      case MSTATE_NEW:
        if (hSocket > 0)
          medusaDisconnect(hSocket);

        hSocket = medusaConnectUDP(&params);
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
        nState = sendRead(hSocket, _psSessionData, psCredSet->pPass);
        if (nState == MSTATE_FAILURE)
        {
          psLogin->iResult = LOGIN_RESULT_UNKNOWN;
          return FAILURE;
        }

        /* don't want to overwhelm the device being tested */
        writeError(ERR_DEBUG_MODULE, "Delaying %d microseconds before sending next query.", _psSessionData->nSendDelay);
        usleep(_psSessionData->nSendDelay);

        /* initially set all passwords as invalid -- we don't know their validity yet */
        psLogin->iResult = LOGIN_RESULT_FAIL;
        setPassResult(psLogin, psCredSet->pPass);
        
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

              /* Medusa has exhausted all credential sets and reset psLogin->psUser to NULL. This 
                 creates issues as we haven't actually received the responses yet from our SNMP
                 queries. Our solution is to create a temporary sUser structure, which allows us
                 to report on successful community strings via normal methods. */ 
              psUser = malloc(sizeof(sUser));
              memset(psUser, 0, sizeof(sUser));
              psLogin->psUser = psUser; 

              nState = MSTATE_EXITING;
            }
            else if (psCredSet->iStatus == CREDENTIAL_NEW_USER)
            {
              writeError(ERR_DEBUG_MODULE, "[%s] Starting testing for new user: %s.", MODULE_NAME, psCredSet->psUser->pUser);
              nState = MSTATE_RUNNING;
            }
            else
              writeError(ERR_DEBUG_MODULE, "[%s] Next credential set - user: %s password: %s", MODULE_NAME, psCredSet->psUser->pUser, psCredSet->pPass);
          }
        }
        break;
      case MSTATE_EXITING:
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

  /* check if server responded to GET queries */
  writeError(ERR_DEBUG_MODULE, "[%s] Checking for server responses.", MODULE_NAME);
  if (receiveRequest(hSocket, _psSessionData, &nPassCount, &arrszPassList, &szLocation) == FAILURE)
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Failed to find valid READ community string.", MODULE_NAME);
    return SUCCESS;
  }

  for (i=0; i < nPassCount; i++)
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Located valid community string (%d/%d): %s.", MODULE_NAME, i+1, nPassCount, arrszPassList[i]);

    if (_psSessionData->nReadWrite == SNMP_WRITE)
    {
      writeError(ERR_DEBUG_MODULE, "[%s] Checking if community string has WRITE access.", MODULE_NAME);
      
      /* send SET request to server */
      if (sendWrite(hSocket, _psSessionData, arrszPassList[i], szLocation))
      {
        writeError(ERR_ERROR, "[%s] Failed to send SET request.", MODULE_NAME);
        return FAILURE;
      }
      FREE(szLocation);

      /* check if community string has WRITE access */
      if (receiveRequest(hSocket, _psSessionData, &nPassCountWrite, &arrszPassListWrite, &szLocation) == SUCCESS)
      {
        writeError(ERR_DEBUG_MODULE, "[%s] Located valid WRITE community string: %s.", MODULE_NAME, arrszPassList[i]);
        psLogin->iResult = LOGIN_RESULT_SUCCESS;
        setPassResult(psLogin, arrszPassList[i]);
      }
      else
      {
        writeError(ERR_ERROR, "[%s] Community string appears to have only READ access.", MODULE_NAME);
        psLogin->iResult = LOGIN_RESULT_ERROR;
        setPassResult(psLogin, arrszPassList[i]);
      }
      FREE(arrszPassListWrite);
    }
    else
    {
      writeError(ERR_DEBUG_MODULE, "[%s] Located valid READ community string: %s.", MODULE_NAME, arrszPassList[i]);
      psLogin->iResult = LOGIN_RESULT_SUCCESS;
      setPassResult(psLogin, arrszPassList[i]);
    }
    
    FREE(arrszPassList[i]);
    FREE(szLocation);
  }
        
  if (hSocket > 0)
    medusaDisconnect(hSocket);

  FREE(psUser);
  FREE(psCredSet);
  FREE(arrszPassList);
  FREE(arrszPassListWrite);
  return SUCCESS;
}

/* Module Specific Functions */

/*
  http://book.opensourceproject.org.cn/embedded/tcpipembedded/opensource/0061.html

  The first TLV in the request is called sequence and is used to identify the length of the following TLVs. 
  The sequence type is 0x30 and the next octet is used to decode the length of this TLV. If the length octet 
  has the high-order bit set (0x80), then the length octet masked with 0x7f yields the number of bytes that 
  follow that will make up the value length (in big-endian order). If the high-order bit is not set, then 
  this octet is the length (no length octets follow).
  
  Example:  0x30 0x2f 0x02 0x01 0x00
  Sequence: 0x30 0x2f
  Version:  0x02 0x01 0x00

  Example:  0x30 0x82 0x00 0x2f 0x02 0x01 0x00
  Sequence: 0x30 0x82 0x00 0x2f
  Version:  0x02 0x01 0x00
*/
int parseLength(unsigned char* bufReceive)
{
  int nLength = 0;
  int nOctets = 0;

  if (bufReceive[0] == 0x30)
  {
    if (bufReceive[1] & 0x80) /* multi-octet mode */
    {
      nOctets = bufReceive[1] & 0x7f;

      /* limited to 4 octets worth of length data */
      if (nOctets == 1)
        nLength = bufReceive[2];
      else if (nOctets == 2)
        nLength = (bufReceive[2] << 8) + bufReceive[3];
      else if (nOctets == 3)
        nLength = (bufReceive[2] << 16) + (bufReceive[3] << 8) + bufReceive[4];
      else if (nOctets == 4)
        nLength = (bufReceive[2] << 24) + (bufReceive[3] << 16) + (bufReceive[4] << 8) + bufReceive[5];

      if ((nLength > 0) && ((bufReceive[2+nOctets] == 0x02) && (bufReceive[2+nOctets+1] == 0x01)))
        writeError(ERR_DEBUG_MODULE, "[%s] Multi-octet mode length: %d", MODULE_NAME, nLength);
      else
      {
        writeError(ERR_ERROR, "[%s] Failed to parse length or SNMP version (multi-octet mode).", MODULE_NAME);
        nLength = -1;
      }
    }
    else if ((bufReceive[2] == 0x02) && (bufReceive[3] == 0x01))  /* single octet mode, version check */
    {
      nLength = bufReceive[1];
      writeError(ERR_DEBUG_MODULE, "[%s] Single octet mode length: %d", MODULE_NAME, nLength);
    }
    else
    {
      writeError(ERR_ERROR, "[%s] Failed to parse length or SNMP version.", MODULE_NAME);
      nLength = -1;
    }
  }  

  return nLength;
}


int countResponses(int nReceiveBufferSize, unsigned char* bufReceive)
{
  int i = 0;
  int nLength = 0;
  int nResponseCount = 0;

  for (i = 0; i < nReceiveBufferSize; i++) {
    if (bufReceive[i] == 0x30)
    {
      nLength = parseLength(&bufReceive[i]);
      if (nLength > 0)
      {
        writeError(ERR_DEBUG_MODULE, "[%s] Located start of SNMP response (%d bytes).", MODULE_NAME, nLength);
        nResponseCount++;
        i += nLength;
      }
    }
  }

  return nResponseCount;
}

int processResponse(int nReceiveBufferSize, unsigned char* bufReceive, int *nSNMPLength, char** szPassword, char** szLocation)
{
  int i;
  writeError(ERR_DEBUG_MODULE, "[%s] Parsing SNMP response data.", MODULE_NAME);
 
  for (i = 0; i < nReceiveBufferSize; i++) {
    *nSNMPLength = parseLength(&bufReceive[i]);
    if (*nSNMPLength > 0)
    {
      writeError(ERR_DEBUG_MODULE, "[%s] Located start of SNMP response (%d bytes).", MODULE_NAME, *nSNMPLength);

      for (; i < nReceiveBufferSize; i++) {
        if (bufReceive[i] == 0x04) {
          writeError(ERR_DEBUG_MODULE, "[%s] Located start of SNMP community string.", MODULE_NAME);
          if (bufReceive[i+1] > 0)
          {
            writeError(ERR_DEBUG_MODULE, "[%s] Located SNMP community string size: %d.", MODULE_NAME, bufReceive[i+1]);
            *szPassword = malloc(bufReceive[i+1] + 1);
            memset(*szPassword, 0, bufReceive[i+1] + 1);
            memcpy(*szPassword, bufReceive + i + 2, bufReceive[i+1]);
            writeError(ERR_DEBUG_MODULE, "[%s] Located community string: %s.", MODULE_NAME, *szPassword);
          }
          else
          {
            writeError(ERR_DEBUG_MODULE, "[%s] Failed to locate community string.", MODULE_NAME);
            return FAILURE;
          }
        
          for (i = i + bufReceive[i + 1]; i + 2 < nReceiveBufferSize; i++) { /* skip community string */
            if (bufReceive[i] == 0xa2) {
              writeError(ERR_DEBUG_MODULE, "[%s] Located PDU Response.", MODULE_NAME);
              for (; i + 2 < nReceiveBufferSize; i++) {
                if (bufReceive[i] == 0x02) {
                  writeError(ERR_DEBUG_MODULE, "[%s] Located ID.", MODULE_NAME);
                  for (i = i + (bufReceive[i + 1]); i + 2 < nReceiveBufferSize; i++) { /* skip Request ID */
                    if ((bufReceive[i] == 0x02) && (bufReceive[i + 1] == 0x01) && (bufReceive[i + 2] == 0x00)) {
                      writeError(ERR_DEBUG_MODULE, "[%s] Located success status flag.", MODULE_NAME);
                     
                      *szLocation = malloc(bufReceive[i + 6 + 14 + 1] + 1);
                      memset(*szLocation, 0, bufReceive[i + 6 + 14 + 1] + 1);
                      memcpy(*szLocation, bufReceive + i + 6 + 14 + 2, bufReceive[i + 6 + 14 + 1]);
                      
                      writeError(ERR_DEBUG_MODULE, "[%s] sysLocation: %s.", MODULE_NAME, *szLocation);
                      return(SUCCESS);
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  return FAILURE;
}

int sendRead(int hSocket, _SNMP_DATA* _psSessionData, char* szPassword)
{
  unsigned char* bufSend;
  int nSendBufferSize = 0;
 
  struct _SNMPV1_A {
    char ID;
    char len;
    char ver[3];
    char comid;
    char comlen;
  } snmpv1_a = { 
    .ID = '\x30',
    .len = '\x00',
    .ver = "\x02\x01\x00",  /* \x02\x01\x01 for snmp v2c */
    .comid = '\x04',
    .comlen = '\x00'
  };

  struct _SNMPV1_R {
    char type[2];
    char identid[2];
    char ident[4];
    char errstat[3];
    char errind[3];
    char objectid[2];
    char object[12];
    char value[3];
  } snmpv1_r = {
    .type = "\xa0\x1c",                                       /* GET */
    .identid = "\x02\x04",
    .ident = "\x6f\x67\x4e\xe1",                              /* request id - doesn't matter */
    .errstat = "\x02\x01\x00",                                /* no error */
    .errind = "\x02\x01\x00",                                 /* error index 0 */
    .objectid = "\x30\x0e",
    .object = "\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x06\x00", /* sysLocation */
    .value = "\x05\x00"                                       /* we just read, so value = 0 */
  };

  if (_psSessionData->nVersion == SNMP_VER_V2C)  
    snmpv1_a.ver[2] = '\x01';

  /* GET system.sysLocation */
  nSendBufferSize = sizeof(snmpv1_a) + sizeof(snmpv1_r) + strlen(szPassword); 
  snmpv1_a.comlen = (char) strlen(szPassword);
  snmpv1_a.len = nSendBufferSize - 3;
  
  bufSend = malloc(nSendBufferSize); 
  memset(bufSend, 0, nSendBufferSize);
  memcpy(bufSend, &snmpv1_a, sizeof(snmpv1_a));
  memcpy(bufSend + sizeof(snmpv1_a), szPassword, strlen(szPassword));
  memcpy(bufSend + sizeof(snmpv1_a) + strlen(szPassword), &snmpv1_r, sizeof(snmpv1_r));

  writeError(ERR_DEBUG_MODULE, "[%s] Sending GET request for system.sysLocation.", MODULE_NAME);
  if (medusaSend(hSocket, bufSend, nSendBufferSize - 1, 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
    free(bufSend);
    return(MSTATE_FAILURE);
  }
  free(bufSend);

  return(MSTATE_RUNNING);
}

int sendWrite(int hSocket, _SNMP_DATA* _psSessionData, char* szPassword, char* szLocation)
{
  unsigned char* bufSend;
  int nSendBufferSize = 0;
 
  struct _SNMPV1_A {
    char ID;
    char len;
    char ver[3];
    char comid;
    char comlen;
  } snmpv1_a = { 
    .ID = '\x30',
    .len = '\x00',
    .ver = "\x02\x01\x00",  /* \x02\x01\x01 for snmp v2c */
    .comid = '\x04',
    .comlen = '\x00'
  };

  struct _SNMPV1_W {
    char type[2];
    char identid[2];
    char ident[4];
    char errstat[3];
    char errind[3];
    char objectid[2];
    char object[12];
    char value[2];
  } snmpv1_w = {
    .type = "\xa3\x20",                                       /* SET */
    .identid = "\x02\x04",
    .ident = "\x6f\x67\x4e\xe1",                              /* request id - doesn't matter */
    .errstat = "\x02\x01\x00",                                /* no error */
    .errind = "\x02\x01\x00",                                 /* error index 0 */
    .objectid = "\x30\x0c",
    .object = "\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x06\x00", /* sysLocation */
    .value = "\x04\x00"                                       /* write value */
  };

  if (_psSessionData->nVersion == SNMP_VER_V2C)  
    snmpv1_a.ver[2] = '\x01';

  if (szLocation == NULL) 
    szLocation = "";

  nSendBufferSize = sizeof(snmpv1_a) + sizeof(snmpv1_w) + strlen(szPassword) + strlen(szLocation) + 1; 
  snmpv1_a.comlen = (char) strlen(szPassword);
  snmpv1_a.len = nSendBufferSize - 3;
  
  bufSend = malloc(nSendBufferSize); 
  memset(bufSend, 0, nSendBufferSize);
  memcpy(bufSend, &snmpv1_a, sizeof(snmpv1_a));
  memcpy(bufSend + sizeof(snmpv1_a), szPassword, strlen(szPassword));
  memcpy(bufSend + sizeof(snmpv1_a) + strlen(szPassword), &snmpv1_w, sizeof(snmpv1_w));
  memset(bufSend + sizeof(snmpv1_a) + strlen(szPassword) + 1, 28 + strlen(szLocation), 1); /* set length remaining */
  memset(bufSend + sizeof(snmpv1_a) + strlen(szPassword) + 15, 14 + strlen(szLocation), 1); /* set length remaining */
  memset(bufSend + sizeof(snmpv1_a) + strlen(szPassword) + 17, 12 + strlen(szLocation), 1); /* set length remaining */
  memset(bufSend + sizeof(snmpv1_a) + strlen(szPassword) + sizeof(snmpv1_w) - 1, strlen(szLocation), 1);
  strncpy((char *)bufSend + sizeof(snmpv1_a) + strlen(szPassword) + sizeof(snmpv1_w), szLocation, strlen(szLocation));

  writeError(ERR_DEBUG_MODULE, "[%s] Sending SET request for system.sysLocation.", MODULE_NAME);
  if (medusaSend(hSocket, bufSend, nSendBufferSize - 1, 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
    free(bufSend);
    return(FAILURE);
  }
  free(bufSend);
  
  return(SUCCESS);
}

int receiveRequest(int hSocket, _SNMP_DATA* _psSessionData, int* nPassCount, char*** arrszPassList, char** szLocation)
{
  unsigned char *bufReceive = NULL;
  unsigned char *bufReceiveTmp = NULL;
  int i, nReceiveBufferSize, nReceiveBufferSizeTmp;
  int nResponse = FAILURE;
  int nSNMPLength;

  nReceiveBufferSize = 0;
  bufReceive = medusaReceiveRawDelay(hSocket, &nReceiveBufferSize, _psSessionData->nReadTimeout, _psSessionData->nReadTimeout);
  if (bufReceive == NULL)
  {
    writeError(ERR_DEBUG_MODULE, "[%s] No data received. Possible incorrect community string.", MODULE_NAME);
    return(FAILURE);
  }
  
  *nPassCount = countResponses(nReceiveBufferSize, bufReceive);
  if (*nPassCount <= 0)
  {
    writeError(ERR_ERROR, "[%s] Responses received, however, no community strings were located.", MODULE_NAME);
    return(FAILURE);
  }
  else
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Creating password array for %d entries.", MODULE_NAME, *nPassCount);
    *arrszPassList = malloc(*nPassCount * sizeof(char*));
    memset(*arrszPassList, 0, *nPassCount * sizeof(char*));
  }

  bufReceiveTmp = bufReceive;
  nReceiveBufferSizeTmp = nReceiveBufferSize;
  for (i = 0; i < *nPassCount; i++)
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Retrieving data for response: %d.", MODULE_NAME, i+1);
    nResponse = processResponse(nReceiveBufferSizeTmp, bufReceiveTmp, &nSNMPLength, &(*arrszPassList)[i], szLocation);
    if (nResponse == SUCCESS)
    {
      writeError(ERR_DEBUG_MODULE, "[%s] Retrieved SNMP data (%d bytes). Community String: %s Location: %s.", MODULE_NAME, nSNMPLength, (*arrszPassList)[i], *szLocation);  
    }
    else
      writeError(ERR_ERROR, "[%s] Error processing SNMP response (%d).", MODULE_NAME, i+1);
 
    bufReceiveTmp += (nSNMPLength + 2);
    nReceiveBufferSizeTmp -= (nSNMPLength + 2);
  }

  free(bufReceive);  

  return(nResponse);
}
