/*
**   M$-SQL Password Checking Medusa Module
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
**   Based on code from:
**     Hydra 4.7 [van Hauser <vh@thc.org>]
**     Nessus [HD Moore <hdm@digitaloffense.net>]
**
**   Tested:
**     Microsoft SQL Server 2005 9.00.1399; RTM (mixed authentication)
**     Microsoft SQL Server 2005 9.00.2047; SP1 (mixed authentication)
**     Microsoft SQL Server 2005 9.00.3042; SP2 (mixed authentication)
**
**   Notes:
**     SQL 2005: SQL logins use the password policy of the underlying operating system 
**     Windows Authentication mode is selected during installation, the sa login is disabled
**
*/

#include <sys/types.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "module.h"

#define MODULE_NAME    "mssql.mod"
#define MODULE_AUTHOR  "JoMo-Kun <jmk@foofus.net>"
#define MODULE_SUMMARY_USAGE  "Brute force module for M$-SQL sessions"
#define MODULE_VERSION    "2.0"
#define MODULE_VERSION_SVN "$Id: mssql.c 9217 2015-05-07 18:07:03Z jmk $"
#define MODULE_SUMMARY_FORMAT  "%s : version %s"
#define MODULE_SUMMARY_FORMAT_WARN  "%s : version %s (%s)"
#define OPENSSL_WARNING "No usable OPENSSL. Module disabled."

#ifdef HAVE_LIBSSL

#include <openssl/md4.h>
#include <openssl/des.h>

#define PORT_MSSQL 1433
#define PORT_MSSQLM 1434
#define MSLEN 30

typedef struct __MODULE_DATA {
  int nPort;
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
int connectMSSQL(sLogin *psLogin, _MODULE_DATA *_psSessionData);
int tryLogin(int hSocket, sLogin** login, char* szLogin, char* szPassword);
int initModule(sLogin* login, _MODULE_DATA* _psSessionData);

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
  writeVerbose(VB_NONE, "NOTE: MS-SQL Developer Edition or MSDE's concurrent workload governor limits you");
  writeVerbose(VB_NONE, "      to no more than five concurrent connections to the server at any one time.");
}

// The "main" of the medusa module world - this is what gets called to actually do the work
int go(sLogin* logins, int argc, char *argv[] __attribute__((unused)))
{
  _MODULE_DATA *psSessionData;

  psSessionData = malloc(sizeof(_MODULE_DATA));
  memset(psSessionData, 0, sizeof(_MODULE_DATA));

  if (argc != 0)
  {
    writeError(ERR_ERROR, "%s: Incorrect number of parameters passed to module (%d). Use \"-q\" option to display module usage.", MODULE_NAME, argc);
    return FAILURE;
  }
  else 
  {
    writeError(ERR_DEBUG_MODULE, "OMG teh %s module has been called!!", MODULE_NAME);
 
    initModule(logins, psSessionData);
  }  

  FREE(psSessionData);
  return SUCCESS;
}

int initModule(sLogin* psLogin, _MODULE_DATA *_psSessionData)
{
  int hSocket = -1;
  enum MODULE_STATE nState = MSTATE_NEW;
  sCredentialSet *psCredSet = NULL;

  _psSessionData->nPort = 0;

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

  while (nState != MSTATE_COMPLETE)
  {
    switch (nState)
    {
      case MSTATE_NEW:

        if ((hSocket = connectMSSQL(psLogin, _psSessionData)) < 0)
        {
          writeError(ERR_ERROR, "[%s] Failed to establish MS-SQL connection.", MODULE_NAME);
          return FAILURE;
        }

        nState = MSTATE_RUNNING;
        break;
      case MSTATE_RUNNING:
        nState = tryLogin(hSocket, &psLogin, psCredSet->psUser->pUser, psCredSet->pPass);
        
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

/* MS-SQL Specific Functions */

/*
  Establish connection to remote MS-SQL server using the following logic:

  * if the user specified a TCP port, we use it
  * else if this is a new connection, we send a SQL ping to the SQL monitor port
  * 
  * if a response is received, we use the port listed for the first SQL instance
  * (2433/tcp is used if the first instance is "hiding" its port)
  *
  * else we use the default port identified by PORT_MSSQL (i.e. 1433/tcp)
*/
int connectMSSQL(sLogin *_psLogin, _MODULE_DATA *_psSessionData)
{
  sConnectParams params;
  int nReceiveBufferSize = 0;
  unsigned char *bufReceive = NULL; 
  int nPort = PORT_MSSQL; 
  int nPortTmp = 0; 
  int hSocket;
  unsigned char pkt_sqlping[] = { 0x02 };
  int nPingResponseLen = 0;
  int nSQLInstance = 0;
  int nSQLInstancePort = 0;
  char *szTmp = NULL;
  char *szTmp1 = NULL;
  char *szTmp2 = NULL;

  writeError(ERR_DEBUG_MODULE, "[%s] Querying MS-SQL monitor port to enumerate MS-SQL server TCP port.", MODULE_NAME);

  /* 
    Query MS-SQL Monitor (SQL Server Browser) port to enumerate MS-SQL server TCP port

    The MS-SQL server instances and information about those instances for a given system
    can be enumerated anonymous via a simple query. For additional information about this 
    operation, see "Threat Profiling Microsoft SQL Server"
    (www.nextgenss.com/papers/tp-SQL2000.pdf). The following are two example responses:
    

    Single SQL Server Instance Installation:
    [0x05][0x76][0x00]ServerName;WIN2K3STD;InstanceName;MSSQLSERVER;IsClustered;No;Version;8.00.194;tcp;1433;np;\\WIN2K3STD\pipe\sql\query;;
  
    Three SQL Server Instance Installation (first using port hiding option):
    [0x05[0x85][0x01]ServerName;WIN2K3STD;InstanceName;MSSQLSERVER;IsClustered;No;Version;8.00.194;np;\\WIN2K3STD\pipe\sql\query;;
    ServerName;WIN2K3STD;InstanceName;SQL_INSTANCE_2;IsClustered;No;Version;8.00.194;tcp;1308;np;\\WIN2K3STD\pipe\MSSQL$SQL_INSTANCE_2\sql\query;;
    ServerName;WIN2K3STD;InstanceName;SQLINSTANCE3;IsClustered;No;Version;8.00.194;tcp;1422;np;\\WIN2K3STD\pipe\MSSQL$SQLINSTANCE3\sql\query;;

    It is assumed the first byte of the response (0x05) signals a valid response. The next 
    two bytes indicate the length of the actual data. For example, [0x85][0x01] -> 0x0185
    -> 389 bytes

    It's possible that if a system has many instances, the UDP packet may exceed our 
    default recv() buffer, or arrive in multiple datagrams. We don't currently handle
    either of these situations and some of the information would be lost.
  */
  if ((_psLogin->psServer->psAudit->iPortOverride == 0) && (_psSessionData->nPort == 0))
  { 
    memset(&params, 0, sizeof(sConnectParams));
    params.nPort = PORT_MSSQLM;
    initConnectionParams(_psLogin, &params);
    
    hSocket = medusaConnectUDP(&params);
    if (hSocket < 0)
    {
      writeError(ERR_ERROR, "[%s] Failed to connect to MS-SQL monitor UDP port (%d). Auto-identification of MS-SQL port unsuccessful on host: %s.", MODULE_NAME, PORT_MSSQLM, _psLogin->psServer->pHostIP);
      _psLogin->iResult = LOGIN_RESULT_UNKNOWN;
      return FAILURE;
    }

    if (medusaSend(hSocket, pkt_sqlping, 1, 0) < 0)
    {
      writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
    }

    nReceiveBufferSize = 0;
    bufReceive = medusaReceiveRaw(hSocket, &nReceiveBufferSize);
    if (bufReceive == NULL)
    {
      writeError(ERR_ERROR, "[%s] SQL server (%s) did not respond to port query request. Using default value of 1433/tcp.", MODULE_NAME, _psLogin->psServer->pHostIP);
      nPort = 1433;
    } 
    else if (bufReceive[0] == 0x05)
    {
      writeError(ERR_DEBUG_MODULE, "[%s] Processing SQL ping response.", MODULE_NAME);

      nPingResponseLen = ((bufReceive[2] & 0xFF) << 8) | (bufReceive[1] & 0xFF);
      writeError(ERR_DEBUG_MODULE, "[%s] SQL ping response packet reported data length: %d", MODULE_NAME, nPingResponseLen);
      
      if (nReceiveBufferSize != nPingResponseLen + 3) 
        writeError(ERR_ERROR, "[%s] Reported SQL ping data length does not match our receive buffer length. Response data may have been lost.", MODULE_NAME);

      nSQLInstance = 1;
      szTmp = (char*)bufReceive + 3;
      while ((szTmp = strstr(szTmp, "ServerName;")) != NULL)
      {
        szTmp1 = strstr(szTmp, ";;");
        
        if (szTmp1 == NULL)
        {
            writeError(ERR_ERROR, "[%s] Possible incomplete capture of service information on host %s. There may be additional SQL services.", MODULE_NAME, _psLogin->psServer->pHostIP);
            break;
        }

        memset(szTmp1, 0, 1);
        szTmp1 += 2; 
        writeError(ERR_DEBUG_MODULE, "[%s] SQL server (%s) ping response (instance: %d) - %s", MODULE_NAME, _psLogin->psServer->pHostIP, nSQLInstance, szTmp);

        /* ServerName;MACHINE_NAME;InstanceName;MICROSOFT##SSEE;IsClustered;No;Version;9.00.4035.00;np; */
        if (strstr(szTmp, "InstanceName;MICROSOFT##SSEE") != NULL)
        {
          writeError(ERR_ERROR, "[%s] Internal database (SQL Server Embedded Edition) identified (NOT TESTED) - server %s", MODULE_NAME, _psLogin->psServer->psHost->pHost);
          writeVerbose(VB_NONE_FILE, "[%s] Internal database (SQL Server Embedded Edition) identified (NOT TESTED) - server %s\n", MODULE_NAME, _psLogin->psServer->psHost->pHost);
        }
        /* ServerName;MACHINE_NAME;InstanceName;DATABASE_NAME;IsClustered;No;Version;9.00.3042.00 */
        else if ((szTmp2 = strstr(szTmp, ";tcp;")) == NULL)
        {
          writeError(ERR_ERROR, "[%s] Internal or hidden database identified (NOT TESTED) - server %s. (Default hidden value is 2433/tcp)", MODULE_NAME, _psLogin->psServer->psHost->pHost);
          writeVerbose(VB_NONE_FILE, "[%s] Internal or hidden database identified (NOT TESTED) - server %s. (Default hidden value is 2433/tcp)\n", MODULE_NAME, _psLogin->psServer->psHost->pHost);
        }
        /* ServerName;MACHINE_NAME;InstanceName;MSSQLSERVER;IsClustered;No;Version;8.00.194;tcp;1433;np; */
        else
        {
          szTmp2 += 5; /* skip ";tcp;" */
          if ( index(szTmp2, 0x3B) ) { memset( index(szTmp2, 0x3B), 0, 1); }  /* ";" */
          nPortTmp = atoi(szTmp2);
  
          if (nSQLInstancePort == 0)
          {
            nPort = nPortTmp;
            nSQLInstancePort++;
            writeError(ERR_DEBUG_MODULE, "[%s] Connecting to SQL server %s on port %d/tcp.", MODULE_NAME, _psLogin->psServer->pHostIP, nPort);
          }
          else
          {
            writeError(ERR_ERROR, "[%s] Additional SQL server identified (NOT TESTED) - server %s on port %d/tcp", MODULE_NAME, _psLogin->psServer->psHost->pHost, nPortTmp);
            writeVerbose(VB_NONE_FILE, "[%s] Additional SQL server identified (NOT TESTED) - server %s on port %d/tcp\n", MODULE_NAME, _psLogin->psServer->psHost->pHost, nPortTmp);
          }
        }

        szTmp = szTmp1;
        nSQLInstance++;
      }
    }
    else
    {
      writeError(ERR_ERROR, "[%s] SQL server (%s) sent unknown response to \"SQL Ping\" request.", MODULE_NAME, _psLogin->psServer->pHostIP);
    }

    FREE(bufReceive);

    if (hSocket > 0)
      medusaDisconnect(hSocket);
  }
  else if ((_psLogin->psServer->psAudit->iPortOverride == 0) && (_psSessionData->nPort != 0))
  {
    nPort = _psSessionData->nPort;
    writeError(ERR_DEBUG_MODULE, "[%s] Using previously set port: %d/tcp", MODULE_NAME, nPort);
  }

  memset(&params, 0, sizeof(sConnectParams));
  if (_psLogin->psServer->psAudit->iPortOverride > 0)
    params.nPort = _psLogin->psServer->psAudit->iPortOverride;
  else
    params.nPort = nPort;
  initConnectionParams(_psLogin, &params);
  _psSessionData->nPort = params.nPort;

  hSocket = medusaConnect(&params);
  if (hSocket < 0)
  {
     writeError(ERR_NOTICE, "[%s] Failed to connect, port %d was not open on %s", MODULE_NAME, params.nPort, _psLogin->psServer->psHost->pHost);
     _psLogin->iResult = LOGIN_RESULT_UNKNOWN;
     return FAILURE;
   }

  return hSocket;
}

void makeSQLLogin(char* szLogin, char* szPassword, unsigned char* buffer) 
{
  unsigned char pkt_hdr[] = {
    0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };

  unsigned char pkt_pt2[] = {
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x61, 0x30, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x20, 0x18, 0x81, 0xb8, 0x2c, 0x08, 0x03,
    0x01, 0x06, 0x0a, 0x09, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x73, 0x71, 0x75, 0x65, 0x6c, 0x64, 0x61,
    0x20, 0x31, 0x2e, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00
  };

  unsigned char pkt_pt3[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x4d, 0x53, 0x44,
    0x42, 0x4c, 0x49, 0x42, 0x00, 0x00, 0x00, 0x07, 0x06, 0x00, 0x00,
    0x00, 0x00, 0x0d, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };

  char ms_login[MSLEN + 1];
  char ms_pass[MSLEN + 1];
  
  memset(ms_login, 0, MSLEN + 1);
  memset(ms_pass, 0, MSLEN + 1);

  strncpy(ms_login, szLogin, MSLEN);
  strncpy(ms_pass, szPassword, MSLEN);
  
  unsigned char len_login, len_pass;
  len_login = (unsigned char)strlen(ms_login);
  len_pass = (unsigned char)strlen(ms_pass);

  memcpy(buffer, pkt_hdr, 39);
  memcpy(buffer + 39, ms_login, MSLEN);
  memcpy(buffer + MSLEN + 39, &len_login, 1);
  memcpy(buffer + MSLEN + 1 + 39, ms_pass, MSLEN);
  memcpy(buffer + MSLEN + 1 + 39 + MSLEN, &len_pass, 1);
  memcpy(buffer + MSLEN + 1 + 39 + MSLEN + 1, pkt_pt2, 110);
  memcpy(buffer + MSLEN + 1 + 39 + MSLEN + 1 + 110, &len_pass, 1);
  memcpy(buffer + MSLEN + 1 + 39 + MSLEN + 1 + 110 + 1, ms_pass, MSLEN);
  memcpy(buffer + MSLEN + 1 + 39 + MSLEN + 1 + 110 + 1 + MSLEN, pkt_pt3, 270);

  return;
}

int tryLogin(int hSocket, sLogin** psLogin, char* szLogin, char* szPassword)
{
  int iRet;
  unsigned char bufSend[3 * MSLEN + 422 + 1];
  unsigned char* bufReceive;
  int nReceiveBufferSize = 0;

  unsigned char pkt_langp[] = {
    0x02, 0x01, 0x00, 0x47, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x30, 0x30, 0x00, 0x00,
    0x00, 0x03, 0x00, 0x00, 0x00
  };

  memset(bufSend, 0, 3 * MSLEN + 422 + 1);
  makeSQLLogin(szLogin, szPassword, bufSend);

  if (medusaSend(hSocket, bufSend, MSLEN + 1 + 39 + MSLEN + 1 + 110 + 1 + MSLEN + 270, 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
  }

  if (medusaSend(hSocket, pkt_langp, 71, 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
  }

  nReceiveBufferSize = 0;
  bufReceive = medusaReceiveRaw(hSocket, &nReceiveBufferSize);
  if (bufReceive == NULL)
  {
    return FAILURE;
  }
 
  writeError(ERR_DEBUG_MODULE, "[tryLogin] medusaReceiveRaw set nReceiveBufferSize: %d", nReceiveBufferSize);
 
  if (bufReceive[8] == 0xe3)
  {
    (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
    iRet = MSTATE_EXITING;
  } else {
    (*psLogin)->iResult = LOGIN_RESULT_FAIL;
    iRet = MSTATE_NEW;
  }

  writeError(ERR_DEBUG_MODULE, "[tryLogin] set iRet: %d", iRet);
  FREE(bufReceive);
  setPassResult((*psLogin), szPassword);

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
