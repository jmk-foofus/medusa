/*
**   MySQL Password Checking Medusa Module
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
**    MySQL 4.1 authentication support added by: pmonkey <pmonkey@foofus.net>
**
**    MySQL <4.1 Pass Hash Support: jmk <jmk@foofus.net>
**
**    This module supports MySQL protocol 10.
**
**    The older MySQL pre-4.1 authentication scheme is vulnerable to a pass-the-
**    hash authentication attack. Utilizing the old-style hashes gathered from a
**    MySQL database, a user can use Medusa to verify their validity on other 
**    servers. A modified MySQL client can also be use to connect to located 
**    services directly utilizing a valid hash.
**
*/

#include <sys/types.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "module.h"

#define MODULE_NAME    "mysql.mod"
#define MODULE_AUTHOR  "JoMo-Kun <jmk@foofus.net>"
#define MODULE_SUMMARY_USAGE  "Brute force module for MySQL sessions"
#define MODULE_VERSION    "2.0"
#define MODULE_VERSION_SVN "$Id: mysql.c 9217 2015-05-07 18:07:03Z jmk $"
#define MODULE_SUMMARY_FORMAT  "%s : version %s"
#define BUF_SIZE 300

#define PORT_MYSQL 3306
#define PROTO_UNKNOWN 0
#define PROTO_OLD 1
#define PROTO_NEW 2
#define PASSWORD 1
#define HASH 2

typedef struct __MYSQL_DATA {
  int protoFlag;
  int hashFlag;
} _MYSQL_DATA;

// Tells us whether we are to continue processing or not
enum MODULE_STATE
{
  MSTATE_NEW,
  MSTATE_RUNNING,
  MSTATE_EXITING,
  MSTATE_COMPLETE
};

// Forward declarations
int tryLogin(int hSocket, sLogin** login, _MYSQL_DATA* _psSessionData, char* szLogin, char* szPassword);
int initModule(sLogin* login, _MYSQL_DATA *_psSessionData);

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
  writeVerbose(VB_NONE, "  PASS:?  (PASSWORD*, HASH)");
  writeVerbose(VB_NONE, "    PASSWORD: Use normal password.");
  writeVerbose(VB_NONE, "    HASH:     Use a hash rather than a password. (non-SHA1 hashes only)");
  writeVerbose(VB_NONE, "\n(*) Default value");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "Usage examples:");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "1: Normal boring check...");
  writeVerbose(VB_NONE, "    medusa -M mysql -h somehost -u someuser -p somepassword");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "2: Using an old-style MySQL hash...");
  writeVerbose(VB_NONE, "    medusa -M mysql -h somehost -U users.txt -p 39b52a209cf03d62 -m PASS:HASH");
  writeVerbose(VB_NONE, "");
}

// The "main" of the medusa module world - this is what gets called to actually do the work
int go(sLogin* logins, int argc, char *argv[])
{
  int i;
  char *strtok_ptr = NULL, *pOpt = NULL, *pOptTmp = NULL;
  _MYSQL_DATA *psSessionData;

  psSessionData = malloc(sizeof(_MYSQL_DATA));
  memset(psSessionData, 0, sizeof(_MYSQL_DATA));
  psSessionData->protoFlag = PROTO_NEW;

  if ((argc < 0) || (argc > 1))
  {
    writeError(ERR_ERROR, "%s: Incorrect number of parameters passed to module (%d). Use \"-q\" option to display module usage.", MODULE_NAME, argc);
    return FAILURE;
  }
  else 
  {
    writeError(ERR_DEBUG_MODULE, "OMG teh %s module has been called!!", MODULE_NAME);

    psSessionData->hashFlag = PASSWORD;

    for (i=0; i<argc; i++) {
      pOptTmp = malloc( strlen(argv[i]) + 1);
      memset(pOptTmp, 0, strlen(argv[i]) + 1);
      strncpy(pOptTmp, argv[i], strlen(argv[i]));
      writeError(ERR_DEBUG_MODULE, "Processing complete option: %s", pOptTmp);
      pOpt = strtok_r(pOptTmp, ":", &strtok_ptr);
      writeError(ERR_DEBUG_MODULE, "Processing option: %s", pOpt);

      if (strcmp(pOpt, "PASS") == 0) {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if (pOpt == NULL)
          writeError(ERR_WARNING, "Method PASS requires value to be set.");
        else if (strcmp(pOpt, "PASSWORD") == 0)
          psSessionData->hashFlag = PASSWORD;
        else if (strcmp(pOpt, "HASH") == 0)
          psSessionData->hashFlag = HASH;
        else
          writeError(ERR_WARNING, "Invalid value for method PASS.");
      }

      free(pOptTmp);
    }

    initModule(logins, psSessionData);
  }  

  FREE(psSessionData);
  return SUCCESS;
}

int initModule(sLogin* psLogin, _MYSQL_DATA *_psSessionData)
{
  int hSocket = -1;
  enum MODULE_STATE nState = MSTATE_NEW;
  sCredentialSet *psCredSet = NULL;
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
  if (psLogin->psServer->psAudit->iPortOverride > 0)
    params.nPort = psLogin->psServer->psAudit->iPortOverride;
  else
    params.nPort = PORT_MYSQL;
  initConnectionParams(psLogin, &params);

  while (nState != MSTATE_COMPLETE)
  {  
    switch (nState)
    {
      case MSTATE_NEW:
        // Already have an open socket - close it
        if (hSocket > 0)
          medusaDisconnect(hSocket);

        if (psLogin->psServer->psHost->iUseSSL > 0)
          hSocket = medusaConnectSSL(&params);
        else
          hSocket = medusaConnect(&params);

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
        nState = tryLogin(hSocket, &psLogin, _psSessionData, psCredSet->psUser->pUser, psCredSet->pPass);

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

/* Module Specific Functions */
int MySQLSessionQuit(int hSocket)
{
  unsigned char com_quit_packet[5] = { 0x01, 0x00, 0x00, 0x00, 0x01 };

  if (medusaSend(hSocket, com_quit_packet, 5, 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
    return FAILURE;
  }

  return SUCCESS;
}

/* 
   Code used verbatim from: 
   MySQL 3.21 [mysql_com.h / password.c]
*/
struct rand_struct {
  unsigned long seed1, seed2, max_value;
  double max_value_dbl;
};

void randominit(struct rand_struct *rand_st, unsigned long seed1, unsigned long seed2)
{                               
  /* for mysql 3.21.# */
  rand_st->max_value = 0x3FFFFFFFL;
  rand_st->max_value_dbl = (double) rand_st->max_value;
  rand_st->seed1 = seed1 % rand_st->max_value;
  rand_st->seed2 = seed2 % rand_st->max_value;
}

double rnd(struct rand_struct *rand_st)
{
  rand_st->seed1 = (rand_st->seed1 * 3 + rand_st->seed2) % rand_st->max_value;
  rand_st->seed2 = (rand_st->seed1 + rand_st->seed2 + 33) % rand_st->max_value;
  return (((double) rand_st->seed1) / rand_st->max_value_dbl);
}

/* 
   Code used verbatim from: 
   MySQL 4.1 [password.c]
*/
#define PVERSION41_CHAR '*'
typedef unsigned char    uint8;
typedef unsigned char    uchar; 
typedef unsigned long long int ulonglong;
typedef unsigned int     uint32;
typedef short    int16; 
typedef unsigned long    ulong;
#include "sha1.h"
#define SCRAMBLE_LENGTH 20
#define SCRAMBLE_LENGTH_323 8

#define char_val(X) (X >= '0' && X <= '9' ? X-'0' :\
                     X >= 'A' && X <= 'Z' ? X-'A'+10 :\
                     X >= 'a' && X <= 'z' ? X-'a'+10 :\
                     '\177')

void hash_password(ulong *result, const char *password, uint password_len)
{
  register ulong nr=1345345333L, add=7, nr2=0x12345671L;
  ulong tmp;
  const char *password_end= password + password_len;
  for (; password < password_end; password++)
  {
    if (*password == ' ' || *password == '\t')
      continue;                                 /* skip space in password */
    tmp= (ulong) (uchar) *password;
    nr^= (((nr & 63)+add)*tmp)+ (nr << 8);
    nr2+=(nr2 << 8) ^ nr;
    add+=tmp;
  }
  result[0]=nr & (((ulong) 1L << 31) -1L); /* Don't use sign bit (str2int) */;
  result[1]=nr2 & (((ulong) 1L << 31) -1L);
}

void octet2hex(char *to, const uint8 *str, unsigned int len)
{
  char _dig_vec_upper[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const uint8 *str_end= str + len;
  for (; str != str_end; ++str)
  {
    *to++= _dig_vec_upper[(*str & 0xF0) >> 4];
    *to++= _dig_vec_upper[*str & 0x0F];
  }
  *to= '\0';
}

void hex2octet(uint8 *to, const char *str, uint len)
{
  const char *str_end= str + len;
  while (str < str_end)
  {
    register char tmp= char_val(*str++);
    *to++= (tmp << 4) | char_val(*str++);
  }
}

static void my_crypt(char *to, const uchar *s1, const uchar *s2, uint len)
{
  const uint8 *s1_end= s1 + len;
  while (s1 < s1_end)
    *to++= *s1++ ^ *s2++;
}

double my_rnd(struct rand_struct *rand_st)
{
  rand_st->seed1=(rand_st->seed1*3+rand_st->seed2) % rand_st->max_value;
  rand_st->seed2=(rand_st->seed1+rand_st->seed2+33) % rand_st->max_value;
  return (((double) rand_st->seed1)/rand_st->max_value_dbl);
}

void scramble_323(char *to, _MYSQL_DATA *_psSessionData, const char *message, const char *password)
{
  struct rand_struct rand_st;
  ulong hash_pass[2], hash_message[2];

  if (password && password[0])
  {
    char extra, *to_start=to;
    const char *message_end= message + SCRAMBLE_LENGTH_323;
    
    /* Idea borrowed from "The Database Hacker's Handbook: Defending Database Servers" */
    if (_psSessionData->hashFlag == HASH)
    {
      if (strlen(password) != 16)
        writeError(ERR_ERROR, "[%s] Invalid Hash Type (Old Style Hash Required)", MODULE_NAME);

      sscanf(password, "%08lx%08lx", &hash_pass[0], &hash_pass[1]);
    }
    else
      hash_password(hash_pass, password, strlen(password));

    hash_password(hash_message, message, SCRAMBLE_LENGTH_323);
    randominit(&rand_st, hash_pass[0] ^ hash_message[0], hash_pass[1] ^ hash_message[1]);
    for (; message < message_end; message++)
      *to++= (char) (floor(my_rnd(&rand_st)*31)+64);
    extra=(char) (floor(my_rnd(&rand_st)*31));
    while (to_start != to)
      *(to_start++)^=extra;
  }
  *to= 0;
}

void scramble(char *to, _MYSQL_DATA *_psSessionData, const char *message, const char *password)
{
  SHA1_CONTEXT sha1_context;
  uint8 hash_stage1[SHA1_HASH_SIZE];
  uint8 hash_stage2[SHA1_HASH_SIZE];

  sha1_reset(&sha1_context);
  
  /* Stock pass-the-hash Attacks do not appear feasible. However, if another conversation is
     intercepted and the SHA1 hash (hash_stage2) is known, hash_stage1 could probably be
     derived. A new reply could then be generated based on that information. Of course, if
     we already have this sort of network access, what are we messing with this for?
  */
  if (_psSessionData->hashFlag == HASH)
    if ( (strncmp(password, "*", 1) == 0) && (strlen(password) == 2 * SHA1_HASH_SIZE + 1) )  
      writeError(ERR_ERROR, "[%s] MySQL 4.1 and above use a SHA1-based authentication scheme which does not appear to be susceptible to pass-the-hash style attacks.", MODULE_NAME);

  /* stage 1: hash password */
  sha1_input(&sha1_context, (uint8 *) password, strlen(password));
  sha1_result(&sha1_context, hash_stage1);
  /* stage 2: hash stage 1; note that hash_stage2 is stored in the database */
  sha1_reset(&sha1_context);
  sha1_input(&sha1_context, hash_stage1, SHA1_HASH_SIZE);
  sha1_result(&sha1_context, hash_stage2);
  /* create crypt string as sha1(message, hash_stage2) */;
  sha1_reset(&sha1_context);
  sha1_input(&sha1_context, (const uint8 *) message, SCRAMBLE_LENGTH);
  sha1_input(&sha1_context, hash_stage2, SHA1_HASH_SIZE);
  /* xor allows 'from' and 'to' overlap: lets take advantage of it */
  sha1_result(&sha1_context, (uint8 *) to);
  my_crypt(to, (const uchar *) to, hash_stage1, SCRAMBLE_LENGTH);
}

/* End of MySQL copy and paste items */ 

int MySQLPrepareAuthOld(_MYSQL_DATA *_psSessionData, char* szLogin, char* szPassword, char* szSessionSalt, unsigned char** szResponse, unsigned long* iResponseLength)
{
  unsigned char* response;
  /* usernames limited to 16 characters - http://dev.mysql.com/doc/refman/5.1/en/user-names.html */
  int login_len = strlen(szLogin) > 16 ? 16 : strlen(szLogin);
  int response_len = 4 /* header */  +
                     2 /* client flags */  +
                     3 /* max packet len */  +
                     login_len /* username length */ + 
                     1 /* NULL terminate username */ + 
                     8; /* scrambled password len */


  response = (unsigned char *) malloc(response_len + 1);
  memset(response, 0, response_len + 1);

  response[0] = response_len - 4;   /* packet length */
  response[1] = 0x00;
  response[2] = 0x00;
  response[3] = 0x01;               /* packet number */

  response[4] = 0x85;               /* client flag */
  response[5] = 0x24;

  response[6] = 0x00;               /* max packet */
  response[7] = 0x00;
  response[8] = 0x00;
  
  strncpy((char*)response + 9, szLogin, login_len);

  response[9 + login_len] = '\0';       /* null terminate login */
  
  if ( strcmp(szPassword, "") != 0) /* password set */
    scramble_323((char *) &response[9 + login_len + 1], _psSessionData, szSessionSalt, szPassword);

  *(iResponseLength) = response_len;
  *szResponse = response;
  return SUCCESS;
}

/* Protocol 10 is used by MySQL 3.22 and later. However, MySQL 4.1 introduced a new password algorithm.
   In some cases, MySQL 4.1 and later systems will contain accounts which are still configured with password
   hashes generated using the older algorithm. When we authenticate to a 4.1 server and this is the case,
   the server is nice enough to tell us and allow us to reauthenticate. This function generates the appropriate
   response for this particular case.
*/
int MySQLPrepareAuthNewOld(_MYSQL_DATA *_psSessionData, char* szPassword, char* szSessionSalt, unsigned char** szResponse, unsigned long* iResponseLength)
{
  unsigned char* response;
  int response_len = 4 +  /* header */
                     1 +
                     8; /* scrambled password length */

  response = (unsigned char *) malloc(response_len + 1);
  memset(response, 0, response_len + 1);

  response[0] = response_len - 4;   /* packet length */
  response[3] = 0x03;               /* packet number */
  scramble_323((char *) &response[4], _psSessionData, szSessionSalt, szPassword);

  *(iResponseLength) = response_len;
  *szResponse = response;
  return SUCCESS;
}

/* http://www.redferni.uklinux.net/mysql/MySQL-Protocol.html */ 
int MySQLPrepareAuth(_MYSQL_DATA *_psSessionData, char* szLogin, char* szPassword, char* szSessionSalt, unsigned char** szResponse, unsigned long* iResponseLength)
{
  unsigned char* response;
  /* usernames limited to 16 characters - http://dev.mysql.com/doc/refman/5.1/en/user-names.html */
  int login_len = strlen(szLogin) > 16 ? 16 : strlen(szLogin);
  int response_len = 4  /* header */  +
                     4  /* client flags */  +
                     4  /* max packet len */  +
                     1  /* charset */ +
                     23 /* future expansion */ +
                     login_len /* username */ +
                     1 /* NULL termination */ + 
                     1; /* password length */
    
  if ( strcmp(szPassword, "") != 0 ) /* password set */
    response_len += 20;

  response = (unsigned char *) malloc(response_len + 1);
  memset(response, 0, response_len + 1);

  response[0] = response_len - 4;     /* packet body length - exclude header */
  response[1] = 0x00;
  response[2] = 0x00;
  response[3] = 0x01;                 /* packet number */
  
  //response[4] = 0x85;               /* client flag */
  response[4] = 0x05;                 /* client flag */
  //response[5] = 0x24;
  response[5] = 0xa6;
  response[6] = 0x03;
  response[7] = 0x00;
  
  response[8] = 0x00;                 /* max packet */
  response[9] = 0x00;
  response[10] = 0x00;    
  response[11] = 0x01;    
  
  response[12] = 0x21;                /* charset utf8 */

  strncpy((char*)response + 36, szLogin, login_len);  /* NULL terminated username */

  if ( strcmp(szPassword, "") == 0 ) /* no password set */
  {
    response[36 + login_len + 1] = 0x00;
  }
  else
  {
    response[36 + login_len + 1] = 0x14;  /* set length of scrambled password - 0x14 (20) */

    /* generate SHA password hash */
    scramble((char *) &response[36 + login_len + 1 + 1], _psSessionData, szSessionSalt, szPassword); 
  }
  
  *(iResponseLength) = response_len; 
  *szResponse = response;
  return SUCCESS;
}

int MySQLSessionInit(int hSocket, char** szSessionSalt)
{
  unsigned char* bufReceive;
  char* szServerVersion;
  int nReceiveBufferSize = 0;
  int newerauth = 0;

  bufReceive = medusaReceiveRaw(hSocket, &nReceiveBufferSize);
  if (bufReceive == NULL)
  {
    writeError(ERR_ERROR, "%s failed: medusaReceive returned no data.", MODULE_NAME);
    return FAILURE;
  }

  /* check protocol version */
  if (bufReceive[4] == 0xff)
  {
    if (strstr((char*)bufReceive + 7, "is not allowed to connect to this MySQL server"))
    {
      writeError(ERR_WARNING, "%s: Server responded that host is not allowed to connect to MySQL service.", MODULE_NAME);
      FREE(bufReceive);
      return FAILURE;
    }
    else
    {
      writeError(ERR_ERROR, "%s: Failed to retrieve server version: %s", MODULE_NAME, bufReceive + 7);
      FREE(bufReceive);
      return FAILURE;
    }
  }

  if (bufReceive[4] < 10)
  {
    writeError(ERR_ERROR, "%s: Server responded requesting protocol version (%d). Version 10 support required.", MODULE_NAME, bufReceive[4]);
    FREE(bufReceive);
    return FAILURE;
  }
  else if (bufReceive[4] > 10)
  {
    writeError(ERR_WARNING, "%s: Server responded requesting protocol version (%d). Support for versions >10 is unknown.", MODULE_NAME, bufReceive[4]);
  }

  /* check server version */
  szServerVersion = (char*)bufReceive + 5;

  if (!(strstr(szServerVersion, "3.") || strstr(szServerVersion, "4.") || strstr(szServerVersion, "5.") ))
  {
    writeError(ERR_ERROR, "%s: Server responded requesting version (%d). Only versions 3.x, 4.x, and 5.x are currently supported.", MODULE_NAME, szServerVersion);
    FREE(bufReceive);
    return FAILURE;
  }

  if ((strstr(szServerVersion, "4.1") || strstr(szServerVersion, "5.") ))
  {
     newerauth=1;    
     writeError(ERR_DEBUG_MODULE, "%s: Server version %s is using newer auth method.", MODULE_NAME, szServerVersion);
  }

  if (newerauth)
  {
    /* retrieve session salt for newer auth */
    *szSessionSalt = malloc(22);
    memset(*szSessionSalt, 0, 22);
    memcpy(*szSessionSalt, bufReceive + strlen(szServerVersion) + 10, 9);
    memcpy(*szSessionSalt+8 , bufReceive + strlen(szServerVersion) + 37 , 12); 

    if (strlen(*szSessionSalt) != 20)
    {
      writeError(ERR_ERROR, "%s: Failed to retrieve valid session salt.", MODULE_NAME);
      FREE(bufReceive);
      return FAILURE;
    }
    else
    {
      writeError(ERR_DEBUG_MODULE, "%s: Retrieved session salt: %s", MODULE_NAME, *szSessionSalt);
    }
  } 
  else 
  {
    /* use the older salt code */
    *szSessionSalt = malloc(10);
    memset(*szSessionSalt, 0, 10);
    memcpy(*szSessionSalt, bufReceive + strlen(szServerVersion) + 10, 9);

    if (strlen(*szSessionSalt) != 8) {
      writeError(ERR_ERROR, "%s: Failed to retrieve valid session salt.", MODULE_NAME);
      FREE(bufReceive);
      return FAILURE;
    }
    else
    {
      writeError(ERR_DEBUG_MODULE, "%s: Retrieved session salt: %s.", MODULE_NAME, *szSessionSalt);
    }
  }

  FREE(bufReceive);
  return SUCCESS;
}

int tryLogin(int hSocket, sLogin** psLogin, _MYSQL_DATA* _psSessionData, char* szLogin, char* szPassword)
{
  int iRet;
  int iReturnCode = MSTATE_EXITING;
  unsigned char* bufReceive = NULL;
  char* szSessionSalt = NULL;
  unsigned char* szResponse = NULL;
  unsigned long iResponseLength = 0;
  int nReceiveBufferSize = 0;

  /* initialize MySQL connection */
  iRet = MySQLSessionInit(hSocket, &szSessionSalt);
  if (iRet == FAILURE)
  {
    writeError(ERR_ERROR, "[%s] Failed to initialize MySQL connection (%s).", MODULE_NAME, (*psLogin)->psServer->pHostIP);
    (*psLogin)->iResult = LOGIN_RESULT_ERROR;
    return MSTATE_EXITING;
  }

  /* prepare client authentication packet */
  if (strlen(szSessionSalt) == 8 || _psSessionData->protoFlag == PROTO_OLD)
  {
    if (_psSessionData->protoFlag == PROTO_OLD) {
      writeError(ERR_DEBUG_MODULE, "[%s] Using older style authentication based on previous server response.", MODULE_NAME);
    }
    
    iRet = MySQLPrepareAuthOld(_psSessionData, szLogin, szPassword, szSessionSalt, &szResponse, &iResponseLength);
    if (iRet == FAILURE)
    {
      writeError(ERR_ERROR, "[%s] Failed to create client authentication packet.", MODULE_NAME);
      return FAILURE;
    }
  } 
  else 
  {
    iRet = MySQLPrepareAuth(_psSessionData, szLogin, szPassword, szSessionSalt, &szResponse, &iResponseLength);
    if (iRet == FAILURE)
    {
      writeError(ERR_ERROR, "%s: Failed to create client authentication packet.", MODULE_NAME);
      return FAILURE;
    }
  }

  /* send authentication attempt */
  if (medusaSend(hSocket, szResponse, iResponseLength, 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
    FREE(szResponse);
    return FAILURE;
  }
  FREE(szResponse);

  /* process authentication response */
  nReceiveBufferSize = 0;
  bufReceive = medusaReceiveRaw(hSocket, &nReceiveBufferSize);
  if (bufReceive == NULL)
  {
    writeError(ERR_ERROR, "%s failed: medusaReceive returned no data.", MODULE_NAME);
    return FAILURE;
  }

  if (bufReceive[4] == 0x00)
  {
    (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
    iReturnCode = MSTATE_EXITING;
  }
  else if (bufReceive[4] == 0xFF)
  {
    (*psLogin)->iResult = LOGIN_RESULT_FAIL;
    
    if (bufReceive[5] == 0xe3 && bufReceive[6] == 0x04)
    {
      writeError(ERR_ERROR, "[%s] failed: MYSQL VERSION IS NEWER\n", MODULE_NAME);
      (*psLogin)->iResult = LOGIN_RESULT_ERROR;
      iReturnCode = MSTATE_EXITING;
    }
    else 
      iReturnCode = MSTATE_NEW;
  }
  else if (bufReceive[4] == 0xFE)
  {
    /* Protocol 10 is used by MySQL 3.22 and later. However, MySQL 4.1 introduced a new password algorithm.
       In some cases, MySQL 4.1 and later systems will contain accounts which are still configured with password
       hashes generated using the older algorithm. When we authenticate to a 4.1 server and this is the case,
       the server is nice enough to tell us and allow us to reauthenticate.
    */

    writeError(ERR_DEBUG_MODULE, "[%s] Server requested older authentication type. It is likely the remote account exists and has an older style password hash.", MODULE_NAME);
    (*psLogin)->iResult = LOGIN_RESULT_FAIL;

    /* Attempt authentication again using old-style password hash and existing connection */
    _psSessionData->protoFlag = PROTO_OLD;
    
    iRet = MySQLPrepareAuthNewOld(_psSessionData, szPassword, szSessionSalt, &szResponse, &iResponseLength);
    if (iRet == FAILURE)
    {
      writeError(ERR_ERROR, "[%s] Failed to create client authentication packet.", MODULE_NAME);
      return FAILURE;
    }

    /* send authentication attempt */
    if (medusaSend(hSocket, szResponse, iResponseLength, 0) < 0)
    {
      writeError(ERR_ERROR, "[%s] medusaSend was not successful", MODULE_NAME);
      FREE(szResponse);
      return FAILURE;
    }
    FREE(szResponse);

    /* process authentication response */
    FREE(bufReceive);
    nReceiveBufferSize = 0;
    bufReceive = medusaReceiveRaw(hSocket, &nReceiveBufferSize);
    if (bufReceive == NULL)
    {
      writeError(ERR_ERROR, "%s failed: medusaReceive returned no data.", MODULE_NAME);
      return FAILURE;
    }

    if (bufReceive[4] == 0x00)
    {
      (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
      iReturnCode = MSTATE_EXITING;
    }
    else if (bufReceive[4] == 0xFF)
    {
      (*psLogin)->iResult = LOGIN_RESULT_FAIL;

      if (bufReceive[5] == 0xe3 && bufReceive[6] == 0x04) {
        writeError(ERR_ERROR, "%s failed: MYSQL VERSION IS NEWER\n", MODULE_NAME);
        (*psLogin)->iResult = LOGIN_RESULT_ERROR;
        iReturnCode = MSTATE_EXITING;
      }
      else
        iReturnCode = MSTATE_NEW;
    }
    /* End of the weird downshift resend case */
  }
  else
  {
    writeError(ERR_ERROR, "%s: Unknown response code received from server: %X", MODULE_NAME, bufReceive[4]);
    (*psLogin)->iResult = LOGIN_RESULT_UNKNOWN;
    iReturnCode = MSTATE_EXITING;
  }

  /* close MySQL connection */
  iRet = MySQLSessionQuit(hSocket);
  if (iRet == FAILURE)
  {
    writeError(ERR_ERROR, "%s: Failed to terminate MySQL connection.", MODULE_NAME);
    return FAILURE;
  }

  FREE(bufReceive);
  setPassResult((*psLogin), szPassword);

  return(iReturnCode);
}
