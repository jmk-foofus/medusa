/*
 * Medusa Parallel Login Auditor
 *
 *    Copyright (C) 2006 Joe Mondloch
 *    JoMo-Kun / jmk@foofus.net
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License version 2,
 *    as published by the Free Software Foundation
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    http://www.gnu.org/licenses/gpl.txt
 *
 *    This program is released under the GPL with the additional exemption
 *    that compiling, linking, and/or using OpenSSL is allowed.
 *
*/

#ifndef _MEDUSA_H
#define _MEDUSA_H

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <time.h>
#include <math.h>

#include "medusa-trace.h"
#include "medusa-net.h"
#include "medusa-thread-pool.h"
#include "medusa-thread-ssl.h"

#ifdef HAVE_CONFIG_H
  #include <config.h>
#endif

#ifdef HAVE_LIBSSL
  #include <openssl/crypto.h>
#endif

#define PROGRAM   "Medusa"
#ifndef VERSION
  #define VERSION   "1.0"
#endif
#define AUTHOR    "JoMo-Kun / Foofus Networks"
#define EMAIL     "<jmk@foofus.net>"
#define WWW       "http://www.foofus.net"

#define SUCCESS 0
#define FAILURE -1

#define FALSE 0
#define TRUE 1

/* GLOBAL VARIABLES */
extern FILE *pOutputFile;
extern pthread_mutex_t ptmFileMutex;
extern int iVerboseLevel;      // Global control over general message verbosity
extern int iErrorLevel;        // Global control over error debugging verbosity

//#define MAX_BUF (16 * 1024)
#define MAX_BUF 16384 

/* Older Solaris doesn't seem to define INADDR_NONE */
#ifndef INADDR_NONE
  #define INADDR_NONE ((unsigned long) -1
#endif

/* Cygwin doesn't seem to define INET_ADDRSTRLEN */
#ifndef INET_ADDRSTRLEN
  #define INET_ADDRSTRLEN 16
#endif

// Number of seconds that idle threads can linger before exiting, when no tasks 
// come in. The idle threads can only exit if they are extra threads, above the 
// number of minimum threads.
#define POOL_THREAD_LINGER 1

#define FREE(x) \
        if (x != NULL) { \
           free(x); \
           x = NULL; \
        }

#define L_UNSET 0
#define L_SINGLE 1
#define L_FILE 2
#define L_COMBO 3
#define L_PWDUMP 4

typedef struct __sPass {
  struct __sPass *psPassNext;
  char *pPass;
} sPass;

/* Used in __sUser to define progress of an individual username audit */
#define PL_UNSET 0
#define PL_NULL 1
#define PL_USERNAME 2
#define PL_LOCAL 3
#define PL_GLOBAL 4
#define PL_DONE 5
#define PASS_AUDIT_COMPLETE 6 

typedef struct __sUser {
  struct __sUser *psUserNext;
  char *pUser;
  struct __sPass *psPass;
  struct __sPass *psPassCurrent;
  struct __sPass *psPassPrevTmp;
  char *pPass;
  int iPassCnt;
  int iLoginsDone;
  int iPassStatus;
  int iId;
} sUser;

/* Used in __sHost to define progress of the audit of the host's users */
#define UL_UNSET 0
#define UL_NORMAL 1
#define UL_MISSED 2
#define UL_DONE 3
#define UL_ERROR 4

typedef struct __sHost {
  struct __sHost *psHostNext;
  char *pHost;
  int iUseSSL;            // use SSL
  int iPortOverride;      // use this port instead of the module's default port
  int iTimeout;           // Number of seconds to wait before a connection times out
  int iRetryWait;         // Number of seconds to wait between retries
  int iRetries;           // Number of retries to attempt
  sUser *psUser;
  sUser *psUserCurrent;
  sUser *psUserPrevTmp;
  int iUserCnt;
  int iUserPassCnt;
  int iUsersDone;        // number of users tested
  int iUserStatus;
  int iId;
} sHost;

/* Used in __sCredentialSet to relay information to module regarding user */
#define CREDENTIAL_SAME_USER 1
#define CREDENTIAL_NEW_USER 2
#define CREDENTIAL_DONE 3

typedef struct __sCredentialSet {
  struct __sCredentialSet *psCredentialSetNext;
  struct __sUser *psUser;
  char *pPass;
  int iStatus;
} sCredentialSet;

typedef struct __sServer {
  struct __sAudit *psAudit;
  struct __sHost *psHost;
  char *pHostIP;
  int iValidPairFound;
  int iId;
  int iLoginCnt;          // total number of logins performed concurrently against specific server
  int iLoginsDone;       // number of logins performed by all threads under this server
  
  sCredentialSet *psCredentialSetMissed;
  sCredentialSet *psCredentialSetMissedCurrent;
  sCredentialSet *psCredentialSetMissedTail;
  int iCredentialsMissed;

  pthread_mutex_t ptmMutex;
} sServer;

#define LOGIN_RESULT_UNKNOWN 1
#define LOGIN_RESULT_SUCCESS 2
#define LOGIN_RESULT_FAIL 3
#define LOGIN_RESULT_ERROR 4

typedef struct __sLogin {
  struct __sServer *psServer;
  struct __sUser *psUser;
  int iResult;
  char *pErrorMsg;
  int iId;
  int iLoginsDone;       // number of logins performed by this thread
} sLogin;


#define AUDIT_IN_PROGRESS 0 
#define AUDIT_COMPLETE 1
#define LIST_IN_PROGRESS 0 
#define LIST_COMPLETE 1

#define FOUND_PAIR_EXIT_HOST 1
#define FOUND_PAIR_EXIT_AUDIT 2

#define PARALLEL_LOGINS_USER 1
#define PARALLEL_LOGINS_PASSWORD 2

#define AUDIT_ABORT 1

typedef struct __sAudit {
  char *pOptHost;         // user specified host or host file
  char *pOptUser;         // user specified username or username file
  char *pOptPass;         // user specified password or password file
  char *pOptCombo;        // user specified combo host/username/password file
  char *pOptOutput;       // user specified output file
  char *pOptResume;       // user specified resume command

  char *pModuleName;      // current module name

  char *pGlobalHost; 
  char *pGlobalUser;
  char *pGlobalPass;
  char *pGlobalCombo;
  char *pHostFile; 
  char *pUserFile;
  char *pPassFile;
  char *pComboFile;

  int iHostCnt;           // total number of hosts supplied for testing
  int iUserCnt;           // total number of users supplied for testing
  int iPassCnt;           // total number of passwords supplied for testing
  int iComboCnt;          // total number of entries in combo file
  int iServerCnt;         // total number of hosts scanned concurrently
  int iLoginCnt;          // total number of logins performed concurrently

  int iHostsDone;         // number of hosts tested

  int iPortOverride;      // use this port instead of the module's default port
  int iUseSSL;            // enable SSL
  int iTimeout;           // Number of seconds to wait before a connection times out
  int iRetryWait;         // Number of seconds to wait between retries
  int iRetries;           // Number of retries to attempt
  int iSocketWait;        // Number of usec to wait when module calls medusaCheckSocket function
  int HostType;
  int UserType;
  int PassType;
  int iShowModuleHelp;    // Flag used to show individual module help

  char *pComboEntryTmp;   // used to managed processing of user supplied files
  int iHostListFlag;
  int iUserListFlag;

  int iAuditFlag;             /* Tracks loading of user supplied information */
  
  int iPasswordBlankFlag;     /* Submit a blank password for each user account */
  int iPasswordUsernameFlag;  /* Submit a password matching the username for each user account */
  int iFoundPairExitFlag;     /* When a valid login pair is found, end scan of host or of complete audit */
  int iParallelLoginFlag;     /* Parallel logins by user or password */
  int iValidPairFound;
  int iStatus;                /* Flag to indicate to threads that audit is aborting */ 
 
  sHost *psHostRoot;
 
  thr_pool_t *server_pool;
 
  pthread_mutex_t ptmMutex;
} sAudit;

typedef struct __sModuleStart
{
  char*   szModuleName;
  sLogin* pLogin;
  int     argc;
  char**  argv;  
} sModuleStart;


void listModules(char* arrPaths[], int nTerminateNow);
int invokeModule(char* pModuleName, sLogin* pLogin, int argc, char* argv[]);

int getNextCredSet(sLogin *_psLogin, sCredentialSet *_psCredSet);
void setPassResult(sLogin *_psLogin, char *_pPass);
int addMissedCredSet(sLogin *_psLogin, sCredentialSet *_psCredSet);

#endif
