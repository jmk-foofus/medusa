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
 * Based on ideas from Hydra 3.1 by VanHauser [vh@thc.org]
 * Do only use for legal purposes. Illegal purposes cost $1 each.
 *
*/

#define VERSION_SVN "$Id: medusa.c 9217 2015-05-07 18:07:03Z jmk $" 

#include <dlfcn.h>
#include "medusa.h"
#include "modsrc/module.h"

char* szModuleName;
char* szTempModuleParam;
char* szModulePaths[3] = {"a", "b", "c"};         // will look at 3 different locations for modules if possible
char** arrModuleParams;    // the "argv" for the module
int nModuleParamCount;    // the "argc" for the module
//int ctrlc = 0;
sAudit *psAudit = NULL;

int iVerboseLevel;
int iErrorLevel;
FILE *pOutputFile;
pthread_mutex_t ptmFileMutex;

void freeModuleParams()
{
  int i;

  for (i = 0; i < nModuleParamCount; i++)
  {
    free(arrModuleParams[i]);
  }

  free(arrModuleParams);
}

/*
  Display appropriate usage information for application.
*/
void usage()
{
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "Syntax: %s [-h host|-H file] [-u username|-U file] [-p password|-P file] [-C file] -M module [OPT]", PROGRAM);
  writeVerbose(VB_NONE, "  -h [TEXT]    : Target hostname or IP address");
  writeVerbose(VB_NONE, "  -H [FILE]    : File containing target hostnames or IP addresses");
  writeVerbose(VB_NONE, "  -u [TEXT]    : Username to test");
  writeVerbose(VB_NONE, "  -U [FILE]    : File containing usernames to test");
  writeVerbose(VB_NONE, "  -p [TEXT]    : Password to test");
  writeVerbose(VB_NONE, "  -P [FILE]    : File containing passwords to test");
  writeVerbose(VB_NONE, "  -C [FILE]    : File containing combo entries. See README for more information.");
  writeVerbose(VB_NONE, "  -O [FILE]    : File to append log information to");
  writeVerbose(VB_NONE, "  -e [n/s/ns]  : Additional password checks ([n] No Password, [s] Password = Username)");
  writeVerbose(VB_NONE, "  -M [TEXT]    : Name of the module to execute (without the .mod extension)");
  writeVerbose(VB_NONE, "  -m [TEXT]    : Parameter to pass to the module. This can be passed multiple times with a"); 
  writeVerbose(VB_NONE, "                 different parameter each time and they will all be sent to the module (i.e.");
  writeVerbose(VB_NONE, "                 -m Param1 -m Param2, etc.)"); 
  writeVerbose(VB_NONE, "  -d           : Dump all known modules");
  writeVerbose(VB_NONE, "  -n [NUM]     : Use for non-default TCP port number");
  writeVerbose(VB_NONE, "  -s           : Enable SSL");
  writeVerbose(VB_NONE, "  -g [NUM]     : Give up after trying to connect for NUM seconds (default 3)"); 
  writeVerbose(VB_NONE, "  -r [NUM]     : Sleep NUM seconds between retry attempts (default 3)");   
  writeVerbose(VB_NONE, "  -R [NUM]     : Attempt NUM retries before giving up. The total number of attempts will be NUM + 1.");
  writeVerbose(VB_NONE, "  -c [NUM]     : Time to wait in usec to verify socket is available (default 500 usec).");
  writeVerbose(VB_NONE, "  -t [NUM]     : Total number of logins to be tested concurrently");
  writeVerbose(VB_NONE, "  -T [NUM]     : Total number of hosts to be tested concurrently");
  writeVerbose(VB_NONE, "  -L           : Parallelize logins using one username per thread. The default is to process ");
  writeVerbose(VB_NONE, "                 the entire username before proceeding.");
  writeVerbose(VB_NONE, "  -f           : Stop scanning host after first valid username/password found.");
  writeVerbose(VB_NONE, "  -F           : Stop audit after first valid username/password found on any host.");
  writeVerbose(VB_NONE, "  -b           : Suppress startup banner");
  writeVerbose(VB_NONE, "  -q           : Display module's usage information");
  writeVerbose(VB_NONE, "  -v [NUM]     : Verbose level [0 - 6 (more)]");
  writeVerbose(VB_NONE, "  -w [NUM]     : Error debug level [0 - 10 (more)]");
  writeVerbose(VB_NONE, "  -V           : Display version");
  writeVerbose(VB_NONE, "  -Z [TEXT]    : Resume scan based on map of previous scan");
  writeVerbose(VB_NONE, "\n");
  return;
}

/*
  Read user options and check validity.
*/
int checkOptions(int argc, char **argv, sAudit *_psAudit)
{
  int opt;
  extern char *optarg;
  extern int   opterr;
  int ret = 0;
  int i = 0;
  int nIgnoreBanner = 0;

  /* initialize options */
  _psAudit->iServerCnt = 1;
  _psAudit->iLoginCnt = 1;
  _psAudit->iParallelLoginFlag = PARALLEL_LOGINS_PASSWORD;
  _psAudit->iPortOverride = 0;                        /* Use default port */
  _psAudit->iUseSSL = 0;                              /* No SSL */
  _psAudit->iTimeout = DEFAULT_WAIT_TIME;             /* Default wait of 3 seconds */
  _psAudit->iRetryWait = WAIT_BETWEEN_CONNECT_RETRY;  /* Default wait of 3 seconds */
  _psAudit->iRetries = MAX_CONNECT_RETRY;             /* Default of 2 retries (3 total attempts) */
  _psAudit->iSocketWait = 500;                        /* Default wait of 500 usec */
  _psAudit->iShowModuleHelp = 0;
  iVerboseLevel = 5;
  iErrorLevel = 5;

  for (i =0; i < argc; i++)
  {
    if (strstr(argv[i], "-b") != NULL)
    {
      nIgnoreBanner = 1;
      break;
    }
  }

  if (nIgnoreBanner == 0)
    writeVerbose(VB_NONE, "%s v%s [%s] (C) %s %s\n", PROGRAM, VERSION, WWW, AUTHOR, EMAIL);

  while ((opt = getopt(argc, argv, "h:H:u:U:p:P:C:O:e:M:m:g:r:R:c:t:T:n:bqdsLfFVv:w:Z:")) != EOF)
  {
    switch (opt)
    {
    case 'h':
      if (_psAudit->HostType)
      {
        writeError(ERR_ALERT, "Options 'h' and 'H' are mutually exclusive.");
        ret = EXIT_FAILURE;
      }
      else
      {
        _psAudit->pGlobalHost = strdup(optarg);
        _psAudit->HostType = L_SINGLE;
      }
      break;
    case 'H':
      if (_psAudit->HostType)
      {
        writeError(ERR_ALERT, "Options 'h' and 'H' are mutually exclusive.");
        ret = EXIT_FAILURE;
      }
      else
      {
        _psAudit->pOptHost = strdup(optarg);
        _psAudit->HostType = L_FILE;
      }
      break;
    case 'u':
      if (_psAudit->UserType)
      {
        writeError(ERR_ALERT, "Options 'u' and 'U' are mutually exclusive.");
        ret = EXIT_FAILURE;
      }
      else
      {
        _psAudit->pGlobalUser = strdup(optarg);
        _psAudit->UserType = L_SINGLE;
        _psAudit->iUserCnt = 1;
      }
      break;
    case 'U':
      if (_psAudit->UserType)
      {
        writeError(ERR_ALERT, "Options 'u' and 'U' are mutually exclusive.");
        ret = EXIT_FAILURE;
      }
      else
      {
        _psAudit->pOptUser = strdup(optarg);
        _psAudit->UserType = L_FILE;
      }
      break;
    case 'p':
      if (_psAudit->PassType)
      {
        writeError(ERR_ALERT, "Options 'p' and 'P' are mutually exclusive.");
        ret = EXIT_FAILURE;
      }
      else
      {
        _psAudit->pGlobalPass = malloc( strlen(optarg) + 2 );
        memset(_psAudit->pGlobalPass, 0, strlen(optarg) + 2);
        strcpy(_psAudit->pGlobalPass, optarg);
        _psAudit->PassType = L_SINGLE;
        _psAudit->iPassCnt = 1;
      }
      break;
    case 'P':
      if (_psAudit->PassType)
      {
        writeError(ERR_ALERT, "Options 'p' and 'P' are mutually exclusive.");
        ret = EXIT_FAILURE;
      }
      else
      {
        _psAudit->pOptPass = strdup(optarg);
        _psAudit->PassType = L_FILE;
      }
      break;
    case 'C':
      _psAudit->pOptCombo = strdup(optarg);
      break;
    case 'O':
      _psAudit->pOptOutput = strdup(optarg);
      break;
    case 'e':
      if (strcmp(optarg, "n") == 0)
      {
        _psAudit->iPasswordBlankFlag = TRUE;
        _psAudit->iPasswordUsernameFlag = FALSE;
      }
      else if (strcmp(optarg, "s") == 0)
      {
        _psAudit->iPasswordBlankFlag = FALSE;
        _psAudit->iPasswordUsernameFlag = TRUE;
      }
      else if ((strcmp(optarg, "ns") == 0) || (strcmp(optarg, "sn") == 0))
      {
        _psAudit->iPasswordBlankFlag = TRUE;
        _psAudit->iPasswordUsernameFlag = TRUE;
      }
      else
      {
        writeError(ERR_ALERT, "Option 'e' requires value of n, s, or ns.");
        ret = EXIT_FAILURE;
      }
      break;
    case 's':
      _psAudit->iUseSSL = 1;  
      break;
    case 'L':
      _psAudit->iParallelLoginFlag = PARALLEL_LOGINS_USER;
      break;
    case 'f':
      _psAudit->iFoundPairExitFlag = FOUND_PAIR_EXIT_HOST;
      break;
    case 'F':
      _psAudit->iFoundPairExitFlag = FOUND_PAIR_EXIT_AUDIT;
      break;
    case 't':
      _psAudit->iLoginCnt = atoi(optarg);
      break;
    case 'T':
      _psAudit->iServerCnt = atoi(optarg);
      break;
    case 'n':
      _psAudit->iPortOverride = atoi(optarg);
      break;
    case 'v':
      iVerboseLevel = atoi(optarg);
      break;
    case 'w':
      iErrorLevel = atoi(optarg);
      break;
    case 'V':
      writeVerbose(VB_EXIT, "");  // Terminate now
      break;
    case 'M':
      szModuleName = strdup(optarg);
      _psAudit->pModuleName = szModuleName;
      break;
    case 'm':
      nModuleParamCount++;
      szTempModuleParam = strdup(optarg);
      arrModuleParams = realloc(arrModuleParams, nModuleParamCount * sizeof(char*));
      arrModuleParams[nModuleParamCount - 1] = szTempModuleParam;
      break;
    case 'd':
      listModules(szModulePaths, 1);  // End the program after this executes by passing a 1 as the second param
      break;
    case 'b':
      // Do nothing - supression of the startup banner is handled before the switch statement
      break;
    case 'q':
      _psAudit->iShowModuleHelp = 1;
      break;
    case 'g':
      _psAudit->iTimeout = atoi(optarg);
      break;
    case 'r':
      _psAudit->iRetryWait = atoi(optarg);
      break;
    case 'R':
      _psAudit->iRetries = atoi(optarg);
      break;
    case 'c':
      _psAudit->iSocketWait = atoi(optarg);
      break;
    case 'Z':
      _psAudit->pOptResume = strdup(optarg);
      break;
    default:
      writeError(ERR_CRITICAL, "Unknown error processing command-line options.");
      ret = EXIT_FAILURE;
    }
  }

  if (argc <= 1) {
    ret = EXIT_FAILURE;
  }
  
  if (_psAudit->iShowModuleHelp)
  {
    ret = invokeModule(_psAudit->pModuleName, NULL, 0, NULL);
    if (ret < 0)
    {
      writeError(ERR_CRITICAL, "invokeModule failed - see previous errors for an explanation");
    }
  }
  else
  {
    if ( !((_psAudit->HostType) || (_psAudit->pOptCombo)) )
    {
      writeError(ERR_ALERT, "Host information must be supplied.");
      ret = EXIT_FAILURE;
    }
    else if ( !((_psAudit->UserType) || (_psAudit->pOptCombo)) )
    {
      writeError(ERR_ALERT, "User logon information must be supplied.");
      ret = EXIT_FAILURE;
    }
    else if ( !((_psAudit->PassType) || (_psAudit->pOptCombo) || (_psAudit->iPasswordBlankFlag) || ( _psAudit->iPasswordUsernameFlag)) )
    {
      writeError(ERR_ALERT, "Password information must be supplied.");
      ret = EXIT_FAILURE;
    }
  }

  return ret;
}

int invokeModule(char* pModuleName, sLogin* pLogin, int argc, char* argv[])
{
  void    *pLibrary;
  int    iReturn;
  function_go  pGo;
  function_showUsage pUsage;
  char* modPath;
  int nPathLength;
  int i;
  int nSuccess = 0;

  iReturn   = -1;
  pLibrary  = NULL;
  pGo       = NULL;
  pUsage    = NULL;

  if (NULL == pModuleName)
  {
    listModules(szModulePaths, 0);
    writeError(ERR_CRITICAL, "invokeModule called with no name");
    return -1;
  }

  // Find the first available path to use
  for(i = 0; i < 3; i++)
  {
    if (szModulePaths[i] != NULL)
    {
      // Is the module available under here?
      writeError(ERR_DEBUG, "Trying module path of %s", szModulePaths[i]);
      nPathLength = strlen(szModulePaths[i]) + strlen(pModuleName) + strlen(MODULE_EXTENSION) + 2;  // Going to add a slash too
      modPath = malloc(nPathLength);
      memset(modPath, 0, nPathLength);
      strcpy(modPath, szModulePaths[i]);
      strcat(modPath, "/");
      strcat(modPath, pModuleName);
      strcat(modPath, MODULE_EXTENSION);

      // Now try the load
      writeError(ERR_DEBUG, "Attempting to load %s", modPath);
      pLibrary = dlopen(modPath, RTLD_NOW);

      if (pLibrary == NULL)
      {
        continue;
      }
      else if (!pLogin)
      {
        pUsage = (function_showUsage)dlsym(pLibrary, "showUsage");
       
        writeError(ERR_DEBUG, "Attempting to display usage information for module: %s", modPath);
        
        if (pUsage == NULL)
        {
          writeError(ERR_ALERT, "Couldn't get a pointer to \"showUsage\" for module %s [%s]", modPath, dlerror());
          return -1;
        }
        else
        {
          nSuccess = 1;
          pUsage();
        }
        dlclose(pLibrary);
        exit(EXIT_SUCCESS); // TEMP FIX
      }
      else
      {
        pGo = (function_go)dlsym(pLibrary, "go");

        if (pGo == NULL)
        {
          writeError(ERR_ALERT, "Couldn't get a pointer to \"go\" for module %s [%s]", modPath, dlerror());
          return -1;
        }
        else
        {
          nSuccess = 1;
          iReturn = pGo(pLogin, argc, argv);
          break;
        }
        dlclose(pLibrary);
      }
    }
  }

  if (!nSuccess)
  {
    writeVerbose(VB_IMPORTANT, "Couldn't load \"%s\" [%s]. Place the module in the medusa directory, set the MEDUSA_MODULE_NAME environment variable or run the configure script again using --with-default-mod-path=[path].", pModuleName, dlerror());
    iReturn = -1;
  }

  return iReturn;
}

/*
  Read the contents of a user supplied file. Store contents in memory and provide
  a count of the total file lines processed.
*/
void loadFile(char *pFile, char **pFileContent, int *iFileCnt)
{
  FILE *pfFile;
  size_t stFileSize = 0;
  char tmp[MAX_BUF];
  char *ptr;

  *iFileCnt = 0;

  if ((pfFile = fopen(pFile, "r")) == NULL)
  {
    writeError(ERR_FATAL, "Failed to open file %s - %s", pFile, strerror( errno ) );
  }
  else
  {
    /* get file stats */
    while (! feof(pfFile) )
    {
      if ( fgets(tmp, MAX_BUF, pfFile) != NULL )
      {
        if (tmp[0] != '\0')
        {
          stFileSize += strlen(tmp) + 1;
          (*iFileCnt)++;
        }
      }
    }
    rewind(pfFile);

    *pFileContent = malloc(stFileSize + 1);    /* extra end NULL */

    if (pFileContent == NULL)
    {
      writeError(ERR_FATAL, "Failed to allocate memory for file %s.", pFile);
    }

    memset(*pFileContent, 0, stFileSize + 1);
    ptr = *pFileContent;

    /* load file into mem */
    while (! feof(pfFile) )
    {
      if (fgets(tmp, MAX_BUF, pfFile) != NULL)
      {
        /* ignore blank lines */
        if ((tmp[0] == '\n') || (tmp[0] == '\r'))
        {
          (*iFileCnt)--;
          writeError(ERR_DEBUG, "Ignoring blank line in file: %s. Resetting total count: %d.", pFile, (*iFileCnt));
        }
        else if (tmp[0] != '\0')
        {
          if (tmp[strlen(tmp) - 1] == '\n') tmp[strlen(tmp) - 1] = '\0';
          if (tmp[strlen(tmp) - 1] == '\r') tmp[strlen(tmp) - 1] = '\0';
          memcpy(ptr, tmp, strlen(tmp) + 1);
          ptr += strlen(tmp) + 1;
        }
      }
    }
    *ptr = '\0';  /* extra NULL to identify end of list */
  }

  if((*iFileCnt) == 0)
  {
    writeError(ERR_FATAL, "Error loading user supplied file (%s) -- file may be empty.", pFile);
  }

  free(pFile);
  return;
}

/*
  Examine the first row of the combo file to determine information provided.
  Combo files are colon separated and in the following format: host:user:password.
  If any of the three fields are left empty, the respective information should be
  provided either as a single global value or as a list in a file.

  The following combinations are possible in the combo file:
  1. foo:bar:fud
  2. foo:bar:
  3. foo::
  4. :bar:fud
  5. :bar:
  6. ::fud
  7. foo::fud

  Medusa also supports using PwDump files as a combo file. The format of these
  files should be user:id:lm:ntlm. We look for ':::' at the end of the first line
  to determine if the file contains PwDump output. In addition, a LM/NTLM hash
  pair can be supplied in lieu of a password (e.g. host:user:lm:ntlm).
*/
int processComboFile(sAudit **_psAudit)
{
  int ret = 0, iColonCount = 0;
  char *pComboTmp;

  writeError(ERR_DEBUG, "[processComboFile] Processing user supplied combo file.");

  pComboTmp = (*_psAudit)->pGlobalCombo;

  /* PwDump file check */
  /* USERNAME:ID:LM HASH:NTLM HASH::: */
  writeError(ERR_DEBUG, "[processComboFile] PwDump file check.");
  while (*pComboTmp != '\0')
  {
    if (strcmp(pComboTmp, ":::") == 0)
    {
      iColonCount += 3;
      pComboTmp += 3;
    }
    else if (*pComboTmp == ':')
    {
      iColonCount++;
      pComboTmp++;
    }
    else 
    {
      pComboTmp++;
    }

    if ((iColonCount == 6) && (*pComboTmp == '\0')) {
      writeError(ERR_DEBUG, "[processComboFile] Combo format scan detected PwDump file.");

      if (((*_psAudit)->HostType != L_SINGLE) && ((*_psAudit)->HostType != L_FILE))
      {
        writeError(ERR_FATAL, "Combo format used requires host information via (-h/-H).");
      }

      if (((*_psAudit)->UserType != L_SINGLE) && ((*_psAudit)->UserType != L_FILE))
      {
        (*_psAudit)->UserType = L_PWDUMP;
      }

      (*_psAudit)->PassType = L_PWDUMP;

      return ret;
    }
  }

  if ( ! ((iColonCount == 2) || (iColonCount == 3)) )
  {
    writeError(ERR_DEBUG, "[processComboFile] Number of colons detected in first entry: %d", iColonCount);
    writeError(ERR_FATAL, "Invalid combo file format.");
  }

  pComboTmp = (*_psAudit)->pGlobalCombo;

  if (*pComboTmp == ':')
  {               /* no host specified */
    writeError(ERR_DEBUG, "[processComboFile] No host combo field specified.");
    if (((*_psAudit)->HostType != L_SINGLE) && ((*_psAudit)->HostType != L_FILE))
    {
      writeError(ERR_FATAL, "Combo format used requires host information via (-h/-H).");
    }
  }
  else
  {
    writeError(ERR_DEBUG, "[processComboFile] Host combo field specified.");
    (*_psAudit)->HostType = L_COMBO;

    while (*pComboTmp != ':')
    {
      if (pComboTmp == NULL)
      {
        writeError(ERR_FATAL, "Failed to process combo file. Incorrect format.");
      }

      pComboTmp++;
    }
  }
  pComboTmp++;

  if (*pComboTmp == ':')
  {              /* no user specified */
    writeError(ERR_DEBUG, "[processComboFile] No user combo field specified.");
    if (((*_psAudit)->UserType != L_SINGLE) && ((*_psAudit)->UserType != L_FILE))
    {
      writeError(ERR_FATAL, "Combo format used requires user information via (-u/-U).");
    }
  }
  else
  {
    writeError(ERR_DEBUG, "[processComboFile] User combo field specified.");
    (*_psAudit)->UserType = L_COMBO;

    while (*pComboTmp != ':')
    {
      if (pComboTmp == NULL)
      {
        writeError(ERR_FATAL, "Failed to process combo file. Incorrect format.");
      }

      pComboTmp++;
    }
  }
  pComboTmp++;

  if (*pComboTmp == '\0')
  {             /* no password specified */
    writeError(ERR_DEBUG, "[processComboFile] No password combo field specified.");
    if (((*_psAudit)->PassType != L_SINGLE) && ((*_psAudit)->PassType != L_FILE) && 
        ((*_psAudit)->iPasswordBlankFlag == FALSE) && ((*_psAudit)->iPasswordUsernameFlag == FALSE))
    {
      writeError(ERR_FATAL, "Combo format used requires password information via (-p/-P).");
    }
  }
  else
  {
    writeError(ERR_DEBUG, "[processComboFile] Password combo field specified.");
    (*_psAudit)->PassType = L_COMBO;
  }

  return ret;
}


/*
  Return next user-specified host during audit data table building process.
  This host information may be a single global entry, from a file containing
  a list of hosts, or from a combo file.
*/
char* findNextHost(sAudit *_psAudit, char *_pHost)
{

  if (_psAudit->pGlobalCombo)
  {
    writeError(ERR_DEBUG, "[findNextHost] Process global combo file.");
    /* advance to next entry in combo list */
    if ((_psAudit->iUserListFlag == LIST_COMPLETE) && (_psAudit->iHostListFlag == LIST_COMPLETE))
    {
      writeError(ERR_DEBUG, "[findNextHost] Advance to next entry in combo list.");
      /* skip host */
      while (*_psAudit->pGlobalCombo != '\0')
        _psAudit->pGlobalCombo++;
      _psAudit->pGlobalCombo++;

      /* skip user */
      while (*_psAudit->pGlobalCombo != '\0')
        _psAudit->pGlobalCombo++;
      _psAudit->pGlobalCombo++;

      /* skip pass */
      while (*_psAudit->pGlobalCombo != '\0')
        _psAudit->pGlobalCombo++;
      _psAudit->pGlobalCombo++;

      if (*_psAudit->pGlobalCombo == '\0')
      {
        _psAudit->iAuditFlag = AUDIT_COMPLETE;
      }
      else
      {
        _psAudit->iAuditFlag = AUDIT_IN_PROGRESS;
      }
    }

    /* convert ':' to '\0' in combo entries */
    if ((_psAudit->pComboEntryTmp == NULL) || ((_psAudit->iUserListFlag == LIST_COMPLETE) && (_psAudit->iHostListFlag == LIST_COMPLETE)))
    {
      writeError(ERR_DEBUG, "[findNextHost] Convert ':' to '\\0' in combo entries.");
      _psAudit->pComboEntryTmp = _psAudit->pGlobalCombo;

      if (*_psAudit->pComboEntryTmp != '\0')
      {
        /* host:user ==> host\0user */
        while (*_psAudit->pComboEntryTmp != ':')
          _psAudit->pComboEntryTmp++;
        memset(_psAudit->pComboEntryTmp, 0, 1);

        /* user:pass ==> user\0pass */
        while (*_psAudit->pComboEntryTmp != ':')
          _psAudit->pComboEntryTmp++;
        memset(_psAudit->pComboEntryTmp, 0, 1);
      }
    }

    _psAudit->pComboEntryTmp = _psAudit->pGlobalCombo;
  }
  else
  {
    if ((_psAudit->iUserListFlag == LIST_COMPLETE) && (_psAudit->iHostListFlag == LIST_COMPLETE))
    {
      _psAudit->iAuditFlag = AUDIT_COMPLETE;
    }
  }

  _psAudit->iHostListFlag = LIST_COMPLETE;

  if (_psAudit->iAuditFlag == AUDIT_COMPLETE)
  {
    _pHost = NULL;
  }
  else if (_psAudit->HostType == L_COMBO)
  {
    if (*_psAudit->pGlobalCombo == '\0')
    {
      _pHost = NULL;
    }
    else
    {
      _pHost = _psAudit->pGlobalCombo;
    }
  }
  else if (_psAudit->HostType == L_FILE)
  {
    if (*_psAudit->pGlobalHost != '\0')
    {
      _pHost = _psAudit->pGlobalHost;

      /* advancing host list */
      while (*_psAudit->pGlobalHost != '\0')
        _psAudit->pGlobalHost++;
      _psAudit->pGlobalHost++;

      if (*_psAudit->pGlobalHost != '\0')
      {
        _psAudit->iHostListFlag = LIST_IN_PROGRESS;
      }
      else
      {
        /* resetting host list */
        _psAudit->pGlobalHost = _psAudit->pHostFile;
      }
    }
  }
  else if (_psAudit->HostType == L_SINGLE)
  {
    _pHost = _psAudit->pGlobalHost;
    _psAudit->iAuditFlag = AUDIT_COMPLETE;
  }
  else
  {
    writeError(ERR_FATAL, "[findNextHost] HostType not properly defined.");
  }

  return _pHost;
}


/*
  Return next user-specified user during audit data table building process.
  This host information may be a single global entry, from a file containing
  a list of users, or from a combo file.
*/
char* findNextUser(sAudit *_psAudit, char *_pUser)
{
  char* pComboTmp;

  _psAudit->iUserListFlag = LIST_COMPLETE;

  if (_psAudit->UserType == L_COMBO)
  {
    /* advance to username */
    if (_psAudit->pGlobalCombo)
    {
      pComboTmp = _psAudit->pComboEntryTmp;
      while (*pComboTmp != '\0')
        pComboTmp++;
      pComboTmp++;
    }

    if (_pUser != NULL)
      _pUser = NULL;
    else
      _pUser = pComboTmp;

    writeError(ERR_DEBUG, "[findNextUser] Combo User: %s", _pUser);
  }
  else if (_psAudit->UserType == L_PWDUMP)
  {
    if (_pUser != NULL)
      _pUser = NULL;
    else
      _pUser = _psAudit->pComboEntryTmp;

    writeError(ERR_DEBUG, "[findNextUser] PwDump User: %s", _pUser);
  }
  else if (_psAudit->UserType == L_FILE)
  {
    _pUser = _psAudit->pGlobalUser;

    if (*_psAudit->pGlobalUser != '\0')
    {
      /* advance user list pointer */
      while (*_psAudit->pGlobalUser != '\0')
        _psAudit->pGlobalUser++;
      _psAudit->pGlobalUser++;

      _psAudit->iUserListFlag = LIST_IN_PROGRESS;
    }
    else
    {
      /* reset list */
      _psAudit->pGlobalUser = _psAudit->pUserFile;
      _pUser = NULL;
    }

    writeError(ERR_DEBUG, "[findNextUser] L_FILE User: %s", _pUser);
  }
  else if (_psAudit->UserType == L_SINGLE)
  {
    if (_pUser != NULL)
      _pUser = NULL;
    else
      _pUser = _psAudit->pGlobalUser;
  }
  else
  {
    writeError(ERR_FATAL, "[findNextUser] UserType (%d) not properly defined.", _psAudit->UserType);
  }

  return _pUser;
}

/*
  Return next user-specified password during audit data table building process.
  This password information is only from the combo file.
*/
char* findLocalPass(sAudit *_psAudit)
{
  char *pPass;
  char *pComboTmp;

  if ((_psAudit->PassType == L_COMBO) || (_psAudit->PassType == L_PWDUMP))
  {
    /* advance to password */
    if (_psAudit->pGlobalCombo)
    {
      pComboTmp = _psAudit->pComboEntryTmp;

      while (*pComboTmp != '\0')
        pComboTmp++;
      pComboTmp++;

      while (*pComboTmp != '\0')
        pComboTmp++;
      pComboTmp++;
    }

    pPass = pComboTmp;
    writeError(ERR_DEBUG, "[findLocalPass] pPass: %s", pPass);
  }
  else
  {
    pPass = NULL;
  }

  return pPass;
}

int loadLoginInfo(sAudit *_psAudit)
{
  sHost *psHost = NULL;
  sHost *psHostPrevTmp = NULL;
  char *pHost = NULL;

  sUser *psUser = NULL;
  char *pUser = NULL;

  sPass *psPass = NULL;
  char *pPass = NULL;

  /* initialize / reset */
  _psAudit->iHostCnt = 0;
  _psAudit->iHostsDone = 0;

  while ((pHost = findNextHost(_psAudit, pHost)))
  {
    /* combo file: search list to see if host has already been added */
    psHost = _psAudit->psHostRoot;
    while (psHost)
    {
      if ( strcmp(pHost,psHost->pHost) )
        psHost = psHost->psHostNext;
      else
        break;
    }

    /* create new host table in list */
    if (psHost == NULL)
    {
      _psAudit->iHostCnt++;
      psHost = malloc(sizeof(sHost));
      memset(psHost, 0, sizeof(sHost));

      /* set root pointer if this is the first host */
      if (_psAudit->psHostRoot == NULL)
      {
        _psAudit->psHostRoot = psHost;
        psHostPrevTmp = _psAudit->psHostRoot;
      }
      else
      {
        psHostPrevTmp->psHostNext = psHost;
        psHostPrevTmp = psHost;
      }

      psHost->pHost = strdup(pHost);
      psHost->iPortOverride = _psAudit->iPortOverride;
      psHost->iUseSSL = _psAudit->iUseSSL;
      psHost->iTimeout = _psAudit->iTimeout;
      psHost->iRetryWait = _psAudit->iRetryWait;
      psHost->iRetries = _psAudit->iRetries;
      psHost->iUserCnt = 0;
      psHost->iId = _psAudit->iHostCnt; 
    }

    while ((pUser = findNextUser(_psAudit, pUser)))
    {
      /* combo file: search list to see if user has already been added */
      psUser = psHost->psUser;
      while (psUser)
      {
        if ( strcmp(pUser,psUser->pUser) )
          psUser = psUser->psUserNext;
        else
          break;
      }

      /* create new user table in list */
      if (psUser == NULL)
      {
        psHost->iUserCnt++;
        psUser = malloc(sizeof(sUser));
        memset(psUser, 0, sizeof(sUser));

        if (psHost->psUserPrevTmp)
        {
          /* setting host next user pointer */
          psHost->psUserPrevTmp->psUserNext = psUser;
        }
        else
        {
          /* setting host root user pointer */
          psHost->psUser = psUser;
        }

        psHost->psUserPrevTmp = psUser;

        psUser->pUser = strdup(pUser);
        psUser->iPassCnt = _psAudit->iPassCnt;
        psUser->iPassStatus = PL_UNSET;
        psUser->iId = psHost->iUserCnt;
        psHost->iUserPassCnt += _psAudit->iPassCnt;

        if (_psAudit->iPasswordUsernameFlag) {
          psHost->iUserPassCnt++;
          psUser->iPassCnt++;
        }

        if (_psAudit->iPasswordBlankFlag) {
          psHost->iUserPassCnt++;
          psUser->iPassCnt++;
        }
      }

      pPass = findLocalPass(_psAudit);
      if (pPass)
      {
        psPass = malloc(sizeof(sPass));
        memset(psPass, 0, sizeof(sPass));
        psPass->pPass = strdup(pPass);
        psUser->iPassCnt++;
        psHost->iUserPassCnt++;

        if (psUser->psPassPrevTmp)
        {
          /* setting user next pass pointer */
          psUser->psPassPrevTmp->psPassNext = psPass;
        }
        else
        {
          /* setting user root pass pointer */
          psUser->psPass = psPass;
          psUser->psPassCurrent = psPass;
        }

        psUser->psPassPrevTmp = psPass;
      }
    }
  }

  return SUCCESS;
}


/*
  Grab the next password for a particular user
*/
char* getNextPass(sLogin *_psLogin)
{
  sAudit *_psAudit = _psLogin->psServer->psAudit;
  sUser *_psUser = _psLogin->psUser;
  char *pPass = NULL;

  /* is this user's password list complete? */
  if ((_psUser->iPassStatus != PL_DONE) && (_psUser->iPassStatus != PASS_AUDIT_COMPLETE))
  {
    /* is this the user's first password request? */
    if (_psUser->iPassStatus == PL_UNSET)
      _psUser->iPassStatus = PL_NULL;

    /* process blank password or password matching username */ 
    if ((_psUser->iPassStatus == PL_NULL) || (_psUser->iPassStatus == PL_USERNAME))
    {
      if ((_psUser->iPassStatus == PL_NULL) && (_psAudit->iPasswordBlankFlag))
      {
        pPass = "";
        _psUser->iPassStatus = PL_USERNAME;
      }
      else if (_psAudit->iPasswordUsernameFlag)
      {
        pPass = _psUser->pUser;
        _psUser->iPassStatus = PL_LOCAL;
      }
      else
      {
        _psUser->iPassStatus = PL_LOCAL;
      }
    }

    if (pPass == NULL )
    {
      /* process local passwords - i.e. passwords specified within combo file for user */
      if ((_psUser->iPassStatus == PL_LOCAL) && (_psUser->psPassCurrent))
      {
        pPass = _psUser->psPassCurrent->pPass;
        _psUser->psPassCurrent = _psUser->psPassCurrent->psPassNext;
      }
      /* process global passwords - i.e. passwords specified via "-p" or "-P" options */
      else if (_psAudit->pGlobalPass)
      {
        _psUser->iPassStatus = PL_GLOBAL;

        if (_psUser->pPass)
        {
          while (*_psUser->pPass != '\0')
            _psUser->pPass++;
          _psUser->pPass++;

          if (*_psUser->pPass != '\0')
          {
            pPass = _psUser->pPass;
          }
          else
          {
            /* password auditing of host is complete */
            _psUser->iPassStatus = PL_DONE;
            _psLogin->psServer->psHost->iUsersDone++;
          }
        }
        else
        {
          _psUser->pPass = _psAudit->pGlobalPass;
          pPass = _psUser->pPass;
        }
      }
      else
      {
         /* password auditing of host is complete */
        _psUser->iPassStatus = PL_DONE;
        _psLogin->psServer->psHost->iUsersDone++;
      }
    }
  }

  return pPass;
}


/* 
  Generates the next credential set for login module to test. The module is
  responsible for allocating and releasing memory used for the credential set.
*/
int getNextNormalCredSet(sLogin *_psLogin, sCredentialSet *_psCredSet)
{
  int nUserListChecked = FALSE;

  _psCredSet->iStatus = CREDENTIAL_SAME_USER;

  /* is this the first user for a login thread? */
  if (_psLogin->psUser == NULL)
  {
    writeError(ERR_DEBUG, "[getNextNormalCred] Initial credential set request for login module.");

    _psLogin->psServer->psHost->iUserStatus = UL_NORMAL;
    _psCredSet->iStatus = CREDENTIAL_NEW_USER;
    
    /* multiple login threads of same user */
    if (_psLogin->psServer->psAudit->iParallelLoginFlag == PARALLEL_LOGINS_PASSWORD)
    {
      if (_psLogin->psServer->psHost->psUserCurrent == NULL)
        _psLogin->psServer->psHost->psUserCurrent = _psLogin->psServer->psHost->psUser;

      _psLogin->psUser = _psLogin->psServer->psHost->psUserCurrent;
      
      if (_psLogin->psUser)
        writeError(ERR_DEBUG, "[getNextNormalCred] (PARALLEL_LOGINS_PASSWORD) setting user: %s", _psLogin->psUser->pUser);
    }
    /* multiple login threads of one unique user per thread */
    else
    {
      /* only increment user pointer if this is not the first module */
      if (_psLogin->psServer->psHost->psUserCurrent == NULL)
      {
        writeError(ERR_DEBUG, "[getNextNormalCred] Assigning initial user for host being tested.");
        _psLogin->psServer->psHost->psUserCurrent = _psLogin->psServer->psHost->psUser;
        _psLogin->psUser = _psLogin->psServer->psHost->psUserCurrent;
        //_psLogin->psServer->psHost->iUserStatus = UL_NORMAL;
      }
      else
      {
        writeError(ERR_DEBUG, "[getNextNormalCred] Assigning next available user for host being tested.");
        _psLogin->psUser = _psLogin->psServer->psHost->psUserCurrent->psUserNext;
        _psLogin->psServer->psHost->psUserCurrent = _psLogin->psUser;
      }

      if (_psLogin->psUser)
        writeError(ERR_DEBUG, "[getNextNormalCred] (PARALLEL_LOGINS_USER) setting NEW user: %s", _psLogin->psUser->pUser);
    }
  }

  /* find next available password - if password list is exhausted for user, move on to the next user */
  while ((_psLogin->psUser) && ((_psCredSet->pPass = getNextPass(_psLogin)) == NULL))
  {
    /* is password testing for user complete */
    if ((_psLogin->psUser->iPassStatus == PL_DONE) || (_psLogin->psUser->iPassStatus == PASS_AUDIT_COMPLETE))
    {
      writeError(ERR_INFO, "Login Module: %d - Current user password list is complete, selecting next user.", _psLogin->iId);  
    
      if (_psLogin->psServer->psHost->psUserCurrent == NULL)
      {
        _psLogin->psUser = NULL;
      }
      /* if another thread has already selected the next user, process that user */
      else if ((_psLogin->psServer->psHost->psUserCurrent->iPassStatus != PL_DONE) && (_psLogin->psServer->psHost->psUserCurrent->iPassStatus != PASS_AUDIT_COMPLETE))
      {
        _psLogin->psUser = _psLogin->psServer->psHost->psUserCurrent;
      }
      else
      {
        _psLogin->psUser = _psLogin->psServer->psHost->psUserCurrent->psUserNext;
        _psLogin->psServer->psHost->psUserCurrent = _psLogin->psUser;
      }

      if (_psLogin->psUser == NULL)
      {
        /* end of list - check entire list for unfinished credentials */
        if (nUserListChecked == FALSE)
        { 
          writeError(ERR_INFO, "Login Module: %d - Current user password list is complete, rescanning userlist for unfinished credentials.", _psLogin->iId);  
          _psLogin->psUser = _psLogin->psServer->psHost->psUser;
          _psLogin->psServer->psHost->psUserCurrent = _psLogin->psUser;
          nUserListChecked = TRUE;
        }
        else
        {
          writeError(ERR_INFO, "Login Module: %d - No more user accounts available for testing.", _psLogin->iId);  
          _psCredSet->iStatus = CREDENTIAL_DONE;
        }
      }
      else
      {
        writeError(ERR_INFO, "Login Module: %d - Selecting next password for user: %s", _psLogin->iId, _psLogin->psUser->pUser);  
        _psCredSet->iStatus = CREDENTIAL_NEW_USER;
      }
    }
  }

  if ((_psLogin->psUser == NULL) || (_psCredSet->pPass == NULL))
  {
    //writeError(ERR_INFO, "Login Module: %d - No more available users/passwords, setting credential status to CREDENTIAL_DONE.", _psLogin->iId);
    writeError(ERR_INFO, "Login Module: %d - No more users/passwords available in the normal queue.", _psLogin->iId);
    //_psCredSet->iStatus = CREDENTIAL_DONE;
    _psLogin->psServer->psHost->iUserStatus = UL_MISSED;
  }

  _psCredSet->psUser = _psLogin->psUser;

  return SUCCESS;
}

/*
  In certain situations we need to scale back the number of concurrent
  login threads targetting a specific service. For example, MSDE's workload
  governor limits the service to no more than 5 concurrent connections. If
  the user kicked-off 10 parallel login threads, 5 of those are going to
  fail and terminate. The challenge is that each of those threads was 
  already assigned a credential set to test.

  The addMissedCredSet() function creates a linked list of credentials
  which were not tested for a given host. This function retrieves the
  next credential set from that list for testing.
*/
int getNextMissedCredSet(sLogin *_psLogin, sCredentialSet *_psCredSet)
{
  sCredentialSet *psCredSetMissed = NULL;

  writeError(ERR_DEBUG, "Retrieving the next available credential set from list of previously missed sets.");

  /* skip credential if user testing is complete (e.g. password found, account locked) */
  psCredSetMissed = _psLogin->psServer->psCredentialSetMissedCurrent;
  while ((psCredSetMissed) && (psCredSetMissed->psUser->iPassStatus == PASS_AUDIT_COMPLETE))
  {
    psCredSetMissed = _psLogin->psServer->psCredentialSetMissedCurrent->psCredentialSetNext; 
    _psLogin->psServer->psCredentialSetMissedCurrent = psCredSetMissed;
  }

  /* located next credential set that was not previously tested */
  if (psCredSetMissed)
  {
    _psCredSet->psUser = psCredSetMissed->psUser;
    _psCredSet->pPass = psCredSetMissed->pPass;
    _psLogin->psServer->psCredentialSetMissedCurrent = psCredSetMissed->psCredentialSetNext; 
    
    if (_psLogin->psUser == _psCredSet->psUser)
      _psCredSet->iStatus = CREDENTIAL_SAME_USER;
    else
      _psCredSet->iStatus = CREDENTIAL_NEW_USER;

    _psLogin->psServer->iCredentialsMissed--;

    writeError(ERR_DEBUG, "Login Module: %d - Selected next credential set from list of previously missed sets (%s/%s).", _psLogin->iId, _psCredSet->psUser->pUser, _psCredSet->pPass);
  }
  else
  {
    writeError(ERR_INFO, "Login Module: %d - No additional missed users/passwords, setting credential status to CREDENTIAL_DONE.", _psLogin->iId);
    _psCredSet->iStatus = CREDENTIAL_DONE;
    _psLogin->psServer->psHost->iUserStatus = UL_DONE;
  }
    
  _psLogin->psUser = _psCredSet->psUser;

  return SUCCESS;
}

/*
  Function returns next available username and password to module for testing.
  The normal host's list of users and their respective passwords (local, global, etc)
  are tested first. If any credential sets were not successfully tested (module
  instance died for some reason) they re-checked after all normal tests are done. 
*/
int getNextCredSet(sLogin *_psLogin, sCredentialSet *_psCredSet)
{
  if (_psCredSet == NULL)
    writeError(ERR_FATAL, "getNextCredSet() called, but not supplied allocated memory for _psCredSet");
  
  memset(_psCredSet, 0, sizeof(sCredentialSet));
  pthread_mutex_lock(&_psLogin->psServer->ptmMutex);
 
  /* terminate all login threads */
  if (_psLogin->psServer->psAudit->iStatus == AUDIT_ABORT)
  {
    writeError(ERR_INFO, "Audit aborting... notifying login module: %d", _psLogin->iId);
    _psCredSet->iStatus = CREDENTIAL_DONE;
  } 
  /* valid credential set found -- exit host flag set */
  else if ((_psLogin->psServer->iValidPairFound) && (_psLogin->psServer->psAudit->iFoundPairExitFlag == FOUND_PAIR_EXIT_HOST))
  {
    writeError(ERR_INFO, "Exiting Login Module: %d [Stop Host Scan After Valid Pair Found Enabled]", _psLogin->iId);
    _psCredSet->iStatus = CREDENTIAL_DONE;
  }
  /* valid credential set found -- exit audit flag set */
  else if ((_psLogin->psServer->psAudit->iValidPairFound) && (_psLogin->psServer->psAudit->iFoundPairExitFlag == FOUND_PAIR_EXIT_AUDIT))
  {
    writeError(ERR_INFO, "Exiting Login Module: %d [Stop Audit Scans After Valid Pair Found Enabled]", _psLogin->iId);
    _psCredSet->iStatus = CREDENTIAL_DONE;
  }
  else
  {
    switch (_psLogin->psServer->psHost->iUserStatus)
    {
      case UL_UNSET:
      case UL_NORMAL:
        /* check for next available login to perform */
        if (getNextNormalCredSet(_psLogin, _psCredSet) != SUCCESS)
          writeError(ERR_FATAL, "getNextNormalCredSet() function call failed.");

        /* the normal queue is exhausted - check the missed credentials queue */
        if (_psLogin->psServer->psHost->iUserStatus == UL_MISSED)
          if (getNextMissedCredSet(_psLogin, _psCredSet) != SUCCESS)
            writeError(ERR_FATAL, "getNextMissedCredSet() function call failed.");
        
        break;
      case UL_MISSED:
        /* check for next available login missed during normal testing */
        if (getNextMissedCredSet(_psLogin, _psCredSet) != SUCCESS)
          writeError(ERR_FATAL, "getNextMissedCredSet() function call failed.");
        break;
      case UL_DONE:
        writeError(ERR_INFO, "Login Module: %d - No additional users/passwords, setting credential status to CREDENTIAL_DONE.", _psLogin->iId);
        _psCredSet->iStatus = CREDENTIAL_DONE;
        break;
      default:
        writeError(ERR_DEBUG, "Login Module: %d - Entered undefined state (%d) within getNextCredSet()", _psLogin->iId, _psLogin->psServer->psHost->iUserStatus);
        break;
    }
  }
 
  pthread_mutex_unlock(&_psLogin->psServer->ptmMutex);
  
  return SUCCESS;
}

/*
  Process password result from login module
*/
void setPassResult(sLogin *_psLogin, char *_pPass)
{
  pthread_mutex_lock(&_psLogin->psServer->ptmMutex);

  writeVerbose(VB_CHECK,
               "[%s] Host: %s (%d of %d, %d complete) User: %s (%d of %d, %d complete) Password: %s (%d of %d complete)",
               _psLogin->psServer->psAudit->pModuleName,
               _psLogin->psServer->psHost->pHost,
               _psLogin->psServer->psHost->iId,
               _psLogin->psServer->psAudit->iHostCnt,
               _psLogin->psServer->psAudit->iHostsDone,
               _psLogin->psUser->pUser,
               _psLogin->psUser->iId,
               _psLogin->psServer->psHost->iUserCnt,
               _psLogin->psServer->psHost->iUsersDone,
               _pPass,
               _psLogin->psUser->iLoginsDone + 1,
               _psLogin->psUser->iPassCnt
              );

  _psLogin->iLoginsDone++;
  _psLogin->psUser->iLoginsDone++,
  _psLogin->psServer->iLoginsDone++;

  switch (_psLogin->iResult)
  {
  case LOGIN_RESULT_SUCCESS:
    if (_psLogin->pErrorMsg) {
      writeVerbose(VB_FOUND, "[%s] Host: %s User: %s Password: %s [SUCCESS (%s)]", _psLogin->psServer->psAudit->pModuleName, _psLogin->psServer->psHost->pHost, _psLogin->psUser->pUser, _pPass, _psLogin->pErrorMsg);
      free(_psLogin->pErrorMsg);
      _psLogin->pErrorMsg = NULL;
    }
    else
      writeVerbose(VB_FOUND, "[%s] Host: %s User: %s Password: %s [SUCCESS]", _psLogin->psServer->psAudit->pModuleName, _psLogin->psServer->psHost->pHost, _psLogin->psUser->pUser, _pPass);
    
    _psLogin->psServer->psAudit->iValidPairFound = TRUE;
    _psLogin->psServer->iValidPairFound = TRUE;
    _psLogin->psUser->iPassStatus = PASS_AUDIT_COMPLETE;
    _psLogin->psServer->psHost->iUsersDone++;
    break;
  case LOGIN_RESULT_FAIL:
    if (_psLogin->pErrorMsg) {
      writeError(ERR_INFO, "[%s] Host: %s User: %s [FAILED (%s)]", _psLogin->psServer->psAudit->pModuleName, _psLogin->psServer->psHost->pHost, _psLogin->psUser->pUser, _psLogin->pErrorMsg);
      free(_psLogin->pErrorMsg);
      _psLogin->pErrorMsg = NULL;
    }
    else
      writeError(ERR_INFO, "[%s] Host: %s User: %s [FAILED]", _psLogin->psServer->psAudit->pModuleName, _psLogin->psServer->psHost->pHost, _psLogin->psUser->pUser);
    
    break;
  case LOGIN_RESULT_ERROR:
    if (_psLogin->pErrorMsg) {
      writeVerbose(VB_FOUND, "[%s] Host: %s User: %s Password: %s [ERROR (%s)]", _psLogin->psServer->psAudit->pModuleName, _psLogin->psServer->psHost->pHost, _psLogin->psUser->pUser, _pPass, _psLogin->pErrorMsg);
      free(_psLogin->pErrorMsg);
      _psLogin->pErrorMsg = NULL;
    }
    else
      writeVerbose(VB_FOUND, "[%s] Host: %s User: %s Password: %s [ERROR]", _psLogin->psServer->psAudit->pModuleName, _psLogin->psServer->psHost->pHost, _psLogin->psUser->pUser, _pPass);
    
    _psLogin->psUser->iPassStatus = PASS_AUDIT_COMPLETE;
    _psLogin->psServer->psHost->iUsersDone++;
    break;
  default:
    writeError(ERR_INFO, "[%s] Host: %s User: %s [UNKNOWN %d]", _psLogin->psServer->psAudit->pModuleName, _psLogin->psServer->psHost->pHost, _psLogin->psUser->pUser, _psLogin->iResult);
    break;
  }

  pthread_mutex_unlock(&_psLogin->psServer->ptmMutex);
}


/*
  In certain situations we need to scale back the number of concurrent
  login threads targetting a specific service. For example, MSDE's workload
  governor limits the service to no more than 5 concurrent connections. If
  the user kicked-off 10 parallel login threads, 5 of those are going to
  fail and terminate. The challenge is that each of those threads was 
  already assigned a credential set to test. This function creates a 
  list of those credentials so that they can be tested by the remaining 
  threads at the end of their current run. 
*/
int addMissedCredSet(sLogin *_psLogin, sCredentialSet *_psCredSet)
{
  sCredentialSet *psCredSetMissed = NULL;

  pthread_mutex_lock(&_psLogin->psServer->ptmMutex);

  writeError(ERR_NOTICE, "[%s] Host: %s - Login thread (%d) prematurely ended. The current number of parallel login threads may exceed what this service can reasonably handle. The total number of threads for this host will be decreased.",
               _psLogin->psServer->psAudit->pModuleName,
               _psLogin->psServer->psHost->pHost,
               _psLogin->iId
            );

  if (_psLogin->psServer->iLoginCnt > 1)
    _psLogin->psServer->iLoginCnt--;
  
  writeError(ERR_NOTICE, "[%s] Host: %s User: %s Password: %s - The noted credentials have been added to the end of the queue for testing.",
               _psLogin->psServer->psAudit->pModuleName,
               _psLogin->psServer->psHost->pHost,
               _psCredSet->psUser->pUser,
               _psCredSet->pPass
            );
  
  /* build structure for missed credential set */
  psCredSetMissed = malloc(sizeof(sCredentialSet));
  memset(psCredSetMissed, 0, sizeof(sCredentialSet));
  
  psCredSetMissed->psUser = _psCredSet->psUser;

  psCredSetMissed->pPass = strdup(_psCredSet->pPass);

  /* append structure to host's list of missed credentials */
  if (_psLogin->psServer->psCredentialSetMissed == NULL) /* first missed credential set */
  {
    _psLogin->psServer->psCredentialSetMissed = psCredSetMissed;
    _psLogin->psServer->psCredentialSetMissedCurrent = psCredSetMissed;
  }
  else
    _psLogin->psServer->psCredentialSetMissedTail->psCredentialSetNext = psCredSetMissed;

  _psLogin->psServer->psCredentialSetMissedTail = psCredSetMissed;

  _psLogin->psServer->iCredentialsMissed++;

  pthread_mutex_unlock(&_psLogin->psServer->ptmMutex);

  return SUCCESS;
}


void startModule(void* pParams)
{
  int64_t nRet = 0;
  sModuleStart* modParams = (sModuleStart*)pParams;
  if (NULL == modParams)
  {
    writeError(ERR_FATAL, "Bad pointer passed to invokeModule");
    return;
  }

  writeError(ERR_DEBUG, "startModule iId: %d pLogin: %X modParams->argv: %X modParams: %X", modParams->pLogin->iId, modParams->pLogin, modParams->argv, modParams);
  
  nRet = invokeModule(modParams->szModuleName, modParams->pLogin, modParams->argc, modParams->argv);
  if (nRet < 0)
    writeVerbose(VB_EXIT, "invokeModule failed - see previous errors for an explanation");

  return;
}


/*
  Initiate and manage host-specific thread pool for logins. Each target host
  has a single thread for this purpose. The thread spawns multiple child 
  threads which each initiate the selected module to perform the actual logons.
*/
void startLoginThreadPool(void *arg)
{
  sServer *_psServer = (sServer *)arg;
  thr_pool_t *login_pool = NULL;
  sLogin psLogin[_psServer->psAudit->iLoginCnt];
  sModuleStart modParams[_psServer->psAudit->iLoginCnt];
  int iLoginId = 0;
  int iLoginCnt = _psServer->psAudit->iLoginCnt;
 
  struct addrinfo hints, *res;
  int errcode;
  void *ptr;

  writeError(ERR_DEBUG_SERVER, "Server ID: %d Host: %s iUserPassCnt: %d iLoginCnt: %d", _psServer->iId, _psServer->psHost->pHost, _psServer->psHost->iUserPassCnt, iLoginCnt);
  
  /* create thread pool - min threads, max threads, linger time, attributes */
  if (iLoginCnt > _psServer->psHost->iUserPassCnt)
    iLoginCnt = _psServer->psHost->iUserPassCnt;

  if ((login_pool = thr_pool_create(0, iLoginCnt, POOL_THREAD_LINGER, NULL)) == NULL)
  {
    writeError(ERR_FATAL, "Failed to create root login thread pool for host: %s", _psServer->psHost->pHost);
  }
  
  /* resolve host name */
  _psServer->pHostIP = malloc(100);
  memset(_psServer->pHostIP, 0, 100);

  memset(&hints, 0, sizeof (hints));
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags |= AI_CANONNAME;

  errcode = getaddrinfo(_psServer->psHost->pHost, NULL, &hints, &res);
  if (errcode != 0)
  {
    writeError(ERR_CRITICAL, "Failed to resolve hostname: %s - %s", _psServer->psHost->pHost, gai_strerror(errcode));
    return;
  }

  if (res->ai_next != NULL)
    writeError(ERR_ERROR, "Hostname resolved to multiple addresses. Selecting first address for testing.");

  inet_ntop (res->ai_family, res->ai_addr->sa_data, _psServer->pHostIP, 100);

  switch (res->ai_family)
  {
    case AF_INET:
      ptr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
      break;
    case AF_INET6:
      ptr = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
      break;
  }

  inet_ntop (res->ai_family, ptr, _psServer->pHostIP, 100);
  writeError(ERR_DEBUG_SERVER, "Set IPv%d address: %s (%s)",res->ai_family == PF_INET6 ? 6 : 4, _psServer->pHostIP, res->ai_canonname);
  freeaddrinfo(res);

  /* add login tasks to pool queue */
  for (iLoginId = 0; iLoginId < iLoginCnt; iLoginId++)
  {
    writeError(ERR_DEBUG_SERVER, "Adding new login task (%d) to server queue (%d)", iLoginId, _psServer->iId);

    psLogin[iLoginId].iId = iLoginId;
    psLogin[iLoginId].psServer = _psServer;
    psLogin[iLoginId].iResult = LOGIN_RESULT_UNKNOWN;
    psLogin[iLoginId].pErrorMsg = NULL;
    psLogin[iLoginId].iLoginsDone = 0;
    psLogin[iLoginId].psUser = NULL;

    modParams[iLoginId].szModuleName = szModuleName;
    modParams[iLoginId].pLogin = &(psLogin[iLoginId]); //psLogin + (iLoginId * sizeof(sLogin));
    modParams[iLoginId].argc = nModuleParamCount;
    modParams[iLoginId].argv = (char**)arrModuleParams;

    if ( thr_pool_queue(login_pool, startModule, (void *) &modParams[iLoginId]) < 0 )
    {
      writeError(ERR_CRITICAL, "Failed to add module launch task to login thread pool for server queue: %d.", _psServer->iId);
      return;
    }
  }

  /* wait for login thread pool to finish */
  writeError(ERR_DEBUG_SERVER, "waiting for server %d login pool to end", _psServer->iId);
  thr_pool_wait(login_pool);

  /* 
    In certain situations we need to scale back the number of concurrent
    login threads targetting a specific service. For example, MSDE's workload
    governor limits the service to no more than 5 concurrent connections. If
    the user kicked-off 10 parallel login threads, 5 of those are going to
    fail and terminate. The challenge is that each of those threads was 
    already assigned a credential set to test.

    When these threads failed, we pushed the missed credentials into a queue
    assigned to the target host. This queue may already have been taken care of 
    by running threads when they finished their normal tasks. However, if the 
    missed logons were pushed to the queue by exiting threads after the other
    threads had terminated, they are still sitting there. To deal with this 
    problem, we kick off a single thread to run through these.
  */
  iLoginId = 0;
  if ((_psServer->psAudit->iStatus != AUDIT_ABORT) && (_psServer->iCredentialsMissed > 0))
  {
    writeError(ERR_DEBUG_SERVER, "Adding new clean-up login task to server queue (%d) for %d missed logins", _psServer->iId, _psServer->iCredentialsMissed);
   
    _psServer->psHost->iUserStatus = UL_MISSED; 
    psLogin[iLoginId].iResult = LOGIN_RESULT_UNKNOWN;
    psLogin[iLoginId].pErrorMsg = NULL;
    psLogin[iLoginId].psUser = NULL;

    if ( thr_pool_queue(login_pool, startModule, (void *) &modParams[iLoginId]) < 0 )
    {
      writeError(ERR_CRITICAL, "Failed to add module launch task to login thread pool for server queue: %d.", _psServer->iId);
      return;
    }
  
    /* wait for login thread pool to finish */
    writeError(ERR_DEBUG_SERVER, "waiting for server %d login pool to end", _psServer->iId);
    thr_pool_wait(login_pool);
  }
  
  writeError(ERR_DEBUG_SERVER, "destroying server %d login pool", _psServer->iId);
  thr_pool_destroy(login_pool);

  /* track the number of hosts which have been completed */
  pthread_mutex_lock(&_psServer->psAudit->ptmMutex);
  _psServer->psAudit->iHostsDone++;
  pthread_mutex_unlock(&_psServer->psAudit->ptmMutex);
    
  /* The logon modules for server have all terminated, however, the server's userlist is not marked
     as completed. This may be due to the module exiting prematurely (e.g. the service being tested 
     became unavailable). We mark the host as UL_ERROR to avoid having it added to the resume list.
  */
  if ((_psServer->psAudit->iStatus != AUDIT_ABORT) && ((_psServer->psHost->iUserStatus == UL_NORMAL) || (_psServer->psHost->iUserStatus == UL_MISSED)))
  {
     writeError(ERR_DEBUG_SERVER, "Server thread exiting and server's userlist testing was marked as in progress. Was this host prematurely aborted?");
    _psServer->psHost->iUserStatus = UL_ERROR; 
  }

  writeError(ERR_DEBUG_SERVER, "exiting server: %d", _psServer->iId);

  free(_psServer->pHostIP); 
 
  return;
}


/*
  Initiate and manage thread pool for target systems. Each target host
  will have a single parent thread, which manages all childs login threads
  specific to that individual machine.
*/
int startServerThreadPool(sAudit *_psAudit)
{
  sServer psServer[_psAudit->iHostCnt];
  sHost *psHost;
  int iServerId;

  sUser *psUser;
  char *szResumeMap = NULL;
  char *szUserMap = NULL;
  int nAddHost;
  int nUserMapSize;
  int nFirstNewHostFound;
  int nFirstNewUserFound;
  char szTmp[11];
  char szTmp1[11];
  char szTmp2[11];

  writeVerbose(VB_GENERAL, "Parallel Hosts: %d Parallel Logins: %d", _psAudit->iServerCnt, _psAudit->iLoginCnt);

  writeVerbose(VB_GENERAL, "Total Hosts: %d ", _psAudit->iHostCnt);
  if (_psAudit->iUserCnt == 0) writeVerbose(VB_GENERAL, "Total Users: [combo]");
  else writeVerbose(VB_GENERAL, "Total Users: %d", _psAudit->iUserCnt);
  if (_psAudit->iPassCnt == 0) writeVerbose(VB_GENERAL, "Total Passwords: [combo]");
  else writeVerbose(VB_GENERAL, "Total Passwords: %d", _psAudit->iPassCnt);

  /* create thread pool - min threads, max threads, linger time, attributes */
  if (_psAudit->iServerCnt > _psAudit->iHostCnt)
    _psAudit->iServerCnt = _psAudit->iHostCnt;

  /* initialize global crypto (OpenSSL, Libgcrypt) variables */
  init_crypto_locks();

  if ((_psAudit->server_pool = thr_pool_create(0, _psAudit->iServerCnt, POOL_THREAD_LINGER, NULL)) == NULL)
  {
    writeError(ERR_ERROR, "Failed to create root server thread pool.");
    return FAILURE;
  }

  /* initialize servers */
  memset(psServer, 0, sizeof(sServer) * _psAudit->iHostCnt);
  psHost = _psAudit->psHostRoot;

  nFirstNewHostFound = FALSE;

  /* add server tasks to pool queue (one task per host to be tested) */
  for (iServerId = 0; iServerId < _psAudit->iHostCnt; iServerId++)
  {
    /* resume map was supplied by user - skip hosts and users which were previously completed */
    nAddHost = TRUE;
    if (_psAudit->pOptResume)
    {
      memset(szTmp, 0, 11);
      memset(szTmp1, 0, 11);
      snprintf(szTmp, 10, "h%d.", psHost->iId);
      snprintf(szTmp1, 10, "h%du", psHost->iId);

      if (nFirstNewHostFound == TRUE)
      {    
        writeError(ERR_DEBUG_SERVER, "[Host Resume] Adding host: %d (we've passed the point of the previous run)", psHost->iId);
      }
      else if ((szResumeMap = strstr(_psAudit->pOptResume, szTmp1)))
      {
        writeError(ERR_DEBUG_SERVER, "[Host Resume] Adding host: %d (host was located in resume map)", psHost->iId);

        /* extract host's user resume map */
        if (index(szResumeMap + 1, 0x68))
          nUserMapSize = index(szResumeMap + 1, 0x68) - szResumeMap; /* calculate length of host resume map from start to the next "h" */
        else if (index(szResumeMap + 1, 0x2e))
          nUserMapSize = index(szResumeMap + 1, 0x2e) - szResumeMap; /* calculate length of host resume map from start to the terminating "." */
        else
          nUserMapSize = strlen(szResumeMap); /* single, or last, host resume */ 

        if (nUserMapSize < 4)
          writeError(ERR_FATAL, "Error extacting user resume map for host: %d", psHost->iId);

        szUserMap = malloc(nUserMapSize + 1);
        memset(szUserMap, 0, nUserMapSize + 1);
        strncpy(szUserMap, szResumeMap, nUserMapSize);
        writeError(ERR_DEBUG_SERVER, "[Host Resume] Host: %d - Processing host's user resume map: %s", psHost->iId, szUserMap);

        /* examine each user for the host and mark previously tested accounts as completed */
        nFirstNewUserFound = FALSE;
        psUser = psHost->psUser;
        while (psUser)
        {
          memset(szTmp, 0, 11);
          memset(szTmp1, 0, 11);
          snprintf(szTmp, 10, "u%du", psUser->iId);
          snprintf(szTmp1, 10, "u%dh", psUser->iId);
          snprintf(szTmp2, 10, "u%d.", psUser->iId);

          if (nFirstNewUserFound == TRUE)
          {
            writeError(ERR_DEBUG_SERVER, "[User Resume] Adding user: %d (we've passed the point of the previous run)", psUser->iId);
          }
          else if (strstr(szResumeMap, szTmp))
          {
            writeError(ERR_DEBUG_SERVER, "[User Resume] Adding user: %d (user was located in resume map)", psUser->iId);
          }
          else if ((strstr(szResumeMap, szTmp1)) || (strstr(szResumeMap, szTmp2)))
          {
            writeError(ERR_DEBUG_SERVER, "[User Resume] Adding user: %d (user was located in resume map and identified as first untouched account)", psUser->iId);
            nFirstNewUserFound = TRUE;
          }
          else
          {
            writeError(ERR_DEBUG_SERVER, "[User Resume] Skipping user: %d (user has already been tested)", psUser->iId);
            psUser->iPassStatus = PL_DONE;
          }

          psUser = psUser->psUserNext;
        }
      }
      else if (strstr(_psAudit->pOptResume, szTmp))
      {
        writeError(ERR_DEBUG_SERVER, "[Host Resume] Adding host: %d (host was located in resume map and identified as first untouched system)", psHost->iId);
        nFirstNewHostFound = TRUE;
      }
      else
      {
        writeError(ERR_DEBUG_SERVER, "[Host Resume] Skipping host: %d (host has already been tested)", psHost->iId);
        nAddHost = FALSE;
        psHost->iUserStatus = UL_DONE;
      }
    }

    if (nAddHost)
    {
      writeError(ERR_DEBUG_AUDIT, "adding new server (%d) to queue", iServerId);
      
      if (pthread_mutex_init(&(psServer[iServerId].ptmMutex), NULL) != 0)
        writeError(ERR_FATAL, "Server (%d) mutex initialization failed - %s\n", iServerId, strerror( errno ) );

      psServer[iServerId].psAudit = _psAudit;
      psServer[iServerId].iId = iServerId;
      psServer[iServerId].psHost = psHost;
      psServer[iServerId].iLoginCnt = _psAudit->iLoginCnt;
      psServer[iServerId].iLoginsDone = 0;
      psServer[iServerId].iCredentialsMissed = 0;
    
      if ( thr_pool_queue(_psAudit->server_pool, startLoginThreadPool, (void *) &psServer[iServerId]) < 0 )
      {
        writeError(ERR_ERROR, "Failed to add host task to server thread pool.");
        return FAILURE;
      }
    }

    psHost = psHost->psHostNext;
  }

  /* wait for thread pool to finish */
  writeError(ERR_DEBUG_AUDIT, "waiting for server pool to end");
  thr_pool_wait(_psAudit->server_pool);
  writeError(ERR_DEBUG_AUDIT, "destroying server pool");
  thr_pool_destroy(_psAudit->server_pool);
  
  /* destroy and clean-up server objects */
  for (iServerId = 0; iServerId < _psAudit->iHostCnt; iServerId++)
  {
    if (pthread_mutex_init(&(psServer[iServerId].ptmMutex), NULL) != 0)
      writeError(ERR_FATAL, "Server (%d) mutex destroy call failed - %s\n", iServerId, strerror( errno ) );
  }
  
  kill_crypto_locks();

  return SUCCESS;
} 

/*
  Function called on SIGINT. We process the host and user tables and generate
  a map representing their current state. This map can then be supplied to
  Medusa to essentially resume the run. It should be noted, however, that users 
  which were partially tested will be resumed from the start of their password
  list.
*/
void sigint_handler(int sig __attribute__((unused)))
{
  sHost *psHost;
  sUser *psUser;
  char szTmp[10+1]; // we can only resume h + 7 + . + \0, so 7 digits... 9,999,999 (should be enough) hosts
  char *szResumeMap = NULL;
  int nResumeMapSize = 0;
  int nItemByteSize = 0;
  struct sigaction sig_action;
 
  /* SIGINT is blocked by default within the handler. We explicitly unblock it here.
     This allows us to hit CTRL-C a second time and really quit the application 
     without waiting for the threads to complete their work.
  */
  sig_action.sa_flags = 0;
  sigemptyset(&sig_action.sa_mask);
  sigaddset(&sig_action.sa_mask, SIGINT);
  sig_action.sa_handler = SIG_DFL;
  sigaction(SIGINT, &sig_action, 0);
  sigprocmask(SIG_UNBLOCK, &sig_action.sa_mask, 0);

  /* notify threads that they should be exiting and then wait for them to finish */
  writeError(ERR_ALERT, "Medusa received SIGINT - Sending notification to login threads that we are aborting.");
  psAudit->iStatus = AUDIT_ABORT; 

  writeError(ERR_INFO, "Waiting for login threads to terminate...");
  thr_pool_wait(psAudit->server_pool);

  /*
    We note each partially finished host and the first new host for which
    testing has not started. We do the same for each partially completed
    host's user list. The number of partially completed hosts likely 
    matches the number of parallel hosts being tested (T). The number of
    partially completed users for a given host likely matches the number
    of parallel logins being performed (t). This results in us reporting
    T(t + 1) + 1 items. Let's assume each item will require X bytes to 
    report, which leads us to X(Tt + T + 1) bytes needed.

    Example: h6u1u2h7u3u4h8.
             +---------------- First host which was not 100% completed
               +-------------- First user for host which was not 100% completed
                 +------------ First user for host which was not started
                         +---- First host which was not started
  */

  /* base our byte count on the largest number we may need to record - ex: h1236\0 */
  if (psAudit->iHostCnt > psAudit->iUserCnt)
    nItemByteSize = 1 + (int)log10(psAudit->iHostCnt) + 1;
  else  
    nItemByteSize = 1 + (int)log10(psAudit->iUserCnt) + 1;
 
  nResumeMapSize = nItemByteSize * (psAudit->iServerCnt * psAudit->iLoginCnt + psAudit->iServerCnt + 1) + 1; /* include terminating "." */
  szResumeMap = malloc(nResumeMapSize + 1);
  memset(szResumeMap, 0, nResumeMapSize + 1);
  memset(szTmp, 0, 10 + 1);

  psHost = psAudit->psHostRoot;
  while ((psHost) && (psHost->iUserStatus != UL_UNSET))
  {
    /* identify the hosts which are not 100% complete */
    if ((psHost->iUserStatus != UL_DONE) && (psHost->iUserStatus != UL_ERROR))
    {
      writeError(ERR_DEBUG, "Incomplete Host: %d", psHost->iId);
      memset(szTmp, 0, 10 + 1);
      snprintf(szTmp, 10, "h%d", psHost->iId);
      strncat(szResumeMap, szTmp, 10);

      /* identify the users which are not 100% complete for specific host */
      psUser = psHost->psUser;
      while ((psUser) && (psUser->iPassStatus != PL_UNSET))
      {
        if ((psUser->iPassStatus == PL_DONE) || (psUser->iPassStatus == PASS_AUDIT_COMPLETE))
          writeError(ERR_DEBUG, "Complete User: %d", psUser->iId);
        else 
        {    
          writeError(ERR_DEBUG, "Incomplete User: %d", psUser->iId);
          memset(szTmp, 0, 10 + 1);
          snprintf(szTmp, 10, "u%d", psUser->iId);
          strncat(szResumeMap, szTmp, 10);
        } 

        psUser = psUser->psUserNext;
      }

      /* identify the first untouched user */
      if ((psUser) && (psUser->iPassStatus == PL_UNSET))
      {
        writeError(ERR_DEBUG, "First New User: %d", psUser->iId);
        memset(szTmp, 0, 10 + 1);
        snprintf(szTmp, 10, "u%d", psUser->iId);
        strncat(szResumeMap, szTmp, 10);
      }
    }
    else
    {
      writeError(ERR_DEBUG, "Complete Host: %d", psHost->iId);
    }    

    psHost = psHost->psHostNext;
  }
  
  /* identify the first untouched host */
  if ((psHost) && (psHost->iUserStatus == UL_UNSET))
  {
    writeError(ERR_DEBUG, "First New Host: %d", psHost->iId);
    memset(szTmp, 0, 10 + 1);
    snprintf(szTmp, 8, "h%d", psHost->iId);
    strncat(szResumeMap, szTmp, 8);
  }

  /* terminate resume map */
  strcat(szResumeMap, ".");
  
  writeError(ERR_ALERT, "To resume scan, add the following to your original command: \"-Z %s\"", szResumeMap);
      
  free(szResumeMap);

  exit(0);
}

int main(int argc, char **argv, char *envp[] __attribute__((unused)))
{
  struct sigaction sig_action;
  int iExitStatus = EXIT_SUCCESS;
  int i;

  struct tm *tm_ptr;
  time_t the_time;
  char time_buf[256];

  /* set signal handling for SIGINT */
  sig_action.sa_flags = 0;
  sigemptyset(&sig_action.sa_mask);
  sigaddset(&sig_action.sa_mask, SIGINT);
  sig_action.sa_handler = sigint_handler;
  sigaction(SIGINT, &sig_action, 0);

  /* initial module settings and parameters 
     Don't worry if there are NULL or blank values here 
     (they will be checked when loading the module)
  */
  szModuleName = NULL;
  szModulePaths[0] = getenv("MEDUSA_MODULE_PATH");
  szModulePaths[1] = ".";
#ifdef DEFAULT_MOD_PATH
  szModulePaths[2] = DEFAULT_MOD_PATH;
#else
  szModulePaths[2] = "/usr/lib/medusa/modules";
#endif

  szTempModuleParam = NULL;
  arrModuleParams = malloc(sizeof(char*));
  memset(arrModuleParams, 0, sizeof(char*));
  nModuleParamCount = 0;

  /* initialized audit structure */
  psAudit = malloc(sizeof(sAudit));
  memset(psAudit, 0, sizeof(sAudit));

  if (pthread_mutex_init(&(psAudit->ptmMutex), NULL) != 0)
    writeError(ERR_FATAL, "Audit mutex initialization failed - %s\n", strerror( errno ) );

  /* parse user-supplied parameters - populate module parameters */
  if (checkOptions(argc, argv, psAudit))
  {
    usage();
    exit(EXIT_FAILURE);
  }

  for (i = 0; i < nModuleParamCount; i++)
  {
    writeVerbose(VB_GENERAL, "Module parameter: %s", arrModuleParams[i]);
  }

  if (szModuleName == NULL)
  {
    writeVerbose(VB_EXIT, "You must specify a module to execute using -M MODULE_NAME");
    freeModuleParams();
    exit(EXIT_FAILURE);
  }

  if (psAudit->HostType == L_FILE)
  {
    loadFile(psAudit->pOptHost, &psAudit->pHostFile, &psAudit->iHostCnt);
    psAudit->pGlobalHost = psAudit->pHostFile;
  }

  if (psAudit->UserType == L_FILE)
  {
    loadFile(psAudit->pOptUser, &psAudit->pUserFile, &psAudit->iUserCnt);
    psAudit->pGlobalUser = psAudit->pUserFile;
  }

  if (psAudit->PassType == L_FILE)
  {
    loadFile(psAudit->pOptPass, &psAudit->pPassFile, &psAudit->iPassCnt);
    psAudit->pGlobalPass = psAudit->pPassFile;
  }

  if (psAudit->pOptCombo != NULL)
  {
    loadFile(psAudit->pOptCombo, &psAudit->pComboFile, &psAudit->iComboCnt);
    psAudit->pGlobalCombo = psAudit->pComboFile;
    if (processComboFile(&psAudit))
    {
      exit(iExitStatus);
    }
  }

  if ( loadLoginInfo(psAudit) == SUCCESS )
    writeError(ERR_DEBUG, "Successfully loaded login information.");
  else
    writeError(ERR_FATAL, "Failed to load login information.");

  if (psAudit->pOptCombo != NULL) free(psAudit->pComboFile);
  if (psAudit->pHostFile != NULL) free(psAudit->pHostFile);
  if (psAudit->pUserFile != NULL) free(psAudit->pUserFile);

  if (psAudit->pOptOutput != NULL)
  {
    if ((pOutputFile = fopen(psAudit->pOptOutput, "a+")) == NULL)
    {
      writeError(ERR_FATAL, "Failed to open output file %s - %s", psAudit->pOptOutput, strerror( errno ) );
    }
    else
    {
      if (pthread_mutex_init((&ptmFileMutex), NULL) != 0)
        writeError(ERR_FATAL, "File mutex initialization failed - %s\n", strerror( errno ) );

      /* write start time and user options to log */ 
      (void) time(&the_time);
      tm_ptr = localtime(&the_time);
      strftime(time_buf, 256, "%Y-%m-%d %H:%M:%S", tm_ptr); 
      writeVerbose(VB_NONE_FILE, "# Medusa v.%s (%s)\n", VERSION, time_buf);
      writeVerbose(VB_NONE_FILE, "# ");

      for (i =0; i < argc; i++)
      {
        writeVerbose(VB_NONE_FILE, "%s ", argv[i]);
      }
      writeVerbose(VB_NONE_FILE, "\n");
    }
  }

  /* launch actually password auditing threads */
  if ( startServerThreadPool(psAudit) == SUCCESS )
  {
    /* stop time */ 
    (void) time(&the_time);
    tm_ptr = localtime(&the_time);
    strftime(time_buf, 256, "%Y-%m-%d %H:%M:%S", tm_ptr); 
    
    writeVerbose(VB_NONE_FILE, "# Medusa has finished (%s).\n", time_buf);
    writeVerbose(VB_GENERAL, "Medusa has finished.");
    iExitStatus = EXIT_SUCCESS;
  }
  else
  {
    /* stop time */ 
    (void) time(&the_time);
    tm_ptr = localtime(&the_time);
    strftime(time_buf, 256, "%Y-%m-%d %H:%M:%S", tm_ptr); 
    
    writeVerbose(VB_NONE_FILE, "# Medusa failed (%s).\n", time_buf);
    writeError(ERR_CRITICAL, "Medusa failed.");
    iExitStatus = EXIT_FAILURE;
  }

  /* general memory clean-up */
  if ((psAudit->pOptOutput != NULL) && (pthread_mutex_destroy(&ptmFileMutex) != 0))
    writeError(ERR_FATAL, "File mutex destroy call failed - %s\n", strerror( errno ) );
  
  if (pthread_mutex_destroy(&(psAudit->ptmMutex)) != 0)
    writeError(ERR_FATAL, "Audit mutex destroy call failed - %s\n", strerror( errno ) );

  free(psAudit->pPassFile);
  free(psAudit);

  if (szModuleName != NULL)
    free(szModuleName);

  freeModuleParams();

  exit(iExitStatus);
}
