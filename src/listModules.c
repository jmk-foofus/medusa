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

/*
**  listModules.c
**
**  prints out a list of local modules, along with their
**  brief descriptions.  If no other directory is specified,
**  (i.e., pszDir is NULL), we assume "."
**
**  CHANGE LOG
**  02-17-2004 - Created by Foofus
**  02-18-2004 - Works with test module (Foofus).
**  
*/

#include <sys/types.h>
#include <dirent.h>
#include <libgen.h>
#include <stdio.h>
#include <dlfcn.h>

#include "modsrc/module.h"

void listModules(char* arrPaths[], int nTerminateNow)
{
  // If nTerminateNow > 0, the application will exit immediately
  struct dirent  **pdeEntry;
  char   *pszTarget;
  int    iLength;
  void   *pLibrary;
  int    (*pSummary)(char**);
  char   *pszUsage;
  char   *pszLibName;
  char   *pszDir;
  int     i, j, k;

  /*  Initialize variables  */
  pszTarget  = NULL;
  iLength    = 0;
  pLibrary  = NULL;
  pSummary  = NULL;
  pszUsage  = NULL;
  pszLibName  = NULL;

  /*  Say hello  */
  for(i = 0; i < 3; i++)
  {
    /*  Format the directory name  */
    pszDir = arrPaths[i];
    if (pszDir == NULL)
    {
      continue;
    }
    else
    {
      pszTarget = strdup(pszDir);
      iLength = 0;
    }  /*  (was a directory specified?)  */
      
    writeVerbose(VB_NONE, "  Available modules in \"%s\" :", pszTarget);
  
    /*  Open the directory  */
    if ((k = scandir( pszTarget, &pdeEntry, 0, alphasort )) < 0)
    {
      if (nTerminateNow > 0)
        writeVerbose(VB_EXIT, "\tCouldn't open directory \"%s\"", pszTarget);
      else
        writeVerbose(VB_NONE, "\tCouldn't open directory \"%s\"", pszTarget);
    }
    else
    {
      /*  For each file, is it a module?  */
      j = -1;
      while (++j < k)
      {
        iLength = strlen( pdeEntry[j]->d_name );
        if (iLength > 4)
        {
          /*  Check the file suffix  */
          if (strcmp( (char*)(pdeEntry[j]->d_name + strlen( pdeEntry[j]->d_name ) - 4), MODULE_EXTENSION ) == 0)
          {
            /*  Build the complete filename  */
            iLength = strlen( pdeEntry[j]->d_name ) + strlen( pszTarget ) + 2;
            pszLibName = (char*)malloc( iLength );
            memset( pszLibName, 0, iLength );
            strcpy(pszLibName, pszTarget);
            strcat(pszLibName, "/");
            strcat(pszLibName, pdeEntry[j]->d_name);
  
            /*  Load this as a shared library  */
            pLibrary = dlopen( pszLibName, RTLD_NOW );
  
            if (pLibrary == NULL)
            {
              writeVerbose(VB_NONE, "    + %s : Couldn't load \"%s\" [%s]", pdeEntry[j]->d_name,
                          pszLibName,
                          dlerror());
            }
            else
            {
              /*  Get a pointer to the summary usage function  */
              pSummary = (int(*)(char**))dlsym( pLibrary, "summaryUsage" );
  
              if (pSummary == NULL)
              {
                writeVerbose(VB_NONE, "    + %s : Invalid module %s [no export of summaryUsage() : %s]",
                            pdeEntry[j]->d_name,
                            pszLibName,
                            dlerror());
              }
              else
              {
                pszUsage = NULL;
                pSummary((char**)&pszUsage);
                writeVerbose(VB_NONE, "    + %s : %s", pdeEntry[j]->d_name, pszUsage);
                free( pszUsage );
              }  /*  (could we get a pointer to the function?)  */
  
              /*  Let go of the library  */
              dlclose( pLibrary );
            }  /*  (could we load the library?)  */
            /*  Don't need the library name any more  */
            free( pszLibName );
  
          }  /*  (did the file have the proper extension?)  */
  
        }  /*  (is the name long enough to bother considering?)  */
 
        /* free finished entry */
        free(pdeEntry[j]);

      }  /*  (while)  */

      writeVerbose(VB_NONE, "");
    }  /*  (could we open the directory?)  */
  
    /*  All done.  */
    free( pszTarget );
  }
  if (nTerminateNow > 0)
    writeVerbose(VB_EXIT, "");
}  /*  (listModules)  */
