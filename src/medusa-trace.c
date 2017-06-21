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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>

#include "medusa.h"
#include "medusa-trace.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

void writeVerbose(int iLevel, char *pMsg, ...) {
  va_list ap;
  char buf[512];
  char bufOut[2049]; // 1 character is represented by 4 -- [01]
  char temp[6];
  unsigned char cTemp;
  unsigned int i = 0;

  struct tm *tm_ptr;
  time_t the_time;
  char time_buf[256];

  if (pMsg == NULL) {
    fprintf(stderr, "CRITICAL: writeDebug() called with NULL message.\n");
  }
  else if (iLevel <= iVerboseLevel) {
    va_start(ap, pMsg);
    memset(bufOut, 0, sizeof(bufOut));
    memset(buf, 0, sizeof(buf));
    vsnprintf(buf, sizeof(buf) - 1, pMsg, ap);

    /*
      Convert specific non-printable characters to HEX
      Non-printable: < 32d or > 126d
      Ignore: \n, \r and TAB
    */
    for (i = 0; i < sizeof(buf); i++)
    {
      memset(temp, 0, 6);
      cTemp = (unsigned char)buf[i];
      if ((cTemp < 32 && cTemp > 0 && cTemp != 9 && cTemp != 10 && cTemp != 13) || cTemp > 126)
      {
        sprintf(temp, "[%02X]", cTemp);        
      }
      else
        sprintf(temp, "%c", cTemp);
      
      strncat(bufOut, temp, 6);
    }

    (void) time(&the_time);
    tm_ptr = localtime(&the_time);
    strftime(time_buf, 256, "%Y-%m-%d %H:%M:%S", tm_ptr); 

    switch (iLevel)
    {
      case VB_FOUND:
        fprintf(stdout, "%s ACCOUNT FOUND: %s\n", time_buf, bufOut);
        
        if (pOutputFile != NULL) {
          pthread_mutex_lock(&ptmFileMutex);
          fprintf(pOutputFile, "%s ACCOUNT FOUND: %s\n", time_buf, buf);
          fflush(pOutputFile);
          pthread_mutex_unlock(&ptmFileMutex);
        }

        va_end(ap);
        break;
      case VB_CHECK:
        fprintf(stdout, "%s ACCOUNT CHECK: %s\n", time_buf, bufOut);
        va_end(ap);
        break;
      case VB_IMPORTANT:
        fprintf(stdout, "IMPORTANT: %s\n", bufOut);
        va_end(ap);
        break;
      case VB_GENERAL:
        fprintf(stdout, "GENERAL: %s\n", bufOut);
        va_end(ap);
        break;
      case VB_NONE:
        fprintf(stdout, "%s\n", bufOut);
        va_end(ap);
        break;
      case VB_NONE_FILE:
        if (pOutputFile != NULL) {
          pthread_mutex_lock(&ptmFileMutex);
          fprintf(pOutputFile, "%s", bufOut);
          fflush(pOutputFile);
          pthread_mutex_unlock(&ptmFileMutex);
        }
        
        va_end(ap);
        break;
      case VB_EXIT:
        fprintf(stdout, "%s\n", bufOut);
        va_end(ap);
        exit(EXIT_SUCCESS);
        break;
      default:
        fprintf(stdout, "UNKNOWN: %s\n", bufOut);
        va_end(ap);
        break;
    }
  }

  return;
}

void writeError(int iLevel, char *pMsg, ...) {
  va_list ap;
  char buf[4096];
  char bufOut[16384];
  char temp[6];
  unsigned char cTemp;
  unsigned int i = 0, len;
 
  if (pMsg == NULL) {
    fprintf(stderr, "CRITICAL: writeError() called with NULL message.\n");
  }
  else if (iLevel <= iErrorLevel) {
    va_start(ap, pMsg);
    memset(bufOut, 0, sizeof(bufOut));
    memset(buf, 0, sizeof(buf));
    len = vsnprintf(buf, sizeof(buf), pMsg, ap);
 
    // Convert any chars less than 32d or greater than 126d to hex
    for (i = 0; i < len; i++)
    {
      memset(temp, 0, 6);
      cTemp = (unsigned char)buf[i];
      if ((cTemp < 32 && cTemp >= 0) || cTemp > 126)
      {
        snprintf(temp, 6, "[%02X]", cTemp);        
      }
      else
        snprintf(temp, 6, "%c", cTemp);
      
      strncat(bufOut, temp, 6);
    }

    switch (iLevel)
    {
      case ERR_FATAL:
        fprintf(stderr, "FATAL: %s\n", bufOut);
        va_end(ap);
        exit(EXIT_FAILURE);
        break;
      case ERR_ALERT:
        fprintf(stderr, "ALERT: ");
        break;
      case ERR_CRITICAL:
        fprintf(stderr, "CRITICAL: ");
        break;
      case ERR_ERROR:
        fprintf(stderr, "ERROR: ");
        break;
      case ERR_WARNING:
        fprintf(stderr, "WARNING: ");
        break;
      case ERR_NOTICE:
        fprintf(stderr, "NOTICE: ");
        break;
      case ERR_INFO:
        fprintf(stderr, "INFO: ");
        break;
      case ERR_DEBUG:
        fprintf(stderr, "DEBUG [%X]: ", (int)pthread_self());
        break;
      case ERR_DEBUG_AUDIT:
        fprintf(stderr, "DEBUG AUDIT [%X]: ", (int)pthread_self());
        break;
      case ERR_DEBUG_SERVER:
        fprintf(stderr, "DEBUG SERVER [%X]: ", (int)pthread_self());
        break;
      case ERR_DEBUG_MODULE:
        fprintf(stderr, "DEBUG MODULE [%X]: ", (int)pthread_self());
        break;
      default:
        fprintf(stdout, "UNKNOWN ERROR [%X]: ", (int)pthread_self());
        break;
    }
  
    fprintf(stderr, "%s\n", bufOut);
    va_end(ap);
  }
  
  return;
}

void writeErrorBin(int iLevel, char *pMsg, unsigned char *pData, int iLength)
{
  int i;

  if (iLevel <= iErrorLevel) 
  {
    fprintf(stderr, "DATA: %s ", pMsg);

    for(i=0; i<iLength; i++)
      fprintf(stderr, "%2.2X", pData[i] & 0xFF);

    fprintf(stderr, "\n");
  }

  return;
}


