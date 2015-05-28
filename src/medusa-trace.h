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

#ifndef _MEDUSATRACE_H
#define _MEDUSATRACE_H

#define VB_EXIT       0
#define VB_NONE       1
#define VB_NONE_FILE  2
#define VB_IMPORTANT  3
#define VB_FOUND      4
#define VB_CHECK      5
#define VB_GENERAL    6

#define ERR_FATAL     0
#define ERR_ALERT     1
#define ERR_CRITICAL  2
#define ERR_ERROR     3
#define ERR_WARNING   4
#define ERR_NOTICE    5
#define ERR_INFO      6
#define ERR_DEBUG     7
#define ERR_DEBUG_AUDIT    8
#define ERR_DEBUG_SERVER   9
#define ERR_DEBUG_MODULE   10

void writeVerbose(int iLevel, char *pMsg, ...);
void writeError(int iLevel, char *pMsg, ...);
void writeErrorBin(int iLevel, char *pMsg, unsigned char *pData, int iLength);

#endif
