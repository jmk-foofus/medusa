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

#ifndef _MEDUSA_NET_H
#define _MEDUSA_NET_H

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <errno.h>
#include "medusa.h"

#define OPTION_SSL 1
#define MAX_CONNECT_RETRY 3
#define WAIT_BETWEEN_CONNECT_RETRY 3
#define DEFAULT_WAIT_TIME 3     // 3 second max wait on connects
#define READ_WAIT_TIME  20 * 1000000 // Time to wait for a receive in microseconds

typedef struct __sConnectParams 
{
  long nHost;
  int nPort;
  int nUseSSL;
  float nSSLVersion;
  int nProtocol;
  int nType;
  unsigned long nProxyStringIP;
  int nProxyStringPort;
  char* szProxyAuthentication;
  int nTimeout;
  int nRetries;
  int nRetryWait;  
  int nSourcePort;
} sConnectParams;

extern int medusaConnect(sConnectParams* pParams);
extern int medusaConnectSSL(sConnectParams* pParams);
extern int medusaConnectSocketSSL(sConnectParams* pParams, int hSocket);
extern int medusaConnectTCP(sConnectParams* pParams);
extern int medusaConnectUDP(sConnectParams* pParams);
extern int medusaDisconnect(int socket);
extern int medusaDataReadyWritingTimed(int socket, time_t sec, time_t usec);
extern int medusaDataReadyWriting(int socket);
extern int medusaDataReadyTimed(int socket, time_t sec, time_t usec);
extern int medusaDataReady(int socket);
extern int medusaCheckSocket(int socket, int usec);
extern int medusaReceive(int socket, unsigned char *buf, int length);
extern unsigned char* medusaReceiveRaw(int socket, int* nBufferSize);
extern unsigned char* medusaReceiveRawDelay(int socket, int* nBufferSize, int nReceiveDelay1, int nReceiveDelay2);
extern unsigned char* medusaReceiveLine(int socket, int* nBufferSize);
extern unsigned char* medusaReceiveLineDelay(int socket, int* nBufferSize, int nReceiveDelay, int nReceiveDelay2);
extern int medusaReceiveRegex(int hSocket, unsigned char **szBufReceive, int* nBufReceive, const char* regex);
extern int medusaSend(int socket, unsigned char *buf, int size, int options);
extern int makeToLower(char *buf);


#endif
