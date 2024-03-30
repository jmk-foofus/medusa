/***************************************************************************
 *   medusa-net.c                                                          *
 *   Copyright (C) 2006 by fizzgig                                         *
 *   fizzgig@foofus.net                                                    *
 *                                                                         *
 *   Low level networking stuff used by all medusa modules.                *
 *   Based heavily on the original hydra networking code by                *
 *   VanHauser and the good folks at thc (vh@thc.org).                     *
 *                                                                         *
 *                                                                         *
 *   CHANGE LOG                                                            *
 *   04/04/2005 -- Created by fizzgig (fizzgig@foofus.net)                 *
 *   04/12/2005 -- Final "alpha" implementation                            *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 *                                                                         *
 *   This program is released under the GPL with the additional exemption  *
 *   that compiling, linking, and/or using OpenSSL is allowed.             *
 *                                                                         *
 ***************************************************************************/

#include "medusa.h"
#include "medusa-trace.h"
#include "medusa-net.h"
#include "uthash.h"
#include <pthread.h>
#include <regex.h>

#ifdef HAVE_LIBSSL
  #include <openssl/ssl.h>
  #include <openssl/err.h>
#endif

#ifdef HAVE_LIBSSL

/*
  Original code utilized global variables for SSL socket support.
  Unfortunately, this could potentially be an issue in cases where
  modules utilize both SSL and non-SSL within a session (e.g. FTPS). 
  It's possible one thread could connect to a service in the clear 
  while another requires SSL. The global variable obviously makes this 
  impossible.

  Ideally, this data should be unique to thread and tracked there.
  However, I believe implementing this would require rewriting all
  send/receive calls. For now, we are utilizing a hash of socket id
  to SSL information structure for tracking which connections require
  SSL. 
*/
struct SSLSOCKETINFO {
  int id;                    /* key --> socket id */
  int nUseSSL;
  SSL *ssl;
  SSL_CTX *sslContext;

  UT_hash_handle hh;         /* required for UThash */
};

struct SSLSOCKETINFO *psSSLSocketInfo = NULL; 
pthread_mutex_t ptmSSLMutex;

#endif

// Modules can call this function to set up the sConnectParams structure needed for connection functions.
// It copies data from the login structure and overrides default values if the user specified command-line
// parameters. The typical use of this function, then, is:
// 1) Create a sConnectParams structure
// 2) Zero all members of the structure
// 3) Set individual members of the structure with default module values (like port)
// 4) Call initConnectionParams
void initConnectionParams(sLogin* pLogin, sConnectParams* pParams)
{
  pParams->nHost = inet_addr(pLogin->psServer->pHostIP);
  if (pLogin->psServer->psHost->iPortOverride != 0)
  {
    // Override the port
    pParams->nPort = pLogin->psServer->psHost->iPortOverride;
  }
  pParams->nUseSSL = pLogin->psServer->psHost->iUseSSL;
  pParams->nTimeout = pLogin->psServer->psHost->iTimeout;
  pParams->nRetryWait = pLogin->psServer->psHost->iRetryWait;
  pParams->nRetries = pLogin->psServer->psHost->iRetries;
  if (pParams->nProtocol == 0)
    pParams->nProtocol = SOCK_STREAM;
  if (pParams->nType == 0)
    pParams->nType = 6;
}

int medusaConnectInternal(unsigned long nHost, int nPort, int nProtocol, int nType, int nWaitTime, int nRetries, int nRetryWait,unsigned long nProxyStringIP, int nProxyStringPort, char* szProxyAuthentication, int nSourcePort)
{
  int s, ret = -1;
  int nFail = 0;
  struct sockaddr_in target, source;
  char *buf, *tmpptr = NULL;
  char out[16];
  long flag;
  int nOpt;
  unsigned int nSize;
  fd_set myset; 
  struct timeval tv;
  int nUseProxy = nProxyStringIP > 0 ? 1 : 0;

  s = socket(PF_INET, nProtocol, nType);
  if (s >= 0) 
  {
    /* Handle a source port request from a module */
    if ( nSourcePort != 0 ) {
      int bind_ok=0;
       
      source.sin_family = PF_INET;
      source.sin_port = htons(nSourcePort);
      source.sin_addr.s_addr = INADDR_ANY;
  
      /* We will try to find a free port down to 512 */
      while (!bind_ok && nSourcePort >= 512)
      {   
        if (bind(s, (struct sockaddr *)&source, sizeof(source))==-1)
        {
          if (errno == EADDRINUSE)
          {
            writeError(ERR_DEBUG, "Port %d in use trying next lower port.", nSourcePort);
            nSourcePort--;
            source.sin_port = htons(nSourcePort);
          }
          else
          {
            if (errno == EACCES && (getuid() > 0))
            {
              writeError(ERR_ERROR, "Source port for this service requires root privileges.");
              return FAILURE;
            }
          }
        }
        else
          bind_ok=1;
      }
    }
    /* End of source port fun */

    if (nUseProxy > 0)
    {
      target.sin_port = htons(nProxyStringPort);
      memcpy(&target.sin_addr.s_addr, &nProxyStringIP, sizeof(unsigned long));
    }
    else
    {
      target.sin_port = htons(nPort);
      memcpy(&target.sin_addr.s_addr, &nHost, sizeof(unsigned long));
    }
    target.sin_family = AF_INET;

    // Set non-blocking 
    if((flag = fcntl(s, F_GETFL, NULL)) < 0) 
    { 
      writeError(ERR_ERROR, "Error fcntl(..., F_GETFL) (%s)", strerror(errno)); 
      return -1; 
    } 
    flag |= O_NONBLOCK; 
    if(fcntl(s, F_SETFL, flag) < 0) 
    { 
      writeError(ERR_ERROR, "Error fcntl(..., F_SETFL) (%s)", strerror(errno)); 
      return -1; 
    } 
 
    nFail = 0;    
    ret = connect(s, (struct sockaddr*)&target, sizeof(struct sockaddr_in));
    if (errno == EINPROGRESS) 
    { 
      do 
      { 
          if (nFail > 0 && nFail <= nRetries)
          {
            writeError(ERR_ERROR, "Thread %X: Host: %s Cannot connect [unreachable], retrying (%d of %d retries)", (int)pthread_self(), inet_ntop(AF_INET, &target.sin_addr, out, sizeof(out)), nFail, nRetries);
            sleep(nRetryWait);
          }
          else if (nFail > nRetries)
            return -1;
            
          tv.tv_sec = nWaitTime; 
          tv.tv_usec = 0; 
          FD_ZERO(&myset); 
          FD_SET(s, &myset); 
          ret = select(s + 1, NULL, &myset, NULL, &tv); 
          if (ret < 0 && errno != EINTR) 
          { 
            writeError(ERR_ERROR, "Error connecting to host: %s", strerror(errno)); 
            return -1; 
          } 
          else if (ret > 0) 
          { 
            nSize = sizeof(int);
            if (getsockopt(s, SOL_SOCKET, SO_ERROR, (void*)(&nOpt), &nSize) < 0) 
            { 
              writeError(ERR_ERROR, "Error in getsockopt() %s", strerror(errno)); 
              return -1;
            } 
            if (nOpt != 0) 
            { 
              // Socket is not valid - connection failed
              writeVerbose(VB_GENERAL, "Unable to connect (invalid socket): unreachable destination - %s", inet_ntop(AF_INET, &target.sin_addr, out, sizeof(out)));
              return -1; 
            }
            
            // If we get here, the socket should be valid
            ret = 0;
            break; 
          } 
          else 
          { 
            nFail++; 
          } 
      } while (1); 
    }       
    if (ret != 0 || nFail > nRetries)
    {
      writeVerbose(VB_GENERAL, "Unable to connect: unreachable destination");

      ret = -1;
      return ret;
    }

    // Set the socket to be blocking again
    if((flag = fcntl(s, F_GETFL, NULL)) < 0) 
    { 
      writeError(ERR_ERROR, "Error fcntl(..., F_GETFL) (%s)", strerror(errno)); 
      return -1; 
    } 
    flag &= ~O_NONBLOCK; 
    if(fcntl(s, F_SETFL, flag) < 0) 
    { 
      writeError(ERR_ERROR, "Error fcntl(..., F_SETFL) (%s)", strerror(errno)); 
      return -1; 
    } 
    ret = s;

    /*
    // Possible issue with MTU/MSS values and our use of fixed buffer sizes.
    // Example: OWA/EWS HTTPS
    // We set a MTU of 616 (MSS of 576) in our SYN packet
    // Windows responds with a MSS value of 536
    // Windows sends a non-fragmented packet of 955 bytes
    // Our buffer of 576 has issues... moving to a buffer of 1500 for now...
   
      int option = 576 + 40;
      int optlen = sizeof(option);
 
      // getsockopt call doesn't seem to work... use "ifconfig eth0 mtu 616" 

      if (setsockopt(s, SOL_IP, IP_MTU, &option, optlen) < 0)
        writeError(ERR_ERROR, "Error setting MTU size.");
   
      option = 0; 
      if (getsockopt(s, SOL_IP, IP_MTU, &option, &optlen) < 0)
        writeError(ERR_ERROR, "Error retrieving MTU size.");
    
      writeError(ERR_DEBUG, "MTU size: %d", option);
    
      #define TCP_MAXSEG  0x02
      if (getsockopt(s, IPPROTO_TCP, TCP_MAXSEG, &option, &optlen) < 0)
        writeError(ERR_ERROR, "Error retrieving TCP_MAXSEG size.");

      writeError(ERR_DEBUG, "MSS size: %d", option);
    */

    writeError(ERR_DEBUG, "Connected (internal)");

    if (nUseProxy > 0)
    {
      buf = malloc(4096);
      memset(buf, 0, 4096);
      memset(&target, 0, sizeof(struct sockaddr_in));
      memcpy(&target.sin_addr.s_addr, &nHost, sizeof(unsigned long));
      target.sin_family = AF_INET;

      if (szProxyAuthentication == NULL)
        snprintf(buf, 4095, "CONNECT %s:%d HTTP/1.0\r\n\r\n", inet_ntop(AF_INET, &target.sin_addr, out, sizeof(out)), nPort);
      else
        snprintf(buf, 4095, "CONNECT %s:%d HTTP/1.0\r\nProxy-Authorization: Basic %s\r\n\r\n", inet_ntop(AF_INET, &target.sin_addr, out, sizeof(out)), nPort,
                 szProxyAuthentication);

      send(s, buf, strlen(buf), 0);
      recv(s, buf, 4096, 0);

      if (strncmp("HTTP/", buf, strlen("HTTP/")) == 0 && (tmpptr = index(buf, ' ')) != NULL && *++tmpptr == '2')
      {
        writeError(ERR_DEBUG, "Connected (with proxy)");
      }
      else
      {
        //writeError(ERR_DEBUG, "Unable to connect using SSL (Code: %c%c%c)", *tmpptr, *(tmpptr + 1), *(tmpptr + 2));
        writeError(ERR_ERROR, "CONNECT call to proxy failed with code %c%c%c", *tmpptr, *(tmpptr + 1), *(tmpptr + 2));

        close(s);
        ret = -1;
        free(buf);

        return ret;
      }
      free(buf);
    }
    nFail = 0;

    return ret;
  }

  return ret;
}

int medusaConnectSSLInternal(sConnectParams* pParams, int hSocket)
{
  int err;
  struct SSLSOCKETINFO *s;
  SSL *ssl = NULL;
  SSL_CTX *sslContext = NULL;
  
  pthread_mutex_lock(&ptmSSLMutex);

  SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();

  /* OpenSSL 1.1.0 introduced TLS_client_method() and deprecated all version specific functions. */
  sslContext = SSL_CTX_new(TLS_client_method());
  if (sslContext == NULL)
  {
    err = ERR_get_error();
    writeError(ERR_ERROR, "SSL: Error allocating context: %s", ERR_error_string(err, NULL));
    pthread_mutex_unlock(&ptmSSLMutex);
    return -1;
  }

  // set the compatbility mode
  SSL_CTX_set_options(sslContext, SSL_OP_ALL);

  // we set the default verifiers and dont care for the results
  SSL_CTX_set_default_verify_paths(sslContext);
  SSL_CTX_set_verify(sslContext, SSL_VERIFY_NONE, NULL);

  if ((hSocket < 0) && ((hSocket = medusaConnect(pParams)) < 0))
  {
    pthread_mutex_unlock(&ptmSSLMutex);
    return -1;
  }

  if ((ssl = SSL_new(sslContext)) == NULL)
  {
    err = ERR_get_error();
    writeError(ERR_ERROR, "Error preparing an SSL context: %s", ERR_error_string(err, NULL));
    pthread_mutex_unlock(&ptmSSLMutex);
    return -1;
  }

  SSL_set_fd(ssl, hSocket);
  if (SSL_connect(ssl) <= 0)
  {
    err = ERR_get_error();
    writeError(ERR_ERROR, "Could not create an SSL session: %s", ERR_error_string(err, NULL));
    pthread_mutex_unlock(&ptmSSLMutex);
    return -1;
  }

  writeError(ERR_DEBUG, "SSL negotiated cipher: %s", SSL_get_cipher(ssl));

  s = malloc(sizeof(struct SSLSOCKETINFO));
  memset(s, 0, sizeof(struct SSLSOCKETINFO));
  s->id = hSocket;
  s->nUseSSL = 1;
  s->ssl = ssl;
  s->sslContext = sslContext;
  
  HASH_ADD_INT( psSSLSocketInfo, id, s ); 
  
  pthread_mutex_unlock(&ptmSSLMutex);

  return hSocket;
}

int medusaReceiveInternal(int socket, unsigned char *buf, int length)
{
#ifdef HAVE_LIBSSL
  int err;
  int nRet;
  struct SSLSOCKETINFO *s;

  HASH_FIND_INT( psSSLSocketInfo, &socket, s );
  if ((s != NULL) && (s->nUseSSL))
  {
    do
    {
      nRet = SSL_read(s->ssl, buf, length);

      if (nRet <= 0)
      {
        err = SSL_get_error(s->ssl, nRet);
        switch(err)
        {
          case SSL_ERROR_ZERO_RETURN:
            writeError(ERR_DEBUG, "The TLS/SSL connection has been closed.");
            break;
          case SSL_ERROR_SSL:
            writeError(ERR_ERROR, "A failure in the SSL library occurred, usually a protocol error.");
            break;
          case SSL_ERROR_SYSCALL:
            writeError(ERR_DEBUG, "TLS/SSL I/O error occurered (%d - %s)", err, ERR_error_string(err, NULL));
            break;
          default:
            writeError(ERR_ERROR, "Unknown TLS/SSL error occurred (%d - %s)", err, ERR_error_string(err, NULL));
        }
      }
    }
    while (nRet == -1 && err == SSL_ERROR_SYSCALL && errno == EINTR);

    return nRet;
  }
  else
#endif
    return recv(socket, buf, length, 0);
}


/*
  This is a more robust receive function that can optionally convert NULLS to spaces
  Callers should check the value of *nBufferSize on return - IT MAY HAVE BEEN CHANGED
*/
unsigned char* medusaReceiveDataInternal(int socket, int* nBufferSize, int nConvertNullsToSpaces, int nReceiveDelay1, int nReceiveDelay2)
{
  /*
    When receiving UDP packets, we need to be mindful of packets exceeding our default buffer size.
    Since we configure our UDP socket as SOCK_DGRAM, any packets beyond the buffer size will be 
    discarded following a recv() call. UDP messages, or datagrams, should have the entire message 
    within a single packet. The actual maximum size of this packet is unknown, however, due to a 
    number of variables (see reference below). For our purposes, we are going to use the value
    of 576.

    http://www.uic.rsu.ru/doc/inet/tcp_stevens/ip_inter.htm#3_2

    Although it's possible to send a 65535-byte IP datagram, most link layers will fragment this. 
    Furthermore, a host is not required to receive a datagram larger than 576 bytes. TCP divides 
    the user's data into pieces, so this limit normally doesn't affect TCP. With UDP we'll 
    encounter numerous applications in later chapters (RIP, TFTP, BOOTP, the DNS, and SNMP) that 
    limit themselves to 512 bytes of user data, to stay below this 576-byte limit. Realistically, 
    however, most implementations today (especially those that support the Network File System, 
    NFS) allow for just over 8192-byte IP datagrams. 

    As of 2013/07/25, we are increasing the buffer size from 576 to 1500. The reason for this
    change is to deal with a OWA/EWS servers sending non-fragment packets larger than 576 and
    having data missed. Attempts to negotiate a lower MTU/MSS value with the target Windows
    host has failed for an unknown reason.
  */
  const int BUFFER_SIZE = 1500;
  
  unsigned char *szBufReceive, *szBufReceiveTmp;
  int nBufReceive = 0, nBufReceiveTmp = 0, BufReceiveIndex = 0;
  int bSocketStatus = 0;
  int nReceiveDelay1sec = 0, nReceiveDelay1usec = 0;
  int nReceiveDelay2sec = 0, nReceiveDelay2usec = 0;
  
  *nBufferSize = 0;

  szBufReceive = malloc(BUFFER_SIZE + 1);
  memset(szBufReceive, 0, BUFFER_SIZE + 1);

  nReceiveDelay1sec = nReceiveDelay1 / 1000000;
  nReceiveDelay1usec = nReceiveDelay1 % 1000000;
  nReceiveDelay2sec = nReceiveDelay2 / 1000000;
  nReceiveDelay2usec = nReceiveDelay2 % 1000000;

  bSocketStatus = medusaDataReadyTimed(socket, nReceiveDelay1sec, nReceiveDelay1usec);
  if (bSocketStatus > 0)
  {
    writeError(ERR_DEBUG, "Data receive: Data waiting.");
    nBufReceive = medusaReceive(socket, szBufReceive, BUFFER_SIZE);
    if (nBufReceive <= 0)
    {
      writeError(ERR_DEBUG, "Data receive: Socket indicated data present, but none found.");
      free(szBufReceive);
      return NULL;
    }
  }
  else if (bSocketStatus == 0)
  {
    writeError(ERR_DEBUG, "Data receive: No data.");
    free(szBufReceive);
    return NULL;
  }
  else
  {
    writeError(ERR_ERROR, "Data receive: Failed to read from network socket.");
    free(szBufReceive);
    return NULL;
  }

  /* check for any addition data which may have been sent */
  while (medusaDataReadyTimed(socket, nReceiveDelay2sec, nReceiveDelay2usec) > 0)
  {
    szBufReceiveTmp = malloc(BUFFER_SIZE + 1);
    memset(szBufReceiveTmp, 0, BUFFER_SIZE + 1);
    nBufReceiveTmp = medusaReceive(socket, szBufReceiveTmp, BUFFER_SIZE);
    if (nBufReceiveTmp <= 0)
    {
      writeError(ERR_DEBUG, "Data receive: No additional data.");
      free(szBufReceiveTmp);
      break;
    }
   
    if (nBufReceive + nBufReceiveTmp > BUFFER_SIZE) 
    {
      writeError(ERR_DEBUG, "Additional data received. Increasing receive buffer %d bytes to %d.", nBufReceiveTmp, nBufReceive + nBufReceiveTmp + 1);
      szBufReceive = realloc(szBufReceive, nBufReceive + nBufReceiveTmp + 1);
    }

    memcpy(szBufReceive + nBufReceive, szBufReceiveTmp, nBufReceiveTmp);
    nBufReceive += nBufReceiveTmp;

    nBufReceiveTmp = 0;
    free(szBufReceiveTmp);
  }

  szBufReceive[nBufReceive] = 0; /* explicit NULL termination */

  /* convert NULLS to spaces */
  if (nConvertNullsToSpaces != 0)
    for (BufReceiveIndex = 0; BufReceiveIndex < nBufReceive; BufReceiveIndex++)
      if (szBufReceive[BufReceiveIndex] == 0)
        szBufReceive[BufReceiveIndex] = 32;

  writeError(ERR_DEBUG, "Formatted data received (size %d): %s", nBufReceive, szBufReceive);
  
  *nBufferSize = nBufReceive;
  return szBufReceive;
}

int medusaSendInternal(int socket, unsigned char *buf, int size, int options)
{
#ifdef HAVE_LIBSSL
  struct SSLSOCKETINFO *s;

  HASH_FIND_INT( psSSLSocketInfo, &socket, s );
  if ((s != NULL) && (s->nUseSSL))
  {
    return SSL_write(s->ssl, buf, size);
  }
  else
  {
#endif
    int nRet;
    //char *bufReceive = NULL;
    //int nReceiveBufferSize = 0;
    
    /* flush any extraneous data remaining on socket */
    //while (medusaDataReadyTimed(socket, 0, 1) > 0) 
    //{
    //  bufReceive = medusaReceiveRaw(socket, &nReceiveBufferSize);
    //  writeError(ERR_DEBUG, "Purging extraneous data on socket from previous request (size %d): %s", nReceiveBufferSize, bufReceive);
    //  if (bufReceive == NULL) { break; }
    //}
 
    nRet = send(socket, buf, size, options); 
    if (nRet < 0)
    {
      writeError(ERR_ERROR, "Error in send() %s", strerror(errno)); 
    }
    
    return nRet;
#ifdef HAVE_LIBSSL
  }
#endif
}

// ------------------ public functions ------------------

// Variants of medusaConnectInternal
int medusaConnect(sConnectParams* pParams)
{
  return medusaConnectInternal(pParams->nHost, pParams->nPort, pParams->nProtocol, pParams->nType, pParams->nTimeout, pParams->nRetries, pParams->nRetryWait,
                               pParams->nProxyStringIP, pParams->nProxyStringPort, pParams->szProxyAuthentication, pParams->nSourcePort);
}

int medusaConnectSSL(sConnectParams* pParams)
{
#ifdef HAVE_LIBSSL
  int hSocket;

  hSocket = medusaConnectSSLInternal(pParams, -1);

  if (hSocket > 0)
    pParams->nUseSSL = 1;

  return hSocket;
#else
  writeError(ERR_ERROR, "Trying to connect via SSL, but medusa was not compiled with OPENSSL support. Using non-SSL connection.");
  pParams->nUseSSL = 0;
  return (medusaConnect(pParams));
#endif
}

/* Requires medusaConnect() to already have been called and for the socket to passed as an argument. 
   Used for protocols which switch from non-SSL to SSL mid-connection. */
int medusaConnectSocketSSL(sConnectParams* pParams, int hSocket)
{
#ifdef HAVE_LIBSSL
  if (hSocket > 0)
  {
    pParams->nUseSSL = 1;
    return (medusaConnectSSLInternal(pParams, hSocket));
  }
  else
  {
    writeError(ERR_ERROR, "Invalid socket handle.");
    pParams->nUseSSL = 0;
    return FAILURE;
  }
#else
  writeError(ERR_ERROR, "Trying to connect via SSL, but medusa was not compiled with OPENSSL support.");
  pParams->nUseSSL = 0;
  return FAILURE;
#endif
}

int medusaConnectTCP(sConnectParams* pParams)
{
  pParams->nProtocol = SOCK_STREAM;
  pParams->nType = 6;
  return (medusaConnect(pParams));
}

int medusaConnectUDP(sConnectParams* pParams)
{
  // Modify the sConnectParams structure to make certain UDP stuff is set
  pParams->nProtocol = SOCK_DGRAM;
  pParams->nType = 17;
  return (medusaConnect(pParams));
}

int medusaDisconnect(int hSocket)
{
#ifdef HAVE_LIBSSL
  struct SSLSOCKETINFO *s;

  if (hSocket <= 0)
    return -1;

  pthread_mutex_lock(&ptmSSLMutex);
  
  /* Remove socket's SSL informational structure (if it exists) */
  HASH_FIND_INT( psSSLSocketInfo, &hSocket, s );
  if (s != NULL)
  {
    HASH_DEL( psSSLSocketInfo, s );
  }

  close(hSocket);

  pthread_mutex_unlock(&ptmSSLMutex);

  writeError(ERR_DEBUG, "Disconnect successful");
  return -1;
#else
  close(hSocket);
  writeError(ERR_DEBUG, "Disconnect successful");
  return -1;
#endif
}

int medusaDataReadyWritingTimed(int socket, time_t sec, time_t usec)
{
  fd_set fds;
  struct timeval tv;

  FD_ZERO(&fds);
  FD_SET(socket, &fds);
  tv.tv_sec = sec;
  tv.tv_usec = usec;

  return (select(socket + 1, &fds, NULL, NULL, &tv));
}

int medusaDataReadyWriting(int socket)
{
  return (medusaDataReadyWritingTimed(socket, 30, 0));
}

int medusaDataReadyTimed(int socket, time_t sec, time_t usec)
{
  fd_set fds;
  struct timeval tv;

  FD_ZERO(&fds);
  FD_SET(socket, &fds);
  tv.tv_sec = sec;
  tv.tv_usec = usec;

  return (select(socket + 1, &fds, NULL, NULL, &tv));
}

int medusaDataReady(int socket)
{
  return (medusaDataReadyTimed(socket, 0, 0));
}

/* Check socket status. Return 1 if connection is still valid. */
int medusaCheckSocket(int socket, int usec)
{
  writeError(ERR_DEBUG, "Socket Check - wait time: %d", usec);
  
  if (medusaDataReadyTimed(socket, 0, usec) == 0)
    return 1;
  else
    return 0;
}

int medusaReceive(int socket, unsigned char *buf, int length)
{
  int ret;

  ret = medusaReceiveInternal(socket, buf, length);
  writeError(ERR_DEBUG, "Data received (%d): %s", ret, buf);
  return ret;
}

unsigned char* medusaReceiveRaw(int socket, int* nBufferSize)
{
  return medusaReceiveDataInternal(socket, nBufferSize, 0, READ_WAIT_TIME, 0);
}

unsigned char* medusaReceiveRawDelay(int socket, int* nBufferSize, int nReceiveDelay1, int nReceiveDelay2)
{
  return medusaReceiveDataInternal(socket, nBufferSize, 0, nReceiveDelay1, nReceiveDelay2);
}

unsigned char* medusaReceiveLine(int socket, int* nBufferSize)
{
  return medusaReceiveDataInternal(socket, nBufferSize, 1, READ_WAIT_TIME, 0);
}

unsigned char* medusaReceiveLineDelay(int socket, int* nBufferSize, int nReceiveDelay1, int nReceiveDelay2)
{
  return medusaReceiveDataInternal(socket, nBufferSize, 1, nReceiveDelay1, nReceiveDelay2);
}


/*
  Receive function which uses regular expressions to determine whether we read 
  all the data we're intending to. The goal is to address the issue of varying 
  network speeds of servers. We don't want to retrieve only the first few bytes
  of a response and then start responding before the remote end is finished.

  The function will recheck the socket 5 times before giving up finding a match.
  Each recheck uses a larger timeout value.
*/
int medusaReceiveRegex(int hSocket, unsigned char **szBufReceive, int* nBufReceive, const char* regex)
{
  unsigned char *szBufReceiveTmp = NULL;
  int nBufReceiveTmp = 0;
  regex_t preg;
  int errcode = REG_NOMATCH;
  char errmsg[512];
  int nAttempt = 1;
  const int BUFFER_SIZE = 1500;
    
  writeError(ERR_DEBUG, "Regular expression: \"%s\"", regex);
  errcode = regcomp(&preg, regex, REG_EXTENDED|REG_ICASE|REG_NOSUB);
  if (errcode)
  {
    memset(errmsg, 0, 512);
    regerror(errcode, &preg, errmsg, 512);
    writeError(ERR_ERROR, "Regex compilation failed: %s", errmsg);
    return FAILURE;
  }  

  *szBufReceive = medusaReceiveDataInternal(hSocket, nBufReceive, 0, READ_WAIT_TIME, 0);
  if (*szBufReceive == NULL)
    return FAILURE;

  do
  {
    errcode = regexec(&preg, (char* const) *szBufReceive, 0, 0, 0);
    if (errcode == REG_NOMATCH)
    {
      writeError(ERR_DEBUG, "Failed to match regex. Checking for additional data.");

      /* there more be more data waiting for us... */
      if (medusaDataReadyTimed(hSocket, 0, 20000 * nAttempt) > 0)
      {
        szBufReceiveTmp = malloc(BUFFER_SIZE + 1);
        memset(szBufReceiveTmp, 0, BUFFER_SIZE + 1);

        nBufReceiveTmp = medusaReceive(hSocket, szBufReceiveTmp, BUFFER_SIZE);
        if (nBufReceiveTmp <= 0)
        {
          writeError(ERR_DEBUG, "Data receive: No additional data.");
          free(szBufReceiveTmp);
          break;
        }
 
        if (*nBufReceive + nBufReceiveTmp > BUFFER_SIZE) 
        {
          writeError(ERR_DEBUG, "Additional data received. Increasing receive buffer %d bytes to %d.", nBufReceiveTmp, *nBufReceive + nBufReceiveTmp + 1);
          *szBufReceive = realloc(*szBufReceive, *nBufReceive + nBufReceiveTmp + 1);
        }

        memcpy(*szBufReceive + *nBufReceive, szBufReceiveTmp, nBufReceiveTmp);
        *nBufReceive += nBufReceiveTmp;

        nBufReceiveTmp = 0;
        free(szBufReceiveTmp);
      }
      else
      {
        /* no additional data found... let's check it a few times */
        writeError(ERR_DEBUG, "No additional data found (attempt %d/5)", nAttempt);
        nAttempt++;
      }
    }
    else
    {
      regfree(&preg);
      writeError(ERR_DEBUG, "Successfully matched regex.");
      return SUCCESS;
    }
  } while (nAttempt <= 5);

  regfree(&preg);
  writeError(ERR_ERROR, "Failed to match regex pattern within server's response.");
  return FAILURE;
}

int medusaSend(int socket, unsigned char *buf, int size, int options)
{
  char debugbuf[size + 1];
  int k;

  memset(debugbuf, 0, size + 1);
  for (k = 0; k < size; k++)
    if (buf[k] == 0)
      debugbuf[k] = 32;
    else
      debugbuf[k] = buf[k];
  writeError(ERR_DEBUG, "Data sent: %s", debugbuf);

  return (medusaSendInternal(socket, buf, size, options));
}

int makeToLower(char *buf)
{
  if (buf == NULL)
    return 1;

  while (buf[0] != 0)
  {
    buf[0] = tolower(buf[0]);
    buf++;
  }

  return 1;
}
