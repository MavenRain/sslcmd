
// sslcmd - Command prompt over SChannel
// Odzhan

#define SECURITY_WIN32
#define IO_BUFFER_SIZE  0x10000
#define DLL_NAME TEXT("Secur32.dll")
#define NT4_DLL_NAME TEXT("Security.dll")

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <windows.h>
#include <winsock.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <schannel.h>
#include <security.h>
#include <sspi.h>

#pragma comment(lib, "WSock32.Lib")
#pragma comment(lib, "Crypt32.Lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "MSVCRTD.lib")

// Globals.
BOOL    fVerbose        = FALSE; // FALSE; // TRUE;


INT     iPortNumber     = 465; // gmail TLS
LPSTR   pszServerName   = "smtp.gmail.com"; // DNS name of server
LPSTR   pszUser         = 0; // if specified, a certificate in "MY" store is searched for

DWORD   dwProtocol      = SP_PROT_TLS1; // SP_PROT_TLS1; // SP_PROT_PCT1; SP_PROT_SSL2; SP_PROT_SSL3; 0=default
ALG_ID  aiKeyExch       = 0; // = default; CALG_DH_EPHEM; CALG_RSA_KEYX;

BOOL    fUseProxy       = FALSE;
LPSTR   pszProxyServer  = "proxy";
INT     iProxyPort      = 80;

HCERTSTORE hMyCertStore = NULL;
HMODULE g_hSecurity            = NULL;

SCHANNEL_CRED SchannelCred;
PSecurityFunctionTable g_pSSPI;

/*****************************************************************************/
static void DisplayCertChain( PCCERT_CONTEXT  pServerCert, BOOL fLocal )
{
  CHAR szName[1000];
  PCCERT_CONTEXT pCurrentCert, pIssuerCert;
  DWORD dwVerificationFlags;

  printf("\n");

  // display leaf name
  if( !CertNameToStr( pServerCert->dwCertEncodingType,
        &pServerCert->pCertInfo->Subject,
        CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
        szName, sizeof(szName) ) )
  { printf("**** Error 0x%x building subject name\n", GetLastError()); }

  if(fLocal) printf("Client subject: %s\n", szName);
  else printf("Server subject: %s\n", szName);

  if( !CertNameToStr( pServerCert->dwCertEncodingType,
        &pServerCert->pCertInfo->Issuer,
        CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
        szName, sizeof(szName) ) )
  { printf("**** Error 0x%x building issuer name\n", GetLastError()); }

  if(fLocal) printf("Client issuer: %s\n", szName);
  else printf("Server issuer: %s\n\n", szName);


  // display certificate chain
  pCurrentCert = pServerCert;
  while(pCurrentCert != NULL)
  {
    dwVerificationFlags = 0;
    pIssuerCert = CertGetIssuerCertificateFromStore( pServerCert->hCertStore, pCurrentCert, NULL, &dwVerificationFlags );
    if(pIssuerCert == NULL)
    {
      if(pCurrentCert != pServerCert) CertFreeCertificateContext(pCurrentCert);
      break;
    }

    if( !CertNameToStr( pIssuerCert->dwCertEncodingType,
          &pIssuerCert->pCertInfo->Subject,
          CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
          szName, sizeof(szName) ) )
    { printf("**** Error 0x%x building subject name\n", GetLastError()); }

    printf("CA subject: %s\n", szName);

    if( !CertNameToStr( pIssuerCert->dwCertEncodingType,
          &pIssuerCert->pCertInfo->Issuer,
          CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
          szName, sizeof(szName) ) )
    { printf("**** Error 0x%x building issuer name\n", GetLastError()); }

    printf("CA issuer: %s\n\n", szName);

    if(pCurrentCert != pServerCert) CertFreeCertificateContext(pCurrentCert);
    pCurrentCert = pIssuerCert;
    pIssuerCert = NULL;
  }
}

/*****************************************************************************/
static void DisplayConnectionInfo( CtxtHandle *phContext )
{

  SECURITY_STATUS Status;
  SecPkgContext_ConnectionInfo ConnectionInfo;

  Status = g_pSSPI->QueryContextAttributes( phContext, SECPKG_ATTR_CONNECTION_INFO, (PVOID)&ConnectionInfo );
  if(Status != SEC_E_OK) { printf("Error 0x%x querying connection info\n", Status); return; }

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

  case CALG_DH_EPHEM:
    printf("Key exchange: DH Ephemeral\n");
    break;

  default:
    printf("Key exchange: 0x%x\n", ConnectionInfo.aiExch);
  }

  printf("Key exchange strength: %d\n", ConnectionInfo.dwExchStrength);
}

/*****************************************************************************/
BOOL LoadSecurityLibrary( void ) // load SSPI.DLL, set up a special table - PSecurityFunctionTable
{
  INIT_SECURITY_INTERFACE pInitSecurityInterface;
  //  QUERY_CREDENTIALS_ATTRIBUTES_FN pQueryCredentialsAttributes;
  OSVERSIONINFO VerInfo;
  UCHAR lpszDLL[MAX_PATH];


  //  Find out which security DLL to use, depending on
  //  whether we are on Win2K, NT or Win9x
  VerInfo.dwOSVersionInfoSize = sizeof (OSVERSIONINFO);
  if ( !GetVersionEx (&VerInfo) ) return FALSE;

  if ( VerInfo.dwPlatformId == VER_PLATFORM_WIN32_NT  &&  VerInfo.dwMajorVersion == 4 )
  {
    strcpy (lpszDLL, NT4_DLL_NAME ); // NT4_DLL_NAME TEXT("Security.dll")
  }
  else if ( VerInfo.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS ||
      VerInfo.dwPlatformId == VER_PLATFORM_WIN32_NT )
  {
    strcpy(lpszDLL, DLL_NAME); // DLL_NAME TEXT("Secur32.dll")
  }
  else
  { printf( "System not recognized\n" ); return FALSE; }


  //  Load Security DLL
  g_hSecurity = LoadLibrary(lpszDLL);
  if(g_hSecurity == NULL) { printf( "Error 0x%x loading %s.\n", GetLastError(), lpszDLL ); return FALSE; }

  pInitSecurityInterface = (INIT_SECURITY_INTERFACE)GetProcAddress( g_hSecurity, "InitSecurityInterfaceA" );
  if(pInitSecurityInterface == NULL) { printf( "Error 0x%x reading InitSecurityInterface entry point.\n", GetLastError() ); return FALSE; }

  g_pSSPI = pInitSecurityInterface(); // call InitSecurityInterfaceA(void);
  if(g_pSSPI == NULL) { printf("Error 0x%x reading security interface.\n", GetLastError()); return FALSE; }

  return TRUE; // and PSecurityFunctionTable
}


/*****************************************************************************/
void UnloadSecurityLibrary(void)
{
  FreeLibrary(g_hSecurity);
  g_hSecurity = NULL;
}


/*****************************************************************************/
static DWORD VerifyServerCertificate( PCCERT_CONTEXT pServerCert, PSTR pszServerName, DWORD dwCertFlags )
{
  HTTPSPolicyCallbackData  polHttps;
  CERT_CHAIN_POLICY_PARA   PolicyPara;
  CERT_CHAIN_POLICY_STATUS PolicyStatus;
  CERT_CHAIN_PARA          ChainPara;
  PCCERT_CHAIN_CONTEXT     pChainContext = NULL;
  DWORD                                         cchServerName, Status;
  LPSTR rgszUsages[]     = { szOID_PKIX_KP_SERVER_AUTH,
    szOID_SERVER_GATED_CRYPTO,
    szOID_SGC_NETSCAPE };

  DWORD cUsages          = sizeof(rgszUsages) / sizeof(LPSTR);

  PWSTR   pwszServerName = NULL;


  if(pServerCert == NULL)
  { Status = SEC_E_WRONG_PRINCIPAL; goto cleanup; }

  // Convert server name to unicode.
  if(pszServerName == NULL || strlen(pszServerName) == 0)
  { Status = SEC_E_WRONG_PRINCIPAL; goto cleanup; }

  cchServerName = MultiByteToWideChar(CP_ACP, 0, pszServerName, -1, NULL, 0);
  pwszServerName = LocalAlloc(LMEM_FIXED, cchServerName * sizeof(WCHAR));
  if(pwszServerName == NULL)
  { Status = SEC_E_INSUFFICIENT_MEMORY; goto cleanup; }

  cchServerName = MultiByteToWideChar(CP_ACP, 0, pszServerName, -1, pwszServerName, cchServerName);
  if(cchServerName == 0)
  { Status = SEC_E_WRONG_PRINCIPAL; goto cleanup; }


  // Build certificate chain.
  ZeroMemory(&ChainPara, sizeof(ChainPara));
  ChainPara.cbSize = sizeof(ChainPara);
  ChainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_OR;
  ChainPara.RequestedUsage.Usage.cUsageIdentifier     = cUsages;
  ChainPara.RequestedUsage.Usage.rgpszUsageIdentifier = rgszUsages;

  if( !CertGetCertificateChain( NULL,
        pServerCert,
        NULL,
        pServerCert->hCertStore,
        &ChainPara,
        0,
        NULL,
        &pChainContext ) )
  {
    Status = GetLastError();
    printf("Error 0x%x returned by CertGetCertificateChain!\n", Status);
    goto cleanup;
  }


  // Validate certificate chain.
  ZeroMemory(&polHttps, sizeof(HTTPSPolicyCallbackData));
  polHttps.cbStruct           = sizeof(HTTPSPolicyCallbackData);
  polHttps.dwAuthType         = AUTHTYPE_SERVER;
  polHttps.fdwChecks          = dwCertFlags;
  polHttps.pwszServerName     = pwszServerName;

  memset(&PolicyPara, 0, sizeof(PolicyPara));
  PolicyPara.cbSize            = sizeof(PolicyPara);
  PolicyPara.pvExtraPolicyPara = &polHttps;

  memset(&PolicyStatus, 0, sizeof(PolicyStatus));
  PolicyStatus.cbSize = sizeof(PolicyStatus);

  if( !CertVerifyCertificateChainPolicy( CERT_CHAIN_POLICY_SSL,
        pChainContext,
        &PolicyPara,
        &PolicyStatus ) )
  {
    Status = GetLastError();
    printf("Error 0x%x returned by CertVerifyCertificateChainPolicy!\n", Status);
    goto cleanup;
  }

  if(PolicyStatus.dwError)
  {
    Status = PolicyStatus.dwError;
    DisplayWinVerifyTrustError(Status);
    goto cleanup;
  }

  Status = SEC_E_OK;


cleanup:
  if(pChainContext)  CertFreeCertificateChain(pChainContext);
  if(pwszServerName) LocalFree(pwszServerName);

  return Status;
}


/*****************************************************************************/
static SECURITY_STATUS CreateCredentials( LPSTR pszUser, PCredHandle phCreds )   
{ //                                                in                     out
  TimeStamp        tsExpiry;
  SECURITY_STATUS  Status;
  DWORD            cSupportedAlgs = 0;
  ALG_ID           rgbSupportedAlgs[16];
  PCCERT_CONTEXT   pCertContext = NULL;


  // Open the "MY" certificate store, where IE stores client certificates.
  // Windows maintains 4 stores -- MY, CA, ROOT, SPC.
  if(hMyCertStore == NULL)
  {
    hMyCertStore = CertOpenSystemStore(0, "MY");
    if(!hMyCertStore)
    {
      printf( "**** Error 0x%x returned by CertOpenSystemStore\n", GetLastError() );
      return SEC_E_NO_CREDENTIALS;
    }
  }


  // If a user name is specified, then attempt to find a client
  // certificate. Otherwise, just create a NULL credential.
  if(pszUser)
  {
    // Find client certificate. Note that this sample just searches for a
    // certificate that contains the user name somewhere in the subject name.
    // A real application should be a bit less casual.
    pCertContext = CertFindCertificateInStore( hMyCertStore,                     // hCertStore
    X509_ASN_ENCODING,             // dwCertEncodingType
    0,                                             // dwFindFlags
    CERT_FIND_SUBJECT_STR_A,// dwFindType
    pszUser,                         // *pvFindPara
    NULL );                                 // pPrevCertContext


    if(pCertContext == NULL)
    {
      printf("**** Error 0x%x returned by CertFindCertificateInStore\n", GetLastError());
      if( GetLastError() == CRYPT_E_NOT_FOUND ) printf("CRYPT_E_NOT_FOUND - property doesn't exist\n");
      return SEC_E_NO_CREDENTIALS;
    }
  }


  // Build Schannel credential structure. Currently, this sample only
  // specifies the protocol to be used (and optionally the certificate,
  // of course). Real applications may wish to specify other parameters as well.
  ZeroMemory( &SchannelCred, sizeof(SchannelCred) );

  SchannelCred.dwVersion  = SCHANNEL_CRED_VERSION;
  if(pCertContext)
  {
    SchannelCred.cCreds     = 1;
    SchannelCred.paCred     = &pCertContext;
  }

  SchannelCred.grbitEnabledProtocols = dwProtocol;

  if(aiKeyExch) rgbSupportedAlgs[cSupportedAlgs++] = aiKeyExch;

  if(cSupportedAlgs)
  {
    SchannelCred.cSupportedAlgs    = cSupportedAlgs;
    SchannelCred.palgSupportedAlgs = rgbSupportedAlgs;
  }

  SchannelCred.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS;

  // The SCH_CRED_MANUAL_CRED_VALIDATION flag is specified because
  // this sample verifies the server certificate manually.
  // Applications that expect to run on WinNT, Win9x, or WinME
  // should specify this flag and also manually verify the server
  // certificate. Applications running on newer versions of Windows can
  // leave off this flag, in which case the InitializeSecurityContext
  // function will validate the server certificate automatically.
  SchannelCred.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;


  // Create an SSPI credential.
  Status = g_pSSPI->AcquireCredentialsHandleA( NULL,                 // Name of principal    
  UNISP_NAME_A,         // Name of package
  SECPKG_CRED_OUTBOUND, // Flags indicating use
  NULL,                 // Pointer to logon ID
  &SchannelCred,        // Package specific data
  NULL,                 // Pointer to GetKey() func
  NULL,                 // Value to pass to GetKey()
  phCreds,              // (out) Cred Handle
  &tsExpiry );          // (out) Lifetime (optional)

  if(Status != SEC_E_OK) printf("**** Error 0x%x returned by AcquireCredentialsHandle\n", Status);

  // cleanup: Free the certificate context. Schannel has already made its own copy.
  if(pCertContext) CertFreeCertificateContext(pCertContext);

  return Status;
}

/*****************************************************************************/
static INT ConnectToServer( LPSTR pszServerName, INT iPortNumber, SOCKET * pSocket )      
{ //                                    in                in                 out
  SOCKET Socket;
  struct sockaddr_in sin;
  struct hostent *hp;


  Socket = socket(PF_INET, SOCK_STREAM, 0);
  if(Socket == INVALID_SOCKET)
  {
    printf("**** Error %d creating socket\n", WSAGetLastError());
    DisplayWinSockError( WSAGetLastError() );
    return WSAGetLastError();
  }


  if(fUseProxy)
  {
    sin.sin_family = AF_INET;
    sin.sin_port = ntohs((u_short)iProxyPort);
    if((hp = gethostbyname(pszProxyServer)) == NULL)
    {
      printf("**** Error %d returned by gethostbyname using Proxy\n", WSAGetLastError());
      DisplayWinSockError( WSAGetLastError() );
      return WSAGetLastError();
    }
    else
    memcpy(&sin.sin_addr, hp->h_addr, 4);
  }

  else // No proxy used
  {
    sin.sin_family = AF_INET;
    sin.sin_port = htons((u_short)iPortNumber);
    if((hp = gethostbyname(pszServerName)) == NULL)
    {
      printf("**** Error returned by gethostbyname\n");
      DisplayWinSockError( WSAGetLastError() );
      return WSAGetLastError();
    }
    else
    memcpy (&sin.sin_addr, hp->h_addr, 4);
  }

  if (connect(Socket, (struct sockaddr *)&sin, sizeof(sin)) == SOCKET_ERROR)
  {
    printf( "**** Error %d connecting to \"%s\" (%s)\n",  WSAGetLastError(), pszServerName,  inet_ntoa(sin.sin_addr) );
    closesocket(Socket);
    DisplayWinSockError( WSAGetLastError() );
    return WSAGetLastError();
  }

  if (fUseProxy)
  {
    BYTE  pbMessage[200];
    DWORD cbMessage;

    // Build message for proxy server
    strcpy(pbMessage, "CONNECT ");
    strcat(pbMessage, pszServerName);
    strcat(pbMessage, ":");
    _itoa(iPortNumber, pbMessage + strlen(pbMessage), 10);
    strcat(pbMessage, " HTTP/1.0\r\nUser-Agent: webclient\r\n\r\n");
    cbMessage = (DWORD)strlen(pbMessage);

    // Send message to proxy server
    if(send(Socket, pbMessage, cbMessage, 0) == SOCKET_ERROR)
    {
      printf("**** Error %d sending message to proxy!\n", WSAGetLastError());
      DisplayWinSockError( WSAGetLastError() );
      return WSAGetLastError();
    }

    // Receive message from proxy server
    cbMessage = recv(Socket, pbMessage, 200, 0);
    if(cbMessage == SOCKET_ERROR)
    {
      printf("**** Error %d receiving message from proxy\n", WSAGetLastError());
      DisplayWinSockError( WSAGetLastError() );
      return WSAGetLastError();
    }
    // this sample is limited but in normal use it
    // should continue to receive until CR LF CR LF is received
  }
  *pSocket = Socket;

  return SEC_E_OK;
}

/*****************************************************************************/
static LONG DisconnectFromServer( SOCKET Socket, PCredHandle phCreds, CtxtHandle * phContext )
{
  PBYTE         pbMessage;
  DWORD         dwType, dwSSPIFlags, dwSSPIOutFlags, cbMessage, cbData, Status;
  SecBufferDesc OutBuffer;
  SecBuffer     OutBuffers[1];
  TimeStamp     tsExpiry;

  dwType = SCHANNEL_SHUTDOWN; // Notify schannel that we are about to close the connection.

  OutBuffers[0].pvBuffer   = &dwType;
  OutBuffers[0].BufferType = SECBUFFER_TOKEN;
  OutBuffers[0].cbBuffer   = sizeof(dwType);

  OutBuffer.cBuffers  = 1;
  OutBuffer.pBuffers  = OutBuffers;
  OutBuffer.ulVersion = SECBUFFER_VERSION;

  Status = g_pSSPI->ApplyControlToken(phContext, &OutBuffer);
  if(FAILED(Status)) { printf("**** Error 0x%x returned by ApplyControlToken\n", Status); goto cleanup; }

  // Build an SSL close notify message.
  dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT   |
  ISC_REQ_REPLAY_DETECT     |
  ISC_REQ_CONFIDENTIALITY   |
  ISC_RET_EXTENDED_ERROR    |
  ISC_REQ_ALLOCATE_MEMORY   |
  ISC_REQ_STREAM;

  OutBuffers[0].pvBuffer   = NULL;
  OutBuffers[0].BufferType = SECBUFFER_TOKEN;
  OutBuffers[0].cbBuffer   = 0;

  OutBuffer.cBuffers  = 1;
  OutBuffer.pBuffers  = OutBuffers;
  OutBuffer.ulVersion = SECBUFFER_VERSION;

  Status = g_pSSPI->InitializeSecurityContextA (phCreds, phContext, NULL, dwSSPIFlags, 0, 
  SECURITY_NATIVE_DREP, NULL, 0, phContext, &OutBuffer, &dwSSPIOutFlags, &tsExpiry);
  if(FAILED(Status)) { printf("**** Error 0x%x returned by InitializeSecurityContext\n", Status); goto cleanup; }

  pbMessage = OutBuffers[0].pvBuffer;
  cbMessage = OutBuffers[0].cbBuffer;

  // Send the close notify message to the server.
  if(pbMessage != NULL && cbMessage != 0)
  {
    cbData = send(Socket, pbMessage, cbMessage, 0);
    if(cbData == SOCKET_ERROR || cbData == 0)
    {
      Status = WSAGetLastError();
      printf("**** Error %d sending close notify\n", Status);
      DisplayWinSockError( WSAGetLastError() );
      goto cleanup;
    }
    printf("Sending Close Notify\n");
    printf("%d bytes of handshake data sent\n", cbData);
    if(fVerbose) { PrintHexDump(cbData, pbMessage); printf("\n"); }
    g_pSSPI->FreeContextBuffer(pbMessage); // Free output buffer.
  }
  
cleanup:
  g_pSSPI->DeleteSecurityContext(phContext); // Free the security context.
  closesocket(Socket); // Close the socket.

  return Status;
}



/*****************************************************************************/
static void GetNewClientCredentials (CredHandle *phCreds, CtxtHandle *phContext)
{
  CredHandle                     hCreds;
  SecPkgContext_IssuerListInfoEx IssuerListInfo;
  PCCERT_CHAIN_CONTEXT           pChainContext;
  CERT_CHAIN_FIND_BY_ISSUER_PARA FindByIssuerPara;
  PCCERT_CONTEXT                 pCertContext;
  TimeStamp                      tsExpiry;
  SECURITY_STATUS                Status;

  // Read list of trusted issuers from schannel.
  Status = g_pSSPI->QueryContextAttributes( phContext, SECPKG_ATTR_ISSUER_LIST_EX, (PVOID)&IssuerListInfo );
  if(Status != SEC_E_OK) { printf("Error 0x%x querying issuer list info\n", Status); return; }

  // Enumerate the client certificates.
  ZeroMemory(&FindByIssuerPara, sizeof(FindByIssuerPara));

  FindByIssuerPara.cbSize = sizeof(FindByIssuerPara);
  FindByIssuerPara.pszUsageIdentifier = szOID_PKIX_KP_CLIENT_AUTH;
  FindByIssuerPara.dwKeySpec = 0;
  FindByIssuerPara.cIssuer   = IssuerListInfo.cIssuers;
  FindByIssuerPara.rgIssuer  = IssuerListInfo.aIssuers;

  pChainContext = NULL;

  while (TRUE)
  {   // Find a certificate chain.
    pChainContext = CertFindChainInStore (hMyCertStore,X509_ASN_ENCODING,0, CERT_CHAIN_FIND_BY_ISSUER, &FindByIssuerPara, pChainContext );
    if(pChainContext == NULL) { printf("Error 0x%x finding cert chain\n", GetLastError()); break; }

    printf("\ncertificate chain found\n");

    // Get pointer to leaf certificate context.
    pCertContext = pChainContext->rgpChain[0]->rgpElement[0]->pCertContext;

    // Create schannel credential.
    SchannelCred.dwVersion = SCHANNEL_CRED_VERSION;
    SchannelCred.cCreds = 1;
    SchannelCred.paCred = &pCertContext;

    Status = g_pSSPI->AcquireCredentialsHandleA (NULL, UNISP_NAME_A, SECPKG_CRED_OUTBOUND, 
    NULL, &SchannelCred, NULL, NULL, &hCreds, &tsExpiry );            // (out) Lifetime (optional)

    if(Status != SEC_E_OK) {printf("**** Error 0x%x returned by AcquireCredentialsHandle\n", Status); continue;}

    printf("\nnew schannel credential created\n");

    g_pSSPI->FreeCredentialsHandle(phCreds); // Destroy the old credentials.

    *phCreds = hCreds;
  }
}

/*****************************************************************************/
static SECURITY_STATUS ClientHandshakeLoop (SOCKET Socket, PCredHandle phCreds, 
CtxtHandle *phContext, BOOL fDoInitialRead, SecBuffer *pExtraData)
{
  SecBufferDesc   OutBuffer, InBuffer;
  SecBuffer       InBuffers[2], OutBuffers[1];
  DWORD           dwSSPIFlags, dwSSPIOutFlags, cbData, cbIoBuffer;
  TimeStamp       tsExpiry;
  SECURITY_STATUS scRet;
  PUCHAR          IoBuffer;
  BOOL            fDoRead;

  dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT   | ISC_REQ_CONFIDENTIALITY |
  ISC_RET_EXTENDED_ERROR  | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

  // Allocate data buffer.
  IoBuffer = LocalAlloc(LMEM_FIXED, IO_BUFFER_SIZE);
  if(IoBuffer == NULL) { printf("**** Out of memory (1)\n"); return SEC_E_INTERNAL_ERROR; }
  cbIoBuffer = 0;
  fDoRead = fDoInitialRead;

  // Loop until the handshake is finished or an error occurs.
  scRet = SEC_I_CONTINUE_NEEDED;

  while( scRet == SEC_I_CONTINUE_NEEDED        ||
  scRet == SEC_E_INCOMPLETE_MESSAGE     ||
  scRet == SEC_I_INCOMPLETE_CREDENTIALS )
  {
    if(0 == cbIoBuffer || scRet == SEC_E_INCOMPLETE_MESSAGE) // Read data from server.
    {
      if(fDoRead)
      {
        cbData = recv(Socket, IoBuffer + cbIoBuffer, IO_BUFFER_SIZE - cbIoBuffer, 0 );
        if(cbData == SOCKET_ERROR)
        {
          printf("**** Error %d reading data from server\n", WSAGetLastError());
          scRet = SEC_E_INTERNAL_ERROR;
          break;
        }
        else if(cbData == 0)
        {
          printf("**** Server unexpectedly disconnected\n");
          scRet = SEC_E_INTERNAL_ERROR;
          break;
        }
        printf("%d bytes of handshake data received\n", cbData);
        if(fVerbose) { PrintHexDump(cbData, IoBuffer + cbIoBuffer); printf("\n"); }
        cbIoBuffer += cbData;
      }
      else
      fDoRead = TRUE;
    }

    // Set up the input buffers. Buffer 0 is used to pass in data
    // received from the server. Schannel will consume some or all
    // of this. Leftover data (if any) will be placed in buffer 1 and
    // given a buffer type of SECBUFFER_EXTRA.
    InBuffers[0].pvBuffer   = IoBuffer;
    InBuffers[0].cbBuffer   = cbIoBuffer;
    InBuffers[0].BufferType = SECBUFFER_TOKEN;

    InBuffers[1].pvBuffer   = NULL;
    InBuffers[1].cbBuffer   = 0;
    InBuffers[1].BufferType = SECBUFFER_EMPTY;

    InBuffer.cBuffers       = 2;
    InBuffer.pBuffers       = InBuffers;
    InBuffer.ulVersion      = SECBUFFER_VERSION;


    // Set up the output buffers. These are initialized to NULL
    // so as to make it less likely we'll attempt to free random
    // garbage later.
    OutBuffers[0].pvBuffer  = NULL;
    OutBuffers[0].BufferType= SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer  = 0;

    OutBuffer.cBuffers      = 1;
    OutBuffer.pBuffers      = OutBuffers;
    OutBuffer.ulVersion     = SECBUFFER_VERSION;


    // Call InitializeSecurityContext.
    scRet = g_pSSPI->InitializeSecurityContextA(  phCreds, phContext, NULL, dwSSPIFlags, 0, SECURITY_NATIVE_DREP, &InBuffer, 0, NULL, &OutBuffer, &dwSSPIOutFlags, &tsExpiry );


    // If InitializeSecurityContext was successful (or if the error was
    // one of the special extended ones), send the contends of the output
    // buffer to the server.
    if(scRet == SEC_E_OK                ||
        scRet == SEC_I_CONTINUE_NEEDED   ||
        FAILED(scRet) && (dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR))
    {
      if(OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL)
      {
        cbData = send(Socket, OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer, 0 );
        if(cbData == SOCKET_ERROR || cbData == 0)
        {
          printf( "**** Error %d sending data to server (2)\n",  WSAGetLastError() );
          DisplayWinSockError( WSAGetLastError() );
          g_pSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
          g_pSSPI->DeleteSecurityContext(phContext);
          return SEC_E_INTERNAL_ERROR;
        }
        printf("%d bytes of handshake data sent\n", cbData);
        if(fVerbose) { PrintHexDump(cbData, OutBuffers[0].pvBuffer); printf("\n"); }

        // Free output buffer.
        g_pSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
        OutBuffers[0].pvBuffer = NULL;
      }
    }



    // If InitializeSecurityContext returned SEC_E_INCOMPLETE_MESSAGE,
    // then we need to read more data from the server and try again.
    if(scRet == SEC_E_INCOMPLETE_MESSAGE) continue;


    // If InitializeSecurityContext returned SEC_E_OK, then the
    // handshake completed successfully.
    if(scRet == SEC_E_OK)
    {
      // If the "extra" buffer contains data, this is encrypted application
      // protocol layer stuff. It needs to be saved. The application layer
      // will later decrypt it with DecryptMessage.
      printf("Handshake was successful\n");

      if(InBuffers[1].BufferType == SECBUFFER_EXTRA)
      {
        pExtraData->pvBuffer = LocalAlloc( LMEM_FIXED, InBuffers[1].cbBuffer );
        if(pExtraData->pvBuffer == NULL) { printf("**** Out of memory (2)\n"); return SEC_E_INTERNAL_ERROR; }

        MoveMemory( pExtraData->pvBuffer,
        IoBuffer + (cbIoBuffer - InBuffers[1].cbBuffer),
        InBuffers[1].cbBuffer );

        pExtraData->cbBuffer   = InBuffers[1].cbBuffer;
        pExtraData->BufferType = SECBUFFER_TOKEN;

        printf( "%d bytes of app data was bundled with handshake data\n", pExtraData->cbBuffer );
      }
      else
      {
        pExtraData->pvBuffer   = NULL;
        pExtraData->cbBuffer   = 0;
        pExtraData->BufferType = SECBUFFER_EMPTY;
      }
      break; // Bail out to quit
    }



    // Check for fatal error.
    if(FAILED(scRet)) { printf("**** Error 0x%x returned by InitializeSecurityContext (2)\n", scRet); break; }

    // If InitializeSecurityContext returned SEC_I_INCOMPLETE_CREDENTIALS,
    // then the server just requested client authentication.
    if(scRet == SEC_I_INCOMPLETE_CREDENTIALS)
    {
      // Busted. The server has requested client authentication and
      // the credential we supplied didn't contain a client certificate.
      // This function will read the list of trusted certificate
      // authorities ("issuers") that was received from the server
      // and attempt to find a suitable client certificate that
      // was issued by one of these. If this function is successful,
      // then we will connect using the new certificate. Otherwise,
      // we will attempt to connect anonymously (using our current credentials).
      GetNewClientCredentials(phCreds, phContext);

      // Go around again.
      fDoRead = FALSE;
      scRet = SEC_I_CONTINUE_NEEDED;
      continue;
    }

    // Copy any leftover data from the "extra" buffer, and go around again.
    if ( InBuffers[1].BufferType == SECBUFFER_EXTRA )
    {
      MoveMemory( IoBuffer, IoBuffer + (cbIoBuffer - InBuffers[1].cbBuffer), InBuffers[1].cbBuffer );
      cbIoBuffer = InBuffers[1].cbBuffer;
    }
    else
    cbIoBuffer = 0;
  }

  // Delete the security context in the case of a fatal error.
  if(FAILED(scRet)) g_pSSPI->DeleteSecurityContext(phContext);
  LocalFree(IoBuffer);

  return scRet;
}


/*****************************************************************************/
static SECURITY_STATUS PerformClientHandshake (SOCKET Socket, PCredHandle phCreds, LPSTR pszServerName, 
    CtxtHandle *phContext, SecBuffer *pExtraData)
{
  SecBufferDesc   OutBuffer;
  SecBuffer       OutBuffers[1];
  DWORD           dwSSPIFlags, dwSSPIOutFlags, cbData;
  TimeStamp       tsExpiry;
  SECURITY_STATUS scRet;

  dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT | 
                ISC_REQ_REPLAY_DETECT   | 
                ISC_REQ_CONFIDENTIALITY | 
                ISC_RET_EXTENDED_ERROR  | 
                ISC_REQ_ALLOCATE_MEMORY | 
                ISC_REQ_STREAM;

  //  Initiate a ClientHello message and generate a token.
  OutBuffers[0].pvBuffer   = NULL;
  OutBuffers[0].BufferType = SECBUFFER_TOKEN;
  OutBuffers[0].cbBuffer   = 0;

  OutBuffer.cBuffers  = 1;
  OutBuffer.pBuffers  = OutBuffers;
  OutBuffer.ulVersion = SECBUFFER_VERSION;

  scRet=g_pSSPI->InitializeSecurityContextA (phCreds, NULL, pszServerName, dwSSPIFlags, 
      0, SECURITY_NATIVE_DREP, NULL, 0, phContext, &OutBuffer, &dwSSPIOutFlags, &tsExpiry);

  if (scRet != SEC_I_CONTINUE_NEEDED) { 
    printf("**** Error %d returned by InitializeSecurityContext (1)\n", scRet); 
    return scRet; 
  }

  // Send response to server if there is one.
  if (OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL)
  {
    cbData = send (Socket, OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer, 0 );
    if (cbData == SOCKET_ERROR || cbData == 0)
    {
      printf("**** Error %d sending data to server (1)\n", WSAGetLastError());
      
      g_pSSPI->FreeContextBuffer (OutBuffers[0].pvBuffer);
      g_pSSPI->DeleteSecurityContext (phContext);
      
      return SEC_E_INTERNAL_ERROR;
    }
    printf("%d bytes of handshake data sent\n", cbData);
    
    if (fVerbose) { 
      PrintHexDump (cbData, OutBuffers[0].pvBuffer); 
      printf("\n"); 
    }
    g_pSSPI->FreeContextBuffer (OutBuffers[0].pvBuffer); // Free output buffer.
    OutBuffers[0].pvBuffer = NULL;
  }
  return ClientHandshakeLoop (Socket, phCreds, phContext, TRUE, pExtraData);
}


// http://msdn.microsoft.com/en-us/library/aa375378(VS.85).aspx
// The encrypted message is encrypted in place, overwriting the original contents of its buffer.
/*****************************************************************************/
static DWORD EncryptSend (SOCKET Socket, CtxtHandle *phContext, PBYTE pbIoBuffer, SecPkgContext_StreamSizes Sizes )
{
  SECURITY_STATUS scRet;            // unsigned long cbBuffer;    // Size of the buffer, in bytes
  SecBufferDesc   Message;        // unsigned long BufferType;  // Type of the buffer (below)
  SecBuffer       Buffers[4];    // void    SEC_FAR * pvBuffer;   // Pointer to the buffer
  DWORD           cbMessage, cbData;
  PBYTE           pbMessage;

  pbMessage = pbIoBuffer + Sizes.cbHeader; // Offset by "header size"
  cbMessage = (DWORD)strlen(pbMessage);
  printf("Sending %d bytes of plaintext:", cbMessage); PrintText(cbMessage, pbMessage);
  if(fVerbose) { PrintHexDump(cbMessage, pbMessage); printf("\n"); }


  // Encrypt the HTTP request.
  Buffers[0].pvBuffer     = pbIoBuffer;                                // Pointer to buffer 1
  Buffers[0].cbBuffer     = Sizes.cbHeader;                        // length of header
  Buffers[0].BufferType   = SECBUFFER_STREAM_HEADER;    // Type of the buffer

  Buffers[1].pvBuffer     = pbMessage;                                // Pointer to buffer 2
  Buffers[1].cbBuffer     = cbMessage;                                // length of the message
  Buffers[1].BufferType   = SECBUFFER_DATA;                        // Type of the buffer
  
  Buffers[2].pvBuffer     = pbMessage + cbMessage;        // Pointer to buffer 3
  Buffers[2].cbBuffer     = Sizes.cbTrailer;                    // length of the trailor
  Buffers[2].BufferType   = SECBUFFER_STREAM_TRAILER;    // Type of the buffer

  Buffers[3].pvBuffer     = SECBUFFER_EMPTY;                    // Pointer to buffer 4
  Buffers[3].cbBuffer     = SECBUFFER_EMPTY;                    // length of buffer 4
  Buffers[3].BufferType   = SECBUFFER_EMPTY;                    // Type of the buffer 4


  Message.ulVersion       = SECBUFFER_VERSION;    // Version number
  Message.cBuffers        = 4;                                    // Number of buffers - must contain four SecBuffer structures.
  Message.pBuffers        = Buffers;                        // Pointer to array of buffers
  scRet = g_pSSPI->EncryptMessage(phContext, 0, &Message, 0); // must contain four SecBuffer structures.
  if(FAILED(scRet)) { printf("**** Error 0x%x returned by EncryptMessage\n", scRet); return scRet; }

  // Send the encrypted data to the server.                                            len                                                                         flags
  cbData = send( Socket, pbIoBuffer,    Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer,    0 );

  printf("%d bytes of encrypted data sent\n", cbData);
  if(fVerbose) { PrintHexDump(cbData, pbIoBuffer); printf("\n"); }

  return cbData; // send( Socket, pbIoBuffer,    Sizes.cbHeader + strlen(pbMessage) + Sizes.cbTrailer,  0 );
}


/*****************************************************************************/
static SECURITY_STATUS ReadDecrypt( SOCKET Socket, PCredHandle phCreds, CtxtHandle * phContext, PBYTE pbIoBuffer, DWORD    cbIoBufferLength )

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
      cbData = recv(Socket, pbIoBuffer + cbIoBuffer, cbIoBufferLength - cbIoBuffer, 0);
      if(cbData == SOCKET_ERROR)
      {
        printf("**** Error %d reading data from server\n", WSAGetLastError());
        scRet = SEC_E_INTERNAL_ERROR;
        break;
      }
      else if(cbData == 0) // Server disconnected.
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
        printf("%d bytes of (encrypted) application data received\n", cbData);
        if(fVerbose) { PrintHexDump(cbData, pbIoBuffer + cbIoBuffer); printf("\n"); }
        cbIoBuffer += cbData;
      }
    }

    // Decrypt the received data.
    Buffers[0].pvBuffer     = pbIoBuffer;
    Buffers[0].cbBuffer     = cbIoBuffer;
    Buffers[0].BufferType   = SECBUFFER_DATA;  // Initial Type of the buffer 1
    Buffers[1].BufferType   = SECBUFFER_EMPTY; // Initial Type of the buffer 2
    Buffers[2].BufferType   = SECBUFFER_EMPTY; // Initial Type of the buffer 3
    Buffers[3].BufferType   = SECBUFFER_EMPTY; // Initial Type of the buffer 4

    Message.ulVersion       = SECBUFFER_VERSION;    // Version number
    Message.cBuffers        = 4;                                    // Number of buffers - must contain four SecBuffer structures.
    Message.pBuffers        = Buffers;                        // Pointer to array of buffers
    
    scRet = g_pSSPI->DecryptMessage(phContext, &Message, 0, NULL);
    
    if( scRet == SEC_I_CONTEXT_EXPIRED ) break; // Server signalled end of session
    
    //      if( scRet == SEC_E_INCOMPLETE_MESSAGE - Input buffer has partial encrypted record, read more
    if( scRet != SEC_E_OK &&
        scRet != SEC_I_RENEGOTIATE &&
        scRet != SEC_I_CONTEXT_EXPIRED )
    { printf("**** DecryptMessage ");
      DisplaySECError((DWORD)scRet);
      return scRet; }

    // Locate data and (optional) extra buffers.
    pDataBuffer  = NULL;
    pExtraBuffer = NULL;
    
    for(i = 1; i < 4; i++)
    {
      if( pDataBuffer  == NULL && Buffers[i].BufferType == SECBUFFER_DATA  ) pDataBuffer  = &Buffers[i];
      if( pExtraBuffer == NULL && Buffers[i].BufferType == SECBUFFER_EXTRA ) pExtraBuffer = &Buffers[i];
    }


    // Display the decrypted data.
    if(pDataBuffer)
    {
      length = pDataBuffer->cbBuffer;
      if( length ) // check if last two chars are CR LF
      {
        buff = pDataBuffer->pvBuffer; // printf( "n-2= %d, n-1= %d \n", buff[length-2], buff[length-1] );
        printf("Decrypted data: %d bytes", length); PrintText( length, buff );
        if(fVerbose) { PrintHexDump(length, buff); printf("\n"); }
        if( buff[length-2] == 13 && buff[length-1] == 10 ) break; // printf("Found CRLF\n");
      }
    }

    // Move any "extra" data to the input buffer.
    if(pExtraBuffer)
    {
      MoveMemory(pbIoBuffer, pExtraBuffer->pvBuffer, pExtraBuffer->cbBuffer);
      cbIoBuffer = pExtraBuffer->cbBuffer; // printf("cbIoBuffer= %d  \n", cbIoBuffer);
    }
    else
    cbIoBuffer = 0;


    // The server wants to perform another handshake sequence.
    if(scRet == SEC_I_RENEGOTIATE)
    {
      printf("Server requested renegotiate!\n");
      scRet = ClientHandshakeLoop( Socket, phCreds, phContext, FALSE, &ExtraBuffer);
      if(scRet != SEC_E_OK) return scRet;

      if(ExtraBuffer.pvBuffer) // Move any "extra" data to the input buffer.
      {
        MoveMemory(pbIoBuffer, ExtraBuffer.pvBuffer, ExtraBuffer.cbBuffer);
        cbIoBuffer = ExtraBuffer.cbBuffer;
      }
    }
  } // Loop till CRLF is found at the end of the data

  return SEC_E_OK;
}



/*****************************************************************************/
static SECURITY_STATUS SMTPsession (SOCKET Socket, PCredHandle phCreds, CtxtHandle *phContext)
{
  SecPkgContext_StreamSizes Sizes;            // unsigned long cbBuffer;    // Size of the buffer, in bytes
  SECURITY_STATUS           scRet;            // unsigned long BufferType;  // Type of the buffer (below)        
  PBYTE                     pbIoBuffer;       // void    SEC_FAR * pvBuffer;   // Pointer to the buffer
  DWORD                     cbIoBufferLength, cbData;


  // Read stream encryption properties.
  scRet = g_pSSPI->QueryContextAttributes( phContext, SECPKG_ATTR_STREAM_SIZES, &Sizes );
  if(scRet != SEC_E_OK)
  { printf("**** Error 0x%x reading SECPKG_ATTR_STREAM_SIZES\n", scRet); return scRet; }

  // Create a buffer.
  cbIoBufferLength = Sizes.cbHeader  +  Sizes.cbMaximumMessage  +  Sizes.cbTrailer;
  pbIoBuffer       = LocalAlloc(LMEM_FIXED, cbIoBufferLength);
  if(pbIoBuffer == NULL) { printf("**** Out of memory (2)\n"); return SEC_E_INTERNAL_ERROR; }

  // Receive a Response
  scRet = ReadDecrypt( Socket, phCreds, phContext, pbIoBuffer, cbIoBufferLength );
  if( scRet != SEC_E_OK ) return scRet;

  // Build the request - must be < maximum message size
  sprintf( pbIoBuffer+Sizes.cbHeader, "%s",  "EHLO \r\n" ); // message begins after the header

  // Send a request.
  cbData = EncryptSend( Socket, phContext, pbIoBuffer, Sizes );
  if(cbData == SOCKET_ERROR || cbData == 0)
  { printf("**** Error %d sending data to server (3)\n",  WSAGetLastError()); return SEC_E_INTERNAL_ERROR; }  

  // Receive a Response
  scRet = ReadDecrypt( Socket, phCreds, phContext, pbIoBuffer, cbIoBufferLength );
  if( scRet != SEC_E_OK ) return scRet;

  // Build the request - must be < maximum message size
  sprintf( pbIoBuffer+Sizes.cbHeader, "%s",  "QUIT \r\n" ); // message begins after the header

  // Send a request.
  cbData = EncryptSend( Socket, phContext, pbIoBuffer, Sizes );
  if(cbData == SOCKET_ERROR || cbData == 0)
  { printf("**** Error %d sending data to server (3)\n",  WSAGetLastError()); return SEC_E_INTERNAL_ERROR; }  

  // Receive a Response
  scRet = ReadDecrypt( Socket, phCreds, phContext, pbIoBuffer, cbIoBufferLength );
  if( scRet != SEC_E_OK ) return scRet;

  return SEC_E_OK;
}

/*****************************************************************************/
void _cdecl main( int argc, char *argv[] )
{
  WSADATA WsaData;
  SOCKET  Socket = INVALID_SOCKET;

  CredHandle hClientCreds;
  CtxtHandle hContext;
  BOOL fCredsInitialized   = FALSE;
  BOOL fContextInitialized = FALSE;

  SecBuffer  ExtraData;
  SECURITY_STATUS Status;

  PCCERT_CONTEXT pRemoteCertContext = NULL;

  if( !LoadSecurityLibrary() )
  { printf("Error initializing the security library\n"); goto cleanup; } //
  printf("----- SSPI Initialized\n");


  // Initialize the WinSock subsystem.
  if(WSAStartup(0x0101, &WsaData) == SOCKET_ERROR) // Winsock.h
  { printf("Error %d returned by WSAStartup\n", GetLastError()); goto cleanup; } //
  printf("----- WinSock Initialized\n");


  // Create credentials.
  if(CreateCredentials(pszUser, &hClientCreds))
  { printf("Error creating credentials\n"); goto cleanup; }
  fCredsInitialized = TRUE; //
  printf("----- Credentials Initialized\n");


  // Connect to server.
  if(ConnectToServer(pszServerName, iPortNumber, &Socket))
  { printf("Error connecting to server\n"); goto cleanup; } //
  printf("----- Connectd To Server\n");



  // Perform handshake
  if( PerformClientHandshake( Socket, &hClientCreds, pszServerName, &hContext, &ExtraData ) )
  { printf("Error performing handshake\n"); goto cleanup; }
  fContextInitialized = TRUE; //
  printf("----- Client Handshake Performed\n");


  // Authenticate server's credentials. Get server's certificate.
  Status = g_pSSPI->QueryContextAttributes( &hContext, SECPKG_ATTR_REMOTE_CERT_CONTEXT, (PVOID)&pRemoteCertContext );
  if(Status != SEC_E_OK)
  { printf("Error 0x%x querying remote certificate\n", Status); goto cleanup; } //
  printf("----- Server Credentials Authenticated \n");


  // Display server certificate chain.
  DisplayCertChain( pRemoteCertContext, FALSE ); //
  printf("----- Certificate Chain Displayed \n");


  // Attempt to validate server certificate.
  Status = VerifyServerCertificate( pRemoteCertContext, pszServerName, 0 );
  if(Status) { printf("**** Error 0x%x authenticating server credentials!\n", Status); goto cleanup; }
  // The server certificate did not validate correctly. At this point, we cannot tell
  // if we are connecting to the correct server, or if we are connecting to a
  // "man in the middle" attack server - Best to just abort the connection.
  printf("----- Server Certificate Verified\n");



  // Free the server certificate context.
  CertFreeCertificateContext(pRemoteCertContext);
  pRemoteCertContext = NULL; //
  printf("----- Server certificate context released \n");


  // Display connection info.
  DisplayConnectionInfo(&hContext); //
  printf("----- Secure Connection Info\n");



  // Send Request, recover response. LPSTR pszRequest = "EHLO";
  if( SMTPsession( Socket, &hClientCreds, &hContext ) )
  { printf("Error SMTP Session \n"); goto cleanup; } //
  printf("----- SMTP session Complete \n");


  // Send a close_notify alert to the server and close down the connection.
  if(DisconnectFromServer(Socket, &hClientCreds, &hContext))
  { printf("Error disconnecting from server\n"); goto cleanup; }
  fContextInitialized = FALSE;
  Socket = INVALID_SOCKET; //
  printf("----- Disconnected From Server\n");




cleanup: //
  printf("----- Begin Cleanup\n");

  // Free the server certificate context.
  if(pRemoteCertContext)
  {
    CertFreeCertificateContext(pRemoteCertContext);
    pRemoteCertContext = NULL;
  }

  // Free SSPI context handle.
  if(fContextInitialized)
  {
    g_pSSPI->DeleteSecurityContext(&hContext);
    fContextInitialized = FALSE;
  }

  // Free SSPI credentials handle.
  if(fCredsInitialized)
  {
    g_pSSPI->FreeCredentialsHandle(&hClientCreds);
    fCredsInitialized = FALSE;
  }

  // Close socket.
  if(Socket != INVALID_SOCKET) closesocket(Socket);

  // Shutdown WinSock subsystem.
  WSACleanup();

  // Close "MY" certificate store.
  if(hMyCertStore) CertCloseStore(hMyCertStore, 0);

  UnloadSecurityLibrary();


  printf("----- All Done ----- \n");

}

DWORD            evt_cnt=0, sck_evt, ctrl_evt, stdin_evt, stdout_evt, proc_evt;
SOCKET           s, r;
HANDLE           evt[MAXIMUM_WAIT_OBJECTS];

int              af=AF_INET, secure=0, mode=0;

INPUT_DATA input;

struct sockaddr_in sin_ipv4;
struct sockaddr_in6 sin_ipv6;

int ai_addrlen;
SOCKADDR *ai_addr;

void cmd (void) 
{
  SECURITY_ATTRIBUTES sa;
  PROCESS_INFORMATION pi;
  STARTUPINFO         si;
  OVERLAPPED          lap;
  
  HANDLE              lh[4];
  DWORD               p, e, len;
  
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

            if (e == -1 || e == proc_evt || e == ctrl_evt) break;

            // is this socket event?
            if (e == sck_evt) 
            {
              //pkt.len=recv (s, pkt.buf, BUFSIZ, 0);
              if (recv_pkt () != RCV_ERR_OK) 
              break;
              
              WriteFile (lh[1], pkt.buf, pkt.len, &len, 0);
              p--;  // we're ready to read again.              
            } else
            
            // data from cmd.exe?
            if (e == stdout_evt) 
            {
              if (p == 0)  // still waiting for previous read to complete?
              {
                ReadFile (lh[2], pkt.buf, BUFSIZ, &pkt.len, &lap);
                p++;
              } else {
                if (!GetOverlappedResult (lh[2], &lap, &pkt.len, FALSE)) {
                  break;
                }
              }
              if (pkt.len != 0)
              {
                //send (s, (char*)pkt.buf, pkt.len, 0);
                if (send_pkt() != SND_ERR_OK) 
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

BOOL WINAPI HandlerRoutine (DWORD dwCtrlType)
{
  if (dwCtrlType != CTRL_C_EVENT) return FALSE;
  SetEvent (evt[ctrl_evt]);
  return TRUE;
}

void start_handler (void)
{
  evt[ctrl_evt = evt_cnt++] = CreateEvent (NULL, FALSE, FALSE, NULL);
  SetConsoleCtrlHandler (HandlerRoutine, TRUE);
}

void stop_handler (void)
{
  SetConsoleCtrlHandler (HandlerRoutine, FALSE);
  CloseHandle (evt[ctrl_evt]);
  evt_cnt--;
}

char *addr2ip (void)
{
  static char ip[64];
  DWORD ip_size=64;
  WSAAddressToString (ai_addr, ai_addrlen, NULL, (char*)ip, &ip_size);
  return ip;
}

const char *pwd="password goes here...";

int open_tcp (char host[], char port[])
{
  struct addrinfo *list, *e;
  struct addrinfo hints;
  BOOL bStatus=FALSE;
  
  ZeroMemory (&hints, sizeof (hints));

  hints.ai_family   = af;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  
  // get all resolvable addresses for this machine name
  if (getaddrinfo (host, port, &hints, &list) == 0) 
  {
    for (e=list; e!=NULL; e=e->ai_next) 
    {
      if (af==AF_INET) {
        memcpy (&sin_ipv4, e->ai_addr, e->ai_addrlen);
        ai_addr     = (SOCKADDR*)&sin_ipv4;        
      } else {
        memcpy (&sin_ipv6, e->ai_addr, e->ai_addrlen);
        ai_addr     = (SOCKADDR*)&sin_ipv6;
      }
      ai_addrlen = e->ai_addrlen;
      s=socket (af, SOCK_STREAM, IPPROTO_TCP);
      if (s!=SOCKET_ERROR) {
        evt[sck_evt = evt_cnt++] = WSACreateEvent ();
        bStatus=TRUE;
      }
      break;
    }
    freeaddrinfo (list);
  }
  return bStatus;
}

void close_tcp (void)
{
  shutdown (s, SD_BOTH);
  closesocket (s);
  CloseHandle (evt[sck_evt]);
  evt_cnt--;
}

void xstrerror (const char fmt[], ...) 
{
  char    *error;
  va_list arglist;
  char    buffer[2048];
  
  va_start (arglist, fmt);
  vsnprintf (buffer, sizeof(buffer) - 1, fmt, arglist);
  va_end (arglist);
  
  FormatMessage (
  FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
  NULL, GetLastError (), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
  (LPSTR)&error, 0, NULL);

  printf ("\n  [ %s : %s", buffer, error);
  LocalFree (error);
}

void usage (void) 
{  
  printf ("\n  usage: neptune <host> <port>\n");
  
  printf ("\n  press any key to continue . . .");
  fgetc (stdin);
  exit (0);
}

VOID ConsoleSetBufferWidth (SHORT X) {
  CONSOLE_SCREEN_BUFFER_INFO csbi;
  GetConsoleScreenBufferInfo (GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
  
  if (X <= csbi.dwSize.X) return;
  csbi.dwSize.X = X;
  SetConsoleScreenBufferSize (GetStdHandle(STD_OUTPUT_HANDLE), csbi.dwSize);
}

int main (int argc, char *argv[])
{
  char    *address=NULL, *port="80";   // default is 80
  int     i, n, bitlen=1024;        // default is 1024-bit
  char    opt;
  WSADATA wsa;
  
  ConsoleSetBufferWidth (300);
  
  puts ("\n  Neptune v0.1 - Copyleft (x) 2015 @Odzhan_\n");

  for (i=1; i<argc; i++) {
    if (argv[i][0]=='-'||argv[i][0]=='/') {
      opt=argv[i][1];
      switch (opt) {
      case 'l' :
        mode=1;
        break;
      default:
        usage ();
        break;
      }
    } else {
      // if value is within port range, save it
      n=strlen(argv[i]);
      if (n>0&&n<5) {
        n=atoi(argv[i]);
        if (n>0&&n<65535) { port=argv[i]; continue; }
      }
      // assume it's hostname or ip
      address=argv[i];
    }
  }
  
  WSAStartup (MAKEWORD(2,0), &wsa);
  
  if (open_tcp (address, port)) {
    start_handler ();
    if (mode==0) {
      client ();
    } else {
      server ();
    }
    stop_handler ();
    close_tcp ();
  } else {
    printf ("\n  unable to resolve address for %s", address);
  }
  
  WSACleanup ();
  return 0;
}
