#include <napi.h>
#define _UNICODE 1
#define UNICODE 1

#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <strsafe.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment (lib, "wintrust")

#define ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)

typedef struct {
	LPWSTR lpszProgramName;
	LPWSTR lpszPublisherLink;
	LPWSTR lpszMoreInfoLink;
} SPROG_PUBLISHERINFO, *PSPROG_PUBLISHERINFO;

typedef struct {
	LPWSTR lpszSubjectName;
	LPWSTR lpszIssuerName;
	LPWSTR lpszSerialNumber;
} SIGNING_CERT_INFO, *PSIGNING_CERT_INFO;

BOOL GetProgAndPublisherInfo(PCMSG_SIGNER_INFO pSignerInfo,
	PSPROG_PUBLISHERINFO Info);
BOOL GetDateOfTimeStamp(PCMSG_SIGNER_INFO pSignerInfo, FILETIME* outFt);
BOOL GetCertificateInfo(PCCERT_CONTEXT pCertContext, PSIGNING_CERT_INFO pSigningCertInfo);
BOOL GetTimeStampSignerInfo(PCMSG_SIGNER_INFO pSignerInfo,
	PCMSG_SIGNER_INFO* pCounterSignerInfo);

/*
Resources:
https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--verifying-the-signature-of-a-pe-file
https://docs.microsoft.com/en-us/troubleshoot/windows/win32/get-information-authenticode-signed-executables
https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-creating-a-certificate-chain
*/

BOOL VerifyEmbeddedSignature(LPCWSTR pwszSourceFile) {
	LONG lStatus;
	DWORD dwLastError;

	WINTRUST_FILE_INFO FileData;
	ZeroMemory(&FileData, sizeof(FileData));
	FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
	FileData.pcwszFilePath = pwszSourceFile;
	FileData.hFile = NULL;
	FileData.pgKnownSubject = NULL;

	GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

	WINTRUST_DATA WinTrustData;
	ZeroMemory(&WinTrustData, sizeof(WinTrustData));
	WinTrustData.cbStruct = sizeof(WinTrustData);
	WinTrustData.pPolicyCallbackData = NULL;
	WinTrustData.dwUIChoice = WTD_UI_NONE;
	// Perform revocation checking on entire chain
	WinTrustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
	WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
	WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
	WinTrustData.hWVTStateData = NULL;
	WinTrustData.pwszURLReference = NULL;
	WinTrustData.dwUIContext = 0;
	WinTrustData.pFile = &FileData;

	lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

	switch (lStatus)
	{
	case ERROR_SUCCESS:
		/*
		Signed file:
			- Hash that represents the subject is trusted.

			- Trusted publisher without any verification errors.

			- UI was disabled in dwUIChoice. No publisher or
				time stamp chain errors.

			- UI was enabled in dwUIChoice and the user clicked
				"Yes" when asked to install and run the signed
				subject.
		*/
		wprintf_s(L"The file \"%s\" is signed and the signature "
			L"was verified.\n",
			pwszSourceFile);
		break;

	case TRUST_E_NOSIGNATURE:
		// The file was not signed or had a signature 
		// that was not valid.

		// Get the reason for no signature.
		dwLastError = GetLastError();
		if (TRUST_E_NOSIGNATURE == dwLastError ||
			TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
			TRUST_E_PROVIDER_UNKNOWN == dwLastError)
		{
			// The file was not signed.
			wprintf_s(L"The file \"%s\" is not signed.\n",
				pwszSourceFile);
		}
		else
		{
			// The signature was not valid or there was an error 
			// opening the file.
			wprintf_s(L"An unknown error occurred trying to "
				L"verify the signature of the \"%s\" file.\n",
				pwszSourceFile);
		}

		break;

	case TRUST_E_EXPLICIT_DISTRUST:
		// The hash that represents the subject or the publisher 
		// is not allowed by the admin or user.
		wprintf_s(L"The signature is present, but specifically "
			L"disallowed.\n");
		break;

	case TRUST_E_SUBJECT_NOT_TRUSTED:
		// The user clicked "No" when asked to install and run.
		wprintf_s(L"The signature is present, but not "
			L"trusted.\n");
		break;

	case CRYPT_E_SECURITY_SETTINGS:
		/*
		The hash that represents the subject or the publisher
		was not explicitly trusted by the admin and the
		admin policy has disabled user trust. No signature,
		publisher or time stamp errors.
		*/
		wprintf_s(L"CRYPT_E_SECURITY_SETTINGS - The hash "
			L"representing the subject or the publisher wasn't "
			L"explicitly trusted by the admin and admin policy "
			L"has disabled user trust. No signature, publisher "
			L"or timestamp errors.\n");
		break;

	default:
		// The UI was disabled in dwUIChoice or the admin policy 
		// has disabled user trust. lStatus contains the 
		// publisher or time stamp chain error.
		wprintf_s(L"Error is: 0x%x.\n", lStatus);
		break;
	}

	WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

	lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

	return true;
}

std::wstring StringToWideString(const std::string &str) {
	if (str.empty())
		return std::wstring();
	int wstr_size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
	std::wstring wstr;
	if (wstr_size) {
		wstr.resize(wstr_size);
		if (MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], wstr_size)) {
			return wstr;
		}
	}
	return std::wstring();
}

BOOL VerifyCertificateChain(LPWSTR lpszFileName, LPWSTR lpszSubjectName, LPWSTR lpszIssuerName, LPWSTR lpszSerialNumber)
{
	WCHAR szFileName[MAX_PATH];
	HCERTSTORE hStore = NULL;
	HCRYPTMSG hMsg = NULL;
	PCCERT_CONTEXT pCertContext = NULL;
	PCCERT_CONTEXT pTSCertContext = NULL;
	BOOL fResult = FALSE;
	DWORD dwEncoding, dwContentType, dwFormatType;
	PCMSG_SIGNER_INFO pSignerInfo = NULL;
	PCMSG_SIGNER_INFO pCounterSignerInfo = NULL;
	DWORD dwSignerInfo;
	CERT_INFO CertInfo;
	CERT_INFO TSCertInfo;
	SPROG_PUBLISHERINFO ProgPubInfo;
	FILETIME ft;
	CERT_CHAIN_PARA ChainPara;
	CERT_USAGE_MATCH CertUsage;
	CERT_ENHKEY_USAGE EnhKeyUsage;
	PCCERT_CHAIN_CONTEXT pChainContext = NULL;
	CERT_CHAIN_POLICY_PARA PolicyPara;
	CERT_CHAIN_POLICY_STATUS PolicyStatus;
	SIGNING_CERT_INFO SigningCertInfo;

	ZeroMemory(&ProgPubInfo, sizeof(ProgPubInfo));
	ZeroMemory(&SigningCertInfo, sizeof(SigningCertInfo));
	__try
	{

# ifdef UNICODE
		if (FAILED(StringCchCopy(szFileName, MAX_PATH, lpszFileName)))
		{
			__leave;
		}
#else
		if (mbstowcs(szFileName, argv[1], MAX_PATH) == -1)
		{
			printf("Unable to convert to unicode.\n");
			__leave;
		}
#endif

		// Get message handle and store handle from the signed file.
		fResult = CryptQueryObject(CERT_QUERY_OBJECT_FILE,
			szFileName,
			CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
			CERT_QUERY_FORMAT_FLAG_BINARY,
			0,
			&dwEncoding,
			&dwContentType,
			&dwFormatType,
			&hStore,
			&hMsg,
			NULL);
		if (!fResult)
		{
			_tprintf(_T("CryptQueryObject failed with %x\n"), GetLastError());
			__leave;
		}

		// Get signer information size.
		fResult = CryptMsgGetParam(hMsg,
			CMSG_SIGNER_INFO_PARAM,
			0,
			NULL,
			&dwSignerInfo);
		if (!fResult)
		{
			_tprintf(_T("CryptMsgGetParam failed with %x\n"), GetLastError());
			__leave;
		}

		// Allocate memory for signer information.
		pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSignerInfo);
		if (!pSignerInfo)
		{
			_tprintf(_T("Unable to allocate memory for Signer Info.\n"));
			__leave;
		}

		// Get Signer Information.
		fResult = CryptMsgGetParam(hMsg,
			CMSG_SIGNER_INFO_PARAM,
			0,
			(PVOID)pSignerInfo,
			&dwSignerInfo);
		if (!fResult)
		{
			_tprintf(_T("CryptMsgGetParam failed with %x\n"), GetLastError());
			__leave;
		}

		// Search for the signer certificate in the temporary 
		// certificate store.
		CertInfo.Issuer = pSignerInfo->Issuer;
		CertInfo.SerialNumber = pSignerInfo->SerialNumber;

		pCertContext = CertFindCertificateInStore(hStore,
			ENCODING,
			0,
			CERT_FIND_SUBJECT_CERT,
			(PVOID)& CertInfo,
			NULL);
		if (!pCertContext)
		{
			_tprintf(_T("CertFindCertificateInStore failed with %x\n"),
				GetLastError());
			__leave;
		}

		// Get and print Signer certificate information.
		_tprintf(_T("Signer Certificate:\n\n"));
		GetCertificateInfo(pCertContext, &SigningCertInfo);
		_tprintf(_T("\n"));

		// Get the timestamp certificate signerinfo structure.
		if (!GetTimeStampSignerInfo(pSignerInfo, &pCounterSignerInfo))
		{
			_tprintf(_T("GetTimeStampSignerInfo failed with %x\n"),
				GetLastError());
			__leave;
		}

		// Search for Timestamp certificate in the temporary
		// certificate store.
		TSCertInfo.Issuer = pCounterSignerInfo->Issuer;
		TSCertInfo.SerialNumber = pCounterSignerInfo->SerialNumber;

		pTSCertContext = CertFindCertificateInStore(hStore,
			ENCODING,
			0,
			CERT_FIND_SUBJECT_CERT,
			(PVOID)& CertInfo,
			NULL);
		if (!pTSCertContext)
		{
			_tprintf(_T("CertFindCertificateInStore failed with %x\n"),
				GetLastError());
			__leave;
		}

		// Find Date of timestamp.
		if (!GetDateOfTimeStamp(pCounterSignerInfo, &ft))
		{
			_tprintf(_T("GetDateOfTimeStamp failed with %x\n"),
				GetLastError());
			__leave;
		}
		_tprintf(_T("\n"));

		// Build the ChainPara and related structs
		EnhKeyUsage.cUsageIdentifier = 0;
		EnhKeyUsage.rgpszUsageIdentifier = NULL;
		CertUsage.dwType = USAGE_MATCH_TYPE_AND;
		CertUsage.Usage = EnhKeyUsage;
		ChainPara.cbSize = sizeof(CERT_CHAIN_PARA);
		ChainPara.RequestedUsage = CertUsage;

		fResult = CertGetCertificateChain(NULL,
			pCertContext,
			&ft,
			NULL,
			&ChainPara,
			CERT_CHAIN_TIMESTAMP_TIME | CERT_CHAIN_REVOCATION_CHECK_CHAIN,
			NULL,
			&pChainContext);

		if (!fResult)
		{
			_tprintf(_T("CertGetCertificateChain failed with %x\n"),
				GetLastError());
			__leave;
		}

		printf("The size of the chain context "
			"is %d. \n", pChainContext->cbSize);
		printf("%d simple chains found.\n", pChainContext->cChain);
		printf("\nError status for the chain:\n");

		switch (pChainContext->TrustStatus.dwErrorStatus)
		{
		case CERT_TRUST_NO_ERROR:
			printf("No error found for this certificate or chain.\n");
			break;
		case CERT_TRUST_IS_NOT_TIME_VALID:
			printf("This certificate or one of the certificates in the "
				"certificate chain is not time-valid.\n");
			break;
		case CERT_TRUST_IS_REVOKED:
			printf("Trust for this certificate or one of the certificates "
				"in the certificate chain has been revoked.\n");
			break;
		case CERT_TRUST_IS_NOT_SIGNATURE_VALID:
			printf("The certificate or one of the certificates in the "
				"certificate chain does not have a valid signature.\n");
			break;
		case CERT_TRUST_IS_NOT_VALID_FOR_USAGE:
			printf("The certificate or certificate chain is not valid "
				"in its proposed usage.\n");
			break;
		case CERT_TRUST_IS_UNTRUSTED_ROOT:
			printf("The certificate or certificate chain is based "
				"on an untrusted root.\n");
			break;
		case CERT_TRUST_REVOCATION_STATUS_UNKNOWN:
			printf("The revocation status of the certificate or one of the"
				"certificates in the certificate chain is unknown.\n");
			break;
		case CERT_TRUST_IS_CYCLIC:
			printf("One of the certificates in the chain was issued by a "
				"certification authority that the original certificate "
				"had certified.\n");
			break;
		case CERT_TRUST_IS_PARTIAL_CHAIN:
			printf("The certificate chain is not complete.\n");
			break;
		case CERT_TRUST_CTL_IS_NOT_TIME_VALID:
			printf("A CTL used to create this chain was not time-valid.\n");
			break;
		case CERT_TRUST_CTL_IS_NOT_SIGNATURE_VALID:
			printf("A CTL used to create this chain did not have a valid "
				"signature.\n");
			break;
		case CERT_TRUST_CTL_IS_NOT_VALID_FOR_USAGE:
			printf("A CTL used to create this chain is not valid for this "
				"usage.\n");
		} // End switch

		if (pChainContext->TrustStatus.dwErrorStatus != CERT_TRUST_NO_ERROR)
		{
			printf("Error");
			__leave;
		}

		PolicyPara.dwFlags = 0;
		PolicyPara.cbSize = sizeof(CERT_CHAIN_POLICY_PARA);
		PolicyPara.pvExtraPolicyPara = NULL;
		PolicyStatus.cbSize = sizeof(CERT_CHAIN_POLICY_STATUS);
		PolicyStatus.pvExtraPolicyStatus = NULL;

		// Authenticode chain policy
		fResult = CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_AUTHENTICODE,
			pChainContext,
			&PolicyPara,
			&PolicyStatus);

		if (!fResult)
		{
			_tprintf(_T("CertVerifyCertificateChainPolicy with Authenticode chain policy failed with %x\n"),
				GetLastError());
			__leave;
		}

		printf("\nAuthenticode chain verification status:\n");
		if (PolicyStatus.dwError != ERROR_SUCCESS)
		{
			printf("Error: %d", PolicyStatus.dwError);
			__leave;
		}
		printf("Success");

		// Authenticode timestamp chain policy
		fResult = CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_AUTHENTICODE_TS,
			pChainContext,
			&PolicyPara,
			&PolicyStatus);

		if (!fResult)
		{
			_tprintf(_T("CertVerifyCertificateChainPolicy with Authenticode TS chain policy failed with %x\n"),
				GetLastError());
			__leave;
		}

		fResult = FALSE;

		printf("\nAuthenticode TS chain verification status:\n");
		if (PolicyStatus.dwError != ERROR_SUCCESS)
		{
			printf("Error: %d", PolicyStatus.dwError);
			__leave;
		}
		printf("Success");

		// Verify subject name, issuer name, and serial number
		if (lstrcmp(SigningCertInfo.lpszSubjectName, lpszSubjectName) != 0)
		{
			printf("Subject name does not match, %ws", lpszSubjectName);
			__leave;
		}

		if (lstrcmp(SigningCertInfo.lpszIssuerName, lpszIssuerName) != 0)
		{
			printf("Issuer name does not match, %ws", SigningCertInfo.lpszIssuerName);
			__leave;
		}

		if (lstrcmp(SigningCertInfo.lpszSerialNumber, lpszSerialNumber) != 0)
		{
			printf("Serial number name does not match, %ws", SigningCertInfo.lpszSerialNumber);
			__leave;
		}

		printf("\nCertificate details match\n");

		fResult = TRUE;

	}
	__finally
	{
		// Clean up.
		if (ProgPubInfo.lpszProgramName != NULL)
			LocalFree(ProgPubInfo.lpszProgramName);
		if (ProgPubInfo.lpszPublisherLink != NULL)
			LocalFree(ProgPubInfo.lpszPublisherLink);
		if (ProgPubInfo.lpszMoreInfoLink != NULL)
			LocalFree(ProgPubInfo.lpszMoreInfoLink);

		if (SigningCertInfo.lpszSubjectName != NULL)
			LocalFree(SigningCertInfo.lpszSubjectName);
		if (SigningCertInfo.lpszIssuerName != NULL)
			LocalFree(SigningCertInfo.lpszIssuerName);
		if (SigningCertInfo.lpszSerialNumber != NULL)
			LocalFree(SigningCertInfo.lpszSerialNumber);

		if (pSignerInfo != NULL) LocalFree(pSignerInfo);
		if (pCounterSignerInfo != NULL) LocalFree(pCounterSignerInfo);
		if (pCertContext != NULL) CertFreeCertificateContext(pCertContext);
		if (pChainContext != NULL) CertFreeCertificateChain(pChainContext);
		if (hStore != NULL) CertCloseStore(hStore, 0);
		if (hMsg != NULL) CryptMsgClose(hMsg);
	}
	return fResult;
}

LPWSTR AllocateAndCopyWideString(LPCWSTR inputString)
{
	LPWSTR outputString = NULL;

	outputString = (LPWSTR)LocalAlloc(LPTR,
		(wcslen(inputString) + 1) * sizeof(WCHAR));
	if (outputString != NULL)
	{
		lstrcpyW(outputString, inputString);
	}
	return outputString;
}

BOOL GetCertificateInfo(PCCERT_CONTEXT pCertContext, PSIGNING_CERT_INFO pSigningCertInfo)
{
	BOOL fReturn = FALSE;
	LPTSTR szName = NULL;
	LPTSTR szSerialNum = NULL;
	BYTE* pbSerialNum = NULL;
	DWORD dwData = 0;

	__try
	{
		// Reverse the serial number (Windows has it backwards for some reason)
		BYTE temp;
		dwData = pCertContext->pCertInfo->SerialNumber.cbData;
		pbSerialNum = (BYTE*)malloc(dwData * sizeof(BYTE));
		memcpy_s(pbSerialNum, dwData * sizeof(BYTE), pCertContext->pCertInfo->SerialNumber.pbData, dwData * sizeof(BYTE));
		for (DWORD i = 0; i < dwData / 2; i++)
		{
			temp = pbSerialNum[i];
			pbSerialNum[i] = pbSerialNum[dwData - i - 1];
			pbSerialNum[dwData - i - 1] = temp;
		}

		// Convert to hex string
		CryptBinaryToString(pbSerialNum,
			pCertContext->pCertInfo->SerialNumber.cbData,
			CRYPT_STRING_HEX | CRYPT_STRING_NOCRLF,
			NULL,
			&dwData);

		szSerialNum = (LPTSTR)LocalAlloc(LPTR, dwData * sizeof(TCHAR));

		DWORD result = CryptBinaryToString(pbSerialNum,
			pCertContext->pCertInfo->SerialNumber.cbData,
			CRYPT_STRING_HEX | CRYPT_STRING_NOCRLF,
			szSerialNum,
			&dwData);

		if (!result) {
			_tprintf(_T("CertGetNameString failed.\n"));
			__leave;
		}

		// Print Serial Number
		_tprintf(_T("\n"));
		_tprintf(_T("Serial Number: %s\n"), szSerialNum);
		pSigningCertInfo->lpszSerialNumber = AllocateAndCopyWideString(szSerialNum);
		LocalFree(szSerialNum);
		szSerialNum = NULL;

		// Get Issuer name size.
		if (!(dwData = CertGetNameString(pCertContext,
			CERT_NAME_SIMPLE_DISPLAY_TYPE,
			CERT_NAME_ISSUER_FLAG,
			NULL,
			NULL,
			0)))
		{
			_tprintf(_T("CertGetNameString failed.\n"));
			__leave;
		}

		// Allocate memory for Issuer name.
		szName = (LPTSTR)LocalAlloc(LPTR, dwData * sizeof(TCHAR));
		if (!szName)
		{
			_tprintf(_T("Unable to allocate memory for issuer name.\n"));
			__leave;
		}

		// Get Issuer name.
		if (!(CertGetNameString(pCertContext,
			CERT_NAME_SIMPLE_DISPLAY_TYPE,
			CERT_NAME_ISSUER_FLAG,
			NULL,
			szName,
			dwData)))
		{
			_tprintf(_T("CertGetNameString failed.\n"));
			__leave;
		}

		// print Issuer name.
		_tprintf(_T("Issuer Name: %s\n"), szName);
		pSigningCertInfo->lpszIssuerName = AllocateAndCopyWideString(szName);
		LocalFree(szName);
		szName = NULL;

		// Get Subject name size.
		if (!(dwData = CertGetNameString(pCertContext,
			CERT_NAME_SIMPLE_DISPLAY_TYPE,
			0,
			NULL,
			NULL,
			0)))
		{
			_tprintf(_T("CertGetNameString failed.\n"));
			__leave;
		}

		// Allocate memory for subject name.
		szName = (LPTSTR)LocalAlloc(LPTR, dwData * sizeof(TCHAR));
		if (!szName)
		{
			_tprintf(_T("Unable to allocate memory for subject name.\n"));
			__leave;
		}

		// Get subject name.
		if (!(CertGetNameString(pCertContext,
			CERT_NAME_SIMPLE_DISPLAY_TYPE,
			0,
			NULL,
			szName,
			dwData)))
		{
			_tprintf(_T("CertGetNameString failed.\n"));
			__leave;
		}

		// Print Subject Name.
		_tprintf(_T("Subject Name: %s\n"), szName);
		pSigningCertInfo->lpszSubjectName = AllocateAndCopyWideString(szName);

		fReturn = TRUE;
	}
	__finally
	{
		if (szName != NULL) LocalFree(szName);
	}

	return fReturn;
}

BOOL GetProgAndPublisherInfo(PCMSG_SIGNER_INFO pSignerInfo,
	PSPROG_PUBLISHERINFO Info)
{
	BOOL fReturn = FALSE;
	PSPC_SP_OPUS_INFO OpusInfo = NULL;
	DWORD dwData;
	BOOL fResult;

	__try
	{
		// Loop through authenticated attributes and find
		// SPC_SP_OPUS_INFO_OBJID OID.
		for (DWORD n = 0; n < pSignerInfo->AuthAttrs.cAttr; n++)
		{
			if (lstrcmpA(SPC_SP_OPUS_INFO_OBJID,
				pSignerInfo->AuthAttrs.rgAttr[n].pszObjId) == 0)
			{
				// Get Size of SPC_SP_OPUS_INFO structure.
				fResult = CryptDecodeObject(ENCODING,
					SPC_SP_OPUS_INFO_OBJID,
					pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
					pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
					0,
					NULL,
					&dwData);
				if (!fResult)
				{
					_tprintf(_T("CryptDecodeObject failed with %x\n"),
						GetLastError());
					__leave;
				}

				// Allocate memory for SPC_SP_OPUS_INFO structure.
				OpusInfo = (PSPC_SP_OPUS_INFO)LocalAlloc(LPTR, dwData);
				if (!OpusInfo)
				{
					_tprintf(_T("Unable to allocate memory for Publisher Info.\n"));
					__leave;
				}

				// Decode and get SPC_SP_OPUS_INFO structure.
				fResult = CryptDecodeObject(ENCODING,
					SPC_SP_OPUS_INFO_OBJID,
					pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
					pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
					0,
					OpusInfo,
					&dwData);
				if (!fResult)
				{
					_tprintf(_T("CryptDecodeObject failed with %x\n"),
						GetLastError());
					__leave;
				}

				// Fill in Program Name if present.
				if (OpusInfo->pwszProgramName)
				{
					Info->lpszProgramName =
						AllocateAndCopyWideString(OpusInfo->pwszProgramName);
				}
				else
					Info->lpszProgramName = NULL;

				// Fill in Publisher Information if present.
				if (OpusInfo->pPublisherInfo)
				{

					switch (OpusInfo->pPublisherInfo->dwLinkChoice)
					{
					case SPC_URL_LINK_CHOICE:
						Info->lpszPublisherLink =
							AllocateAndCopyWideString(OpusInfo->pPublisherInfo->pwszUrl);
						break;

					case SPC_FILE_LINK_CHOICE:
						Info->lpszPublisherLink =
							AllocateAndCopyWideString(OpusInfo->pPublisherInfo->pwszFile);
						break;

					default:
						Info->lpszPublisherLink = NULL;
						break;
					}
				}
				else
				{
					Info->lpszPublisherLink = NULL;
				}

				// Fill in More Info if present.
				if (OpusInfo->pMoreInfo)
				{
					switch (OpusInfo->pMoreInfo->dwLinkChoice)
					{
					case SPC_URL_LINK_CHOICE:
						Info->lpszMoreInfoLink =
							AllocateAndCopyWideString(OpusInfo->pMoreInfo->pwszUrl);
						break;

					case SPC_FILE_LINK_CHOICE:
						Info->lpszMoreInfoLink =
							AllocateAndCopyWideString(OpusInfo->pMoreInfo->pwszFile);
						break;

					default:
						Info->lpszMoreInfoLink = NULL;
						break;
					}
				}
				else
				{
					Info->lpszMoreInfoLink = NULL;
				}

				fReturn = TRUE;

				break; // Break from for loop.
			} // lstrcmp SPC_SP_OPUS_INFO_OBJID 
		} // for 
	}
	__finally
	{
		if (OpusInfo != NULL) LocalFree(OpusInfo);
	}

	return fReturn;
}

BOOL GetDateOfTimeStamp(PCMSG_SIGNER_INFO pSignerInfo, FILETIME* outFt)
{
	BOOL fResult;
	FILETIME lft, ft;
	DWORD dwData;
	BOOL fReturn = FALSE;

	// Loop through authenticated attributes and find
	// szOID_RSA_signingTime OID.
	for (DWORD n = 0; n < pSignerInfo->AuthAttrs.cAttr; n++)
	{
		if (lstrcmpA(szOID_RSA_signingTime,
			pSignerInfo->AuthAttrs.rgAttr[n].pszObjId) == 0)
		{
			// Decode and get FILETIME structure.
			dwData = sizeof(ft);
			fResult = CryptDecodeObject(ENCODING,
				szOID_RSA_signingTime,
				pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
				pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
				0,
				(PVOID)& ft,
				&dwData);
			if (!fResult)
			{
				_tprintf(_T("CryptDecodeObject failed with %x\n"),
					GetLastError());
				break;
			}

			// Convert to local time.
			FileTimeToLocalFileTime(&ft, &lft);
			*outFt = lft;

			fReturn = TRUE;

			break; // Break from for loop.

		} //lstrcmp szOID_RSA_signingTime
	} // for 

	return fReturn;
}

BOOL GetTimeStampSignerInfo(PCMSG_SIGNER_INFO pSignerInfo, PCMSG_SIGNER_INFO* pCounterSignerInfo)
{
	PCCERT_CONTEXT pCertContext = NULL;
	BOOL fReturn = FALSE;
	BOOL fResult;
	DWORD dwSize;

	__try
	{
		*pCounterSignerInfo = NULL;

		// Loop through unathenticated attributes for
		// szOID_RSA_counterSign OID.
		for (DWORD n = 0; n < pSignerInfo->UnauthAttrs.cAttr; n++)
		{
			if (lstrcmpA(pSignerInfo->UnauthAttrs.rgAttr[n].pszObjId,
				szOID_RSA_counterSign) == 0)
			{
				// Get size of CMSG_SIGNER_INFO structure.
				fResult = CryptDecodeObject(ENCODING,
					PKCS7_SIGNER_INFO,
					pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
					pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
					0,
					NULL,
					&dwSize);
				if (!fResult)
				{
					_tprintf(_T("CryptDecodeObject failed with %x\n"),
						GetLastError());
					__leave;
				}

				// Allocate memory for CMSG_SIGNER_INFO.
				*pCounterSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSize);
				if (!*pCounterSignerInfo)
				{
					_tprintf(_T("Unable to allocate memory for timestamp info.\n"));
					__leave;
				}

				// Decode and get CMSG_SIGNER_INFO structure
				// for timestamp certificate.
				fResult = CryptDecodeObject(ENCODING,
					PKCS7_SIGNER_INFO,
					pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
					pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
					0,
					(PVOID)* pCounterSignerInfo,
					&dwSize);
				if (!fResult)
				{
					_tprintf(_T("CryptDecodeObject failed with %x\n"),
						GetLastError());
					__leave;
				}

				fReturn = TRUE;

				break; // Break from for loop.
			}
		}
	}
	__finally
	{
		// Clean up.
		if (pCertContext != NULL) CertFreeCertificateContext(pCertContext);
	}

	return fReturn;
}

Napi::Boolean Verify(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (info.Length() < 4) {
		Napi::TypeError::New(env, "Wrong number of arguments").ThrowAsJavaScriptException();
	}

	if (!info[0].IsString() || !info[1].IsString() || !info[2].IsString() || !info[3].IsString()) {
		Napi::TypeError::New(env, "Wrong arguments").ThrowAsJavaScriptException();
	}

	LPWSTR wPath = AllocateAndCopyWideString(StringToWideString(info[0].ToString().Utf8Value()).c_str());
	LPWSTR wExpectedSubjectName = AllocateAndCopyWideString(StringToWideString(info[1].ToString().Utf8Value()).c_str());
	LPWSTR wExpectedIssuerName = AllocateAndCopyWideString(StringToWideString(info[2].ToString().Utf8Value()).c_str());
	LPWSTR wExpectedSerialNumber = AllocateAndCopyWideString(StringToWideString(info[3].ToString().Utf8Value()).c_str());

	BOOL winTrustResult = VerifyEmbeddedSignature(wPath);
	BOOL chainResult = VerifyCertificateChain(wPath, wExpectedSubjectName, wExpectedIssuerName, wExpectedSerialNumber);

	LocalFree(wPath);
	LocalFree(wExpectedSubjectName);
	LocalFree(wExpectedIssuerName);
	LocalFree(wExpectedSerialNumber);

	return Napi::Boolean::New(env, winTrustResult && chainResult);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
	exports.Set(Napi::String::New(env, "verify"),
		Napi::Function::New(env, Verify));
	return exports;
}

NODE_API_MODULE(addon, Init)