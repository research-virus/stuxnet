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

#ifndef __ASSEMBLY_BLOCK2_H__
#define __ASSEMBLY_BLOCK2_H__

#include "define.h"

typedef int      (WINAPI *_tlstrcmpiW)(LPCWSTR, LPCWSTR);
typedef SIZE_T   (WINAPI *_tVirtualQuery)(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
typedef BOOL     (WINAPI *_tVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef FARPROC  (WINAPI *_tGetProcAddress)(HMODULE, LPCSTR);
typedef LPVOID   (WINAPI *_tMapViewOfFile)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL     (WINAPI *_tUnmapViewOfFile)(LPCVOID);
typedef BOOL     (WINAPI *_tFlushInstructionCache)(HANDLE, LPCVOID, SIZE_T);
typedef HMODULE  (WINAPI *_tLoadLibraryW)(LPCWSTR);
typedef BOOL     (WINAPI *_tFreeLibrary)(HMODULE);
typedef NTSTATUS (WINAPI *_tZwCreateSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS (WINAPI *_tZwMapViewOfSection)(HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);
typedef HANDLE   (WINAPI *_tCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD    (WINAPI *_tWaitForSingleObject)(HANDLE, DWORD);
typedef BOOL     (WINAPI *_tGetExitCodeThread)(HANDLE, LPDWORD);
typedef NTSTATUS (WINAPI *_tZwClose)(HANDLE);

typedef struct _HARDCODED_ADDRESSES {
	const HMODULE NTDLL_DLL;
	const HMODULE EMPTY_PTR;

	const _tlstrcmpiW             lstrcmpiW;
	const _tVirtualQuery          VirtualQuery;
	const _tVirtualProtect        VirtualProtect;
	const _tGetProcAddress        GetProcAddress;
	const _tMapViewOfFile         MapViewOfFile;
	const _tUnmapViewOfFile       UnmapViewOfFile;
	const _tFlushInstructionCache FlushInstructionCache;
	const _tLoadLibraryW          LoadLibraryW;
	const _tFreeLibrary           FreeLibrary;
	const _tZwCreateSection       ZwCreateSection;
	const _tZwMapViewOfSection    ZwMapViewOfSection;
	const _tCreateThread          CreateThread;
	const _tWaitForSingleObject   WaitForSingleObject;
	const _tGetExitCodeThread     GetExitCodeThread;
	const _tZwClose               ZwClose;
} HARDCODED_ADDRESSES, *PHARDCODED_ADDRESSES;

HARDCODED_ADDRESSES g_hardAddrs;

void __ASM_REF_3(void);
void __ASM_REF_4(void);
void __ASM_REF_5(void);
void __ASM_REF_6(void);
void __ASM_REF_7(void);

#endif