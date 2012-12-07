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


#ifndef DEFINE_H
#define DEFINE_H

#include <windows.h>

#define _QWORD UINT64
#define _DWORD UINT32
#define _WORD  USHORT
#define _BYTE  UCHAR
#define bool   BOOL

#ifndef NULL
	#define NULL 0
#endif

#define __usercall _cdecl
#define __thiscall _cdecl

#define NTSTATUS                    ULONG
#define STATUS_SUCCESS              0x00000000
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#define STATUS_ACCESS_DENIED        0xC0000022
#define STATUS_BUFFER_OVERFLOW      0x80000005

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
  ULONG Length;
  HANDLE RootDirectory;
  UNICODE_STRING *ObjectName;
  ULONG Attributes;
  PVOID SecurityDescriptor;
  PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

#define POBJECT_ATTRIBUTES OBJECT_ATTRIBUTES*

typedef enum _SECTION_INHERIT 
{ 
    ViewShare = 1, 
    ViewUnmap = 2 
} SECTION_INHERIT;

typedef void (*__tMainModuleInit)(int, int);

#define MZ_HEADER 0x5A4D
#define PE_HEADER 0x4550

typedef int      (*_tlstrcmpiW)(LPCWSTR, LPCWSTR);
typedef SIZE_T   (*_tVirtualQuery)(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
typedef BOOL     (*_tVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef FARPROC  (*_tGetProcAddress)(HMODULE, LPCSTR);
typedef LPVOID   (*_tMapViewOfFile)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL     (*_tUnmapViewOfFile)(LPCVOID);
typedef BOOL     (*_tFlushInstructionCache)(HANDLE, LPCVOID, SIZE_T);
typedef HMODULE  (*_tLoadLibraryW)(LPCWSTR);
typedef BOOL     (*_tFreeLibrary)(HMODULE);
typedef NTSTATUS (*_tZwCreateSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS (*_tZwMapViewOfSection)(HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);
typedef HANDLE   (*_tCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD    (*_tWaitForSingleObject)(HANDLE, DWORD);
typedef BOOL     (*_tGetExitCodeThread)(HANDLE, LPDWORD);
typedef NTSTATUS (*_tZwClose)(HANDLE);

#endif // DEFINE_H