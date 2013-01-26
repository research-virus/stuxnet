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

#ifndef DEFINE_H
#define DEFINE_H

#include <windows.h>

#define _QWORD UINT64
#define _DWORD UINT32
#define _WORD  USHORT
#define _BYTE  UCHAR
#define bool   BOOL

#define __usercall _cdecl
#define __thiscall _cdecl // (?)

#define NTSTATUS                     ULONG
#define STATUS_SUCCESS               0x00000000
#define STATUS_INFO_LENGTH_MISMATCH  0xC0000004
#define STATUS_ACCESS_DENIED         0xC0000022
#define STATUS_BUFFER_OVERFLOW       0x80000005
#define STATUS_CONFLICTING_ADDRESSES 0xC0000018

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

typedef void (*__tLibraryExecEntry)(DWORD, INT32);
typedef NTSTATUS (*__tAlignAddresses)(PIMAGE_DOS_HEADER *);

typedef struct _GENERAL_INFO_BLOCK {
	DWORD  OriginalAddress;
	UINT32 UnknownZero0;
	HANDLE MappedAddress;
	DWORD  AlignAddressesFunction;
	WCHAR  RandomLibraryName[32];
	UINT32 AbsoluteEntryPoint;
	UINT32 UnknownZero1;
	UINT32 SizeOfStackReserve;
	UINT32 SizeOfStackCommit;
	UINT32 Subsystem;
	UINT16 MinorSubsystemVersion;
	UINT16 MajorSubsystemVersion;
	UINT32 UnknownZero2;
	UINT16 Charactersitics;
	UINT16 DllCharacteristics;
	UINT16 Machine;
	UINT8  UnknownOne;
	UINT8  UnknownFour;
	UINT32 LoaderFlags;
	UINT32 VirusModuleSize;
	UINT32 UnknownZero3;
} GENERAL_INFO_BLOCK, *PGENERAL_INFO_BLOCK;

#define MZ_HEADER 0x5A4D
#define PE_HEADER 0x4550

#define _SIZE(x, y) (UINT32)((UINT32)x - (UINT32)y)

#define XADDR_KEY 0xAE1979DD

typedef struct _SECTION_SEGEMENT_INFO {
	DWORD SegmentAddress;
	DWORD SegmentSize;
} SECTION_SEGEMENT_INFO, *PSECTION_SEGEMENT_INFO;

typedef struct _VIRUS_MODULE_BLOCKS_HEADER {
	GENERAL_INFO_BLOCK    InformationBlock;
	HMODULE               VirusModulePointer;
	SECTION_SEGEMENT_INFO UnknownSegment;
	SECTION_SEGEMENT_INFO VirusModuleSegment;
	INT32                 LibraryExecuteEntryNumber;
} VIRUS_MODULE_BLOCKS_HEADER, *PVIRUS_MODULE_BLOCKS_HEADER;

typedef struct _ASM_CODE_BLOCKS_HEADER {
	DWORD                 ExecuteLibrary;
	DWORD                 AlignAddresses;
	SECTION_SEGEMENT_INFO ASMBlock1Segment;
	SECTION_SEGEMENT_INFO CodeBlockSegment;
	SECTION_SEGEMENT_INFO ASMBlock0Segment;
	DWORD                 VirusModuleSection;
} ASM_CODE_BLOCKS_HEADER, *PASM_CODE_BLOCKS_HEADER;

#endif // DEFINE_H