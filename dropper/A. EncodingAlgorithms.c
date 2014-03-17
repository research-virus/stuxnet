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

#include "A. EncodingAlgorithms.h"
#include "config.h"

// 85% (C) CODE MATCH -> [CODE OK]
void DecodeModuleNameA(const WORD *lpEncoded, CHAR *lpszPlain)
{
	if(!lpEncoded)
	{
		*lpszPlain = 0;
		return;
	}
	
	for(; ; lpEncoded++, lpszPlain++)
	{
		*lpszPlain = *(BYTE*)lpEncoded ^ (BYTE)X_STRING_KEY;
		if(*(BYTE*)lpEncoded == (BYTE)X_STRING_KEY)
			break;
	}
}

// 70% (C) CODE MATCH -> [CODE OK]
void DecodeModuleNameW(const WORD *lpEncoded, WCHAR *lpszPlain)
{
	if(!lpEncoded)
	{
		*lpszPlain = 0;
		return;
	}
	
	for(; ; lpEncoded++, lpszPlain++)
	{
		*lpszPlain = *lpEncoded ^ X_STRING_KEY;
		if(*lpEncoded == X_STRING_KEY)
			break;
	}
}

const WORD ENCODED_NTDLL_DLL[10] =
{
	0xAE7C, 0xAE66, 0xAE76, 0xAE7E,
	0xAE7E, 0xAE3C, 0xAE76, 0xAE7E,
	0xAE7E, 0xAE12
};

// 100% (C) CODE MATCH
HMODULE GetModuleNTDLL(void)
{
	WCHAR szModuleName[100];

	DecodeModuleNameW(ENCODED_NTDLL_DLL, szModuleName);
	return GetModuleHandleW(szModuleName);
}

// 100% (C) CODE MATCH
FARPROC GetFunctionFromModule(const WORD *lpEncodedModule, const WORD *lpEncodedFunc)
{
	WCHAR szModule[100];
	CHAR szFunc[100];

	DecodeModuleNameW(lpEncodedModule, szModule);
	DecodeModuleNameA(lpEncodedFunc, szFunc);
	
	return GetProcAddress(GetModuleHandleW(szModule), szFunc);
}

// 100% (ASM) CODE MATCH
__declspec(naked) void __memcpy(void *lpTo, const void *lpFrom, size_t nSize)
{
	__asm {
		push    ebp
		mov     ebp, esp
		push    esi
		push    edi
		mov     edi, lpTo
		mov     esi, lpFrom
		mov     ecx, nSize
		rep movsb
		pop     edi
		pop     esi
		pop     ebp
		retn
	}
}

const WORD ENCODED_KERNEL32_DLL[13] =
{
	0xAE79, 0xAE77, 0xAE60, 0xAE7C,
	0xAE77, 0xAE7E, 0xAE21, 0xAE20,
	0xAE3C, 0xAE76, 0xAE7E, 0xAE7E,
	0xAE12
};

// 100% (C) CODE MATCH
FARPROC GetFunctionFromKERNEL32(const WORD *lpEncodedFunc)
{
	return GetFunctionFromModule(ENCODED_KERNEL32_DLL, lpEncodedFunc);
}

// 100% (C) CODE MATCH
FARPROC GetFunctionFromNTDLL(const WORD *lpEncodedFunc)
{
	return GetFunctionFromModule(ENCODED_NTDLL_DLL, lpEncodedFunc);
}