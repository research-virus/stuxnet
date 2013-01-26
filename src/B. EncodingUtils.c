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

#include "B. EncodingUtils.h"

// 100% (ASM) CODE MATCH
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

// 100% (C) CODE MATCH
FARPROC GetFunctionFromKERNEL32(const char *pEncodedFunctionName)
{
	return GetFunctionFromModule(ENCODED_KERNEL32_DLL, pEncodedFunctionName);
}

// 100% (C) CODE MATCH
FARPROC GetFunctionFromNTDLL(const char *pEncodedFunctionName)
{
	return GetFunctionFromModule(ENCODED_NTDLL_DLL, pEncodedFunctionName);
}