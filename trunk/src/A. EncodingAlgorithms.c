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

#include "A. EncodingAlgorithms.h"

// 85% (C) CODE MATCH -> [CODE OK]
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

// 70% (C) CODE MATCH -> [CODE OK]
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

// 100% (C) CODE MATCH
HMODULE GetModuleNTDLL(void)
{
	WCHAR ModuleName[100]; // [sp+0h] [bp-C8h]@1

	DecodeModuleNameW(ENCODED_NTDLL_DLL, ModuleName);
	return GetModuleHandleW(ModuleName);
}

// 100% (C) CODE MATCH
FARPROC GetFunctionFromModule(const WCHAR *pEncodedModuleName, const char *pEncodedFunctionName)
{
	WCHAR pDecodedModuleName[100]; // [sp+0h] [bp-12Ch]@1
	CHAR ProcName[100]; // [sp+C8h] [bp-64h]@1

	DecodeModuleNameW(pEncodedModuleName, pDecodedModuleName);
	DecodeModuleNameA(pEncodedFunctionName, ProcName);
	
	return GetProcAddress(GetModuleHandleW(pDecodedModuleName), ProcName);
}
