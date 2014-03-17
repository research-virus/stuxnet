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

#ifndef __ENCODING_ALGORITHMS_H__
#define __ENCODING_ALGORITHMS_H__

#include "StdAfx.h"

void DecodeModuleNameA(const WORD *pEncodedFunctionName, char *pDecodedFunctionName);
void DecodeModuleNameW(const WORD *pEncodedModuleName, WCHAR *pDecodedModuleName);

HMODULE GetModuleNTDLL(void);

FARPROC GetFunctionFromModule(const WCHAR *pEncodedModuleName, const char *pEncodedFunctionName);

void __memcpy(void *lpTo, const void *lpFrom, size_t nSize);

FARPROC GetFunctionFromKERNEL32(const WORD *lpEncodedFunc);
FARPROC GetFunctionFromNTDLL(const WORD *lpEncodedFunc);

#endif