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

#ifndef __STUB_HANDLER_H__
#define __STUB_HANDLER_H__

#include "StdAfx.h"

typedef struct SCoreHeader {
	DWORD HeaderLength;		// 552
	DWORD SectionLength;	// 498176
	DWORD FullLength;		// 498728
	DWORD dw4;				// 90
	DWORD dw5;				// 498818 (FullLength + dw4)
	DWORD dw6;				// 4587
	DWORD dw7[130];			// {0}
	DWORD dw137;			// 1
	DWORD dw138;			// 0
} TCoreHeader;

void Core_Load(void);
void Core_Crypt(BYTE *lpStream, DWORD dwLength);
BOOL Core_GetDLL(LPVOID *ppCore, INT32 *pCoreLen);

#endif