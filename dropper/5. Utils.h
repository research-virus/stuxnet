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

#ifndef __UTILS_H__
#define __UTILS_H__

#include "StdAfx.h"
#include "define.h"

INT32 SharedMapViewOfSection(HANDLE hHandle, SIZE_T iSectionSize, PHANDLE pSectionHandle, PVOID *pBaseAddr1, PVOID *pBaseAddr2);
void CopySegmentIntoSections(PVOID *pProcessSection, PVOID pModuleSection, INT32 *pSectionPointer, PSECTION_SEGEMENT_INFO sSegment, PVOID pSegmentContent, UINT32 iSegmentSize);
INT32 GetRandomModuleName(GENERAL_INFO_BLOCK *sInfoBlock, LPCWSTR szDebugLibraryName);

#endif