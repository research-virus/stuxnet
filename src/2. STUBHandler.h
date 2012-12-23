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

#ifndef __STUB_HANDLER_H__
#define __STUB_HANDLER_H__

#include "data.h"
#include "define.h"
#include "6. MemorySections.h"

#define STUB_INTEGRITY_MARK 0xAE39120D
#define STUB_HEADER_LEN     556

void LoadSTUBSection(void);
void DecryptSTUBSection(char *pSectionSTUB, UINT32 pSectionVirtualSize);
BOOL LocateSTUBSection(PVOID *pRawSectionSTUB, INT32 *pSectionVirtualSize);

#endif