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

#ifndef __ENCODING_UTILS_H__
#define __ENCODING_UTILS_H__

#include "data.h"
#include "A. EncodingAlgorithms.h"

void __memcpy(void *pDestination, const void *pSource, size_t iSize);

FARPROC GetFunctionFromKERNEL32(const char *pEncodedFunctionName);
FARPROC GetFunctionFromNTDLL(const char *pEncodedFunctionName);

#endif