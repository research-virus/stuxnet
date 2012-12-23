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

#ifndef __ASSEMBLY_BLOCK1_H__
#define __ASSEMBLY_BLOCK1_H__

#include "9. AssemblyBlock2.h"

#define ASM_EMIT __asm _emit

#define ASM_ZwMapViewOfSection \
	ASM_EMIT 'Z' ASM_EMIT 'w' ASM_EMIT 'M' ASM_EMIT 'a' ASM_EMIT 'p' ASM_EMIT 'V' ASM_EMIT 'i' ASM_EMIT 'e' ASM_EMIT 'w'  ASM_EMIT 'O' ASM_EMIT 'f' ASM_EMIT 'S' ASM_EMIT 'e' ASM_EMIT 'c' ASM_EMIT 't' ASM_EMIT 'i' ASM_EMIT 'o' ASM_EMIT 'n' ASM_EMIT '\0'

#define ASM_ZwCreateSection \
	ASM_EMIT 'Z' ASM_EMIT 'w' ASM_EMIT 'C' ASM_EMIT 'r' ASM_EMIT 'e' ASM_EMIT 'a' ASM_EMIT 't' ASM_EMIT 'e' ASM_EMIT 'S' ASM_EMIT 'e' ASM_EMIT 'c' ASM_EMIT 't' ASM_EMIT 'i' ASM_EMIT 'o' ASM_EMIT 'n' ASM_EMIT '\0'

#define ASM_ZwOpenFile \
	ASM_EMIT 'Z' ASM_EMIT 'w' ASM_EMIT 'O' ASM_EMIT 'p' ASM_EMIT 'e' ASM_EMIT 'n' ASM_EMIT 'F' ASM_EMIT 'i' ASM_EMIT 'l' ASM_EMIT 'e' ASM_EMIT '\0'

#define ASM_ZwClose \
	ASM_EMIT 'Z' ASM_EMIT 'w' ASM_EMIT 'C' ASM_EMIT 'l' ASM_EMIT 'o' ASM_EMIT 's' ASM_EMIT 'e' ASM_EMIT '\0'

#define ASM_ZwQueryAttributesFile \
	ASM_EMIT 'Z' ASM_EMIT 'w' ASM_EMIT 'Q' ASM_EMIT 'u' ASM_EMIT 'e' ASM_EMIT 'r' ASM_EMIT 'y' ASM_EMIT 'A' ASM_EMIT 't'  ASM_EMIT 't' ASM_EMIT 'r' ASM_EMIT 'i' ASM_EMIT 'b' ASM_EMIT 'u' ASM_EMIT 't' ASM_EMIT 'e' ASM_EMIT 's' ASM_EMIT 'F' ASM_EMIT 'i' ASM_EMIT 'l' ASM_EMIT 'e' ASM_EMIT '\0'

#define ASM_ZwQuerySection \
	ASM_EMIT 'Z' ASM_EMIT 'w' ASM_EMIT 'Q' ASM_EMIT 'u' ASM_EMIT 'e' ASM_EMIT 'r' ASM_EMIT 'y' ASM_EMIT 'S' ASM_EMIT 'e' ASM_EMIT 'c' ASM_EMIT 't' ASM_EMIT 'i' ASM_EMIT 'o' ASM_EMIT 'n' ASM_EMIT '\0'

void __ASM_BLOCK1_0(void);
void __ASM_BLOCK1_1(void);
void __ASM_BLOCK1_2(void);
void __ASM_BLOCK1_3(void);
void __ASM_BLOCK1_4(void);
void __ASM_BLOCK1_5(void);
void __ASM_BLOCK1_6(void);

#endif