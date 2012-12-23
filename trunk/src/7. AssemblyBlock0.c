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

#include "7. AssemblyBlock0.h"

/*************************************************************************
** ASSEMBLY BLOCK 0.                                                    **
*************************************************************************/

void __declspec(naked) __ASM_BLOCK0_0(void)
{
	__asm
	{
		cmp     edx, [eax]
		dec     ecx
		stosd

		mov     dl, 0
		jmp     short __ASM_REF_0
		
		mov     dl, 1
		jmp     short __ASM_REF_0
		
		mov     dl, 2
		jmp     short __ASM_REF_0
		
		mov     dl, 3
		jmp     short __ASM_REF_0
		
		mov     dl, 4
		jmp     short __ASM_REF_0
		
		mov     dl, 5
		jmp     short $+2
		
	__ASM_REF_0:
		push    edx
		call    __ASM_BLOCK0_2
	}
}

void __declspec(naked) __ASM_BLOCK0_1(void)
{
	__asm
	{
		xchg    ebx, [ebx+0]
		add     [eax], dl
	}
}

void __declspec(naked) __ASM_BLOCK0_2(void)
{
	__asm
	{
		pop     edx
		jmp     dword ptr [edx]
	}
}